"""Real local Distribution registry. Set CATS_TEST_RUNTIME_REGISTRY=1 to enable."""
from contextlib import ExitStack
import hashlib
import http.client
import json
import os
import ssl
import subprocess
from tempfile import TemporaryDirectory
from pathlib import Path
import time
from uuid import uuid4

import pytest

from app import release_oci
from app.runtime_candidates import RuntimeReleaseCandidate, assessment_for_review, reconcile
from app.runtime_registry_resolution import FAILURES, resolve_requests
from harbor_acceptance_stack import certificates
from test_runtime_candidates import application, runtime


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed: {result.stderr.strip()}')
    return result.stdout.strip()


@pytest.fixture
def isolated_registry(monkeypatch):
    name = 'cats-runtime-registry-' + uuid4().hex
    monkeypatch.setenv('no_proxy', '127.0.0.1')
    with ExitStack() as cleanup:
        directory = Path(cleanup.enter_context(TemporaryDirectory()))
        certificates(directory)
        tls = directory / 'tls'
        container = docker('create', '--pull=never', '--name', name, '--network', 'bridge',
                           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                           '--publish', '127.0.0.1::5000', '--tmpfs', '/var/lib/registry',
                           '--env', 'REGISTRY_HTTP_TLS_CERTIFICATE=/tmp/registry.crt',
                           '--env', 'REGISTRY_HTTP_TLS_KEY=/tmp/registry.key', 'registry:2.8.3')
        cleanup.callback(docker, 'rm', '--force', '--volumes', container)
        docker('cp', str(tls / 'source.crt'), container + ':/tmp/registry.crt')
        docker('cp', str(tls / 'source.key'), container + ':/tmp/registry.key')
        docker('start', container)
        host = docker('port', container, '5000/tcp')
        address, port = host.split(':')
        assert address == '127.0.0.1' and int(port) > 0
        ca_path = tls / 'ca.crt'
        context = ssl.create_default_context(cafile=str(ca_path))
        deadline = time.monotonic() + 12
        while True:
            probe = http.client.HTTPSConnection(address, int(port), context=context, timeout=1)
            try:
                probe.request('GET', '/v2/')
                assert probe.getresponse().status == 200
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
            finally:
                probe.close()
        yield host, ca_path


@pytest.mark.skipif(os.environ.get('CATS_TEST_RUNTIME_REGISTRY') != '1',
                    reason='requires a local Docker daemon with cached registry:2.8.3')
def test_service_mapped_runtime_manifest_resolution(runtime, isolated_registry):
    db, sessions, service, env, mapping = runtime
    host, ca = isolated_registry
    mapping.upstream.endpoint = 'https://' + host
    mapping.upstream.ca_pem = ca.read_text()
    repository = mapping.upstream_repository
    image = host + '/' + repository
    client = release_oci._Client(host, repository, {'SSL_CERT_FILE': str(ca)})
    config = client.upload(release_oci._json({'architecture': 'amd64', 'os': 'linux',
                           'rootfs': {'type': 'layers', 'diff_ids': []}}), 'application/vnd.oci.image.config.v1+json')
    manifest = release_oci._json({'schemaVersion': 2, 'mediaType': release_oci.MANIFEST_TYPE,
                                   'config': config, 'layers': []})
    manifest_digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
    status, headers, _ = client.request('PUT', client.api + '/manifests/smoke', body=manifest,
                                        media_type=release_oci.MANIFEST_TYPE)
    assert status == 201 and headers['Docker-Content-Digest'] == manifest_digest
    pin = image + '@' + manifest_digest

    def resolve(reference, image_id):
        app = application(image_id)
        app.components[0].update(image_ref=reference, desired_image=reference)
        before = reconcile(db, env, service, [app], 'default')
        db.commit()
        budget = [1]
        resolved_id = resolve_requests(sessions, before.id, budget)
        db.expire_all()
        return before.id, db.get(RuntimeReleaseCandidate, resolved_id), budget[0]

    tag = image + ':smoke'
    before, desired, remaining = resolve(tag, '')
    assert desired.id != before and remaining == 0
    evidence = desired.inventory['registry_resolutions'][tag]
    assert evidence['digest'] == manifest_digest and evidence['repository_id'] == mapping.id
    assert evidence['source'] == 'configured_oci_manifest'
    assert desired.inventory['images'] == [dict(kind='image', reference=pin, digest=manifest_digest,
                                               desired=True, observed=False)]
    assert desired.inventory['blockers'] and not assessment_for_review(db, desired, service)['ready']

    before, proven, remaining = resolve(pin, manifest_digest)
    assert proven.id != before and remaining == 0 and not proven.inventory['blockers']
    assert proven.inventory['images'] == [dict(kind='image', reference=pin, digest=manifest_digest,
                                              desired=True, observed=True)]
    assert proven.inventory['registry_resolutions'][pin]['digest'] == manifest_digest

    before, mismatch, remaining = resolve(pin, config['digest'])
    assert mismatch.id == before and remaining == 1
    assert mismatch.inventory['blockers'] and not mismatch.inventory['images'][0]['observed']
    assert not assessment_for_review(db, mismatch, service)['ready']

    missing_tag = image + ':missing'
    before, unknown, remaining = resolve(missing_tag, '')
    assert unknown.id == before and remaining == 0
    assert not unknown.inventory['images'] and unknown.inventory['blockers']
    review = assessment_for_review(db, unknown, service)
    assert not review['ready'] and unknown.resolution_diagnostics[missing_tag]['reason'] == 'not_found'
    assert f'{missing_tag}: {FAILURES["not_found"]}' in review['blockers']
    print(json.dumps({'endpoint': host, 'manifest': manifest_digest, 'config': config['digest'],
                      'manifest_bytes': len(manifest), 'desired_only': desired.id, 'verified_pin': proven.id,
                      'config_mismatch_blocked': mismatch.id, 'unknown_tag_blocked': unknown.id}))
