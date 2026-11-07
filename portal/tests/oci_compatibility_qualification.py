"""Opt-in TLS registry, legacy metadata and current importer qualification.

Use the TLS setup from portable_registry_integration.py. The publisher is
Distribution and replica.test is a separately provisioned Zot instance. Fixtures
are synthetic, including the older inventory with omitted optional retention
metadata. All registry, Cosign, ORAS and production importer operations are real.
Stop the publisher before verify/import, and run negative last (it deletes the
isolated chart root). Never point this driver at a production registry.
Keep publisher.test mapped to its recorded source IP after shutdown; loss of
Docker DNS, HTTP/authentication errors and TLS failures do not qualify as an
offline source. Record the container stop independently of the network probe.
"""
import argparse
import errno
import json
from pathlib import Path
import platform
import socket
import ssl
import subprocess
from urllib.error import HTTPError, URLError
import uuid
from zipfile import ZipFile

import portable_registry_integration as fixture


def write(root, name, value):
    (root / name).write_text(json.dumps(value, indent=2) + '\n')


def publish(root):
    from app import cyber_release_publication as publication
    # Reproduce the older signed wire format; operations still use real native
    # signing and registry clients. No signed bytes are rewritten afterward.
    originals = {kind: getattr(publication, '_' + kind) for kind in ('signature', 'attestations')}
    def omit_retention(operation):
        def call(*args, **kwargs):
            result = operation(*args, **kwargs)
            result.pop('retention_tag', None)
            return result
        return call
    try:
        for kind, operation in originals.items():
            setattr(publication, '_' + kind, omit_retention(operation))
        receipt = fixture.publish(root)
    finally:
        for kind, operation in originals.items():
            setattr(publication, '_' + kind, operation)
    write(root, 'receipt.json', receipt)
    oci, _, _, portable, env = fixture.context(root)
    artifact = receipt['artifacts'][0]
    _, repository, subject = oci._reference(artifact['reference'])
    client = oci._Client('replica.test:5000', repository, env)
    content = client.request('GET', client.api + '/manifests/' + subject)[2]
    # An unrelated native OCI 1.1 referrer tests the alternate implementation's
    # referrers API. CATS must not mistake it for signed approval evidence.
    empty = client.upload(b'{}', 'application/vnd.oci.empty.v1+json')
    probe = portable.canonical(dict(schemaVersion=2, mediaType=oci.MANIFEST_TYPE,
        artifactType='application/vnd.cats.compatibility-probe.v1+json',
        config=empty, layers=[], subject=dict(digest=subject, size=len(content), mediaType=oci.INDEX_TYPE)))
    probe_digest = oci._digest(probe)
    assert client.request('PUT', client.api + '/manifests/compatibility-probe', body=probe,
                          media_type=oci.MANIFEST_TYPE)[0] == 201
    response = client.request('GET', client.api + '/referrers/' + subject)[2]
    refs = json.loads(response)['manifests']
    assert any(item['digest'] == probe_digest for item in refs)
    write(root, 'zot-referrers.json', dict(subject=subject, probe=probe_digest, response=json.loads(response)))
    print(json.dumps(dict(phase='alternate-registry-published', legacy_optional_metadata=True,
                          native_oci11_referrers=True, approval_attestations=2)))


def require_source_transport_unavailable(client):
    """Observe connection failure; container stop evidence belongs to the caller."""
    try:
        client.request('GET', client.base + '/v2/')
    except HTTPError:
        raise AssertionError('Publisher returned HTTP; this is not source disconnection') from None
    except URLError as exc:
        reason = exc.reason
    except OSError as exc:
        reason = exc
    else:
        raise AssertionError('Publisher responded; stop the isolated source before verification')
    unavailable = {errno.ECONNREFUSED: 'connection_refused',
                   errno.EHOSTUNREACH: 'host_unreachable', errno.ENETUNREACH: 'network_unreachable'}
    if (isinstance(reason, (ssl.SSLError, socket.gaierror))
            or not isinstance(reason, OSError) or reason.errno not in unavailable):
        raise AssertionError('Source disconnection requires connection refusal or an unreachable host/network; '
                             'DNS, TLS, timeout and other failures are not accepted') from None
    return dict(transport_unavailable=True, reason=unavailable[reason.errno])


def probe(root):
    oci, _, _, _, env = fixture.context(root)
    result = require_source_transport_unavailable(oci._Client('publisher.test:5000', 'input/application', env))
    write(root, 'source-offline-probe.json', result)
    print(json.dumps(result))


def verify(root):
    oci, _, _, portable, env = fixture.context(root)
    expected = json.loads((root / 'expected.json').read_text())
    source_probe = require_source_transport_unavailable(oci._Client('publisher.test:5000', 'input/application', env))
    result = portable.fetch_release(expected['release']['reference'].replace('publisher.test', 'replica.test'),
                                    env, [expected['fingerprint']])
    assert result['complete'] and result['verified']
    assert result['manifest'] == expected['manifest'] and result['state'] == expected['state']
    assert all(item['attestation']['receipts'] for item in result['artifacts'])
    assert all(receipt['subject'].startswith('publisher.test:5000/')
               for item in result['artifacts'] for receipt in item['attestation']['receipts'])
    assert len(result['artifacts'][0]['manifests']) == 3
    probe = json.loads((root / 'zot-referrers.json').read_text())['probe']
    assert all(item['attestation']['digest'] != probe for item in result['artifacts'])
    report = dict(phase='disconnected-verified', machine=platform.machine(),
                  synthetic_fixture=True, immutable_attachment_fallback=True,
                  original_signed_subject_preserved=True, complete_artifacts=2, image_manifests=3,
                  source_probe=source_probe, unrelated_native_referrer_excluded=True)
    write(root, 'verified-' + platform.machine() + '.json', report)
    print(json.dumps(report))


def backfill(root):
    oci, _, publication, portable, env = fixture.context(root)
    receipt = json.loads((root / 'receipt.json').read_text())
    expected = json.loads((root / 'expected.json').read_text())
    transport = publication._Transport(root / ('backfill-layout-' + uuid.uuid4().hex), env)
    repositories, retained = set(), []
    for artifact in [*receipt['artifacts'], receipt['release'], expected['revocation']]:
        _, repository, _ = oci._reference(artifact['reference'])
        repositories.add(repository)
        source = oci._Client('replica.test:5000', repository, env)
        for kind in ('signature', 'attestation'):
            if kind not in artifact:
                continue
            attachment = artifact[kind]
            descriptor = transport.graph(source, attachment['digest'])
            tag = 'cats-' + kind + '-' + attachment['digest'][7:]
            transport.tag(source, descriptor, tag)
            retained.append(dict(repository=repository, kind=kind, digest=attachment['digest'], tag=tag))
    # Copy exclusively reachable tagged graphs after backfill; there is no
    # attachment-specific rescue or source-publisher access in this step.
    for repository in sorted(repositories):
        source = oci._Client('replica.test:5000', repository, env)
        target = oci._Client('replica.test:5000', repository.replace('approved/', 'backfilled/', 1), env)
        tags = json.loads(source.request('GET', source.api + '/tags/list')[2])['tags']
        for tag in tags:
            identity = oci._digest(source.request('GET', source.api + '/manifests/' + tag)[2])
            descriptor = transport.graph(source, identity, target)
            transport.tag(target, descriptor, tag)
    reference = receipt['release']['reference'].replace('publisher.test', 'replica.test').replace('/approved/', '/backfilled/', 1)
    restored = portable.fetch_release(reference, env, [expected['fingerprint']], repository_prefix='backfilled')
    assert restored['complete'] and restored['manifest'] == expected['manifest']
    report = dict(phase='explicit-retention-backfill', synthetic_legacy_format=True,
                  complete_graphs_required=True, signed_content_unchanged=True,
                  tag_only_copy_verified=True, retained_attachments=retained)
    write(root, 'explicit-backfill.json', report)
    print(json.dumps(report))


def offline_import(root):
    from app import cyber_release_publication as publication
    oci, _, _, _, env = fixture.context(root)
    receipt = json.loads((root / 'receipt.json').read_text())
    expected = json.loads((root / 'expected.json').read_text())
    folder = root / 'current-importer'
    folder.mkdir(exist_ok=True)
    with ZipFile(receipt['bundle_path']) as archive:
        archive.extractall(folder)
    # Operator supplies the current reviewed importer, preserving signed content.
    (folder / 'verify-import.py').write_text(publication.OFFLINE_SCRIPT)
    target = 'replica.test:5000/backfill/legacy'
    subprocess.run(['python', str(folder / 'verify-import.py'), '--fingerprint', expected['fingerprint'],
                    '--destination', target], env=env, check=True, timeout=240)
    inventory = json.loads((folder / 'transport.json').read_text())['artifacts']
    verified = []
    for artifact in inventory:
        client = oci._Client('replica.test:5000', 'backfill/legacy/' + artifact['repository_suffix'], env)
        for kind in ('signature', 'attestation'):
            if kind not in artifact:
                continue
            attachment = artifact[kind]
            assert 'retention_tag' not in attachment
            tag = 'cats-' + kind + '-' + attachment['digest'][7:]
            data = client.request('GET', client.api + '/manifests/' + tag)[2]
            assert oci._digest(data) == attachment['digest']
            verified.append(dict(kind=kind, tag=tag, digest=attachment['digest']))
    report = dict(phase='current-importer-backfill', synthetic_legacy_format=True,
                  signed_content_unchanged=True, real_oras=True, retained_attachments=verified)
    write(root, 'current-importer.json', report)
    print(json.dumps(report))


def negative(root):
    oci, _, _, portable, env = fixture.context(root)
    expected = json.loads((root / 'expected.json').read_text())
    reference = expected['release']['reference'].replace('publisher.test', 'replica.test')
    result = portable.fetch_release(reference, env, [expected['fingerprint']])
    assert result['complete'] and result['verified']
    revocation = portable.fetch_release(expected['revocation']['reference'].replace('publisher.test', 'replica.test'),
                                       env, [expected['fingerprint']])
    assert revocation['complete'] and revocation['manifest']['portable']['release_sequence'] == 2
    try:
        portable.fetch_release(reference, env, ['sha256:' + '0' * 64])
    except ValueError:
        pass
    else:
        raise AssertionError('Untrusted publisher must be rejected')
    artifact = result['artifacts'][0]
    child = next(value for value in artifact['manifests'] if value != artifact['digest'])
    client = oci._Client('replica.test:5000', artifact['repository'], env)
    try:
        client.request('DELETE', client.api + '/manifests/' + child)
    except oci._RegistryError as exc:
        assert exc.status == 405, exc
    else:
        raise AssertionError('Zot must protect an architecture child referenced by an index')
    # Zot prevents partial index deletion. A chart root can still be removed;
    # CATS must reject the now-incomplete signed release on its ordinary path.
    chart = result['artifacts'][1]
    client = oci._Client('replica.test:5000', chart['repository'], env)
    assert client.request('DELETE', client.api + '/manifests/' + chart['digest'])[0] == 202
    try:
        portable.fetch_release(reference, env, [expected['fingerprint']])
    except (ValueError, oci._RegistryError):
        pass
    else:
        raise AssertionError('Missing chart manifest must be rejected')
    report = dict(phase='alternate-registry-negatives', untrusted_key_rejected=True,
                  signed_revocation_verified=True, zot_referenced_child_deletion_denied=405,
                  missing_chart_rejected=True)
    write(root, 'negative.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('publish', 'probe', 'verify', 'backfill', 'offline_import', 'negative'))
    parser.add_argument('workspace', type=Path)
    args = parser.parse_args()
    globals()[args.phase](args.workspace.resolve())
