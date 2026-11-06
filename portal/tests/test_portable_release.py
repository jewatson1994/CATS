"""Trust, completeness and discovery of registry-replicated approved releases."""
from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from app import portable_release as portable, cyber_release_publication as publication, release_oci
from test_cyber_release_publication import environment, publish, descriptor


def fetch(env, receipt):
    return portable.fetch_release(receipt['release']['reference'], {}, [env.fingerprint])


def document_variant(env, receipt, *, remove=None, changed_manifest=None):
    host, repository, digest = release_oci._reference(receipt['release']['reference'])
    store = env.stores[(host, repository)]
    document = json.loads(store['manifests'][digest])
    if remove:
        document['layers'] = [item for item in document['layers']
                              if item['annotations']['org.opencontainers.image.title'] != remove]
    if changed_manifest:
        for item in document['layers']:
            if item['annotations']['org.opencontainers.image.title'] == 'release-manifest.json':
                content = portable.canonical(changed_manifest)
                item.update(descriptor(content, item['mediaType']))
                store['blobs'][item['digest']] = content
    content = portable.canonical(document)
    digest = release_oci._digest(content)
    store['manifests'][digest] = content
    return host + '/' + repository + '@' + digest


def test_complete_mirror_uses_local_host_and_preserves_evidence(environment):
    receipt = publish(environment, [])
    for (host, repository), store in list(environment.stores.items()):
        if host == 'approved.example':
            environment.stores[('offline.example', repository)] = deepcopy(store)
        del environment.stores[(host, repository)]
    result = portable.fetch_release(receipt['release']['reference'].replace('approved.example', 'offline.example'), {}, [environment.fingerprint])
    assert result['verified'] and result['complete']
    assert result['state']['records']['services'][0]['service_key'] == 'demo'
    assert result['evidence']
    assert {item['kind'] for item in result['artifacts']} == {'image', 'chart'}
    assert all(item['reference'].startswith('offline.example/') for item in result['artifacts'])
    assert all(item['digest'] in item['manifests'] and item['blobs'] for item in result['artifacts'])


@pytest.mark.parametrize('missing', ['layer', 'signature', 'evidence_signature'])
def test_missing_replicated_content_never_returns_verified(environment, missing):
    receipt = publish(environment, [])
    reference = receipt['release']['reference']
    artifact = receipt['artifacts'][0]
    host, repository, _ = release_oci._reference(artifact['reference'])
    if missing == 'layer':
        del environment.stores[(host, repository)]['blobs'][environment.layer['digest']]
    elif missing == 'signature':
        # A surviving mutable Cosign tag must not substitute for the signed digest.
        del environment.stores[(host, repository)]['manifests'][artifact['signature']['digest']]
    else:
        reference = document_variant(environment, receipt, remove='evidence.zip.sig')
    with pytest.raises(ValueError):
        portable.fetch_release(reference, {}, [environment.fingerprint])


def test_untrusted_publisher_rejected_even_with_valid_signatures(environment):
    receipt = publish(environment, [])
    with pytest.raises(ValueError, match='independently trusted'):
        portable.fetch_release(receipt['release']['reference'], {}, ['sha256:' + '0' * 64])


def test_unsigned_higher_sequence_cannot_override_release(environment):
    receipt = publish(environment, [])
    manifest = deepcopy(receipt['manifest'])
    manifest['portable']['release_sequence'] = 99999
    reference = document_variant(environment, receipt, changed_manifest=manifest)
    with pytest.raises(ValueError, match='signature verification failed'):
        portable.fetch_release(reference, {}, [environment.fingerprint])


def test_corrupt_blob_with_unchanged_digest_is_rejected(environment):
    receipt = publish(environment, [])
    host, repository, _ = release_oci._reference(receipt['artifacts'][0]['reference'])
    environment.stores[(host, repository)]['blobs'][environment.layer['digest']] = b'tampered'
    with pytest.raises(ValueError, match='corrupt'):
        fetch(environment, receipt)


def test_verification_checks_every_child_of_multiarchitecture_index(environment):
    source = environment.source
    image = environment.approval.snapshot['artifacts'][0]
    original = source.data['manifests'][image['digest']]
    index = portable.canonical({'schemaVersion': 2, 'mediaType': release_oci.INDEX_TYPE,
        'manifests': [descriptor(original, release_oci.MANIFEST_TYPE)]})
    index_digest = release_oci._digest(index)
    source.data['manifests'][index_digest] = index
    image.update(reference='source.example/app@' + index_digest, digest=index_digest)
    environment.approval.snapshot_digest = release_oci._digest(portable.canonical(environment.approval.snapshot))
    receipt = publish(environment, [])
    result = fetch(environment, receipt)
    assert set(result['artifacts'][0]['manifests']) == {index_digest, release_oci._digest(original)}
    host, repository, _ = release_oci._reference(receipt['artifacts'][0]['reference'])
    del environment.stores[(host, repository)]['manifests'][release_oci._digest(original)]
    with pytest.raises(ValueError):
        fetch(environment, receipt)


def test_signed_revocation_is_discoverable_without_original_release(environment):
    approval = environment.approval
    approval.revoked_at = datetime.now(timezone.utc)
    approval.revocation_reason = 'Withdrawn after Cyber review'
    metadata = {**approval.snapshot['portable_release'], 'kind': 'revocation', 'release_sequence': 2,
        'supersedes_release_uuid': '7', 'target_release_uuid': '7', 'revoked_by_id': 4,
        'revoked_at': approval.revoked_at.isoformat(), 'reason': approval.revocation_reason}
    receipt = publication.publish_revocation(environment.db, approval, environment.destination, metadata, lambda receipt: None)
    result = fetch(environment, receipt)
    assert result['verified'] and result['complete'] and result['state'] is None
    assert result['manifest']['portable']['target_release_uuid'] == '7'
    assert result['revoked_at'] == approval.revoked_at
    retry = publication.publish_revocation(environment.db, approval, environment.destination, metadata, lambda receipt: None)
    assert retry['release'] == receipt['release']


def test_discovery_follows_all_pages_and_orders_release_and_revocation(monkeypatch):
    class Registry:
        def __init__(self, host, repository, env, **kwargs):
            self.base, self.api = 'https://' + host, 'https://' + host + '/v2/' + repository
        def request(self, method, url):
            if '/tags/list' in url:
                page = 'last=' in url
                tags = ['release-00000000000000000003-c'] if page else ['release-00000000000000000001-a', 'revocation-00000000000000000002-b']
                headers = {} if page else {'Link': '</v2/team/demo/releases/tags/list?n=100&last=b>; rel="next"'}
                return 200, headers, portable.canonical({'tags': tags})
            return 200, {}, portable.canonical({'tag': url.rsplit('/', 1)[-1]})
    monkeypatch.setattr(release_oci, '_Client', Registry)
    rows = portable.discover_releases('registry.example/team/demo/releases', {})
    assert [int(row['tag'].split('-')[1]) for row in rows] == [1, 2, 3]


@pytest.mark.parametrize('link', ['https://attacker.example/v2/team/releases/tags/list?n=100',
                                '/v2/other/releases/tags/list?n=100', '/v2/team/releases/tags/list?n=100'])
def test_discovery_rejects_cross_origin_cross_repository_and_cycles(monkeypatch, link):
    class Registry:
        def __init__(self, host, repository, env, **kwargs):
            self.api = 'https://' + host + '/v2/' + repository
        def request(self, method, url):
            return 200, {'Link': '<' + link + '>; rel="next"'}, b'{"tags":[]}'
    monkeypatch.setattr(release_oci, '_Client', Registry)
    with pytest.raises(ValueError):
        portable.discover_releases('registry.example/team/releases', {})


def test_project_discovery_catalog_pagination_and_scope(monkeypatch):
    calls = []
    class Registry:
        def __init__(self, host, repository, env, **kwargs):
            self.base = 'https://' + host
        def request(self, method, url):
            if 'last=' in url:
                return 200, {}, b'{"repositories":["team/b/releases","outside/c/releases"]}'
            return 200, {'Link': '</v2/_catalog?n=100&last=a>; rel="next"'}, b'{"repositories":["team/a/releases","team/a/images"]}'
    monkeypatch.setattr(release_oci, '_Client', Registry)
    monkeypatch.setattr(portable, 'discover_releases', lambda repository, env: calls.append(repository) or [{'reference': repository + '@sha256:' + 'a' * 64}])
    assert len(list(portable.discover_release_references('registry.example', 'team/*', {}))) == 2
    assert calls == ['registry.example/team/a/releases', 'registry.example/team/b/releases']


def test_legacy_approval_requires_new_frozen_capture(environment):
    del environment.approval.snapshot['portable_release']
    environment.approval.snapshot_digest = release_oci._digest(portable.canonical(environment.approval.snapshot))
    with pytest.raises(publication.PublicationError, match='Request Cyber approval again'):
        publish(environment, [])


def test_capture_rejects_missing_record_category_even_with_consistent_counts(environment):
    evidence = Path(environment.approval.snapshot['evidence']['path']).read_bytes()
    with ZipFile(BytesIO(evidence)) as archive:
        state = json.loads(archive.read(portable.CAPTURE_NAME))
    del state['records']['findings']
    del state['counts']['findings']
    output = BytesIO()
    with ZipFile(output, 'w') as archive:
        archive.writestr(portable.CAPTURE_NAME, portable.canonical(state))
    with pytest.raises(ValueError, match='Missing or unsupported record categories'):
        portable.evidence_capture(output.getvalue())


@pytest.mark.parametrize('category', portable._CAPTURE_LISTS + ('approval_context', 'display'))
def test_capture_requires_explicit_context_categories(environment, category):
    evidence = Path(environment.approval.snapshot['evidence']['path']).read_bytes()
    state = portable.evidence_capture(evidence)
    del state['extension'][category]
    output = BytesIO()
    with ZipFile(output, 'w') as archive:
        archive.writestr(portable.CAPTURE_NAME, portable.canonical(state))
    with pytest.raises(ValueError, match='frozen .* evidence'):
        portable.evidence_capture(output.getvalue())


@pytest.mark.parametrize('field,value', [('configuration', []), ('services_row', {}),
    ('cyber_row', None), ('captured_at', 'not-a-date'), ('captured_at', '2026-11-05T00:00:00')])
def test_capture_rejects_invalid_frozen_display(environment, field, value):
    state = portable.evidence_capture(Path(environment.approval.snapshot['evidence']['path']).read_bytes())
    state['extension']['display'][field] = value
    output = BytesIO()
    with ZipFile(output, 'w') as archive:
        archive.writestr(portable.CAPTURE_NAME, portable.canonical(state))
    with pytest.raises(ValueError, match='frozen dashboard'):
        portable.evidence_capture(output.getvalue())


def test_verifier_checks_more_than_one_hundred_inventory_entries(environment):
    artifacts = []
    for number in range(101):
        source = environment.Registry('source.example', f'app-{number}')
        config = source.upload(portable.canonical({'architecture': 'amd64', 'test': number}),
                               'application/vnd.oci.image.config.v1+json')
        layer = source.upload(f'layer-{number}'.encode(), 'application/vnd.oci.image.layer.v1.tar')
        content = portable.canonical({'schemaVersion': 2, 'mediaType': release_oci.MANIFEST_TYPE,
                                      'config': config, 'layers': [layer]})
        digest = release_oci._digest(content)
        source.data['manifests'][digest] = content
        artifacts.append({'kind': 'image', 'reference': f'source.example/app-{number}@{digest}', 'digest': digest})
    environment.approval.snapshot['artifacts'] = artifacts
    environment.approval.snapshot_digest = release_oci._digest(portable.canonical(environment.approval.snapshot))
    receipt = publish(environment, [])
    assert len(fetch(environment, receipt)['artifacts']) == 101
    host, repository, digest = release_oci._reference(receipt['artifacts'][-1]['reference'])
    del environment.stores[(host, repository)]['manifests'][digest]
    with pytest.raises(ValueError):
        fetch(environment, receipt)


def test_interrupted_discovery_reuses_exact_retained_signed_package(environment, monkeypatch):
    original = publication._Transport.tag
    interrupted = []
    def stop_after_package(self, client, descriptor, tag):
        if tag.startswith('release-'):
            interrupted.append(descriptor['digest'])
            raise RuntimeError('worker stopped before discovery')
        return original(self, client, descriptor, tag)
    monkeypatch.setattr(publication._Transport, 'tag', stop_after_package)
    with pytest.raises(publication.PublicationError):
        publish(environment, [])
    monkeypatch.setattr(publication._Transport, 'tag', original)
    receipt = publish(environment, [])
    assert receipt['release']['digest'] == interrupted[0]
    assert fetch(environment, receipt)['complete'] is True
