"""Qualification must reject ambiguous inventories and unsupported cold claims."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest

import harbor_inventory_http as verifier


def digest(value):
    return 'sha256:' + hashlib.sha256(str(value).encode()).hexdigest()


def expected_inventory(*, successor=True):
    count = 123 if successor else 100
    value = {'source': 'https://source.test', 'target': 'https://target.test',
        'trusted_fingerprint': digest('signer'), 'namespace': 'qualification/unique', 'service_key': 'inventory',
        'release_repository': 'qualification/unique/inventory/releases',
        'first_indices': list(range(100)), 'successor_indices': list(range(23, 123)),
        'images': [{'index': index, 'digest': digest(index)} for index in range(count)], 'receipts': {}}
    for label, sequence in [('first', 1), *([('successor', 2)] if successor else [])]:
        value['receipts'][label] = {'status': 'published', 'verification_status': 'verified', 'signature_status': 'verified',
            'artifacts': [{'kind': 'image', 'digest': digest(index)} for index in value[label + '_indices']],
            'release': {'reference': 'source.test/' + value['release_repository'] + '@' + digest(label), 'digest': digest(label)},
            'manifest': {'signing_fingerprint': digest('signer'), 'evidence': {'path': '/retained/private/archive.zip'},
                         'portable': {'release_uuid': str(sequence), 'supersedes_release_uuid': '1' if sequence == 2 else None}}}
    return value


def test_first_only_contract_accepts_100_then_preserves_binding_when_corpus_expands():
    first, successor = expected_inventory(successor=False), expected_inventory()
    verifier.validate_expected(first)
    verifier.validate_expected(successor, successor=True)
    assert verifier.binding(first) == verifier.binding(successor)
    public = verifier.public_receipt(first['receipts']['first'])
    assert public['manifest']['evidence'] == {}
    assert first['receipts']['first']['manifest']['evidence']['path'] == '/retained/private/archive.zip'


@pytest.mark.parametrize('mutation', [
    lambda value: value['images'].__setitem__(122, copy.deepcopy(value['images'][121])),
    lambda value: value['images'][122].update(digest=value['images'][121]['digest']),
    lambda value: value.update(successor_indices=list(range(22, 122))),
    lambda value: value['receipts']['successor']['artifacts'].pop(),
    lambda value: value['receipts']['successor']['manifest'].update(signing_fingerprint=digest('other')),
    lambda value: value['receipts']['successor']['manifest']['portable'].update(supersedes_release_uuid='other'),
    lambda value: value['receipts']['successor'].update(signature_status='unverified'),
    lambda value: value.update(target=value['source']),
])
def test_wrong_inventory_or_publication_binding_is_rejected(mutation):
    value = expected_inventory()
    mutation(value)
    with pytest.raises(AssertionError):
        verifier.validate_expected(value, successor=True)


def test_offline_proof_rejects_missing_or_different_online_baseline_before_any_network(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier.requests, 'Session', lambda: pytest.fail('No network before baseline validation'))
    with pytest.raises(AssertionError, match='same successfully contacted'):
        verifier.source_probes(tmp_path, {}, {'source_online': {'urls': ['https://other.test/v2/'], 'reachable': True}},
                               ['https://source.test/v2/'], tmp_path / 'ca', offline=True, label='offline')


def test_publisher_probes_always_include_actual_source_and_preserve_exact_urls():
    expected = {'source': 'https://source.test/'}
    source = 'https://source.test/v2/'
    assert verifier.publisher_urls(expected) == [source]
    assert verifier.publisher_urls(expected, [source, source]) == [source]
    assert verifier.publisher_urls(expected, ['https://other.test/health/', source]) == [
        source, 'https://other.test/health/']
    with pytest.raises(ValueError):
        verifier.publisher_urls(expected, ['https://secret@other.test/health/'])


def test_online_and_offline_probe_preserve_identical_registry_trailing_slash(tmp_path, monkeypatch):
    calls, report = [], {}

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url, **kwargs):
            calls.append(url)
            assert url == 'https://source.test/v2/' and kwargs['allow_redirects'] is False
            if len(calls) == 1:
                return SimpleNamespace(status_code=401, close=lambda: None)
            raise verifier.requests.exceptions.ConnectionError('stopped publisher')

    monkeypatch.setattr(verifier.requests, 'Session', Session)
    monkeypatch.setattr(verifier, 'persist', lambda *args: None)
    urls = ['https://source.test/v2/']
    verifier.source_probes(tmp_path, {}, report, urls, tmp_path / 'ca', offline=False, label='source_online')
    verifier.source_probes(tmp_path, {}, report, urls, tmp_path / 'ca', offline=True, label='offline')
    assert calls == urls * 2
    assert report['source_online']['urls'] == report['offline']['urls'] == urls
    assert report['offline']['probes'] == [{'url': urls[0], 'unavailable': True}]


@pytest.fixture
def cold(tmp_path):
    recovered = datetime.now(timezone.utc) - timedelta(minutes=2)
    proof = {'format': 'cats-inventory-cold-cache-v1', 'checked_at': (recovered + timedelta(minutes=1)).isoformat(),
             'replica_project': 'isolated-inventory', 'cache_directory': '/var/cache/cats-oci',
             'cache_volume': 'fresh-owned-volume', 'prior_volume_retained': True, 'file_count': 0}
    return tmp_path / 'cold.json', proof, {'project': 'isolated-inventory'}, {'recovered_at': recovered.isoformat()}


def test_cold_blob_proof_binds_replica_timing_and_exact_raw_hash(cold):
    path, proof, stack, report = cold
    path.write_text(json.dumps(proof))
    actual = verifier.cold_cache_proof(path, stack, report)
    assert actual['proof_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert 'PostgreSQL manifest cache is retained' in actual['scope']


def test_reformatted_cold_proof_cannot_reuse_observation_before_previous_pull(cold):
    path, proof, stack, report = cold
    report['successor_pull_started_at'] = (datetime.fromisoformat(proof['checked_at']) + timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(proof, indent=4))
    with pytest.raises(AssertionError, match='after the preceding pull attempt'):
        verifier.cold_cache_proof(path, stack, report)
    proof['checked_at'] = (datetime.fromisoformat(report['successor_pull_started_at']) + timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(proof, indent=4))
    assert verifier.cold_cache_proof(path, stack, report)['file_count'] == 0


@pytest.mark.parametrize('mutation', [
    {'file_count': 1}, {'file_count': False}, {'prior_volume_retained': False},
    {'replica_project': 'another-replica'}, {'cache_volume': ''},
    {'checked_at': '2000-01-01T00:00:00+00:00'}, {'checked_at': '2100-01-01T00:00:00+00:00'},
    {'checked_at': '2020-01-01T00:00:00'},
])
def test_cold_proof_rejects_warm_foreign_or_wrong_time(cold, mutation):
    path, proof, stack, report = cold
    proof.update(mutation)
    path.write_text(json.dumps(proof))
    with pytest.raises(AssertionError):
        verifier.cold_cache_proof(path, stack, report)


@pytest.mark.parametrize('failure', ['scope escaped', 'report unavailable', 'wrong-release', 'wide-digests',
                                      'wrong-condition', 'wrong-status', 'wrong-response-status'])
def test_override_is_revoked_if_a_scope_or_report_assertion_fails(tmp_path, monkeypatch, failure):
    expected = expected_inventory()
    first = {'id': 7, 'artifacts': [{'kind': 'image', 'digest': digest(index), 'proxy_repositories': ['qualification/images']}
                                   for index in range(100)]}
    events = []
    def create(url, *, json, headers, timeout, allow_redirects):
        assert url == 'https://replica.test/api/services/inventory/local-overrides'
        assert headers == {'X-CSRF-Token': 'local-csrf'}
        assert timeout == 30 and allow_redirects is False
        grant = {'id': 9, 'expires_at': json['expires_at'], 'release_id': json['release_id'],
                 'digests': [json['digest']], 'denial_condition': json['denial_condition'], 'status': 'active'}
        if failure == 'wrong-release':
            grant['release_id'] += 1
        elif failure == 'wide-digests':
            grant['digests'].append(digest('unrelated'))
        elif failure == 'wrong-condition':
            grant['denial_condition'] = 'expired'
        elif failure == 'wrong-status':
            grant['status'] = 'revoked'
        return SimpleNamespace(status_code=201 if failure == 'wrong-response-status' else 200,
            json=lambda: grant, close=lambda: events.append('response closed'))

    local = SimpleNamespace(base='https://replica.test', csrf='local-csrf',
                            session=SimpleNamespace(post=create, close=lambda: events.append('closed')))
    monkeypatch.setattr(verifier.workflow, 'local_cyber', lambda *args: local)
    persistence_calls = []

    def persist(*args):
        persistence_calls.append(True)
        if failure == 'report unavailable' and len(persistence_calls) == 1:
            raise AssertionError(failure)

    monkeypatch.setattr(verifier, 'persist', persist)
    monkeypatch.setattr(verifier, 'assert_override_admin_denied', lambda *args: {})
    monkeypatch.setattr(verifier, 'pull_graph', lambda *args: {'complete': True})
    monkeypatch.setattr(verifier, 'assert_override_uses', lambda *args, **kwargs: {'matching_uses': [1]})
    monkeypatch.setattr(verifier, 'assert_root_denied', lambda *args: (_ for _ in ()).throw(AssertionError('scope escaped')))
    monkeypatch.setattr(verifier, 'revoke_override', lambda *args: events.append(('revoked', args[4])) or {'status': 'revoked'})
    api = SimpleNamespace(session=object(), base='https://replica.test', csrf='admin-csrf')
    reason = failure if failure in {'scope escaped', 'report unavailable'} else 'exact requested scope'
    with pytest.raises(AssertionError, match=reason):
        verifier.override_checks(api, tmp_path, {'proxy_url': 'https://proxy.test'},
            {'service_key': 'inventory', 'machine': {'id': 12}}, {}, first, expected, object())
    assert events == ['response closed', ('revoked', 9), 'closed']


def test_override_driver_reaches_production_route_through_replica_boundary(tmp_path, monkeypatch):
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
    from app import local_cyber_overrides, operating_mode

    monkeypatch.setenv('CATS_MODE', 'replica')
    application = FastAPI()
    application.add_middleware(operating_mode.ReplicaModeMiddleware)
    application.include_router(local_cyber_overrides.router)
    reached = []

    def stop_before_database():
        reached.append('production override route')
        raise HTTPException(418, 'qualification route reached')

    application.dependency_overrides[local_cyber_overrides.get_db] = stop_before_database
    expected = expected_inventory()
    first = {'id': 7, 'artifacts': [{'kind': 'image', 'digest': digest(index),
        'proxy_repositories': ['qualification/images']} for index in range(100)]}
    responses = []
    with TestClient(application) as client:
        def post(url, *, json, headers, timeout, allow_redirects):
            response = client.post(url, json=json, headers=headers, follow_redirects=allow_redirects)
            responses.append((response.status_code, response.json()))
            return response

        local = SimpleNamespace(base='http://testserver', csrf='local-csrf',
            session=SimpleNamespace(post=post, close=lambda: None))
        monkeypatch.setattr(verifier.workflow, 'local_cyber', lambda *args: local)
        monkeypatch.setattr(verifier, 'assert_override_admin_denied', lambda *args: {})
        api = SimpleNamespace(session=object(), base='http://testserver', csrf='admin-csrf')
        with pytest.raises(AssertionError, match='usable cleanup identity'):
            verifier.override_checks(api, tmp_path, {'proxy_url': 'https://proxy.test'},
                {'service_key': 'inventory', 'machine': {'id': 12}}, {}, first, expected, object())
    assert reached == ['production override route']
    assert responses == [(418, {'detail': 'qualification route reached'})]


@pytest.fixture
def omission(tmp_path, monkeypatch):
    from app import portable_release as portable, release_oci as oci

    expected = expected_inventory()
    marker_body = b'successor-only-marker'
    descriptor = {'digest': oci._digest(marker_body), 'size': len(marker_body), 'mediaType': 'application/vnd.oci.image.layer.v1.tar'}
    parent = json.dumps({'layers': [descriptor]}).encode()
    parent_digest = oci._digest(parent)
    repository = expected['namespace'] + '/inventory/corpus'
    expected['images'][100].update(digest=parent_digest, marker_layer=descriptor)
    expected['omission'] = {**descriptor, 'kind': 'blob', 'index': 100,
                            'parent_digest': parent_digest, 'repository': repository}
    receipt = expected['receipts']['successor']
    receipt['artifacts'][77].update(digest=parent_digest, reference='source.test/' + repository + '@' + parent_digest)
    receipt['target_reference'] = 'target.test/' + expected['release_repository'] + '@' + receipt['release']['digest']
    calls = []
    response = {'parent': parent, 'blob': (200, {'Content-Length': str(len(marker_body))}, b''),
                'fetch_error': ValueError('Incomplete or corrupt replicated OCI content')}

    class Client:
        def __init__(self, host, repo, env, *, pull_only):
            assert host == 'target.test' and repo == repository and pull_only
            assert env['SSL_CERT_FILE'] == str(tmp_path / 'ca.pem')
            self.api = 'https://target.test/v2/' + repository

        def request(self, method, url, **kwargs):
            calls.append(url)
            assert method == 'GET' and url.startswith(self.api + '/')
            if '/manifests/' in url:
                return 200, {}, response['parent']
            if isinstance(response['blob'], Exception):
                raise response['blob']
            return response['blob']

    def fetch(reference, env, pins):
        calls.append('fetch')
        assert reference == receipt['target_reference'] and pins == [expected['trusted_fingerprint']]
        if response['fetch_error'] is not None:
            raise response['fetch_error']
        return {'verified': True}

    monkeypatch.setattr(oci, '_Client', Client)
    monkeypatch.setattr(portable, 'fetch_release', fetch)
    return expected, tmp_path / 'ca.pem', response, calls, marker_body


def test_incomplete_proof_records_harbor_zero_body_quirk_and_exact_production_failure(omission):
    expected, ca, response, calls, marker = omission
    proof = verifier.target_omission(expected, ca)
    assert proof['parent']['digest'] == expected['omission']['parent_digest']
    assert proof['blob'] == {'status': 200, 'bytes': 0, 'digest': digest(''),
                             'content_length': str(len(marker)), 'empty_body_for_nonempty_blob': True}
    assert proof['production_verification']['reason'] == 'Incomplete or corrupt replicated OCI content'
    assert calls[-1] == 'fetch' and proof['source_reads'] == 0


def test_incomplete_proof_accepts_404_only_with_actual_missing_marker(omission):
    from app.release_oci import _RegistryError

    expected, ca, response, calls, marker = omission
    response.update(blob=_RegistryError(404), fetch_error=_RegistryError(404))
    proof = verifier.target_omission(expected, ca)
    assert proof['blob']['status'] == proof['production_verification']['http_status'] == 404
    assert proof['blob']['bytes'] is None  # A discarded error body is not claimed to be empty.


@pytest.mark.parametrize('failure', ['valid-layer', 'wrong-parent', 'wrong-descriptor', 'forbidden-layer',
                                      'wrong-signer', 'unrelated-404', 'accepted'])
def test_incomplete_proof_rejects_unrelated_or_unsupported_failures(omission, failure):
    from app.release_oci import _RegistryError

    expected, ca, response, calls, marker = omission
    if failure == 'valid-layer':
        response['blob'] = (200, {}, marker)
    elif failure == 'wrong-parent':
        response['parent'] = b'not the pinned parent'
    elif failure == 'wrong-descriptor':
        expected['omission']['size'] += 1
    elif failure == 'forbidden-layer':
        response['blob'] = _RegistryError(403)
    elif failure == 'wrong-signer':
        response['fetch_error'] = ValueError('Release publisher is not independently trusted')
    elif failure == 'unrelated-404':
        response['fetch_error'] = _RegistryError(404)
    else:
        response['fetch_error'] = None
    with pytest.raises(AssertionError):
        verifier.target_omission(expected, ca)
    if failure in {'valid-layer', 'wrong-parent', 'wrong-descriptor', 'forbidden-layer'}:
        assert 'fetch' not in calls
