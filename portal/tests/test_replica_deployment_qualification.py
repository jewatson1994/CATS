"""Fail closed when deployment qualification evidence is incomplete or degraded."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from replica_deployment_qualification import compare_snapshots, qualify_password_change, summarize_load, tls_probe


def snapshot():
    return dict(tables={'public.replica_releases': {'rows': 4, 'sha256': 'abc'}},
                sequences={'public.replica_releases_id_seq': [4, True]},
                evidence={'replica/retained.zip': {'bytes': 123, 'sha256': 'def'}})


def test_restore_requires_full_matching_rows_sequences_and_files():
    before = snapshot()
    assert compare_snapshots(before, deepcopy(before)) == dict(equal=True, table_count=1,
        row_count=4, sequence_count=1, evidence_files=1, evidence_bytes=123)
    for category in before:
        changed = deepcopy(before)
        changed[category] = {}
        with pytest.raises(AssertionError, match='Restore differs'):
            compare_snapshots(before, changed)
        del changed[category]
        with pytest.raises(AssertionError, match='Missing snapshot category'):
            compare_snapshots(before, changed)


def test_empty_database_is_not_accepted_as_restore_evidence():
    empty = dict(tables={}, sequences={}, evidence={})
    with pytest.raises(AssertionError, match='Empty state'):
        compare_snapshots(empty, empty)


@pytest.mark.parametrize('url', ['http://localhost', 'https://user:secret@localhost',
                              'https://localhost?token=secret', 'https://localhost#part'])
def test_tls_requires_https_and_no_embedded_secrets(url):
    with pytest.raises(ValueError, match='credential-free HTTPS'):
        tls_probe(url, 'does-not-exist.pem')


def test_bounded_load_rejects_errors_or_excessive_p95():
    for samples, limit in [([(200, 10), (503, 10)], 100), ([(200, 120)], 100)]:
        with pytest.raises(AssertionError, match='status/latency limit'):
            summarize_load(samples, 1, limit)
    result = summarize_load([(200, value) for value in range(1, 101)], 2, 95)
    assert result['latency_ms']['p95'] == 95
    assert result['requests_per_second'] == 50
    assert result['passed'] is True


def password_client(*, challenge=(303, '/account/password'), changed=(303, '/'),
                    rejected=401, authenticated=(303, '/'), csrf='test-csrf'):
    def response(value):
        return SimpleNamespace(status_code=value[0], headers={'Location': value[1]})
    client = Mock(base='https://replica.test')
    client.request.side_effect = [response(challenge), response(authenticated)]
    client.page.return_value = {'csrf_token': csrf}
    client.form.return_value = response(changed)
    client.session.post.return_value = SimpleNamespace(status_code=rejected)
    return client


def test_password_change_proves_challenge_mutation_and_fresh_authentication():
    client = password_client()
    result = qualify_password_change(client, 'viewer', 'initial-password', 'new-password')
    assert result == dict(challenge=dict(status=303, location='/account/password'),
        change=dict(status=303, location='/'), initial_credentials_rejected_status=401,
        fresh_login=dict(status=303, location='/'), authenticated_password_page=True, passed=True)
    client.form.assert_called_once_with('/account/password', current_password='initial-password',
        new_password='new-password', confirmation='new-password')
    assert client.session.cookies.clear.call_count == 2
    client.request.assert_called_with('POST', '/login', data={'username': 'viewer', 'password': 'new-password'})


@pytest.mark.parametrize('alteration,message', [
    ({'challenge': (303, '/')}, 'explicitly require'),
    ({'challenge': (200, '/account/password')}, 'explicitly require'),
    ({'challenge': (303, '/account/access')}, 'explicitly require'),
    ({'changed': (303, '/account/password')}, 'complete successfully'),
    ({'changed': (200, '/')}, 'complete successfully'),
    ({'rejected': 303}, 'initial credentials'),
    ({'authenticated': (303, '/account/password')}, 'without another'),
    ({'authenticated': (303, '/login')}, 'without another'),
    ({'authenticated': (200, '/')}, 'without another'),
    ({'csrf': ''}, 'authenticated CSRF'),
])
def test_password_change_rejects_incomplete_or_bypassed_flow(alteration, message):
    with pytest.raises(AssertionError, match=message):
        qualify_password_change(password_client(**alteration), 'viewer', 'initial-password', 'new-password')


def test_password_change_requires_authenticated_page_after_new_login():
    client = password_client()
    client.page.side_effect = [{'csrf_token': 'initial-csrf'}, {'csrf_token': ''}]
    with pytest.raises(AssertionError, match='establish an authenticated session'):
        qualify_password_change(client, 'viewer', 'initial-password', 'new-password')
