"""Harbor mutation retries require an explicit, unexecuted CSRF rejection."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from harbor_replication_qualification import Harbor
import harbor_replication_qualification as controller


@pytest.mark.parametrize(('alias', 'prefix'), [
    ('approved', 'approved/service'), ('qualification', 'qualification/service'),
    ('interruption', 'qualification/service'), ('Bad', 'approved/service'),
    ('new/path', 'approved/service'), ('new', 'approved'), ('new', 'approved/'),
    ('new', '/approved/service'), ('new', 'approved/service/'), ('new', 'other/service'),
    ('new', 'approved/**'), ('new', 'approved/service?'), ('new', 'approved/../service'),
    ('new', 'approved/service//releases'), ('new', 'approved/service\\releases'),
    ('new', 'approved/service%2fother'), ('new', 'approved/service@sha256:123'),
])
def test_scoped_policy_rejects_broad_or_ambiguous_paths_without_network(tmp_path, monkeypatch, alias, prefix):
    monkeypatch.setattr(controller, 'clients', lambda _: pytest.fail('Invalid scope must not contact Harbor'))
    with pytest.raises(ValueError):
        controller.setup_scoped(tmp_path, alias, prefix)


@pytest.fixture
def scoped_policy(tmp_path, monkeypatch):
    controller.save(tmp_path, 'replication-state.json', {'registry_id': 8, 'policies': {'approved': 2}})
    controller.save(tmp_path, 'harbor-replication.json', {'executions': [{'label': 'preserved'}]})

    class API:
        def __init__(self):
            self.created = []
            self.executions = []
            self.policy = None

        def post(self, path, value):
            accepted = response(201)
            if path == '/replication/policies':
                self.created.append(copy.deepcopy(value))
                self.policy = {**copy.deepcopy(value), 'id': 12, 'secret': 'never-report'}
                accepted.headers['Location'] = '/api/v2.0/replication/policies/12'
            else:
                assert path == '/replication/executions'
                self.executions.append(copy.deepcopy(value))
                accepted.headers['Location'] = '/api/v2.0/replication/executions/20'
            return accepted

        def get(self, path):
            if path == '/replication/policies/12':
                return copy.deepcopy(self.policy)
            assert path == '/replication/executions/20'
            return {'id': 20, 'status': 'Succeed'}

        def pages(self, path):
            if path == '/replication/policies':
                return [copy.deepcopy(self.policy)] if self.policy else []
            assert path == '/replication/executions/20/tasks'
            return [{'id': 30, 'status': 'Succeed'}]

        def request(self, method, path):
            assert method == 'GET' and path == '/replication/executions/20/tasks/30/log'
            return response(200, 'copied service subtree')

    api = API()
    monkeypatch.setattr(controller, 'clients', lambda _: ({}, {'source': api}))
    return tmp_path, api


def test_scoped_setup_is_idempotent_preserves_history_and_refuses_alias_reuse(scoped_policy):
    root, api = scoped_policy
    for _ in range(2):
        controller.setup_scoped(root, 'staging-nginx', 'approved/nginx-unique')
    assert len(api.created) == 1
    assert api.created[0]['filters'] == [{'type': 'name', 'value': 'approved/nginx-unique/**'}]
    report = controller.load(root, 'harbor-replication.json')
    assert report['executions'] == [{'label': 'preserved'}]
    assert report['policy_scopes'] == {'staging-nginx': 'approved/nginx-unique'}
    assert 'never-report' not in json.dumps(report)
    with pytest.raises(ValueError, match='repurposed'):
        controller.setup_scoped(root, 'staging-nginx', 'approved/another-service')
    with pytest.raises(ValueError, match='configured policy alias'):
        controller.replicate(root, 'not-configured', 'unexpected')
    assert not api.executions


@pytest.mark.parametrize('selector', ['staging-inventory', 'qualification/staging-inventory-unique'])
def test_replication_accepts_scoped_alias_or_exact_prefix(scoped_policy, selector):
    root, api = scoped_policy
    controller.setup_scoped(root, 'staging-inventory', 'qualification/staging-inventory-unique')
    controller.replicate(root, selector, 'fresh-source')
    assert api.executions == [{'policy_id': 12}]
    execution = controller.load(root, 'harbor-replication.json')['executions'][-1]
    assert execution['namespace'] == 'staging-inventory'
    assert execution['tasks'] == [{'id': 30, 'status': 'Succeed'}]


def test_scoped_policy_adopts_matching_policy_after_lost_local_state_and_harbor_omits_false(scoped_policy):
    root, api = scoped_policy
    controller.setup_scoped(root, 'fresh', 'qualification/service')
    del api.policy['replicate_deletion']
    del api.policy['dest_namespace']
    controller.save(root, 'replication-state.json', {'registry_id': 8, 'policies': {'approved': 2}})
    controller.setup_scoped(root, 'fresh', 'qualification/service')
    assert len(api.created) == 1
    assert controller.load(root, 'replication-state.json')['policies']['fresh'] == 12
    controller.replicate(root, 'fresh', 'recovered-policy')
    assert api.executions == [{'policy_id': 12}]


@pytest.mark.parametrize('mutation', [
    {'filters': [{'type': 'name', 'value': 'qualification/**'}]},
    {'filters': [{'type': 'name', 'value': 'qualification/service/**', 'decoration': 'excludes'}]},
    {'dest_registry': {'id': 9}}, {'dest_namespace': 'elsewhere'},
    {'dest_namespace_replace_count': 1}, {'replicate_deletion': True},
    {'enabled': False}, {'override': False}, {'trigger': {'type': 'scheduled'}},
])
def test_changed_scoped_policy_is_rejected_before_execution(scoped_policy, mutation):
    root, api = scoped_policy
    controller.setup_scoped(root, 'fresh', 'qualification/service')
    api.policy.update(mutation)
    with pytest.raises(RuntimeError, match='exact subtree'):
        controller.replicate(root, 'fresh', 'should-not-run')
    assert not api.executions


CSRF = {'errors': [{'code': 'FORBIDDEN', 'message': 'CSRF token not found in request'}]}


def response(status, body=None, token=None):
    result = requests.Response()
    result.status_code = status
    result._content = (body if isinstance(body, str) else json.dumps(body)).encode()
    if token is not None:
        result.headers['X-Harbor-CSRF-Token'] = token
    return result


class Session:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.headers = {}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs), dict(self.headers)))
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture
def client(monkeypatch):
    def build(*outcomes):
        session = Session(outcomes)
        monkeypatch.setattr(requests, 'Session', lambda: session)
        return Harbor('https://harbor-source.test:8443/', 'test-admin', 'test-password',
                      Path('test-ca.crt')), session
    return build


def test_client_uses_explicit_auth_ca_and_ignores_environment(client):
    _, session = client()
    assert session.trust_env is False
    assert session.auth == ('test-admin', 'test-password')
    assert session.verify == str(Path('test-ca.crt'))


@pytest.mark.parametrize('method', ['POST', 'PUT'])
def test_explicit_csrf_rejection_retries_once_with_token_and_same_payload(client, method):
    accepted = response(201, {'id': 12})
    api, session = client(response(403, CSRF, 'issued-token'), accepted)
    payload = {'policy_id': 7}

    assert api.request(method, '/replication/executions', json=payload) is accepted
    assert len(session.calls) == 2
    first, retry = session.calls
    assert first[:3] == retry[:3] == (
        method, 'https://harbor-source.test:8443/api/v2.0/replication/executions',
        {'timeout': 120, 'json': payload})
    assert first[3] == {}
    assert retry[3] == {'X-Harbor-CSRF-Token': 'issued-token'}


@pytest.mark.parametrize(('status', 'body', 'token'), [
    (403, CSRF, None),
    (403, CSRF, ''),
    (401, CSRF, 'token'),
    (500, CSRF, 'token'),
    (403, {'errors': [{'code': 'UNAUTHORIZED', 'message': 'CSRF token not found in request'}]}, 'token'),
    (403, {'errors': [{'code': 'FORBIDDEN', 'message': 'permission denied'}]}, 'token'),
    (403, {'errors': [{'code': 'FORBIDDEN', 'message': 'CSRF token not found in request.'}]}, 'token'),
    (403, {'errors': []}, 'token'),
    (403, 'not JSON', 'token'),
])
def test_other_rejections_are_not_replayed(client, status, body, token):
    api, session = client(response(status, body, token))
    with pytest.raises(RuntimeError, match=f': {status}:'):
        api.request('PUT', '/replication/executions/12')
    assert len(session.calls) == 1


def test_repeated_explicit_csrf_rejection_does_not_retry_a_third_time(client):
    api, session = client(response(403, CSRF, 'first-token'), response(403, CSRF, 'second-token'))
    with pytest.raises(RuntimeError, match=': 403:'):
        api.request('PUT', '/replication/executions/12')
    assert len(session.calls) == 2


@pytest.mark.parametrize('error_type', [requests.ConnectionError, requests.Timeout, requests.exceptions.SSLError])
@pytest.mark.parametrize('after_explicit_rejection', [False, True])
def test_transport_failure_never_replays_ambiguous_mutation(client, error_type, after_explicit_rejection):
    failure = error_type('transport failed')
    outcomes = [response(403, CSRF, 'issued-token')] if after_explicit_rejection else []
    api, session = client(*outcomes, failure)
    with pytest.raises(error_type) as raised:
        api.request('POST', '/replication/executions', json={'policy_id': 7})
    assert raised.value is failure
    assert len(session.calls) == 1 + int(after_explicit_rejection)


def test_successful_response_token_is_available_to_next_request_without_replay(client):
    issued = response(200, {'status': 'healthy'}, 'issued-token')
    accepted = response(200, {})
    api, session = client(issued, accepted)
    assert api.request('GET', '/health') is issued
    assert len(session.calls) == 1
    assert api.request('PUT', '/replication/executions/12') is accepted
    assert len(session.calls) == 2
    assert session.calls[1][3] == {'X-Harbor-CSRF-Token': 'issued-token'}


@pytest.fixture
def configured(tmp_path, monkeypatch):
    secret = 'must-not-appear-in-report'
    state = {side: {'id': 1, 'username': 'robot', 'password': secret} for side in ('source', 'target')}
    state.update(registry_id=8, policies={'approved': 2, 'qualification': 3, 'interruption': 4})
    controller.save(tmp_path, 'replication-state.json', state)
    history = {'executions': [{'label': 'retained-execution'}],
               'instances': {'source': {'robot_permissions': ['stale']}},
               'policies': {'approved': {'override': True}}}
    controller.save(tmp_path, 'harbor-replication.json', history)
    stack = {side: {'url': 'https://' + side + '.test', 'registry': side + '.test',
                    'username': 'admin', 'password': secret} for side in ('source', 'target')}
    stack['ca_file'] = str(tmp_path / 'ca.crt')
    Path(stack['ca_file']).write_text('public test CA')
    registry = {'id': 8, 'type': 'harbor', 'url': 'https://target.test', 'ca_certificate': 'public test CA',
                'credential': {'type': 'basic', 'access_key': secret, 'access_secret': secret}, 'secret': secret}
    permissions = [{'kind': 'project', 'namespace': 'approved', 'password': secret,
                    'access': [{'resource': 'repository', 'action': 'pull', 'secret': secret}]}]
    projects = [{'project_id': identity, 'name': name, 'metadata': {'public': 'true', 'secret': secret}}
                for identity, name in enumerate(('approved', 'qualification'), 1)]

    class ReadOnlyAPI:
        def __init__(self):
            self.calls = []
            self.session = SimpleNamespace(close=lambda: None)

        def get(self, path):
            self.calls.append(('GET', path))
            if path == '/systeminfo':
                return {'harbor_version': 'v2.15.4'}
            if path == '/health':
                return {'status': 'healthy'}
            if path == '/robots/1':
                return {'id': 1, 'name': 'robot', 'level': 'system', 'permissions': permissions, 'secret': secret}
            if path.startswith('/projects/'):
                return copy.deepcopy(projects[int(path.rsplit('/', 1)[1]) - 1])
            if path == '/retentions/4':
                return {'id': 4, 'algorithm': 'or', 'scope': {'level': 'project', 'ref': 1, 'secret': secret},
                        'rules': [{'id': 5, 'params': {'latestPushedK': 3, 'secret': secret},
                                   'tag_selectors': [{'kind': 'doublestar', 'pattern': '**', 'secret': secret}]}]}
            if path == '/registries/8':
                return registry
            if path.startswith('/replication/policies/'):
                return {'id': int(path.rsplit('/', 1)[1]), 'name': 'actual-policy', 'override': False,
                        'dest_registry': registry, 'secret': secret,
                        'filters': [{'type': 'name', 'value': 'approved/**', 'secret': secret}]}
            raise AssertionError('Unexpected read: ' + path)

        def pages(self, path):
            self.calls.append(('GET', path))
            if path == '/projects':
                return copy.deepcopy(projects)
            assert path in ('/projects/approved/repositories', '/projects/qualification/repositories')
            return [{'name': 'approved/service/releases', 'artifact_count': 2, 'credential': secret}]

        def post(self, *args, **kwargs):
            raise AssertionError('Existing configuration must not be created again')

    apis = {side: ReadOnlyAPI() for side in ('source', 'target')}
    scoped = []

    def scoped_client(*args):
        api = ReadOnlyAPI()
        scoped.append(api)
        return api

    monkeypatch.setattr(controller, 'clients', lambda root: (stack, apis))
    monkeypatch.setattr(controller, 'Harbor', scoped_client)
    return SimpleNamespace(root=tmp_path, secret=secret, history=history, apis=apis,
                           scoped=scoped, projects=projects, registry=registry)


def test_inspect_is_read_only_sanitized_and_preserves_execution_report(configured):
    c = configured
    first = controller.inspect_configuration(c.root)
    assert c.secret not in json.dumps(first)
    assert controller.load(c.root, 'harbor-replication.json') == c.history
    assert first['registry']['ca_configured'] is True
    assert first['registry']['insecure_field_present'] is False
    assert 'insecure' not in first['registry']  # Do not invent an API value that was omitted.
    assert first['policies']['approved']['override'] is False
    for instance in first['instances'].values():
        assert instance['robot_permissions'][0]['access'] == [{'resource': 'repository', 'action': 'pull'}]
        assert all(project['retention'] == {'configured': False, 'policy': None} for project in instance['projects'])
    assert all('/v2/_catalog' not in path for api in c.scoped for _, path in api.calls)
    assert all('/retentions/' not in path for api in c.apis.values() for _, path in api.calls)

    c.registry['insecure'] = True
    second = controller.inspect_configuration(c.root)
    assert second['registry']['insecure'] is True
    assert controller.load(c.root, 'harbor-configuration.json') == second
    assert controller.load(c.root, 'harbor-replication.json') == c.history


def test_inspect_records_configured_retention_rules_without_secret_fields(configured):
    configured.projects[0]['metadata']['retention_id'] = '4'
    snapshot = controller.inspect_configuration(configured.root)
    assert configured.secret not in json.dumps(snapshot)
    policy = snapshot['instances']['source']['projects'][0]['retention']['policy']
    assert policy['id'] == 4
    assert policy['rules'][0]['params'] == {'latestPushedK': 3}
    assert policy['rules'][0]['tag_selectors'] == [{'kind': 'doublestar', 'pattern': '**'}]


def test_repeated_setup_reports_actual_existing_permissions_and_policies(configured):
    controller.setup(configured.root)
    controller.setup(configured.root)
    report = controller.load(configured.root, 'harbor-replication.json')
    assert report['executions'] == configured.history['executions']
    assert configured.secret not in json.dumps(report)
    assert report['instances']['source']['robot_permissions'][0]['namespace'] == 'approved'
    assert set(report['policies']) == {'approved', 'qualification', 'interruption'}
    assert report['policies']['approved']['override'] is False


@pytest.mark.parametrize('active', [True, False])
def test_interruption_requires_observed_active_task_and_explicit_stop(tmp_path, monkeypatch, active):
    controller.save(tmp_path, 'replication-state.json', {'policies': {'qualification': 3}})
    controller.save(tmp_path, 'harbor-replication.json', {'executions': []})
    calls = []
    statuses = iter(['InProgress', 'Stopped'] if active else ['Failed'])
    tasks = iter([[{'id': 7, 'status': 'InProgress'}], [{'id': 7, 'status': 'Stopped'}]]
                 if active else [[{'id': 7, 'status': 'Failed'}]])

    class ReplicationAPI:
        def post(self, path, value):
            result = response(201)
            result.headers['Location'] = '/api/v2.0/replication/executions/9'
            return result

        def get(self, path):
            return {'id': 9, 'status': next(statuses)}

        def pages(self, path):
            return next(tasks)

        def request(self, method, path):
            calls.append((method, path))
            return response(200, 'retained task log')

    monkeypatch.setattr(controller, 'clients', lambda root: ({}, {'source': ReplicationAPI()}))
    monkeypatch.setattr(controller.time, 'sleep', lambda seconds: None)
    if active:
        controller.replicate(tmp_path, 'qualification', 'interruption', interrupt_after=0)
    else:
        with pytest.raises(AssertionError, match='observed active task'):
            controller.replicate(tmp_path, 'qualification', 'interruption', interrupt_after=0)
    row = controller.load(tmp_path, 'harbor-replication.json')['executions'][0]
    assert row['stop_requested'] is active
    assert bool(row['active_tasks_before_stop']) is active
    assert any(method == 'PUT' for method, _ in calls) is active
