"""Service identity mistakes must fail before acceptance API login or writes."""
import sys

import pytest

import nginx_workflow_integration as workflow


@pytest.fixture
def workspace(tmp_path):
    workflow.save(tmp_path, 'stack.json', {
        'full_url': 'http://acceptance.invalid', 'admin_username': 'test-admin',
        'admin_password': 'initial-test-password', 'admin_new_password': 'final-test-password',
    })
    return tmp_path


@pytest.mark.parametrize('service_key', [
    '', '../other', '.hidden', '/absolute', 'has space', 'has/slash',
    'has\\slash', 'has\nnewline', 'x' * 201,
])
def test_malformed_service_key_rejected_before_api(workspace, monkeypatch, capsys, service_key):
    monkeypatch.setattr(workflow, 'API', lambda _: pytest.fail('Invalid identity must not create an API client'))
    monkeypatch.setattr(sys, 'argv', ['nginx-workflow', 'setup', '--workspace', str(workspace),
                                     '--service-key', service_key])
    with pytest.raises(SystemExit) as error:
        workflow.main()
    assert error.value.code == 2
    assert '--service-key must be a nonempty service identifier' in capsys.readouterr().err
    assert not (workspace / 'workflow-state.json').exists()


@pytest.mark.parametrize('phase', ['setup', 'source', 'patch', 'patched'])
def test_conflicting_retained_service_key_rejected_before_api(workspace, monkeypatch, capsys, phase):
    workflow.save(workspace, 'workflow-state.json', {'service_key': 'already-approved', 'approval_id': 7})
    original = (workspace / 'workflow-state.json').read_bytes()
    monkeypatch.setattr(workflow, 'API', lambda _: pytest.fail('Conflicting identity must not create an API client'))
    monkeypatch.setattr(sys, 'argv', ['nginx-workflow', phase, '--workspace', str(workspace),
                                     '--service-key', 'different-service'])
    with pytest.raises(SystemExit) as error:
        workflow.main()
    assert error.value.code == 2
    assert '--service-key differs from the retained workspace identity' in capsys.readouterr().err
    assert (workspace / 'workflow-state.json').read_bytes() == original


@pytest.mark.parametrize('supplied', ['nginx-staging_20261105.1', 'x' * 200, None])
def test_valid_or_retained_service_identity_reaches_setup_unchanged(workspace, monkeypatch, supplied):
    expected = supplied or 'retained-identity'
    if supplied is None:
        workflow.save(workspace, 'workflow-state.json', {'service_key': expected})
    calls = []

    class API:
        def __init__(self, base):
            assert base == 'http://acceptance.invalid'

        def login(self, *args):
            calls.append('login')

    def setup(api, root, stack, state):
        assert state['service_key'] == expected
        calls.append('setup')

    monkeypatch.setattr(workflow, 'API', API)
    monkeypatch.setattr(workflow, 'setup', setup)
    argv = ['nginx-workflow', 'setup', '--workspace', str(workspace)]
    if supplied is not None:
        argv += ['--service-key', supplied]
    monkeypatch.setattr(sys, 'argv', argv)
    workflow.main()
    assert calls == ['login', 'setup']
    assert workflow.load(workspace, 'workflow-state.json')['service_key'] == expected
