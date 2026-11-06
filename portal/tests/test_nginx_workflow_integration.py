"""Evidence and identity mistakes fail before acceptance API login or writes."""
import copy
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


PATCH_DIGEST = 'sha256:' + 'a' * 64
HARDENED_DIGEST = 'sha256:' + 'b' * 64
PATCH_REFERENCE = 'publisher.test:5000/patched/nginx@' + PATCH_DIGEST
HARDENED_REFERENCE = 'publisher.test:5000/hardened/nginx@' + HARDENED_DIGEST


@pytest.fixture
def hardening(workspace):
    workflow.save(workspace, 'patch-result.json', {
        'status': 'complete', 'result': {
            'status': 'complete', 'output_mode': 'push', 'delivery_status': 'delivered',
            'signature_status': 'verified', 'patch_status': 'PATCHED', 'vulnerabilities_removed': 194,
            'immutable_destination': PATCH_REFERENCE,
        },
    })
    receipt = {
        'format': 'cats-nginx-hardening-runtime-v1', 'complete': True,
        'source_reference': PATCH_REFERENCE, 'hardened_reference': HARDENED_REFERENCE,
        'source_manifest_digest': PATCH_DIGEST, 'source_config_digest': 'sha256:' + 'c' * 64,
        'hardened_manifest_digest': HARDENED_DIGEST, 'hardened_config_digest': 'sha256:' + 'd' * 64,
        'docker_image_id': HARDENED_DIGEST, 'execution_image': HARDENED_DIGEST,
        'recipe_sha256': 'sha256:' + 'e' * 64,
        'checks': dict.fromkeys(workflow.HARDENING_CHECKS, True),
    }
    workflow.save(workspace, 'supplied-hardening.json', receipt)
    return receipt


def deny_api(monkeypatch, workspace, *extra):
    monkeypatch.setattr(workflow, 'API', lambda _: pytest.fail('Invalid evidence must fail before API creation'))
    monkeypatch.setattr(sys, 'argv', ['nginx-workflow', 'patched', '--workspace', str(workspace), *extra])


@pytest.mark.parametrize('phase', ['setup', 'source', 'patch'])
def test_hardening_option_is_only_for_final_scan(workspace, monkeypatch, phase):
    deny_api(monkeypatch, workspace)
    monkeypatch.setattr(sys, 'argv', ['nginx-workflow', phase, '--workspace', str(workspace),
                                     '--hardened-receipt', str(workspace / 'missing.json')])
    with pytest.raises(SystemExit) as error:
        workflow.main()
    assert error.value.code == 2
    assert not (workspace / 'workflow-state.json').exists()


@pytest.mark.parametrize('field,value', [
    ('format', 'unknown'), ('complete', False), ('complete', 1), ('checks', []),
    ('source_reference', 'elsewhere.test/nginx@' + PATCH_DIGEST),
    ('hardened_reference', 'publisher.test/hardened:latest'),
    ('hardened_reference', 'https://publisher.test/hardened@' + HARDENED_DIGEST),
    ('hardened_reference', 'publisher.test/hardened?bad@' + HARDENED_DIGEST),
    ('hardened_reference', 'publisher.test/hardened@' + PATCH_DIGEST),
    ('source_manifest_digest', HARDENED_DIGEST), ('hardened_manifest_digest', PATCH_DIGEST),
    ('source_config_digest', 'sha256:bad'), ('hardened_config_digest', None),
    ('docker_image_id', PATCH_DIGEST), ('execution_image', PATCH_DIGEST),
    ('recipe_sha256', 'unknown'),
])
def test_bad_hardening_receipt_fails_without_actions(workspace, hardening, monkeypatch, field, value):
    hardening[field] = value
    workflow.save(workspace, 'supplied-hardening.json', hardening)
    deny_api(monkeypatch, workspace, '--hardened-receipt', str(workspace / 'supplied-hardening.json'))
    with pytest.raises(RuntimeError):
        workflow.main()
    assert not (workspace / 'workflow-state.json').exists()
    assert not (workspace / 'hardening-result.json').exists()


@pytest.mark.parametrize('check', workflow.HARDENING_CHECKS)
def test_each_runtime_check_is_mandatory(workspace, hardening, monkeypatch, check):
    del hardening['checks'][check]
    workflow.save(workspace, 'supplied-hardening.json', hardening)
    deny_api(monkeypatch, workspace, '--hardened-receipt', str(workspace / 'supplied-hardening.json'))
    with pytest.raises(RuntimeError, match='every runtime verification'):
        workflow.main()
    assert not (workspace / 'workflow-state.json').exists()


@pytest.mark.parametrize('receipt', [None, [], 'not-a-receipt'])
def test_explicit_receipt_must_be_an_object(workspace, hardening, monkeypatch, receipt):
    workflow.save(workspace, 'supplied-hardening.json', receipt)
    deny_api(monkeypatch, workspace, '--hardened-receipt', str(workspace / 'supplied-hardening.json'))
    with pytest.raises(RuntimeError, match='supported runtime receipt'):
        workflow.main()
    assert not (workspace / 'workflow-state.json').exists()


def test_runtime_check_truthiness_is_not_success(workspace, hardening, monkeypatch):
    hardening['checks']['healthy'] = 1
    workflow.save(workspace, 'supplied-hardening.json', hardening)
    deny_api(monkeypatch, workspace, '--hardened-receipt', str(workspace / 'supplied-hardening.json'))
    with pytest.raises(RuntimeError, match='every runtime verification'):
        workflow.main()


def test_retained_hardening_result_without_state_requires_explicit_binding(workspace, hardening, monkeypatch):
    workflow.save(workspace, 'hardening-result.json', hardening)
    deny_api(monkeypatch, workspace)
    with pytest.raises(RuntimeError, match='Unbound hardening evidence'):
        workflow.main()


@pytest.mark.parametrize('use_config_id', [False, True])
def test_hardened_scan_preserves_package_patch_and_resumes_exact_evidence(
        workspace, hardening, monkeypatch, use_config_id):
    if use_config_id:
        hardening['docker_image_id'] = hardening['execution_image'] = hardening['hardened_config_digest']
        workflow.save(workspace, 'supplied-hardening.json', hardening)
    original_patch = (workspace / 'patch-result.json').read_bytes()
    calls = []

    class API:
        def __init__(self, base):
            pass

        def login(self, *args):
            calls.append('login')

    def scan(api, root, state, label, reference, *args):
        assert reference == HARDENED_REFERENCE
        assert label == 'patched'
        assert state['hardening']['source_reference'] == PATCH_REFERENCE
        state[label] = {'reference': reference}
        workflow.save(root, 'workflow-state.json', state)
        calls.append('scan')

    def approve(api, root, state, label):
        assert workflow.patched_scan_reference(root, state)[0] == HARDENED_REFERENCE
        calls.append('approve')

    monkeypatch.setattr(workflow, 'API', API)
    monkeypatch.setattr(workflow, 'discover_scan', scan)
    monkeypatch.setattr(workflow, 'approve', approve)
    argv = ['nginx-workflow', 'patched', '--workspace', str(workspace)]
    monkeypatch.setattr(sys, 'argv', [*argv, '--hardened-receipt', str(workspace / 'supplied-hardening.json')])
    workflow.main()
    binding = workflow.load(workspace, 'workflow-state.json')['hardening']
    monkeypatch.setattr(sys, 'argv', argv)
    workflow.main()
    assert calls == ['login', 'scan', 'approve'] * 2
    assert workflow.load(workspace, 'hardening-result.json') == hardening
    assert workflow.load(workspace, 'workflow-state.json')['hardening'] == binding
    assert (workspace / 'patch-result.json').read_bytes() == original_patch


@pytest.mark.parametrize('conflict', ['receipt', 'binding', 'missing', 'checkpoint', 'supplied'])
def test_hardening_binding_cannot_be_reused_for_changed_evidence(
        workspace, hardening, monkeypatch, conflict):
    _, binding = workflow.validate_hardening_receipt(hardening, PATCH_REFERENCE)
    state = {'hardening': binding, 'patched': {'reference': HARDENED_REFERENCE}}
    workflow.save(workspace, 'hardening-result.json', hardening)
    extra = []
    if conflict == 'receipt':
        hardening['runtime_details'] = {'changed': True}
        workflow.save(workspace, 'hardening-result.json', hardening)
    elif conflict == 'binding':
        state['hardening']['receipt_content_sha256'] = '0' * 64
    elif conflict == 'missing':
        (workspace / 'hardening-result.json').unlink()
    elif conflict == 'checkpoint':
        state['patched']['reference'] = PATCH_REFERENCE
    else:
        hardening['recipe_sha256'] = 'sha256:' + 'f' * 64
        workflow.save(workspace, 'supplied-hardening.json', hardening)
        extra = ['--hardened-receipt', str(workspace / 'supplied-hardening.json')]
    workflow.save(workspace, 'workflow-state.json', state)
    original = (workspace / 'workflow-state.json').read_bytes()
    deny_api(monkeypatch, workspace, *extra)
    with pytest.raises(RuntimeError):
        workflow.main()
    assert (workspace / 'workflow-state.json').read_bytes() == original


def test_cannot_replace_preexisting_package_patch_scan_with_hardened_scan(workspace, hardening, monkeypatch):
    state = {'patched': {'reference': PATCH_REFERENCE, 'scan_id': 'already-scanned', 'approval_id': 3}}
    workflow.save(workspace, 'workflow-state.json', state)
    deny_api(monkeypatch, workspace, '--hardened-receipt', str(workspace / 'supplied-hardening.json'))
    with pytest.raises(RuntimeError, match='different immutable input'):
        workflow.main()
    assert workflow.load(workspace, 'workflow-state.json') == state
    assert not (workspace / 'hardening-result.json').exists()


def test_hardening_does_not_substitute_for_actual_package_remediation(workspace, hardening, monkeypatch):
    patch = workflow.load(workspace, 'patch-result.json')
    patch['result']['vulnerabilities_removed'] = 0
    workflow.save(workspace, 'patch-result.json', patch)
    deny_api(monkeypatch, workspace, '--hardened-receipt', str(workspace / 'supplied-hardening.json'))
    with pytest.raises(RuntimeError, match='actual vulnerability remediation'):
        workflow.main()


@pytest.mark.parametrize('publication_digest', [HARDENED_DIGEST, PATCH_DIGEST])
def test_approval_requires_exact_independently_scanned_hardened_digest(workspace, hardening, publication_digest):
    _, binding = workflow.validate_hardening_receipt(hardening, PATCH_REFERENCE)
    workflow.save(workspace, 'hardening-result.json', hardening)
    state = {'hardening': binding, 'patched': {'reference': HARDENED_REFERENCE, 'approval_id': 7}}
    artifact = {
        'kind': 'image', 'reference': 'publisher.test/approved/nginx@' + publication_digest,
        'digest': publication_digest, 'source_digest': publication_digest,
        'scan_identity_retained': True, 'tag': 'published', 'signature': {'digest': 'sha256:' + 'f' * 64},
    }
    receipt = {
        'status': 'published', 'verification_status': 'verified', 'signature_status': 'verified',
        'artifacts': [artifact], 'release': copy.deepcopy(artifact), 'manifest': {'portable': {'release_uuid': '2'}},
    }

    class API:
        def get(self, path):
            return {'status': 'approved', 'publish_status': 'published', 'publication': receipt}

    if publication_digest == HARDENED_DIGEST:
        workflow.approve(API(), workspace, state, 'patched')
    else:
        with pytest.raises(RuntimeError, match='actual immutable patch output'):
            workflow.approve(API(), workspace, state, 'patched')


def test_legacy_package_patch_reference_is_unchanged(workspace, hardening):
    assert workflow.patched_scan_reference(workspace, {}) == (PATCH_REFERENCE, None, None)
