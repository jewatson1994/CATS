"""Durable managed-validator provisioning readiness regressions."""
from types import SimpleNamespace
import pytest
from app import validator_management as management


def host(status='supported'):
    return SimpleNamespace(ssh_fingerprint='SHA256:trusted', preflight={
        'status': status, 'checks': {'sudo': True, 'api_port': True, 'platform': True},
        'facts': {'os': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64',
                  'sudo': True, 'sudo_password_required': True},
        'warnings': ['Resources meet hard minimum only'] if status == 'supported_with_warnings' else []})


@pytest.fixture
def payload(monkeypatch):
    calls = []
    def inventory():
        calls.append(True)
        return {'available': True, 'digest': 'a' * 64, 'platforms': [
            {'os': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64', 'payload_version': 'test'}]}
    monkeypatch.setattr(management, 'payload_status', inventory)
    return calls


@pytest.mark.parametrize('status', ['supported', 'supported_with_warnings'])
def test_supported_authenticated_preflight_is_durable(status, payload):
    validator = host(status)
    first = management.provisioning_readiness(validator)
    assert first['ready']
    assert first == management.provisioning_readiness(validator)
    assert first['checks']['connectionTest']['ready']
    assert first['checks']['sudo']['password_required'] is True
    assert first['checks']['payload']['platform'] == {'os': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64'}
    assert 'credentials' not in first['checks']
    assert 'upgradeConfirmation' not in first['checks']


def test_unsupported_always_blocks(payload):
    result = management.provisioning_readiness(host('unsupported'))
    assert not result['ready']
    assert not result['checks']['preflight']['ready']


def test_missing_payload_names_actual_host_platform(monkeypatch):
    monkeypatch.setattr(management, 'payload_status', lambda: {'available': False})
    result = management.provisioning_readiness(host())
    assert not result['ready']
    assert 'ubuntu 22.04 amd64' in result['checks']['payload']['reason']
    assert 'verified' in result['blocking_reasons'][0]


def test_wrong_payload_platform_is_rejected(monkeypatch):
    monkeypatch.setattr(management, 'payload_status', lambda: {'available': True, 'platforms': [
        {'os': 'ubuntu', 'os_version': '24.04', 'architecture': 'amd64'}]})
    assert not management.provisioning_readiness(host())['checks']['payload']['ready']


@pytest.mark.parametrize('missing', ['fingerprint', 'connectionTest', 'sudo', 'apiPort'])
def test_missing_prerequisites_have_reasons(missing, payload):
    validator = host()
    if missing == 'fingerprint':
        validator.ssh_fingerprint = None
    elif missing == 'connectionTest':
        validator.preflight = {}
    else:
        validator.preflight['checks']['sudo' if missing == 'sudo' else 'api_port'] = False
    result = management.provisioning_readiness(validator)
    assert not result['ready']
    assert result['checks'][missing]['reason']


def test_missing_platform_does_not_select_default_payload(payload):
    validator = host()
    del validator.preflight['facts']['os_version']
    result = management.provisioning_readiness(validator)
    assert not result['checks']['payload']['ready']
    assert not payload

@pytest.mark.parametrize('root,passwordless,expected', [(True, False, False), (False, True, False), (False, False, True)])
def test_preflight_distinguishes_sudo_password_requirement(root, passwordless, expected):
    import json
    from unittest.mock import patch
    from app.validator_bootstrap import SSHBootstrap
    bootstrap = SSHBootstrap({'host': '192.168.1.4'}, {'sudo_password': 'temporary'})
    facts = {'os': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64',
             'cpus': 4, 'memory_bytes': 8 * 1024**3, 'disk_bytes': 40 * 1024**3,
             'root': root, 'systemd': True}
    with patch.object(bootstrap, '_run', return_value=json.dumps(facts)), patch.object(
            bootstrap, '_sudo_available', side_effect=lambda **kwargs: passwordless if kwargs.get('passwordless') else True) as probe:
        result = bootstrap.preflight()
    assert result['facts']['sudo_password_required'] is expected
    assert result['checks']['sudo'] is True
    assert probe.call_count == (0 if root else 1 if passwordless else 2)


def test_readiness_reuses_verified_inventory_without_rehashing(monkeypatch):
    from unittest.mock import Mock
    inventory = {'available': True, 'digest': 'a' * 64, 'platforms': [
        {'os': 'ubuntu', 'os_version': '22.04', 'architecture': 'amd64'}]}
    monkeypatch.setattr(management, 'payload_status', lambda: inventory)
    material = Mock(side_effect=AssertionError('Rendering must not verify payload bytes'))
    monkeypatch.setattr(management, 'select_payload', material)
    assert management.provisioning_readiness(host())['ready']
    assert management.provisioning_readiness(host())['ready']
    material.assert_not_called()