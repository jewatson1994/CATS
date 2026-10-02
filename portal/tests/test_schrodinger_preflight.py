import importlib.util
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location('schrodinger_preflight', Path(__file__).resolve().parents[2] / 'scripts' / 'schrodinger-preflight.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def test_missing_configuration_fails_without_commands_or_writes(tmp_path):
    before = list(tmp_path.iterdir())
    checks = preflight.check_host({'CATS_VALIDATOR_STATE_DIR': str(tmp_path)}, which=lambda name: None,
                                  run=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('unexpected command')))
    assert any(level == 'FAIL' and 'fingerprints' in message for level, message in checks)
    assert any(level == 'FAIL' and 'SERVER_KEY' in message for level, message in checks)
    assert list(tmp_path.iterdir()) == before


def test_preflight_commands_are_read_only_and_do_not_echo_secrets(tmp_path):
    seen = []
    def run(argv, **kwargs):
        seen.append(argv)
        output = '28.1.0' if argv[:2] == ['docker', 'version'] else 'rootless' if argv[:2] == ['docker', 'info'] else 'SECRET_OUTPUT'
        return subprocess.CompletedProcess(argv, 0, output, '')
    checks = preflight.check_host({'CATS_VALIDATOR_STATE_DIR': str(tmp_path),
        'CATS_VALIDATOR_CLIENT_FINGERPRINTS': 'ab' * 32,
        'CATS_DEPLOYMENT_KIND_NODE_IMAGE': 'kindest/node@sha256:' + 'cd' * 32}, run=run, which=lambda name: name)
    assert seen
    assert all(not any(arg in ('create', 'delete', 'rm', 'load', 'pull', 'apply') for arg in argv) for argv in seen)
    assert 'SECRET_OUTPUT' not in str(checks)
    assert not list(tmp_path.iterdir())


def test_config_rejects_unsafe_network_and_malformed_bounds(tmp_path):
    checks = preflight.check_host({'CATS_VALIDATOR_STATE_DIR': str(tmp_path),
        'CATS_VALIDATOR_MAX_TIMEOUT': 'NaN', 'CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS': 'true',
        'CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES': 'false',
        'CATS_VALIDATOR_PREFLIGHT_ENDPOINT': 'http://user:password@example.test'}, which=lambda name: None)
    failures = [message for level, message in checks if level == 'FAIL']
    assert any('MAX_TIMEOUT' in message for message in failures)
    assert any('egress' in message for message in failures)
    assert any('local image' in message for message in failures)
    assert any('HTTPS' in message for message in failures)
    assert 'password' not in str(checks)


def test_old_docker_fails_closed(tmp_path):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, '27.5.1', '')
    checks = preflight.check_host({'CATS_VALIDATOR_STATE_DIR': str(tmp_path)}, run=run, which=lambda name: name)
    assert ('FAIL', 'Docker Engine 28+ required for isolated gateway networking') in checks
