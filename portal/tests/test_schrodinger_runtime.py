"""Real Helm lifecycle in strict mode retains every sandbox gate."""
import json

import pytest
import yaml
from app.deployment_validation import CommandResult, KindDeploymentValidator, ValidationArtifact, ValidationConfig
from test_deployment_validation import healthy_runner


def strict_runner(calls, *, failure=None):
    base = healthy_runner(calls)
    networks = set()
    def runner(command, **kwargs):
        if command[:2] == ['helm', 'template']:
            completed = base(command, **kwargs)
            resources = list(yaml.safe_load_all(completed.stdout))
            pod = resources[0]['spec']['template']['spec']
            pod['automountServiceAccountToken'] = False
            pod['containers'][0]['securityContext'] = {
                'runAsNonRoot': True, 'allowPrivilegeEscalation': False,
                'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}}
            if failure == 'policy':
                pod['hostNetwork'] = True
            return CommandResult(stdout=yaml.safe_dump_all(resources))
        if command[:3] == ['docker', 'network', 'create']:
            networks.add(command[-1])
        if command[:3] == ['docker', 'network', 'rm']:
            networks.discard(command[-1])
        if failure == 'resource-policy' and command[:2] == ['kubectl', 'apply'] and any(str(arg).endswith('validation-policy.yaml') for arg in command):
            return CommandResult(1, '', 'resource policy unavailable')
        result = base(command, **kwargs)
        if command[:3] == ['docker', 'network', 'inspect'] and command[-1] in networks:
            return CommandResult(stdout=json.dumps([{'Internal': True, 'EnableIPv6': False, 'Driver': 'bridge',
                'Options': {'com.docker.network.bridge.gateway_mode_ipv4': 'isolated'}}]))
        if command[:3] == ['docker', 'inspect', '--format={{json .NetworkSettings.Networks}}']:
            return CommandResult(stdout=json.dumps({next(iter(networks)): {}}))
        if command[:3] == ['docker', 'inspect', '--format={{json .HostConfig}}']:
            return CommandResult(stdout=json.dumps({'NanoCpus': 4000000000, 'Memory': 8589934592, 'PidsLimit': 2048}))
        if failure == 'install' and command[:2] == ['helm', 'upgrade']:
            return CommandResult(1, '', 'install failed')
        if failure == 'status' and command[:2] == ['helm', 'status']:
            return CommandResult(stdout='{"info":{"status":"failed"}}')
        if failure == 'readiness' and command[:2] == ['kubectl', 'rollout']:
            return CommandResult(1, '', 'timed out waiting for readiness')
        return result
    return runner


def execute(tmp_path, calls, failure=None):
    return KindDeploymentValidator(ValidationConfig(strict_sandbox_policy=True, workspace_root=str(tmp_path)),
        strict_runner(calls, failure=failure)).validate_artifact(ValidationArtifact(
            source_files={'Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n'},
            job_id='a' * 32, require_helm_lifecycle=True))


def test_strict_lifecycle_runs_helm_install_status_after_verified_guards(tmp_path):
    calls = []
    result = execute(tmp_path, calls)
    assert result['status'] == 'VERIFIED', result['reason']
    commands = [row[0] for row in calls]
    install = next(index for index, argv in enumerate(commands) if argv[:2] == ('helm', 'upgrade'))
    assert '--install' in commands[install]
    assert any(argv[:2] == ('helm', 'status') for argv in commands[install + 1:])
    assert any(argv[:2] == ('docker', 'update') for argv in commands[:install])
    assert any('pod-security.kubernetes.io/enforce=restricted' in argv for argv in commands[:install])
    assert result['resource_isolation']['overall'] == 'ENFORCED'
    assert result['helm_result']['install'] == 'PASS'
    assert result['helm_result']['release_status'] == 'DEPLOYED'
    assert result['cleanup_status'] == 'COMPLETE'
    assert not list(tmp_path.iterdir())


def test_strict_policy_failure_is_fatal_before_helm_install(tmp_path):
    calls = []
    result = execute(tmp_path, calls, 'policy')
    assert result['status'] != 'VERIFIED'
    assert result['reason_category'] == 'SECURITY_POLICY_VIOLATION'
    assert not any(argv[:2] == ('helm', 'upgrade') for argv, _, _ in calls)
    assert not any(argv[:3] == ('kind', 'create', 'cluster') for argv, _, _ in calls)
    assert result['cleanup_status'] == 'NOT_REQUIRED'
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('failure', ['install', 'status', 'readiness'])
def test_strict_runtime_failures_never_verify_and_always_clean(tmp_path, failure):
    calls = []
    result = execute(tmp_path, calls, failure)
    assert result['status'] != 'VERIFIED', result['reason']
    assert any(argv[:2] == ('helm', 'upgrade') for argv, _, _ in calls)
    assert any(argv[:3] == ('kind', 'delete', 'cluster') for argv, _, _ in calls)
    assert result['cleanup_status'] == 'COMPLETE'
    assert not list(tmp_path.iterdir())



def test_resource_policy_failure_blocks_real_helm_and_cleans(tmp_path):
    calls = []
    result = execute(tmp_path, calls, 'resource-policy')
    assert result['status'] == 'COULD_NOT_VALIDATE'
    assert result['reason_category'] == 'RESOURCE_LIMIT_ENFORCEMENT_UNAVAILABLE'
    assert not any(argv[:2] == ('helm', 'upgrade') for argv, _, _ in calls)
    assert result['cleanup_status'] == 'COMPLETE'
    assert not list(tmp_path.iterdir())
