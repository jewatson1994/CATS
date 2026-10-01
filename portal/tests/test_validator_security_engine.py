import json

import pytest

from app.deployment_validation import CommandResult, ValidationConfig, attempt_resource_isolation, security_preflight, cleanup_stale_clusters, _isolated_network_verified


def workload():
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {
        "automountServiceAccountToken": False, "containers": [{"name": "app", "image": "local:test", "securityContext": {
            "runAsNonRoot": True, "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def test_strict_accepts_restricted_namespace_workload():
    assert not security_preflight([workload()], ValidationConfig(strict_sandbox_policy=True), namespace="run")


@pytest.mark.parametrize("kind,api", [("ClusterRole", "rbac.authorization.k8s.io/v1"), ("RoleBinding", "rbac.authorization.k8s.io/v1"),
    ("Namespace", "v1"), ("NetworkPolicy", "networking.k8s.io/v1"), ("Widget", "operator.example/v1"), ("CronJob", "batch/v1")])
def test_strict_rejects_control_plane_and_unbounded_apis(kind, api):
    assert security_preflight([{"kind": kind, "apiVersion": api}], ValidationConfig(strict_sandbox_policy=True), namespace="run")


@pytest.mark.parametrize("field,value", [("hostNetwork", True), ("hostPID", True), ("hostIPC", True),
    ("serviceAccountName", "admin"), ("automountServiceAccountToken", True), ("volumes", [{"hostPath": {"path": "/tmp"}}])])
def test_strict_rejects_pod_escapes(field, value):
    resource = workload()
    resource["spec"][field] = value
    assert security_preflight([resource], ValidationConfig(strict_sandbox_policy=True), namespace="run")


def test_strict_namespace_and_security_context_are_explicit():
    resource = workload()
    resource["metadata"]["namespace"] = "kube-system"
    resource["spec"]["containers"][0]["securityContext"] = {}
    assert len(security_preflight([resource], ValidationConfig(strict_sandbox_policy=True), namespace="run")) >= 4


def test_strict_rejects_ingress_controller_snippet_escape():
    ingress = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {
        "name": "escape", "annotations": {"nginx.ingress.kubernetes.io/server-snippet": "malicious directive"}}}
    assert security_preflight([ingress], ValidationConfig(strict_sandbox_policy=True), namespace="run")


def test_strict_resource_verification_requires_exact_configured_values():
    def runner(argv, **kwargs):
        return CommandResult(stdout=json.dumps({"NanoCpus": 1, "Memory": 1, "PidsLimit": -1}))
    assert attempt_resource_isolation(ValidationConfig(strict_sandbox_policy=True), "node", runner, timeout=1)["overall"] == "BEST_EFFORT"


def test_strict_stale_cleanup_requires_ownership_not_prefix():
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return CommandResult(stdout="{}")
    outcome = cleanup_stale_clusters(["cats-validation-foreign"], runner=runner, config=ValidationConfig(strict_sandbox_policy=True))
    assert outcome["failed"] == ["cats-validation-foreign"]
    assert not any("delete" in argv or "rm" in argv for argv in calls)


@pytest.mark.parametrize("override", [{"Internal": False}, {"EnableIPv6": True}, {"Options": {}}, {"Driver": "host"}])
def test_strict_network_unsupported_or_weaker_is_fail_closed(override):
    network = {"Internal": True, "EnableIPv6": False, "Driver": "bridge", "Options": {
        "com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}
    assert _isolated_network_verified(CommandResult(stdout=json.dumps([network])))
    network.update(override)
    assert not _isolated_network_verified(CommandResult(stdout=json.dumps([network])))
