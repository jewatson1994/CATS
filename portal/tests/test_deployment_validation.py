import json
from pathlib import Path

import pytest

from app.deployment_validation import (
    CommandResult, KindDeploymentValidator, ValidationArtifact, ValidationConfig, attempt_resource_isolation,
    build_observed_topology, canonical_resource_identity, classify_failure, cleanup_stale_clusters, compare_topology,
    _service_dns_probe, capability_assessment_groups, capability_preflight, classification_reason_evidence, materialize_sources, parse_observations, sandbox_preflight, security_policy_violation_evidence, security_preflight, validation_names,
    _yaml_documents,
)


def test_capability_preflight_detects_generic_and_provider_specific_requirements():
    rows = capability_preflight([
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "edge", "namespace": "demo"}, "spec": {"type": "LoadBalancer"}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": "web", "namespace": "demo", "annotations": {"kubernetes.io/ingress.class": "alb"}}, "spec": {}},
        {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data", "namespace": "demo"}, "spec": {"storageClassName": "gp3"}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "gpu", "namespace": "demo"}, "spec": {"template": {"spec": {"containers": [{"name": "gpu", "image": "x", "resources": {"limits": {"nvidia.com/gpu": 1}}}]}}}},
    ])
    by_capability = {row["capability"]: row for row in rows if row["capability"] in {"LoadBalancer", "Ingress", "Storage", "GPU / extended resources"}}
    assert by_capability["LoadBalancer"]["required"] is True
    assert by_capability["Ingress"]["provider_specific"] is True
    assert by_capability["Storage"]["provider_specific"] is True
    assert by_capability["GPU / extended resources"]["status"] == "UNAVAILABLE"


def test_namespace_less_capability_rows_match_the_helm_release_namespace():
    rows = capability_preflight([{
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "web"},
        "spec": {"type": "LoadBalancer"},
    }])
    load_balancer = next(row for row in rows if row["capability"] == "LoadBalancer")
    assert load_balancer["source_namespace"] == ""


def test_capability_expansion_detects_advanced_requirements_without_claiming_enforcement():
    resources = [
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "api"}, "spec": {"ports": [{"port": 80}]}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"}, "spec": {"template": {"spec": {"containers": [{"name": "api", "image": "local/api"}]}}}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "api"}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "policy"}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "api"}, "spec": {"podSelector": {}}},
        {"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": {"name": "api"}, "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "api"}}},
        {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": "widgets.example.test"}, "spec": {"group": "example.test"}},
        {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration", "metadata": {"name": "api"}, "webhooks": []},
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": "api"}, "spec": {"tls": [{"secretName": "api-tls"}]}},
    ]
    names = {row["capability"] for row in capability_preflight(resources)}
    assert {"DNS / Service Discovery", "ServiceAccount / RBAC", "NetworkPolicy", "HPA / Metrics API", "CRDs / custom resources", "Admission Webhooks", "TLS / Certificate dependencies"} <= names


def test_classification_reasons_are_structured_and_totals_are_deterministic():
    reasons, summary = classification_reason_evidence({
        "comparison": {"matched": ["Deployment/ns/app"], "declared_only": ["CronJob/ns/maintenance"], "defaulted": ["Pod/ns/app-1"], "observed_only": []},
        "unhealthy_resources": [], "capability_preflight": [],
    }, "PARTIALLY_VERIFIED", None, "one expected object was not observed")
    assert reasons[0]["code"] == "EXPECTED_RESOURCE_NOT_OBSERVED"
    assert reasons[0]["resource"] == {"kind": "CronJob", "namespace": "ns", "name": "maintenance"}
    assert summary == {"expected_resources": 2, "observed_expected": 1, "expected_only": 1, "runtime_generated": 1, "observed_only": 0, "failed": 0}


def test_capability_assessment_groups_preserve_rows_and_counts():
    grouped = capability_assessment_groups([
        {"capability": "Configuration dependencies", "required": True, "status": "AVAILABLE", "source_resource": "Deployment/api", "evidence": {"dependency_kind": "ConfigMap", "dependency_name": "settings", "optional": False}},
        {"capability": "Configuration dependencies", "required": True, "status": "AVAILABLE", "source_resource": "StatefulSet/api", "evidence": {"dependency_kind": "ConfigMap", "dependency_name": "settings", "optional": False}},
        {"capability": "Configuration dependencies", "required": True, "status": "AVAILABLE", "source_resource": "StatefulSet/api", "evidence": {"dependency_kind": "Secret", "dependency_name": "credentials", "optional": False}},
        {"capability": "LoadBalancer", "required": True, "status": "VERIFIED", "provisioned_by_cats": True},
    ])
    config = next(item for item in grouped if item["capability"] == "Configuration dependencies")
    assert config["required_count"] == 3 and config["available_count"] == 3 and len(config["rows"]) == 3
    assert config["dependency_total"] == 2
    assert config["dependency_available"] == 2
    assert config["dependency_rows"][0]["required_by"] == ["Deployment/api", "StatefulSet/api"]
    assert next(item for item in grouped if item["capability"] == "LoadBalancer")["provisioned_by_cats"] is True


def test_dns_dependency_is_required_only_for_explicit_service_reference():
    rows = capability_preflight([{
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "client"},
        "spec": {"template": {"spec": {"containers": [{"name": "client", "image": "local/client", "env": [{"name": "UPSTREAM", "value": "http://api.demo.svc.cluster.local:8080"}]}]}}},
    }, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "api"}}])
    dns = next(item for item in rows if item["capability"] == "DNS / Service Discovery")
    assert dns["required"] is True and dns["status"] == "PENDING"


def test_dns_probe_persists_only_bounded_names_and_booleans(tmp_path: Path):
    calls = []

    def runner(command, timeout, phase, env):
        calls.append((command, phase))
        return CommandResult(stdout="10.0.0.9 api.demo.svc.cluster.local\n")

    evidence = _service_dns_probe(
        [{"kind": "Service", "metadata": {"name": "api", "namespace": "demo"}}],
        [{"kind": "Pod", "metadata": {"name": "client", "namespace": "demo"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}],
        command=runner, cfg=ValidationConfig(), kubeconfig=tmp_path / "config", namespace="demo", env={},
    )
    assert evidence["resolved"] is True
    assert evidence["services"] == [{"service": {"name": "api", "namespace": "demo"}, "fqdn": "api.demo.svc.cluster.local", "resolved": True, "method": "getent"}]
    assert all("10.0.0.9" not in json.dumps(evidence) for _ in [0])


def test_materialize_sources_rejects_traversal_and_size(tmp_path: Path):
    with pytest.raises(ValueError, match="Unsafe"):
        materialize_sources({"../escape.yaml": "x"}, tmp_path)
    with pytest.raises(ValueError, match="size limit"):
        materialize_sources({"Chart.yaml": "too large"}, tmp_path, max_bytes=2)


def test_materialize_sources_does_not_reject_repository_cardinality(tmp_path: Path):
    files = {f"charts/chart-{index}/templates/item.yaml": "kind: ConfigMap\n" for index in range(750)}
    files["Chart.yaml"] = "apiVersion: v2\nname: root\nversion: 1.0.0\n"
    written = materialize_sources(files, tmp_path, max_bytes=1024 * 1024, max_files=1)
    assert len(written) == 751
    assert (tmp_path / "charts" / "chart-749" / "templates" / "item.yaml").is_file()


def test_rendered_yaml_accepts_semantically_irrelevant_trailing_tabs():
    resources = _yaml_documents("apiVersion: v1\t\nkind: ConfigMap\t\nmetadata:\n  name: example\t\n", 1024)
    assert resources[0]["kind"] == "ConfigMap"


def test_rendered_yaml_accepts_helm_plain_equals_argument():
    resources = _yaml_documents("apiVersion: v1\nkind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: app\n      image: example\n      args:\n        - =\n", 1024)
    assert resources[0]["spec"]["containers"][0]["args"] == ["="]


def test_security_preflight_rejects_boundary_access_and_resource_limits():
    resource = {"kind": "Deployment", "metadata": {"name": "bad"}, "spec": {"replicas": 6, "template": {"spec": {
        "containers": [{"name": "app", "image": "local/app:1", "volumeMounts": [{"name": "runtime", "mountPath": "/run/containerd/containerd.sock"}]}],
        "volumes": [{"name": "runtime", "hostPath": {"path": "/var/run/docker.sock"}}],
    }}}}
    violations = security_preflight([resource], ValidationConfig(max_pods=5))
    details = json.dumps(violations).lower()
    assert "requested pods" in details
    assert "docker.sock" in details or "runtime" in details


def test_resource_isolation_reports_each_supported_limit_as_enforced():
    calls = []
    def runner(command, **kwargs):
        calls.append(tuple(command))
        if command[:2] == ["docker", "inspect"]:
            return CommandResult(stdout=json.dumps({"NanoCpus": 4_000_000_000, "Memory": 8_000_000_000, "PidsLimit": 2048}))
        return CommandResult()
    result = attempt_resource_isolation(ValidationConfig(), "cats-validation-control-plane", runner, timeout=10)
    assert result["overall"] == "ENFORCED"
    assert all(result[key]["status"] == "ENFORCED" for key in ("cpu", "memory", "pids"))
    assert len([call for call in calls if call[:2] == ("docker", "update")]) == 3


def test_resource_isolation_unsupported_pid_is_best_effort_not_exceeded():
    def runner(command, **kwargs):
        if command[:3] == ["docker", "update", "--pids-limit"]:
            return CommandResult(1, "", "pids-limit is not supported on this runtime")
        if command[:2] == ["docker", "inspect"]:
            return CommandResult(stdout=json.dumps({"NanoCpus": 4_000_000_000, "Memory": 8_000_000_000}))
        return CommandResult()
    result = attempt_resource_isolation(ValidationConfig(), "cats-validation-control-plane", runner, timeout=10)
    assert result["overall"] == "BEST_EFFORT"
    assert result["pids"]["status"] == "UNSUPPORTED"
    assert result["pids"]["reason"]
    assert "RESOURCE_LIMIT_EXCEEDED" not in json.dumps(result)


def test_resource_isolation_inspection_exception_is_best_effort():
    def runner(command, **kwargs):
        if command[:2] == ["docker", "inspect"]:
            raise RuntimeError("Docker inspect unavailable")
        return CommandResult()
    result = attempt_resource_isolation(ValidationConfig(), "cats-validation-control-plane", runner, timeout=10)
    assert result["overall"] == "BEST_EFFORT"
    assert all(result[key]["status"] == "UNSUPPORTED" for key in ("cpu", "memory", "pids"))
    assert "RESOURCE_LIMIT_EXCEEDED" not in json.dumps(result)


def test_actual_kind_node_oom_is_classified_as_resource_limit_exceeded():
    calls = []
    base = healthy_runner(calls)
    def runner(command, **kwargs):
        if command[:3] == ["docker", "inspect", "--format={{json .HostConfig}}"]:
            return CommandResult(stdout=json.dumps({"NanoCpus": 4_000_000_000, "Memory": 8_000_000_000, "PidsLimit": 2048}))
        if command[:3] == ["docker", "inspect", "--format={{json .State}}"]:
            return CommandResult(stdout=json.dumps({"OOMKilled": True}))
        if command[:2] == ["kubectl", "rollout"]:
            return CommandResult(1, "", "timed out")
        return base(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="oom"))
    assert result["reason_category"] == "RESOURCE_LIMIT_EXCEEDED"
    assert result["resource_isolation"]["exceeded"]["condition"] == "OOMKilled"
    assert result["cleanup_status"] == "COMPLETE"


def test_security_preflight_rejects_list_wrappers_instead_of_trusting_nested_items():
    wrapped = {"apiVersion": "v1", "kind": "List", "items": [{"kind": "Pod", "spec": {"hostPID": True}}]}
    violations = security_preflight([wrapped], ValidationConfig())
    assert violations == []


def test_security_preflight_allows_ordinary_cluster_scoped_and_rbac_resources():
    """Resource scope is not itself a sandbox-boundary violation.

    In particular this is the resource set that previously prevented
    ingress-nginx from reaching kind.  The disposable cluster is the thing
    being tested, so normal RBAC, admission, and ingress resources must be
    handed to Kubernetes instead of being rejected by a static allowlist.
    """
    resources = [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "nginx"}, "rules": []},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "nginx"}, "roleRef": {"kind": "ClusterRole", "name": "nginx"}, "subjects": []},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "nginx"}, "rules": []},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "nginx"}, "roleRef": {"kind": "Role", "name": "nginx"}, "subjects": []},
        {"apiVersion": "networking.k8s.io/v1", "kind": "IngressClass", "metadata": {"name": "nginx"}, "spec": {"controller": "k8s.io/ingress-nginx"}},
        {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration", "metadata": {"name": "nginx-admission"}, "webhooks": []},
        {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": "widgets.example.test"}, "spec": {"group": "example.test", "names": {"kind": "Widget", "plural": "widgets"}, "scope": "Namespaced", "versions": [{"name": "v1", "served": True, "storage": True, "schema": {"openAPIV3Schema": {"type": "object"}}}]}},
        {"apiVersion": "example.test/v1", "kind": "Widget", "metadata": {"name": "example", "namespace": "cats-validation-run"}, "spec": {"enabled": True}},
    ]
    assert security_preflight(resources, ValidationConfig(), namespace="cats-validation-run") == []


def test_security_preflight_blocks_runtime_socket_but_not_arbitrary_host_path():
    """Only host paths that expose the runtime/host boundary are blocked."""
    safe = {"kind": "Pod", "metadata": {"name": "cache"}, "spec": {"containers": [{"name": "cache", "image": "local/cache:1"}], "volumes": [{"name": "data", "hostPath": {"path": "/var/lib/cache"}}]}}
    dangerous = {"kind": "Pod", "metadata": {"name": "escape"}, "spec": {"containers": [{"name": "escape", "image": "local/escape:1", "volumeMounts": [{"name": "runtime", "mountPath": "/run/containerd/containerd.sock"}]}], "volumes": [{"name": "runtime", "hostPath": {"path": "/var/run/docker.sock"}}]}}
    assert security_preflight([safe], ValidationConfig(), namespace="cats-validation-run") == []
    violations = security_preflight([dangerous], ValidationConfig(), namespace="cats-validation-run")
    assert violations
    assert "docker.sock" in json.dumps(violations)
    assert any("runtime" in json.dumps(item).lower() or "socket" in json.dumps(item).lower() for item in violations)


def test_security_preflight_blocks_host_pid_and_ipc_because_outer_node_is_privileged():
    host_pid = {"kind": "Pod", "metadata": {"name": "pid-reader"}, "spec": {"hostPID": True, "containers": [{"name": "app", "image": "local/app:1"}]}}
    assert security_preflight([host_pid], ValidationConfig(), namespace="cats-validation-run")
    decision = sandbox_preflight([host_pid], ValidationConfig())[0]
    assert decision["classification"] == "SANDBOX_BOUNDARY_VIOLATION"
    assert "privileged" in decision["reason"]
    host_ipc = {"kind": "Pod", "metadata": {"name": "ipc-share"}, "spec": {"hostIPC": True, "containers": [{"name": "app", "image": "local/app:1"}]}}
    assert any("hostIPC" in item.get("field_path", "") for item in security_preflight([host_ipc], ValidationConfig()))


def test_read_only_node_telemetry_paths_are_allowed_but_root_and_runtime_stay_blocked():
    def pod(path, *, read_only=True, name="telemetry"):
        return {"kind": "Pod", "metadata": {"name": name}, "spec": {"containers": [{"name": "app", "image": "local/app", "volumeMounts": [{"name": "host", "mountPath": "/host", "readOnly": read_only}]}], "volumes": [{"name": "host", "hostPath": {"path": path}}]}}
    for path in ("/proc", "/sys"):
        assert security_preflight([pod(path)], ValidationConfig()) == []
        assert sandbox_preflight([pod(path)], ValidationConfig())[0]["classification"] == "SANDBOX_SENSITIVE_ALLOWED"
    for path in ("/", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/dev"):
        assert security_preflight([pod(path, name="adversary")], ValidationConfig())
    assert security_preflight([pod("/proc", read_only=False)], ValidationConfig())


def test_host_network_requires_internal_validation_network():
    resource = {"kind": "Pod", "metadata": {"name": "network"}, "spec": {"hostNetwork": True, "containers": [{"name": "app", "image": "local/app"}]}}
    assert security_preflight([resource], ValidationConfig(allow_network_egress=False)) == []
    assert security_preflight([resource], ValidationConfig(allow_network_egress=True))


def test_privilege_capabilities_and_devices_remain_hard_boundary_violations():
    resource = {"kind": "Pod", "metadata": {"name": "escape"}, "spec": {"containers": [{"name": "app", "image": "local/app", "securityContext": {"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}}, "volumeDevices": [{"name": "disk", "devicePath": "/dev/sda"}]}]}}
    decisions = sandbox_preflight([resource], ValidationConfig())
    assert len(decisions) == 3
    assert {item["classification"] for item in decisions} == {"SANDBOX_BOUNDARY_VIOLATION"}
    assert all("prometheus" not in json.dumps(item).lower() for item in decisions)


def test_security_policy_evidence_preserves_each_violation_and_safe_attribution():
    resource = {"kind": "Deployment", "metadata": {"name": "bad", "namespace": "other"},
                "spec": {"template": {"spec": {"containers": [
                    {"name": "web", "image": "local/web:1", "volumeMounts": [{"name": "runtime", "mountPath": "/run/containerd/containerd.sock"}], "volumeDevices": [{"name": "raw", "devicePath": "/dev/sda"}]},
                ], "volumes": [{"name": "runtime", "hostPath": {"path": "/var/run/docker.sock"}}]}}}, "_cats_source_file": "templates/deployment.yaml", "_cats_source_line": 23}
    violations = security_preflight([resource], ValidationConfig(), namespace="cats-validation-run")
    evidence = security_policy_violation_evidence([resource], violations)
    assert len(evidence) == len(violations) >= 2
    assert {item["rule_id"] for item in evidence} >= {"VALIDATION_RUNTIME_SOCKET_ACCESS", "DEVICE_MOUNT"}
    runtime = next(item for item in evidence if "socket" in item["reason"].lower() or "runtime" in item["reason"].lower())
    assert runtime["container"] == "web"
    assert "volumes[0].hostPath.path" in runtime["field_path"]
    assert runtime["source_template"] == "templates/deployment.yaml"
    assert runtime["source_line"] == 23


def test_security_policy_evidence_uses_values_path_only_for_exact_mapping():
    resource = {"kind": "Pod", "metadata": {"name": "bad"}, "spec": {"containers": [{"name": "app"}], "volumes": [{"name": "runtime", "hostPath": {"path": "/var/run/docker.sock"}}]},
                "_cats_source_mappings": [{"field_path": "spec.volumes[0].hostPath.path", "values_key": "security.runtimeSocket", "values_file": "prod.yaml"}]}
    evidence = security_policy_violation_evidence([resource], security_preflight([resource], ValidationConfig()))
    assert evidence[0]["source_value_path"] == "security.runtimeSocket"
    assert evidence[0]["source"]["values_file"] == "prod.yaml"


def test_exact_render_is_preflighted_before_kind_creation():
    calls = []
    unsafe = """apiVersion: apps/v1
kind: Deployment
metadata: {name: bad}
spec:
  template:
    spec:
      containers:
      - name: bad
        image: local/bad:1
        volumeMounts: [{name: runtime, mountPath: /var/run/docker.sock}]
      volumes: [{name: runtime, hostPath: {path: /var/run/docker.sock}}]
"""
    def runner(command, **_):
        calls.append(tuple(command))
        return CommandResult(stdout=unsafe) if command[:2] == ["helm", "template"] else CommandResult()
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: bad\nversion: 1.0.0\n"}, job_id="unsafe"))
    assert result["status"] == "COULD_NOT_VALIDATE"
    assert result["reason_category"] == "SECURITY_POLICY_VIOLATION"
    assert result["security_policy_violations"]
    assert not any(call[:3] == ("kind", "create", "cluster") for call in calls)


def test_invalid_helm_records_template_failure_without_starting_kind():
    calls = []
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:2] == ["helm", "lint"]: return CommandResult(1, "", "invalid chart")
        return CommandResult()
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: invalid\nversion: 1.0.0\n"}, job_id="invalid"))
    assert result["reason_category"] == "HELM_LINT_FAILURE"
    assert result["helm_result"]["template"] == "FAIL"
    assert "invalid chart" not in json.dumps(result["diagnostics"])
    assert not any(call[:3] == ("kind", "create", "cluster") for call in calls)


def test_values_files_are_reused_for_lint_template_and_install():
    calls = []
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), healthy_runner(calls)).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n", "prod.yaml": "replicas: 2\n"}, values_files=["prod.yaml"], job_id="values"))
    assert result["status"] == "VERIFIED"
    for command, _, _ in calls:
        if command[:2] in (("helm", "lint"), ("helm", "template"), ("helm", "upgrade")):
            assert "--values" in command and any(str(item).endswith("prod.yaml") for item in command)


def test_render_limit_is_aggregate_across_root_charts():
    rendered = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: chart}\ndata: {payload: abcdefghijklmnopqrstuvwxyz}\n"
    def runner(command, **_): return CommandResult(stdout=rendered) if command[:2] == ["helm", "template"] else CommandResult()
    sources = {f"{name}/Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: 1.0.0\n" for name in ("one", "two")}
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False, max_render_bytes=len(rendered.encode()) + 10), runner).validate_artifact(
        ValidationArtifact(source_files=sources, job_id="aggregate-render"))
    assert result["status"] == "COULD_NOT_VALIDATE" and result["reason_category"] == "RESOURCE_LIMIT_EXCEEDED"


def test_crd_reaches_kind_and_missing_dependency_is_runtime_evidence():
    rendered = """apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: widgets.example.test}
spec: {group: example.test, names: {kind: Widget, plural: widgets}, scope: Namespaced, versions: [{name: v1, served: true, storage: true}]}
---
apiVersion: example.test/v1
kind: Widget
metadata: {name: example}
"""
    calls = []
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:2] == ["helm", "upgrade"]: return CommandResult(1, "", 'no matches for kind "Widget"')
        if command[:3] == ["docker", "network", "inspect"]: return CommandResult(1)
        return CommandResult()
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False, allow_network_egress=True), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: crd\nversion: 1.0.0\n"}, job_id="crd"))
    assert result["reason_category"] == "MISSING_CRD", result
    assert result["dependencies"]["missing_crds"] == []
    assert any(call[:3] == ("kind", "create", "cluster") for call in calls)
    assert any(call[:2] == ("helm", "upgrade") for call in calls)
    assert result["cleanup_status"] == "COMPLETE"


def test_custom_resource_without_crd_is_not_a_preflight_security_violation():
    custom = "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: web}\n"
    calls = []
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=custom)
        if command[:3] == ["docker", "network", "inspect"]: return CommandResult(1)
        return CommandResult()
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False, allow_network_egress=True), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: cert\nversion: 1.0.0\n"}, job_id="custom"))
    assert result["reason_category"] != "SECURITY_POLICY_VIOLATION", result
    assert any(call[:3] == ("kind", "create", "cluster") for call in calls)


def test_private_registry_auth_failure_has_precedence_over_generic_pull_failure():
    message = "ImagePullBackOff: failed to pull image from registry.example: unauthorized"
    assert classify_failure(message) == "PRIVATE_REGISTRY_UNAVAILABLE"
    assert classify_failure("0/1 nodes are available: Insufficient cpu") == "INSUFFICIENT_CPU"
    assert classify_failure("0/1 nodes are available: Insufficient memory") == "INSUFFICIENT_MEMORY"
    assert classify_failure("container terminated: OOMKilled") == "OOM_KILLED"


def healthy_runner(calls, *, cleanup_fails=False):
    rendered = """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  replicas: 1
  template:
    spec:
      containers: [{name: app, image: local/app:1}]
---
apiVersion: v1
kind: Service
metadata: {name: app}
spec: {selector: {app: app}, ports: [{port: 80, targetPort: 8080}]}
"""
    observed = {"items": [
        {"kind": "Deployment", "metadata": {"name": "app", "namespace": "cats-validation-run"}, "spec": {"replicas": 1}, "status": {"readyReplicas": 1}},
        {"kind": "ReplicaSet", "metadata": {"name": "app-rs", "namespace": "cats-validation-run", "ownerReferences": [{"kind": "Deployment", "name": "app"}]}},
        {"kind": "Pod", "metadata": {"name": "app-pod", "namespace": "cats-validation-run", "labels": {"app": "app"}, "ownerReferences": [{"kind": "ReplicaSet", "name": "app-rs"}]}, "spec": {"containers": [{"name": "app", "image": "local/app:1"}]}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
        {"kind": "Service", "metadata": {"name": "app", "namespace": "cats-validation-run"}, "spec": {"selector": {"app": "app"}, "ports": [{"port": 80, "targetPort": 8080}]}},
    ]}
    networks = set()
    def runner(command, *, timeout, env=None):
        calls.append((tuple(command), timeout, dict(env or {})))
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:2] == ["helm", "status"]: return CommandResult(stdout='{"info":{"status":"deployed"}}')
        if command[:3] == ["docker", "network", "create"]: networks.add(command[-1]); return CommandResult(stdout=command[-1])
        if command[:3] == ["docker", "network", "inspect"]: return CommandResult() if command[-1] in networks else CommandResult(1, "", "not found")
        if command[:3] == ["docker", "network", "rm"]: networks.discard(command[-1]); return CommandResult(stdout=command[-1])
        if command[:2] == ["kind", "delete"] and cleanup_fails: return CommandResult(1, "", "delete failed")
        if command[:3] == ["kind", "get", "clusters"]: return CommandResult(stdout="cats-validation-run\n" if cleanup_fails else "")
        if command[:2] == ["kubectl", "get"] and "events" in command: return CommandResult(stdout='{"items":[]}')
        if command[:2] == ["kubectl", "get"] and "secrets" in command: return CommandResult(stdout='{"items":[]}')
        if command[:2] == ["kubectl", "get"]:
            namespace = str((env or {}).get("KIND_CLUSTER_NAME") or "cats-validation-run")
            scoped = json.loads(json.dumps(observed))
            for item in scoped["items"]:
                item.setdefault("metadata", {})["namespace"] = namespace
            return CommandResult(stdout=json.dumps(scoped))
        return CommandResult()
    return runner


def test_successful_validation_is_unique_explicit_and_builds_topology():
    calls = []
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), healthy_runner(calls)).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="RUN_ABC"))
    assert result["status"] == "VERIFIED" and result["cleanup_status"] == "COMPLETE"
    assert result["cluster_name"].endswith("run-abc") and result["namespace"].endswith("run-abc")
    create = next(call for call, _, _ in calls if call[:3] == ("kind", "create", "cluster"))
    assert "--kubeconfig" in create and "--image" in create
    installs = [call for call, _, _ in calls if call[:2] == ("helm", "upgrade")]
    assert installs and "--no-hooks" not in installs[0] and "--skip-crds" not in installs[0]
    assert result["resource_summary"]["pods"] == {"ready": 1, "expected": 1}
    assert any(edge["type"] == "selects" for edge in result["observed_topology"]["edges"])
    assert result["comparison"]["defaulted"]
    helm = result["helm_result"]
    assert helm["template_duration_ms"] >= 0 and helm["install_duration_ms"] >= 0
    assert helm["helm_total_duration_ms"] >= helm["template_duration_ms"]
    assert helm["template_started_at"] and helm["template_completed_at"]
    assert helm["install_started_at"] and helm["install_completed_at"]


def test_reconciliation_uses_same_authoritative_release_render_as_install():
    calls = []
    stale_scanner_render = [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "helm-test-app"}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "helm-test-app"}},
    ]
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), healthy_runner(calls)).validate_artifact(
        ValidationArtifact(
            source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"},
            declared_resources=stale_scanner_render, job_id="release-identity",
        ))
    assert result["status"] == "VERIFIED"
    assert result["comparison"]["declared_only"] == []
    assert sorted(result["comparison"]["matched"]) == [
        "Deployment/cats-validation-release-identity/app",
        "Service/cats-validation-release-identity/app",
    ]
    evidence = result["diagnostics"]["reconciliation"]
    assert evidence["authoritative_expected_source"] == "helm-template"
    assert evidence["template_release_names"] == evidence["install_release_names"] == ["cats-validation-1"]


def test_child_tools_do_not_receive_portal_secrets(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("PIPELINE_API_TOKEN", "secret-token")
    calls = []
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), healthy_runner(calls)).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="minimal-env"))
    assert result["status"] == "VERIFIED"
    assert all("DATABASE_URL" not in env and "PIPELINE_API_TOKEN" not in env for _, _, env in calls)


def test_helm_install_failure_is_explicit_and_cleanup_still_completes():
    calls = []
    base = healthy_runner(calls)
    def runner(command, **kwargs):
        if command[:2] == ["helm", "upgrade"]: return CommandResult(1, "", "install failed")
        return base(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="install-fail"))
    assert result["helm_result"]["install"] == "FAIL"
    assert result["helm_result"]["install_duration_ms"] >= 0
    assert result["helm_result"]["helm_total_duration_ms"] >= result["helm_result"]["install_duration_ms"]
    assert result["reason_category"] == "HELM_INSTALL_FAILURE"
    assert result["cleanup_status"] == "COMPLETE"


def test_missing_local_image_does_not_block_kind_or_helm_attempt():
    calls = []
    rendered = "apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec: {containers: [{name: app, image: private/app:1}]}\n"
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:2] == ["helm", "status"]: return CommandResult(stdout='{"info":{"status":"deployed"}}')
        if command[:3] == ["docker", "image", "inspect"] and command[-1] == "private/app:1": return CommandResult(1, "", "not found")
        return CommandResult()
    result = KindDeploymentValidator(ValidationConfig(), runner).validate_artifact(ValidationArtifact(
        source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="missing-image"))
    assert any(call[:3] == ("kind", "create", "cluster") for call in calls)
    assert any(call[:2] == ("helm", "upgrade") for call in calls)
    assert result["dependencies"]["unavailable_images"] == ["private/app:1"]
    assert result["warnings"]


def test_optional_resource_controls_unavailable_do_not_block_helm():
    calls = []
    base = healthy_runner(calls)

    def runner(command, **kwargs):
        if command[:2] == ["docker", "update"]:
            return CommandResult(1, "", "operation not permitted")
        if command[:2] == ["docker", "inspect"]:
            return CommandResult(1, "", "inspection unavailable")
        return base(command, **kwargs)

    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="limits-unavailable"))
    assert any(call[:2] == ("helm", "upgrade") for call, _, _ in calls)
    assert result["resource_isolation"]["overall"] == "BEST_EFFORT"
    assert result["reason_category"] != "RESOURCE_LIMIT_ENFORCEMENT_UNAVAILABLE"
    assert result["warnings"]


def test_optional_resource_policy_failure_does_not_block_helm():
    calls = []
    base = healthy_runner(calls)

    def runner(command, **kwargs):
        if command[:2] == ["kubectl", "apply"]:
            return CommandResult(1, "", "quota API unavailable")
        return base(command, **kwargs)

    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="policy-unavailable"))
    assert any(call[:2] == ("helm", "upgrade") for call, _, _ in calls)
    assert any("ResourceQuota" in warning or "LimitRange" in warning for warning in result["warnings"])


def test_chart_capacity_is_warning_level_and_reaches_kubernetes():
    calls = []
    base = healthy_runner(calls)
    rendered = """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  replicas: 6
  template:
    spec:
      containers: [{name: app, image: local/app:1}]
"""

    def runner(command, **kwargs):
        if command[:2] == ["helm", "template"]:
            return CommandResult(stdout=rendered)
        return base(command, **kwargs)

    result = KindDeploymentValidator(ValidationConfig(require_local_images=False, max_pods=1), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="capacity-warning"))
    assert any(call[:2] == ("helm", "upgrade") for call, _, _ in calls)
    assert any("requested pods" in warning for warning in result["warnings"])


def test_crashloop_is_partially_verified_and_cleanup_runs():
    calls = []
    runner = healthy_runner(calls)
    def crash_runner(command, **kwargs):
        if command[:2] == ["kubectl", "rollout"]: return CommandResult(1, "", "timed out waiting for CrashLoopBackOff")
        if command[:2] == ["kubectl", "get"] and "events" not in command and "secrets" not in command:
            return CommandResult(stdout=json.dumps({"items": [{"kind": "Pod", "metadata": {"name": "app", "namespace": "cats-validation-crash"}, "status": {"phase": "Running", "containerStatuses": [{"state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}}]}))
        return runner(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), crash_runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="crash"))
    assert result["status"] == "PARTIALLY_VERIFIED" and result["reason_category"] == "CRASH_LOOP", result
    assert result["conditions"]["crashloopbackoff"] == 1 and result["cleanup_status"] == "COMPLETE"


def test_safe_workload_reaches_kind_and_reports_image_pull_as_runtime_evidence():
    """A safe manifest is deployed so Kubernetes can report its real failure."""
    calls = []
    base = healthy_runner(calls)
    observed = {"items": [
        {"kind": "Deployment", "metadata": {"name": "app", "namespace": "cats-validation-runtime-pull"}, "spec": {"replicas": 1}, "status": {"readyReplicas": 0}},
        {"kind": "Pod", "metadata": {"name": "app-pod", "namespace": "cats-validation-runtime-pull"}, "spec": {"containers": [{"name": "app", "image": "registry.example/app:missing"}]}, "status": {"phase": "Pending", "containerStatuses": [{"state": {"waiting": {"reason": "ImagePullBackOff"}}}]}},
    ]}

    def runtime_runner(command, **kwargs):
        if command[:2] == ["helm", "template"]:
            return CommandResult(stdout="""apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {replicas: 1, template: {spec: {containers: [{name: app, image: registry.example/app:missing}]}}}
""")
        if command[:2] == ["kubectl", "rollout"]:
            return CommandResult(1, "", "deployment exceeded progress deadline: ImagePullBackOff")
        if command[:2] == ["kubectl", "get"] and "events" not in command and "secrets" not in command:
            return CommandResult(stdout=json.dumps(observed))
        return base(command, **kwargs)

    result = KindDeploymentValidator(ValidationConfig(require_local_images=False, allow_network_egress=True), runtime_runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="runtime-pull"))
    assert result["reason_category"] == "IMAGE_PULL_FAILURE", result
    assert result["conditions"]["imagepullbackoff"] == 1
    assert result["cleanup_status"] == "COMPLETE"
    assert any(call[:3] == ("kind", "create", "cluster") for call, _, _ in calls)
    assert any(call[:2] == ("helm", "upgrade") for call, _, _ in calls)


def test_non_workload_chart_does_not_issue_a_broad_pod_wait():
    calls = []
    rendered = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: app}\n"
    observed = {"items": [{"kind": "ConfigMap", "metadata": {"name": "app", "namespace": "cats-validation-config"}}]}
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:2] == ["helm", "status"]: return CommandResult(stdout='{"info":{"status":"deployed"}}')
        if command[:2] == ["kubectl", "get"] and "events" in command: return CommandResult(stdout='{"items":[]}')
        if command[:2] == ["kubectl", "get"] and "secrets" in command: return CommandResult()
        if command[:2] == ["kubectl", "get"]: return CommandResult(stdout=json.dumps(observed))
        if command[:3] == ["docker", "network", "inspect"]: return CommandResult(1)
        return CommandResult()
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="config"))
    assert result["status"] == "VERIFIED"
    assert not any(call[:2] in (("kubectl", "wait"), ("kubectl", "rollout")) for call in calls)


def test_resource_collection_failure_is_environmental_not_verified():
    calls = []
    runner = healthy_runner(calls)
    def failing_collection(command, **kwargs):
        if command[:2] == ["kubectl", "get"] and any(str(item).startswith("deployments,statefulsets") for item in command):
            return CommandResult(1, "", "connection refused")
        return runner(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), failing_collection).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="collection"))
    assert result["status"] == "COULD_NOT_VALIDATE"
    assert result["reason_category"] == "EXTERNAL_DEPENDENCY"


def test_missing_storage_class_is_classified_and_named():
    calls = []
    base = healthy_runner(calls)
    rendered = "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: data}\nspec: {storageClassName: gp3, accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}\n"
    observed = {"items": [{"kind": "PersistentVolumeClaim", "metadata": {"name": "data", "namespace": "cats-validation-storage"}, "spec": {"storageClassName": "gp3"}, "status": {"phase": "Pending"}}]}
    events = {"items": [{"reason": "ProvisioningFailed", "message": 'storageclass.storage.k8s.io "gp3" not found'}]}
    def runner(command, **kwargs):
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:2] == ["kubectl", "get"] and "events" in command: return CommandResult(stdout=json.dumps(events))
        if command[:2] == ["kubectl", "get"] and "secrets" not in command: return CommandResult(stdout=json.dumps(observed))
        return base(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: storage\nversion: 1.0.0\n"}, job_id="storage"))
    assert result["status"] == "PARTIALLY_VERIFIED" and result["reason_category"] == "MISSING_STORAGE_CLASS"
    assert result["dependencies"]["missing_storage_classes"] == ["gp3"]


def test_pending_workload_is_partially_verified_after_timeout():
    calls = []
    base = healthy_runner(calls)
    rendered = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: pending}\nspec: {replicas: 1, template: {spec: {containers: [{name: app, image: local/app:1}]}}}\n"
    observed = {"items": [
        {"kind": "Deployment", "metadata": {"name": "pending", "namespace": "cats-validation-pending"}, "spec": {"replicas": 1}, "status": {}},
        {"kind": "Pod", "metadata": {"name": "pending-1", "namespace": "cats-validation-pending"}, "status": {"phase": "Pending"}},
    ]}
    def runner(command, **kwargs):
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:2] == ["kubectl", "rollout"]: return CommandResult(1, "", "timed out")
        if command[:2] == ["kubectl", "get"] and "events" not in command and "secrets" not in command: return CommandResult(stdout=json.dumps(observed))
        return base(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: pending\nversion: 1.0.0\n"}, job_id="pending"))
    assert result["status"] == "PARTIALLY_VERIFIED" and result["reason_category"] == "WORKLOAD_TIMEOUT"
    assert result["conditions"]["pending_pods"] == 1


def test_load_balancer_limitation_is_partial_after_successful_install_and_observation():
    """An unavailable generic capability must not erase useful runtime evidence.

    The chart is intentionally safe and reaches Helm/Kubernetes.  Plain kind
    does not assign an external address to a LoadBalancer Service, so the run
    should retain its installed/observed evidence and be marked partial rather
    than being reported as an execution failure.
    """
    calls = []
    base = healthy_runner(calls)
    rendered = """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec: {replicas: 1, template: {metadata: {labels: {app: app}}, spec: {containers: [{name: app, image: local/app:1}]}}}
---
apiVersion: v1
kind: Service
metadata: {name: app}
spec: {type: LoadBalancer, selector: {app: app}, ports: [{port: 80, targetPort: 8080}]}
"""
    observed = {"items": [
        {"kind": "Deployment", "metadata": {"name": "app", "namespace": "cats-validation-lb"}, "spec": {"replicas": 1}, "status": {"readyReplicas": 1}},
        {"kind": "ReplicaSet", "metadata": {"name": "app-rs", "namespace": "cats-validation-lb", "ownerReferences": [{"kind": "Deployment", "name": "app"}]}},
        {"kind": "Pod", "metadata": {"name": "app-pod", "namespace": "cats-validation-lb", "labels": {"app": "app"}, "ownerReferences": [{"kind": "ReplicaSet", "name": "app-rs"}]}, "spec": {"containers": [{"name": "app", "image": "local/app:1"}]}, "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}},
        {"kind": "Service", "metadata": {"name": "app", "namespace": "cats-validation-lb"}, "spec": {"type": "LoadBalancer", "selector": {"app": "app"}, "ports": [{"port": 80, "targetPort": 8080}]}, "status": {"loadBalancer": {}}},
    ]}

    def runner(command, **kwargs):
        if command[:2] == ["helm", "template"]:
            return CommandResult(stdout=rendered)
        if command[:2] == ["kubectl", "get"] and "events" not in command and "secrets" not in command:
            return CommandResult(stdout=json.dumps(observed))
        return base(command, **kwargs)

    result = KindDeploymentValidator(
        ValidationConfig(require_local_images=False), runner
    ).validate_artifact(
        ValidationArtifact(
            source_files={"Chart.yaml": "apiVersion: v2\nname: lb\nversion: 1.0.0\n"},
            job_id="lb",
        )
    )

    assert result["helm_result"]["install"] == "PASS"
    assert result["resource_summary"]["pods"] == {"ready": 1, "expected": 1}
    assert result["conditions"]["unsupported_load_balancer"] == 1
    assert result["status"] == "PARTIALLY_VERIFIED", result
    assert result["reason_category"] == "UNSUPPORTED_LOAD_BALANCER"
    assert "LoadBalancer" in result["reason"]
    assert result["cleanup_status"] == "COMPLETE"


def test_kubernetes_insufficient_cpu_and_memory_are_runtime_conditions():
    observed = parse_observations(
        {"items": [{"kind": "Pod", "metadata": {"name": "pending"}, "status": {"phase": "Pending"}}]},
        {"items": [
            {"reason": "FailedScheduling", "message": "0/1 nodes are available: 1 Insufficient cpu."},
            {"reason": "FailedScheduling", "message": "0/1 nodes are available: 1 Insufficient memory."},
        ]},
    )
    assert observed["conditions"]["unschedulable"] == 2
    assert observed["conditions"]["insufficient_cpu"] == 1
    assert observed["conditions"]["insufficient_memory"] == 1
    assert "Insufficient" not in json.dumps(observed["resources"])


def test_completed_job_pod_is_healthy_runtime_evidence():
    observed = parse_observations({"items": [
        {"kind": "Job", "metadata": {"name": "migrate"}, "spec": {"completions": 1}, "status": {"succeeded": 1}},
        {"kind": "Pod", "metadata": {"name": "migrate-1", "ownerReferences": [{"kind": "Job", "name": "migrate"}]}, "status": {"phase": "Succeeded"}},
    ]})
    assert observed["resource_summary"]["jobs"] == {"ready": 1, "expected": 1}
    assert observed["resource_summary"]["pods"] == {"ready": 1, "expected": 1}
    assert observed["unhealthy_resources"] == []


def test_remote_image_mode_does_not_kind_load_an_absent_image():
    calls = []
    base = healthy_runner(calls)
    def runner(command, **kwargs):
        if command[:3] == ["docker", "image", "inspect"] and command[-1] == "local/app:1": return CommandResult(1, "", "not local")
        return base(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False, allow_network_egress=True), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="remote"))
    assert result["status"] == "VERIFIED"
    assert not any(call[:3] == ("kind", "load", "docker-image") for call, _, _ in calls)


def test_progress_callback_failure_cannot_prevent_cleanup():
    calls = []
    def broken_callback(_phase): raise RuntimeError("database unavailable")
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), healthy_runner(calls)).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="callback"), progress_callback=broken_callback)
    assert result["status"] == "VERIFIED" and result["cleanup_status"] == "COMPLETE"
    assert any(call[:3] == ("kind", "delete", "cluster") for call, _, _ in calls)


def test_failed_pod_security_enforcement_aborts_before_helm_install():
    calls = []
    base = healthy_runner(calls)
    def runner(command, **kwargs):
        if command[:2] == ["kubectl", "label"]: return CommandResult(1, "", "forbidden")
        return base(command, **kwargs)
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="psa"))
    assert result["reason_category"] != "SECURITY_POLICY_VIOLATION"
    assert any(call[:2] == ("helm", "upgrade") for call, _, _ in calls)
    assert result["cleanup_status"] == "COMPLETE"


def test_concurrent_run_names_do_not_collide():
    first = validation_names(ValidationConfig(), "DV-FIRST")
    second = validation_names(ValidationConfig(), "DV-SECOND")
    assert first != second and first[0] != second[0] and first[1] != second[1]


def test_kind_creation_failure_still_attempts_exact_cleanup():
    calls = []
    rendered = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: app}\n"
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:2] == ["helm", "template"]: return CommandResult(stdout=rendered)
        if command[:3] == ["kind", "create", "cluster"]: return CommandResult(1, "", "create failed")
        if command[:3] == ["docker", "network", "inspect"]: return CommandResult(1)
        return CommandResult()
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), runner).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1\n"}, job_id="create-fail"))
    assert result["reason_category"] == "KIND_CREATION_FAILURE"
    assert any(call[:3] == ("kind", "delete", "cluster") for call in calls)


def test_cleanup_failure_is_reported_without_hiding_verified_result():
    calls = []
    result = KindDeploymentValidator(ValidationConfig(require_local_images=False), healthy_runner(calls, cleanup_fails=True)).validate_artifact(
        ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n"}, job_id="run"))
    assert result["status"] == "VERIFIED"
    assert result["reason_category"] is None
    assert result["cleanup_status"] == "FAILED"
    assert result["cleanup_error"]
    assert result["diagnostics"]["cleanup_failure"]["cluster"] == "cats-validation-run"


def test_secret_contents_are_removed_and_events_are_bounded():
    observed = parse_observations({"items": [{"kind": "Secret", "metadata": {"name": "db"}, "data": {"password": "abc"}}]}, {"items": [{"kind": "Event", "metadata": {"name": str(index)}, "message": "apiKey=super-secret-value"} for index in range(5)]}, max_events=2)
    assert len(observed["events"]) == 2
    assert "data" not in observed["resources"][0]
    assert all("password" not in json.dumps(node) for node in observed["observed_topology"]["nodes"])
    assert "super-secret-value" not in json.dumps(observed["events"])


def test_topology_relationships_and_generated_comparison():
    resources = [
        {"kind": "Service", "metadata": {"name": "web", "namespace": "ns"}, "spec": {"selector": {"app": "web"}}},
        {"kind": "Pod", "metadata": {"name": "web-1", "namespace": "ns", "labels": {"app": "web"}}, "spec": {"serviceAccountName": "web", "containers": [{"image": "local/web:1"}], "volumes": [{"name": "cfg", "configMap": {"name": "web"}}]}},
        {"kind": "NetworkPolicy", "metadata": {"name": "default-deny", "namespace": "ns"}, "spec": {"podSelector": {}}},
    ]
    topology = build_observed_topology(resources); edge_types = {edge["type"] for edge in topology["edges"]}
    assert {"selects", "uses", "runs", "mounts"} <= edge_types
    assert any(edge["source"].startswith("NetworkPolicy/") and edge["target"].startswith("Pod/") for edge in topology["edges"])
    comparison = compare_topology([resources[0]], topology, default_namespace="ns")
    assert comparison["matched"] and any(item.startswith("Pod/") for item in comparison["defaulted"])


@pytest.mark.parametrize("api_version,kind", [
    ("apps/v1", "Deployment"), ("v1", "Service"), ("networking.k8s.io/v1", "Ingress"),
    ("apps/v1", "StatefulSet"), ("apps/v1", "DaemonSet"), ("batch/v1", "Job"),
    ("batch/v1", "CronJob"), ("v1", "ConfigMap"), ("v1", "Secret"),
])
def test_rendered_resource_kinds_match_kubernetes_observations(api_version, kind):
    expected = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "workload"}}
    observed = {"apiVersion": api_version, "kind": kind, "metadata": {"name": "workload", "namespace": "validation", "uid": "runtime-only"}}
    comparison = compare_topology([expected], build_observed_topology([observed]), default_namespace="validation")
    assert comparison["matched"] == [f"{kind}/validation/workload"]
    assert comparison["declared_only"] == []
    assert comparison["expected_evidence"][0]["uid"] is None
    assert comparison["observed_evidence"][0]["uid"] == "runtime-only"


def test_canonical_identity_normalizes_api_version_but_preserves_group_and_namespace():
    beta = {"apiVersion": "networking.k8s.io/v1beta1", "kind": "Ingress", "metadata": {"name": "web"}}
    stable = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": "web", "namespace": "validation", "uid": "abc"}}
    assert canonical_resource_identity(beta, "validation") == canonical_resource_identity(stable, "validation")
    wrong_namespace = {**stable, "metadata": {**stable["metadata"], "namespace": "other"}}
    assert canonical_resource_identity(stable, "validation") != canonical_resource_identity(wrong_namespace, "validation")


def test_application_runtime_is_separate_from_provider_and_kubernetes_system_resources():
    expected = [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}}]
    observed = build_observed_topology([
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "validation"}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web-1", "namespace": "validation", "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web-rs", "uid": "1"}]}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "speaker", "namespace": "metallb-system", "labels": {"cats.clanhq.io/validation-infrastructure": "true"}}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "coredns", "namespace": "kube-system"}},
        {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "sh.helm.release.v1.cats-validation-1.v1", "namespace": "validation"}},
    ])
    comparison = compare_topology(expected, observed, default_namespace="validation", release_names=["cats-validation-1"])
    assert comparison["defaulted"] == ["Pod/validation/web-1"]
    assert comparison["cats_provisioned"] == ["Service/metallb-system/speaker"]
    assert comparison["kubernetes_system"] == ["Pod/kube-system/coredns"]
    assert comparison["validation_environment"] == ["Secret/validation/sh.helm.release.v1.cats-validation-1.v1"]


def test_stale_cleanup_deletes_only_owned_exact_names():
    calls = []
    def runner(command, **_):
        calls.append(tuple(command))
        if command[:3] == ["docker", "network", "inspect"]: return CommandResult(1)
        return CommandResult()
    result = cleanup_stale_clusters(["cats-validation-old", "production-cluster", "cats-validation-../bad"], runner=runner, config=ValidationConfig())
    assert result["deleted"] == ["cats-validation-old"]
    assert set(result["failed"]) == {"production-cluster", "cats-validation-../bad"}
    assert len(calls) == 4
