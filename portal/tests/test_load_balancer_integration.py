"""Exercise the provider boundary through the real validation orchestrator."""

import json

import pytest

from app import deployment_validation as validation
from app.load_balancer import MetalLBProvider


def run_validation(monkeypatch, *, provider_ready=True, service_type="LoadBalancer", annotations=None,
                   load_balancer_class=None, reconciled=True, observed_name=None, provider_error=None,
                   enabled=True, fail_cleanup=False, foreign_address=False):
    calls = []
    provider_calls = []
    networks = set()
    namespace = ""
    service_name = ""

    def service(*, observed=False):
        spec = {"type": service_type, "selector": {"app": "nginx"}, "ports": [{"port": 80, "targetPort": 8080}]}
        if load_balancer_class:
            spec["loadBalancerClass"] = load_balancer_class
        item = {"apiVersion": "v1", "kind": "Service", "metadata": {
            "name": observed_name if observed and observed_name else service_name, "uid": "service-uid",
            "namespace": namespace, "annotations": annotations or {}}, "spec": spec}
        if observed and reconciled:
            item["status"] = {"loadBalancer": {"ingress": [{"ip": "192.0.2.1" if foreign_address else "172.25.0.240"}]}}
        return item

    def bootstrap(**kwargs):
        provider_calls.append(kwargs)
        calls.append(("TEST", "bootstrap"))
        return {"provider": "MetalLB", "status": "AVAILABLE" if provider_ready else "FAILED",
                "controller_ready": provider_ready, "duration_ms": 17,
                "address_pool": {"addresses": ["172.25.0.240"]},
                "warnings": [] if provider_ready else [provider_error or "provider readiness failed"],
                "namespace": "cats-validation-infrastructure", "provisioned_by_cats": True}

    monkeypatch.setattr(validation, "bootstrap_load_balancer", bootstrap)
    monkeypatch.setattr(MetalLBProvider, "collect_evidence", lambda *_args, **_kwargs: {
        "controller_ready": provider_ready, "status": "AVAILABLE" if provider_ready else "FAILED", "pool_addresses": ["172.25.0.240/32"], "items": []})

    def runner(command, *, timeout, env=None):
        nonlocal namespace, service_name
        calls.append(tuple(command))
        if fail_cleanup and command[:3] == ["kind", "delete", "cluster"]:
            return validation.CommandResult(1, "", "cleanup unavailable")
        if command[:2] == ["helm", "template"]:
            namespace = command[command.index("--namespace") + 1]
            service_name = command[2] + "-nginx"
            return validation.CommandResult(stdout=json.dumps(service()))
        if command[:2] == ["helm", "status"]:
            return validation.CommandResult(stdout='{"info":{"status":"deployed"}}')
        if command[:3] == ["docker", "network", "create"]:
            networks.add(command[-1])
        if command[:3] == ["docker", "network", "rm"]:
            networks.discard(command[-1])
        if command[:3] == ["docker", "network", "inspect"]:
            return validation.CommandResult(0 if command[-1] in networks else 1)
        if command[:2] == ["kubectl", "get"]:
            if "secrets" in command:
                return validation.CommandResult()
            if "events" in command:
                return validation.CommandResult(stdout='{"items":[]}')
            slices = {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "metadata": {
                "name": "nginx-slice", "namespace": namespace,
                "ownerReferences": [{"kind": "Service", "name": service_name, "uid": "service-uid"}],
                "labels": {"kubernetes.io/service-name": service_name}}, "addressType": "IPv4",
                "ports": [{"port": 8080, "protocol": "TCP"}],
                "endpoints": [{"addresses": ["10.244.0.5"], "conditions": {"ready": True}}]}
            return validation.CommandResult(stdout=json.dumps({"items": [service(observed=True), slices]}))
        return validation.CommandResult()

    artifact = validation.ValidationArtifact(source_files={"Chart.yaml": "apiVersion: v2\nname: nginx\nversion: 1.0.0\n"}, job_id="lb-integration")
    result = validation.validate_artifact(artifact, config=validation.ValidationConfig(require_local_images=False, load_balancer_provider_enabled=enabled), runner=runner)
    return result, calls, provider_calls


def capability(result, name="LoadBalancer"):
    return next(row for row in result["capability_preflight"] if row["capability"] == name)


def test_generic_lb_bootstraps_before_helm_and_verifies_actual_service(monkeypatch):
    result, calls, providers = run_validation(monkeypatch)
    assert len(providers) == 1
    install = next(call for call in calls if call[:2] == ("helm", "upgrade"))
    template = next(call for call in calls if call[:2] == ("helm", "template"))
    assert template[2] in install
    assert calls.index(("TEST", "bootstrap")) < calls.index(install)
    assert capability(result)["status"] == "VERIFIED"
    assert result["status"] == "VERIFIED"
    assert result["capability_bootstrap"]["duration_ms"] > 0
    lifecycle = result["capability_bootstrap"]["providers"]["metallb"]
    assert lifecycle["reconciliation_result"] == "VERIFIED"
    assert lifecycle["cleanup_result"] == "COMPLETE"
    assert "infrastructure was not configured" not in json.dumps(result)
    assert result["cleanup_status"] == "COMPLETE"


def test_clusterip_does_not_bootstrap_and_nonrequired_capabilities_stay_not_required(monkeypatch):
    result, _, providers = run_validation(monkeypatch, service_type="ClusterIP")
    assert not providers
    assert capability(result)["status"] == "NOT_REQUIRED"
    assert capability(result, "Ingress")["status"] == "NOT_REQUIRED"


@pytest.mark.parametrize("error", ["bundled image archive missing", "provider readiness failed", "provider bootstrap timed out"])
def test_provider_failure_still_installs_collects_and_cleans_up(monkeypatch, error):
    result, calls, providers = run_validation(monkeypatch, provider_ready=False, provider_error=error, reconciled=False)
    assert providers
    assert any(call[:2] == ("helm", "upgrade") for call in calls)
    assert any(call[:2] == ("kubectl", "get") for call in calls)
    assert capability(result)["status"] != "VERIFIED"
    assert result["status"] == "PARTIALLY_VERIFIED"
    assert result["cleanup_status"] == "COMPLETE"
    assert any(call[:3] == ("kind", "delete", "cluster") for call in calls)


@pytest.mark.parametrize("settings", [{"reconciled": False}, {"observed_name": "different-service"}, {"observed_name": "candidate-1-nginx"}, {"provider_ready": False}])
def test_cannot_verify_without_exact_service_reconciliation_and_provider_readiness(monkeypatch, settings):
    result, _, _ = run_validation(monkeypatch, **settings)
    assert capability(result)["status"] != "VERIFIED"
    assert result["status"] != "VERIFIED"


@pytest.mark.parametrize("settings", [
    {"annotations": {"service.beta.kubernetes.io/aws-load-balancer-type": "nlb"}},
    {"load_balancer_class": "service.k8s.aws/nlb"},
])
def test_provider_specific_semantics_never_become_fully_verified(monkeypatch, settings):
    result, calls, _ = run_validation(monkeypatch, **settings)
    assert any(call[:2] == ("helm", "upgrade") for call in calls)
    assert capability(result)["provider_specific"] is True
    assert capability(result)["status"] != "VERIFIED"
    assert result["status"] == "PARTIALLY_VERIFIED"


@pytest.mark.parametrize("mutation", ["wrong_namespace", "wrong_service_uid", "unready_endpoint"])
def test_endpoint_slice_must_belong_to_exact_service_and_have_ready_backend(mutation):
    row = {"capability": "LoadBalancer", "required": True, "source_resource": "Service/nginx", "source_namespace": "workload"}
    service = {"kind": "Service", "metadata": {"name": "nginx", "namespace": "workload", "uid": "current-service"},
               "spec": {"type": "LoadBalancer", "selector": {"app": "nginx"}},
               "status": {"loadBalancer": {"ingress": [{"ip": "172.25.0.240"}]}}}
    slice_item = {"kind": "EndpointSlice", "metadata": {"namespace": "workload",
                  "labels": {"kubernetes.io/service-name": "nginx"},
                  "ownerReferences": [{"kind": "Service", "uid": "current-service"}]},
                  "endpoints": [{"addresses": ["10.244.0.5"], "conditions": {"ready": True}}]}
    if mutation == "wrong_namespace":
        slice_item["metadata"]["namespace"] = "different-workload"
    elif mutation == "wrong_service_uid":
        slice_item["metadata"]["ownerReferences"][0]["uid"] = "previous-service"
    else:
        slice_item["endpoints"][0]["conditions"]["ready"] = False
    validation.reconcile_load_balancer(row, service, [slice_item], {"controller_ready": True, "address_pool": {"addresses": ["172.25.0.240"]}}, "workload")
    assert row["status"] != "VERIFIED"
    assert row["evidence"]["ready_backend_endpoints"] == 0


def test_foreign_address_is_not_proof_of_cats_provider_reconciliation(monkeypatch):
    result, _, _ = run_validation(monkeypatch, foreign_address=True)
    assert capability(result)["status"] == "UNEXERCISED"
    assert result["status"] == "PARTIALLY_VERIFIED"


def test_explicit_disable_is_visible_and_does_not_block_helm(monkeypatch):
    result, calls, providers = run_validation(monkeypatch, enabled=False)
    assert not providers
    assert any(call[:2] == ("helm", "upgrade") for call in calls)
    assert result["capability_bootstrap"]["load_balancer"]["status"] == "DISABLED"
    assert result["status"] == "PARTIALLY_VERIFIED"


def test_cleanup_failure_remains_visible_without_rewriting_verified_evidence(monkeypatch):
    result, _, _ = run_validation(monkeypatch, fail_cleanup=True)
    assert capability(result)["status"] == "VERIFIED"
    assert result["cleanup_status"] == "FAILED"
    assert result["capability_bootstrap"]["load_balancer"]["cleanup_status"] == "FAILED"
    assert result["capability_bootstrap"]["providers"]["metallb"]["cleanup_result"] == "FAILED"
