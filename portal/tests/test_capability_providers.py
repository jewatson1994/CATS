from pathlib import Path
from types import SimpleNamespace

import pytest

from app.capability_providers import (
    BootstrapStatus,
    CallableProvider,
    CapabilityRequirement,
    CleanupStatus,
    ProviderContext,
    ProviderManager,
    ProviderRegistry,
    ProviderResult,
    ReadinessStatus,
    ReconciliationStatus,
)
from app.provider_inventory import (
    INGRESS_NGINX,
    KIND_LOCAL_STORAGE,
    METALLB,
    ProviderImage,
    ProviderSpec,
    provider_inventory,
)


def _context(tmp_path):
    return ProviderContext(
        config=SimpleNamespace(),
        command=lambda *args: None,
        root=tmp_path,
        kubeconfig=tmp_path / "kubeconfig",
        namespace="cats-validation-1",
        env={"KIND_CLUSTER_NAME": "cats-validation-1"},
        timeout=10,
    )


def _spec(provider_id, capability, *, dependencies=(), priority=100):
    return ProviderSpec(
        provider_id=provider_id,
        capability=capability,
        name=provider_id,
        version="1.0.0",
        verification_method="test evidence",
        dependencies=dependencies,
        priority=priority,
    )


def _provider(spec, calls=None, *, ready=True, reconcile=None, cleanup=True):
    calls = calls if calls is not None else []

    def bootstrap(context):
        calls.append(("bootstrap", spec.provider_id))
        return {"status": "AVAILABLE", "controller_ready": ready, "provider": spec.provider_id}

    def reconcile_hook(context, requirement, observations, result):
        calls.append(("reconcile", spec.provider_id, requirement.identity))
        return reconcile

    def cleanup_hook(context, result):
        calls.append(("cleanup", spec.provider_id))
        return cleanup

    return CallableProvider(
        spec=spec,
        bootstrap_hook=bootstrap,
        reconcile_hook=reconcile_hook,
        cleanup_hook=cleanup_hook,
    )


def test_central_inventory_preserves_metallb_identity_and_pins_offline_assets():
    inventory = provider_inventory()

    assert inventory["metallb"] is METALLB
    assert METALLB.capability == "LoadBalancer"
    assert METALLB.name == "MetalLB"
    assert METALLB.version == "0.16.1"
    assert METALLB.provisioned_by_cats is True
    assert {image.archive for image in METALLB.images} == {"controller.tar", "speaker.tar"}
    assert all(image.digest and image.digest.startswith("sha256:") for image in METALLB.images)
    assert INGRESS_NGINX.version == "1.15.1"
    assert INGRESS_NGINX.dependencies == ("metallb",)
    assert all(":latest" not in image.reference for image in INGRESS_NGINX.images)
    assert all(image.digest and image.digest.startswith("sha256:") for image in INGRESS_NGINX.images)
    assert KIND_LOCAL_STORAGE.provisioned_by_cats is False


def test_inventory_rejects_mutable_latest_images():
    with pytest.raises(ValueError, match="latest"):
        ProviderImage(reference="registry.example/controller:latest", archive="controller.tar")
    with pytest.raises(ValueError, match="complete sha256"):
        ProviderImage(reference="registry.example/controller:v1", archive="controller.tar", digest="sha256:1234")


def test_planner_selects_only_required_generic_capabilities():
    registry = ProviderRegistry([
        _provider(METALLB),
        _provider(INGRESS_NGINX),
        _provider(KIND_LOCAL_STORAGE),
    ])
    plan = registry.plan([
        {"capability": "LoadBalancer", "required": True, "source_resource": "Service/web"},
        {"capability": "Ingress", "required": False},
        {"capability": "Storage", "required": False},
    ])

    assert plan.provider_ids == ("metallb",)
    assert [item.source_resource for item in plan.requirements_by_provider["metallb"]] == ["Service/web"]
    assert not plan.unresolved


def test_planner_does_not_substitute_provider_specific_requirement():
    registry = ProviderRegistry([_provider(METALLB)])
    plan = registry.plan([
        {
            "capability": "LoadBalancer",
            "required": True,
            "source_resource": "Service/cloud-only",
            "provider_specific": True,
            "generic_exercise": False,
        }
    ])

    assert plan.providers == ()
    assert plan.unresolved[0].status == "UNSUPPORTED"
    assert plan.unresolved[0].requirement.source_resource == "Service/cloud-only"


def test_planner_orders_explicit_dependencies_before_consumers():
    lb = _spec("lb", "LoadBalancer")
    ingress = _spec("ingress", "Ingress", dependencies=("lb",))
    registry = ProviderRegistry([_provider(ingress), _provider(lb)])

    plan = registry.plan([CapabilityRequirement("Ingress", source_resource="Ingress/web")])

    assert plan.provider_ids == ("lb", "ingress")
    assert "ingress" in plan.requirements_by_provider
    assert "lb" not in plan.requirements_by_provider  # dependency, not an artifact requirement


def test_builtin_ingress_plan_bootstraps_metallb_dependency_first():
    registry = ProviderRegistry([_provider(INGRESS_NGINX), _provider(METALLB)])

    plan = registry.plan([
        CapabilityRequirement("Ingress", source_resource="Ingress/web")
    ])

    assert plan.provider_ids == ("metallb", "ingress-nginx")
    assert tuple(plan.requirements_by_provider) == ("ingress-nginx",)


def test_planner_rejects_missing_and_cyclic_dependencies():
    missing = _spec("consumer", "Ingress", dependencies=("missing",))
    with pytest.raises(KeyError, match="not registered"):
        ProviderRegistry([_provider(missing)]).plan([CapabilityRequirement("Ingress")])

    first = _spec("first", "Ingress", dependencies=("second",))
    second = _spec("second", "LoadBalancer", dependencies=("first",))
    with pytest.raises(ValueError, match="cycle"):
        ProviderRegistry([_provider(first), _provider(second)]).plan([CapabilityRequirement("Ingress")])


def test_manager_bootstraps_in_dependency_order_and_cleans_up_in_reverse(tmp_path):
    calls = []
    lb = _provider(_spec("lb", "LoadBalancer"), calls)
    ingress = _provider(_spec("ingress", "Ingress", dependencies=("lb",)), calls)
    plan = ProviderRegistry([ingress, lb]).plan([CapabilityRequirement("Ingress")])
    manager = ProviderManager()

    results = manager.bootstrap(plan, _context(tmp_path))
    results = manager.cleanup(plan, _context(tmp_path), results)

    assert calls == [
        ("bootstrap", "lb"),
        ("bootstrap", "ingress"),
        ("cleanup", "ingress"),
        ("cleanup", "lb"),
    ]
    assert all(result.cleanup_status is CleanupStatus.COMPLETE for result in results.values())


def test_dependency_failure_blocks_consumer_without_bootstrapping_it(tmp_path):
    calls = []
    dependency = _provider(_spec("dependency", "LoadBalancer"), calls, ready=False)
    consumer = _provider(_spec("consumer", "Ingress", dependencies=("dependency",)), calls)
    plan = ProviderRegistry([consumer, dependency]).plan([CapabilityRequirement("Ingress")])

    results = ProviderManager().bootstrap(plan, _context(tmp_path))

    assert calls == [("bootstrap", "dependency")]
    assert results["dependency"].readiness_status is ReadinessStatus.NOT_READY
    assert results["consumer"].bootstrap_status is BootstrapStatus.BLOCKED
    assert results["consumer"].readiness_status is ReadinessStatus.BLOCKED


def test_timeout_is_environment_evidence_and_does_not_escape(tmp_path):
    spec = _spec("timed", "Ingress")

    def timeout(context):
        raise TimeoutError("controller readiness timed out")

    provider = CallableProvider(spec, timeout)
    plan = ProviderRegistry([provider]).plan([CapabilityRequirement("Ingress")])

    result = ProviderManager().bootstrap(plan, _context(tmp_path))["timed"]

    assert result.bootstrap_status is BootstrapStatus.FAILED
    assert result.readiness_status is ReadinessStatus.TIMED_OUT
    assert "timed out" in result.failure_reason


def test_ready_provider_is_not_verified_until_artifact_reconciliation(tmp_path):
    provider = _provider(METALLB, reconcile={"status": "UNEXERCISED", "assigned_address": False})
    requirement = CapabilityRequirement("LoadBalancer", source_resource="Service/web")
    plan = ProviderRegistry([provider]).plan([requirement])
    manager = ProviderManager()
    result = manager.bootstrap(plan, _context(tmp_path))["metallb"]

    assert result.ready is True
    assert result.verified is False
    result = manager.reconcile(provider, _context(tmp_path), requirement, {}, result)
    assert result.reconciliation_status is ReconciliationStatus.UNEXERCISED
    assert result.verified is False


def test_existing_metallb_evidence_shape_normalizes_without_behavior_change(tmp_path):
    provider = CallableProvider(
        METALLB,
        lambda context: {
            "provider": "metallb",
            "version": "0.16.1",
            "status": "AVAILABLE",
            "controller_ready": True,
            "address_pool": {"addresses": ["172.30.0.240"]},
            "warnings": [],
        },
    )
    plan = ProviderRegistry([provider]).plan([CapabilityRequirement("LoadBalancer")])

    result = ProviderManager().bootstrap(plan, _context(tmp_path))["metallb"]
    persisted = result.to_evidence()

    assert result.ready is True
    assert persisted["provider"] == "MetalLB"
    assert persisted["version"] == "0.16.1"
    assert persisted["bootstrap_status"] == "SUCCEEDED"
    assert persisted["readiness_status"] == "READY"
    assert persisted["reconciliation_result"] == "NOT_ATTEMPTED"


def test_persisted_provider_evidence_redacts_secret_values():
    result = ProviderResult(
        spec=INGRESS_NGINX,
        bootstrap_status=BootstrapStatus.SUCCEEDED,
        readiness_status=ReadinessStatus.READY,
        evidence={
            "dependency": {"kind": "Secret", "name": "app-settings", "data": {"password": "do-not-leak"}},
            "log": "token=do-not-leak controller ready",
        },
    )

    persisted = result.to_evidence()

    assert persisted["evidence"]["dependency"]["name"] == "app-settings"
    assert persisted["evidence"]["dependency"]["data"] == "[REDACTED]"
    assert "do-not-leak" not in str(persisted)
