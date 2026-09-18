from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from app.architecture import build_architecture_graph
from app.architecture_evidence import architecture_verification


def run(**values):
    defaults = dict(id=1, run_key="DV-1", execution_id=10, artifact_revision_id=None,
                    artifact_type="ORIGINAL", artifact_reference="exec-10", phase="COMPLETE",
                    status="VERIFIED", engine="kind", completed_at=datetime.now(timezone.utc),
                    diagnostics={"classification_summary": {"expected_resources": 16, "observed_expected": 16,
                                                             "expected_only": 0, "failed": 0}}, comparison={}, reason="verified")
    return SimpleNamespace(**{**defaults, **values})


def test_architecture_badge_has_exact_four_state_semantics():
    assert architecture_verification(applicable=False, declared_count=0, runs=[], execution_id=10)["state"] == "N/A"
    assert architecture_verification(applicable=True, declared_count=16, runs=[], execution_id=10)["state"] == "DECLARED"
    assert architecture_verification(applicable=True, declared_count=16, runs=[run()], execution_id=10)["state"] == "VERIFIED"
    partial = run(status="PARTIALLY_VERIFIED", diagnostics={"classification_summary": {
        "expected_resources": 16, "observed_expected": 14, "expected_only": 2, "failed": 0,
    }})
    assert architecture_verification(applicable=True, declared_count=16, runs=[partial], execution_id=10)["state"] == "PARTIALLY_VERIFIED"
    failed = run(status="COULD_NOT_VALIDATE", diagnostics={"classification_summary": {"expected_resources": 0}})
    assert architecture_verification(applicable=True, declared_count=16, runs=[failed], execution_id=10)["state"] == "DECLARED"


def test_revision_isolation_never_crosses_subject_boundaries():
    original = run(execution_id=10)
    revision_one = run(id=2, artifact_type="WORKING", execution_id=10, artifact_revision_id=101)
    assert architecture_verification(applicable=True, declared_count=16, runs=[original, revision_one], artifact_revision_id=102)["state"] == "DECLARED"
    assert architecture_verification(applicable=True, declared_count=16, runs=[original, revision_one], artifact_revision_id=101)["state"] == "VERIFIED"
    assert architecture_verification(applicable=True, declared_count=16, runs=[revision_one], execution_id=10)["state"] == "DECLARED"


def test_newer_failed_run_does_not_erase_useful_same_revision_evidence():
    useful = run(id=1, completed_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    failed = run(id=2, status="COULD_NOT_VALIDATE", completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    result = architecture_verification(applicable=True, declared_count=16, runs=[failed, useful], execution_id=10)
    assert result["state"] == "VERIFIED" and result["run"].id == 1


def test_graph_provenance_runtime_views_and_noise_filtering():
    payload = {"complete": True, "rendered_resources": [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api", "namespace": "app"}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "api", "namespace": "app"}, "spec": {"selector": {"app": "api"}}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "settings", "namespace": "app"}},
    ]}
    runtime = {"comparison": {
        "expected_evidence": [
            {"kind": "Deployment", "name": "api", "matched": True},
            {"kind": "Service", "name": "api", "matched": True},
            {"kind": "ConfigMap", "name": "settings", "matched": False},
        ],
        "defaulted": ["Pod/app/api-123", "PersistentVolumeClaim/app/data-api-0"],
        "observed_only": [], "cats_provisioned": ["Deployment/metallb-system/controller"],
        "kubernetes_system": ["Pod/kube-system/coredns"], "validation_environment": [],
    }, "capability_preflight": []}
    graph = build_architecture_graph(payload, runtime_evidence=runtime)
    by_kind = {(node["kind"], node["name"]): node for node in graph["nodes"]}
    assert by_kind[("Deployment", "api")]["provenance"] == "DECLARED_AND_OBSERVED"
    assert by_kind[("ConfigMap", "settings")]["provenance"] == "DECLARED"
    assert by_kind[("PersistentVolumeClaim", "data-api-0")]["provenance"] == "OBSERVED"
    assert ("Pod", "api-123") not in by_kind
    assert not any("metallb" in node["name"] or node["name"] == "coredns" for node in graph["nodes"])
    assert "runtime" in graph["layouts"] and "differences" in graph["layouts"] and "declared" in graph["layouts"]


def test_architecture_correlation_ignores_helm_release_name_for_loadbalancer_path():
    payload = {"complete": True, "rendered_resources": [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "cats-torture-test-api"}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "cats-torture-test-api"},
         "spec": {"type": "LoadBalancer", "selector": {"app": "api"}}},
    ]}
    runtime = {
        "diagnostics": {"reconciliation": {"template_release_names": ["cats-validation-1"],
                                               "install_release_names": ["cats-validation-1"]}},
        "comparison": {"expected_evidence": [
            {"kind": "Deployment", "name": "cats-validation-1-api", "matched": True},
            {"kind": "Service", "name": "cats-validation-1-api", "matched": True},
        ], "defaulted": [], "observed_only": []},
    }
    graph = build_architecture_graph(payload, runtime_evidence=runtime)
    correlated = [node for node in graph["nodes"] if node["kind"] in {"Deployment", "Service"}]
    assert len(correlated) == 2
    assert all(node["provenance"] == "DECLARED_AND_OBSERVED" for node in correlated)
    assert graph["summary"]["runtime_verified"] == 2
    assert graph["summary"]["differences"] == 0


def test_duplicate_declared_resource_identity_merges_evidence_without_breaking_layout():
    payload = {"complete": True, "rendered_resources": [
        {"apiVersion": "example.io/v1", "kind": "Widget", "metadata": {"name": "shared"}, "source_file": "a.yaml"},
        {"apiVersion": "example.io/v1", "kind": "Widget", "metadata": {"name": "shared"}, "source_file": "b.yaml"},
    ]}
    graph = build_architecture_graph(payload)
    widgets = [node for node in graph["nodes"] if node["kind"] == "Widget"]
    assert len(widgets) == 1
    assert len(widgets[0]["evidence"]) == 2
    assert graph["layouts"]["all"]["node_ids"] == [widgets[0]["id"]]


def test_secret_dependency_runtime_evidence_contains_no_secret_values():
    payload = {"complete": True, "rendered_resources": [
        {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "credentials", "namespace": "app"}},
    ]}
    runtime = {"comparison": {"expected_evidence": [{"apiVersion": "v1", "kind": "Secret", "namespace": "app", "name": "credentials", "matched": True}], "defaulted": [], "observed_only": []}, "capability_preflight": []}
    graph = build_architecture_graph(payload, runtime_evidence=runtime)
    secret = next(node for node in graph["nodes"] if node["kind"] == "Secret")
    assert secret["provenance"] == "DECLARED_AND_OBSERVED"
    assert "data" not in secret and "stringData" not in secret


def test_architecture_badge_and_evidence_views_are_wired_for_live_updates():
    root = Path(__file__).parents[1]
    template = (root / "app/templates/service_architecture.html").read_text(encoding="utf-8")
    script = (root / "app/static/architecture_graph.js").read_text(encoding="utf-8")
    assert "data-architecture-verification" in template and "data-architecture-badge" in template
    assert template.index("latest-evidence") < template.index("data-architecture-verification")
    for view in ("declared", "runtime", "differences"):
        assert f'value="{view}"' in template
    assert "updateGraph(nextGraph)" in script
    assert "window.location.reload" not in script


def test_overview_keeps_static_validation_and_architecture_as_separate_dimensions():
    root = Path(__file__).parents[1]
    template = (root / "app/templates/service_overview.html").read_text(encoding="utf-8")
    assert "data-architecture-summary" in template
    assert "Deployment Validation" in template
    assert "Static Scan:" in template
    assert "architecture-evidence-live.js" in template
