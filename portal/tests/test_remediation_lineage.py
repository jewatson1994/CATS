"""Exact retained resource/container lineage and explicit guided choices."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
import yaml

from app.remediation import build_plan, candidate_files, resolve_decisions
from app.remediation_sources import verify_rendered_changes, verify_rendered_scope


def fixture(group="containers", namespace="default", names=("web", "worker")):
    resource = {"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "gauntlet"},
                "spec": {"template": {"spec": {group: [{"name": name} for name in names]}}}}
    if namespace is not None:
        resource["metadata"]["namespace"] = namespace
    source = "chart/templates/deployment.yaml"
    resource["_cats_source_file"] = source
    resource["_cats_resource_lineage"] = {"rendered_artifact": "helm-image-rendered/graph-1.yaml", "document_index": 0,
                                          "source_template": source, "chart_instance_id": "chart-one"}
    plain = {key: value for key, value in resource.items() if not key.startswith("_cats")}
    payload = {"rendered_resources": [resource], "helm_source_files": {source: yaml.safe_dump(plain)}}
    finding = SimpleNamespace(id=106, fingerprint="caps-web", finding="KSV-0106", namespace="builtin.kubernetes.KSV106",
                              target=":: helm-image-rendered/graph-1.yaml")
    return payload, finding


def retained(payload, finding, group="containers", name="web"):
    resource = payload["rendered_resources"][0]
    lineage = {**resource["_cats_resource_lineage"], "api_version": resource["apiVersion"], "kind": resource["kind"],
               "namespace": resource["metadata"].get("namespace", ""), "name": resource["metadata"]["name"],
               "container_type": group, "container_name": name}
    payload["policy_findings"] = [{"fingerprint": finding.fingerprint, "evidence": {"resource_lineage": lineage}}]
    return lineage


@pytest.mark.parametrize("group", ["containers", "initContainers", "ephemeralContainers"])
def test_retained_lineage_changes_only_named_container_and_verifies(group):
    payload, finding = fixture(group)
    retained(payload, finding, group)
    plan = build_plan(payload, [finding], "lineage-job")
    row = plan["configuration_changes"][0]
    assert row["editable"] and row["target_resolution"] == "automatically-resolved"
    assert row["container_name"] == "web" and row["container_type"] == group
    assert row["new_value"] == ["ALL"] and row["original_value"] is None
    accepted = resolve_decisions(plan, "automated", {}, "manager")
    output = candidate_files(payload, accepted)
    result = yaml.safe_load(output["chart/templates/deployment.yaml"])
    containers = result["spec"]["template"]["spec"][group]
    assert containers[0]["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert "securityContext" not in containers[1]
    assert verify_rendered_changes([result], accepted["configuration_changes"])["status"] == "PASS"
    original = {key: value for key, value in payload["rendered_resources"][0].items() if not key.startswith("_cats")}
    assert verify_rendered_scope([original], [result], accepted["configuration_changes"])["status"] == "PASS"


def test_guided_choices_are_container_specific_stable_and_digest_bound():
    payload, finding = fixture()
    source = build_plan(payload, [finding], "one")
    row = source["configuration_changes"][0]
    assert not row["editable"] and row["target_resolution"] == "selection-required"
    assert len(row["target_options"]) == 2
    options = row["target_options"]
    assert len({option["target_id"] for option in options}) == 2
    assert [option["target_id"] for option in options] == [option["target_id"] for option in
            build_plan(payload, [finding], "two")["configuration_changes"][0]["target_options"]]
    with pytest.raises(ValueError):
        resolve_decisions(source, "guided", {"106": {"action": "proposed", "target_resource": options[0]["resource"]}}, "manager")
    with pytest.raises(ValueError):
        resolve_decisions(source, "guided", {"106": {"action": "proposed", "target_id": "foreign"}}, "manager")
    accepted = resolve_decisions(source, "guided", {"106": {"action": "proposed", "target_id": options[1]["target_id"]}}, "manager")
    assert accepted["configuration_changes"][0]["target_resolution"] == "user-selected"
    # The retained decision survives JSON serialization into the queued job.
    import json
    accepted = json.loads(json.dumps(accepted))
    result = yaml.safe_load(candidate_files(payload, accepted)["chart/templates/deployment.yaml"])
    containers = result["spec"]["template"]["spec"]["containers"]
    assert "securityContext" not in containers[0]
    assert containers[1]["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_multiple_documents_uses_exact_identity_and_keeps_service():
    payload, finding = fixture(names=("web",))
    retained(payload, finding)
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "gauntlet", "namespace": "default"}}
    path = "chart/templates/deployment.yaml"
    payload["helm_source_files"][path] += "---\n" + yaml.safe_dump(service)
    payload["rendered_resources"].append(service)
    plan = resolve_decisions(build_plan(payload, [finding], "job"), "automated", {}, "manager")
    docs = list(yaml.safe_load_all(candidate_files(payload, plan)[path]))
    assert docs[1] == service
    assert docs[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_stale_lineage_and_duplicate_resources_do_not_guess():
    payload, finding = fixture()
    lineage = retained(payload, finding)
    lineage["document_index"] = 99
    row = build_plan(payload, [finding], "job")["configuration_changes"][0]
    assert not row["editable"] and not row["target_options"]
    lineage["document_index"] = 0
    payload["rendered_resources"].append(deepcopy(payload["rendered_resources"][0]))
    row = build_plan(payload, [finding], "job")["configuration_changes"][0]
    assert not row["editable"] and not row["target_options"]


def test_known_rendered_target_with_template_expression_is_source_unavailable():
    payload, finding = fixture(names=("web",))
    retained(payload, finding)
    payload["helm_source_files"]["chart/templates/deployment.yaml"] += '\n{{ include "unknown" . }}'
    row = build_plan(payload, [finding], "job")["configuration_changes"][0]
    assert not row["editable"] and row["resource"] == "default/Deployment/gauntlet"


def test_legacy_single_resource_name_reconstructs_and_unknown_stays_unresolved():
    payload, finding = fixture(names=("web",), namespace=None)
    finding.target = "Deployment/gauntlet"
    row = build_plan(payload, [finding], "job")["configuration_changes"][0]
    assert row["editable"] and row["resource_identity"]["namespace"] == ""
    payload["rendered_resources"] = []
    row = build_plan(payload, [finding], "job")["configuration_changes"][0]
    assert not row["editable"] and "Re-scan" in row["reason"]


def test_helm_release_namespace_preserves_namespace_free_authoritative_source():
    payload, finding = fixture(names=("web",), namespace=None)
    resource = payload["rendered_resources"][0]
    resource["metadata"]["namespace"] = "release-ns"
    resource["_cats_resource_lineage"]["namespace_source"] = "helm-release"
    lineage = retained(payload, finding, group="container")
    plan = resolve_decisions(build_plan(payload, [finding], "job"), "automated", {}, "manager")
    row = plan["configuration_changes"][0]
    assert row["resource_identity"]["namespace"] == "release-ns"
    result = yaml.safe_load(candidate_files(payload, plan)["chart/templates/deployment.yaml"])
    assert "namespace" not in result["metadata"]
    assert result["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_final_report_retains_cause_metadata():
    from app.remediation import summarize_configuration_report
    cause = {"Resource": "deployment.api", "StartLine": 4, "EndLine": 8}
    report = {"SchemaVersion": 2, "Results": [{"Target": "render.yaml", "Misconfigurations":
              [{"ID": "KSV-0106", "CauseMetadata": cause}]}]}
    summary = summarize_configuration_report(report)
    assert summary["configuration_scan_findings"][0]["cause_metadata"] == cause


def test_ingestion_attaches_effective_release_namespace_before_planning():
    from app.main import _enrich_rendered_resource_lineage
    payload, finding = fixture(names=("web",), namespace=None)
    resource = payload["rendered_resources"][0]
    lineage = retained(payload, finding, group="container")
    lineage.update(namespace="release-ns", namespace_source="helm-release")
    resource.pop("_cats_resource_lineage")
    _enrich_rendered_resource_lineage(payload)
    assert resource["metadata"]["namespace"] == "release-ns"
    assert resource["_cats_resource_lineage"]["document_index"] == 0
    assert "container_name" not in resource["_cats_resource_lineage"]
    plan = resolve_decisions(build_plan(payload, [finding], "job"), "automated", {}, "manager")
    assert plan["configuration_changes"][0]["editable"]
    result = yaml.safe_load(candidate_files(payload, plan)["chart/templates/deployment.yaml"])
    assert "namespace" not in result["metadata"]
    assert result["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_source_plan_rejoins_old_retained_candidates_without_changing_evidence():
    from app.main import _retained_remediation_plan, _source_remediation_plan
    from app.remediation import plan_digest
    payload, finding = fixture(namespace=None)
    resource = payload["rendered_resources"][0]
    lineage = retained(payload, finding, group="container")
    lineage.update(namespace="default", namespace_source="helm-release")
    resource.pop("_cats_resource_lineage")
    payload["policy_findings"] = [{"finding": finding.finding, "fingerprint": finding.fingerprint,
        "namespace": finding.namespace, "target": finding.target,
        "evidence": {"candidate_resources": [lineage, {**lineage, "container_name": "worker"}]}}]
    original = deepcopy(payload)
    execution = SimpleNamespace(id=17, service_id=1, service_version_id=23, raw_payload=payload)
    db = SimpleNamespace(scalar=lambda statement: execution, scalars=lambda statement: [],
                         execute=lambda statement: SimpleNamespace(all=lambda: []))
    source, plan = _source_remediation_plan(db, SimpleNamespace(id=1))
    assert source is execution
    _, worker_plan = _retained_remediation_plan(db, SimpleNamespace(id=1), execution, job_key="REM-1")
    assert plan["source_digest"] == worker_plan["source_digest"]
    assert plan_digest(plan) == plan_digest(worker_plan)
    row = plan["configuration_changes"][0]
    assert row["source_resolution"] == "editable-candidates"
    assert {option["container_name"] for option in row["target_options"]} == {"web", "worker"}
    assert all(option["editable"] for option in row["target_options"])
    assert payload == original


def test_ingestion_keeps_conflicting_document_and_namespace_evidence_unresolved():
    from app.main import _enrich_rendered_resource_lineage
    payload, finding = fixture(namespace=None)
    resource = payload["rendered_resources"][0]
    lineage = retained(payload, finding)
    resource.pop("_cats_resource_lineage")
    lineage.update(namespace="one", namespace_source="helm-release")
    other = deepcopy(lineage)
    other.update(namespace="two", document_index=1)
    payload["policy_findings"][0]["evidence"]["candidate_resources"] = [lineage, other]
    _enrich_rendered_resource_lineage(payload)
    assert "namespace" not in resource["metadata"]
    assert "_cats_resource_lineage" not in resource


def test_ingestion_never_fabricates_cluster_resource_namespace():
    from app.main import _enrich_rendered_resource_lineage
    resource = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "reader"}}
    lineage = {"api_version": resource["apiVersion"], "kind": "ClusterRole", "name": "reader",
               "namespace": "", "namespace_source": "cluster", "document_index": 0, "rendered_artifact": "graph.yaml"}
    payload = {"service_overview": {"rendered_resources": [resource]},
               "policy_findings": [{"evidence": {"resource_lineage": lineage}}]}
    _enrich_rendered_resource_lineage(payload)
    assert "namespace" not in resource["metadata"]
    assert resource["_cats_resource_lineage"]["namespace"] == ""


def test_ingestion_collapses_same_source_across_render_pipelines():
    from app.main import _enrich_rendered_resource_lineage
    payload, finding = fixture(names=("web",))
    first = retained(payload, finding)
    resource = payload["rendered_resources"][0]
    second = deepcopy(first)
    second.update(rendered_artifact="helm-rendered/hashed.yaml", document_index=2)
    payload["policy_findings"].append({"evidence": {"resource_lineage": second}})
    _enrich_rendered_resource_lineage(payload)
    assert len(resource["_cats_resource_lineage_evidence"]) == 2
    assert resource["_cats_resource_lineage"]["chart_instance_id"] == "chart-one"


@pytest.mark.parametrize("conflict", [{"chart_instance_id": "other"}, {"execution_id": "other"},
                                    {"document_index": 1}])
def test_ingestion_rejects_conflicting_source_or_execution(conflict):
    from app.main import _enrich_rendered_resource_lineage
    payload, finding = fixture(names=("web",))
    first = retained(payload, finding)
    resource = payload["rendered_resources"][0]
    resource.pop("_cats_resource_lineage")
    second = {**first, **conflict}
    payload["policy_findings"].append({"evidence": {"resource_lineage": second}})
    _enrich_rendered_resource_lineage(payload)
    assert "_cats_resource_lineage" not in resource


def test_values_object_mapping_supports_absent_leaves_and_rejects_pod_scope():
    from app.main import _enrich_values_source_mappings
    payload, _ = fixture(names=("web",))
    resource = payload["rendered_resources"][0]
    payload["service_overview"] = {"rendered_resources": [resource]}
    files = {"chart/values.yaml": "containerSecurityContext: {}\nresources: {}\n",
             "chart/templates/deployment.yaml": """spec:
  template:
    spec:
      containers:
        - name: web
          securityContext:
            {{- toYaml .Values.containerSecurityContext | nindent 12 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
"""}
    _enrich_values_source_mappings(payload, files)
    keys = {item["values_key"] for item in resource["_cats_source_mappings"]}
    assert ".Values.containerSecurityContext.capabilities.drop" in keys
    assert ".Values.resources.limits.memory" in keys
    resource.pop("_cats_source_mappings")
    files["chart/templates/deployment.yaml"] = """spec:
  securityContext:
    {{- toYaml .Values.containerSecurityContext | nindent 4 }}
  containers:
    - name: web
"""
    _enrich_values_source_mappings(payload, files)
    assert not resource["_cats_source_mappings"]


@pytest.mark.parametrize("template", [
    """spec:
  containers:
    - name: web
      securityContext:
        {{- toYaml .Values.context | nindent 8 }}
    - name: other
      securityContext:
        {{- toYaml .Values.context | nindent 8 }}
""",
    """{{- range .Values.workloads }}
spec:
  containers:
    - name: web
      securityContext:
        {{- toYaml .Values.context | nindent 8 }}
{{- end }}
""",
    'image: {{ .Values.image | default "busybox" }}\n',
])
def test_values_enrichment_rejects_repeated_scoped_or_transformed_expressions(template):
    from app.main import _enrich_values_source_mappings
    payload, _ = fixture(names=("web",))
    resource = payload["rendered_resources"][0]
    payload["service_overview"] = {"rendered_resources": [resource]}
    _enrich_values_source_mappings(payload, {
        "chart/templates/deployment.yaml": template,
        "chart/values.yaml": "context: {}\nimage: busybox\n",
    })
    assert not resource.get("_cats_source_mappings")


def test_all_targets_applies_each_exact_mapping_and_preserves_plan():
    payload, finding = fixture()
    plan = build_plan(payload, [finding], "all-targets")
    original = deepcopy(plan)
    accepted = resolve_decisions(plan, "guided", {"106": {"target_all": True, "action": "proposed"}}, "manager")
    rows = accepted["configuration_changes"]
    assert {row["container_name"] for row in rows} == {"web", "worker"}
    assert all(row["target_resolution"] == "user-selected" for row in rows)
    result = yaml.safe_load(candidate_files(payload, accepted)["chart/templates/deployment.yaml"])
    assert all(c["securityContext"]["capabilities"]["drop"] == ["ALL"] for c in result["spec"]["template"]["spec"]["containers"])
    assert plan == original
    plan["configuration_changes"][0]["target_options"][1]["editable"] = False
    with pytest.raises(ValueError):
        resolve_decisions(plan, "guided", {"106": {"target_all": True, "action": "proposed"}}, "manager")
