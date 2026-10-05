from copy import deepcopy
import pytest
from app.remediation import AUTO, REVIEW, SAFE_AUTOMATIC, DECISION_REQUIRED, MANUAL_ONLY, resolve_decisions, plan_digest, has_proposal, build_plan, candidate_files
from types import SimpleNamespace
import yaml


def test_missing_security_context_values_leaf_can_be_added_from_retained_chart():
    payload = {"helm_source_files": {"values.yaml": "containerSecurityContext: {}\n",
        "templates/api.yaml": "spec:\n  containers:\n    - name: api\n      securityContext:\n        {{- toYaml .Values.containerSecurityContext | nindent 8 }}\n"},
        "rendered_resources": [{"kind": "Pod", "metadata": {"name": "api"},
            "_cats_source_file": "templates/api.yaml", "spec": {"containers": [{"name": "api", "image": "ubuntu:latest"}]}}]}
    original = deepcopy(payload)
    finding = SimpleNamespace(id=1, finding="KSV-0017", title="Privileged container", target="Pod/api")
    preview = build_plan(payload, [finding], "PREVIEW")
    assert preview["configuration_changes"][0]["editable"] is True
    resolved = resolve_decisions(preview, "guided", {"1": {"action": "proposed"}}, "manager")
    assert yaml.safe_load(candidate_files(payload, resolved)["values.yaml"])["containerSecurityContext"]["privileged"] is False
    assert payload == original
    payload["helm_source_files"]["templates/other.yaml"] = "{{ .Values.containerSecurityContext }}"
    assert build_plan(payload, [finding], "PREVIEW")["configuration_changes"][0]["editable"] is False


def test_vulnerability_only_image_is_in_preview_with_retained_observations():
    preview = build_plan({"findings": [{"image": "ubuntu:latest", "cve": "CVE-test", "severity": "High"}]}, [], "PREVIEW")
    assert preview["images"][0]["original"] == "ubuntu:latest"
    assert preview["images"][0]["vulnerabilities"][0]["cve"] == "CVE-test"
    assert preview["images"][0]["source_mapping"]["ambiguous"] is True


@pytest.mark.parametrize("template", [
    "spec:\n  securityContext:\n    {{- toYaml .Values.context | nindent 4 }}\n  containers:\n    - name: api\n",
    "spec:\n  containers:\n    - name: api\n      securityContext:\n        {{- include \"context\" . | nindent 8 }}\n",
])
def test_mapping_does_not_guess_pod_context_or_helper_expression(template):
    payload = {"helm_source_files": {"values.yaml": "context: {}", "templates/api.yaml": template},
        "rendered_resources": [{"kind": "Pod", "metadata": {"name": "api"}, "_cats_source_file": "templates/api.yaml",
                                "spec": {"containers": [{"name": "api"}]}}]}
    finding = SimpleNamespace(id=1, finding="KSV-0106", title="Drop all capabilities", target="Pod/api")
    assert build_plan(payload, [finding], "PREVIEW")["configuration_changes"][0]["editable"] is False


def plan(category=DECISION_REQUIRED, editable=True):
    return {"configuration_changes": [{"finding_id": 1, "rule_id": "nonroot", "category": category,
        "classification": REVIEW, "editable": editable, "new_value": True,
        "field_path": "securityContext.runAsNonRoot", "proposed_value_source": "Hardening Policy"}], "images": []}


def test_automated_accepts_safe_without_manager_input():
    source = plan(SAFE_AUTOMATIC)
    result = resolve_decisions(source, "automated", {}, "manager")
    row = result["configuration_changes"][0]
    assert row["classification"] == AUTO
    assert row["approval"] == "automatic" and row["actor"] is None
    assert source["configuration_changes"][0]["classification"] == REVIEW


def test_automated_applies_supported_review_proposal():
    row = resolve_decisions(plan(), "automated", {}, "manager")["configuration_changes"][0]
    assert row["classification"] == AUTO
    assert row["approval"] == "automatic"


def test_guided_can_leave_safe_unresolved():
    result = resolve_decisions(plan(SAFE_AUTOMATIC), "guided", {"1": {"action": "unresolved"}}, "manager")
    assert result["configuration_changes"][0]["classification"] == REVIEW


def test_manager_custom_value_has_typed_value_and_audit_source():
    result = resolve_decisions(plan(), "guided", {"1": {"action": "custom", "value": False}}, "manager")
    row = result["configuration_changes"][0]
    assert row["new_value"] is False and row["actor"] == "manager"
    assert row["proposed_value_source"] == "Explicit Service Manager input"
    assert row["timestamp"] and row["post_scan_result"] == "NOT RUN"


@pytest.mark.parametrize("value", ["false", 0, {}, None])
def test_custom_boolean_rejects_wrong_types(value):
    with pytest.raises(ValueError, match="boolean"):
        resolve_decisions(plan(), "guided", {"1": {"action": "custom", "value": value}}, "manager")


def test_manual_only_cannot_be_approved():
    assert resolve_decisions(plan(MANUAL_ONLY), "guided", {}, "manager")["decisions"][0]["decision"] == "unresolved"
    with pytest.raises(ValueError, match="Manual-only"):
        resolve_decisions(plan(MANUAL_ONLY), "guided", {"1": {"action": "proposed"}}, "manager")


@pytest.mark.parametrize("metadata", [{"scanner": "Dockle"}, {"framework": "Docker Image Configuration"}, {"finding": "CIS-DI-0001"}])
def test_dockle_checks_excluded_without_removing_evidence_or_images(metadata):
    finding = SimpleNamespace(id=1, finding="image-check", title="Run as non-root", **{key: value for key, value in metadata.items() if key != "finding"})
    if "finding" in metadata:
        finding.finding = metadata["finding"]
    payload = {"findings": [{"cve": "CVE-test", "severity": "High"}],
               "rendered_resources": [{"kind": "Pod", "metadata": {"name": "api"}, "spec": {"containers": [{"image": "ubuntu:latest"}]}}]}
    result = build_plan(payload, [finding], "R1")
    assert result["configuration_changes"] == []
    assert result["images"][0]["original"] == "ubuntu:latest"
    assert result["before"]["vulnerabilities"]["High"] == 1
    assert result["before"]["configuration_findings"] == 1
    assert payload["findings"][0]["cve"] == "CVE-test"


def test_manual_finding_preserves_original_target_and_context():
    finding = SimpleNamespace(id=1, finding="CUSTOM-1", target="Deployment/api", namespace="production",
                              title="Application-specific check", description="Review the application configuration", scanner="Trivy")
    row = build_plan({}, [finding], "R1")["configuration_changes"][0]
    assert row["category"] == MANUAL_ONLY
    assert row["finding_target"] == "Deployment/api"
    assert row["finding_namespace"] == "production"
    assert row["finding_title"] == finding.title
    assert row["finding_description"] == finding.description
    assert row["scanner"] == "Trivy"


def test_ambiguous_mapping_cannot_be_approved():
    with pytest.raises(ValueError, match="exact editable"):
        resolve_decisions(plan(editable=False), "guided", {"1": {"action": "proposed"}}, "manager")


def test_arbitrary_field_and_foreign_finding_rejected():
    for decisions in ({"1": {"action": "custom", "value": False, "field_path": "metadata.name"}}, {"9": {"action": "proposed"}}):
        with pytest.raises(ValueError):
            resolve_decisions(plan(), "guided", decisions, "manager")


def test_plan_digest_ignores_clock_but_binds_values():
    first = plan(); second = deepcopy(first)
    second["configuration_changes"][0]["timestamp"] = "later"
    assert plan_digest(first) == plan_digest(second)
    second["configuration_changes"][0]["new_value"] = False
    assert plan_digest(first) != plan_digest(second)


@pytest.mark.parametrize("value", [False, True, 0, 7, "", "enum", [], ["ALL"], {}, {"key": False}])
def test_typed_proposals_preserved(value):
    source = plan()
    source["configuration_changes"][0]["new_value"] = value
    assert has_proposal(source["configuration_changes"][0])
    result = resolve_decisions(source, "guided", {"1": {"action": "proposed"}}, "manager")
    assert result["decisions"][0]["new_value"] == value
    assert type(result["decisions"][0]["new_value"]) is type(value)


@pytest.mark.parametrize("absent", [False, True])
def test_absent_or_null_proposal_rejected(absent):
    source = plan()
    source["configuration_changes"][0]["new_value"] = None
    if absent:
        del source["configuration_changes"][0]["new_value"]
    assert not has_proposal(source["configuration_changes"][0])
    with pytest.raises(ValueError, match="no proposed value"):
        resolve_decisions(source, "guided", {"1": {"action": "proposed"}}, "manager")


def privileged_plan(target="unknown"):
    field = "securityContext.privileged"
    resources = [{"kind": "Deployment", "metadata": {"name": name},
                  "_cats_source_mappings": [{"field_path": field, "values_file": "values.yaml",
                      "values_key": f"{name}.privileged", "ambiguous": False}]}
                 for name in ("api", "worker")]
    payload = {"helm_source_files": {"values.yaml": "api: {}\nworker: {}\n"}, "rendered_resources": resources}
    finding = SimpleNamespace(id=17, finding="KSV-0017", title="privileged container", target=target, severity="High")
    return payload, build_plan(payload, [finding], "R1")


def test_automated_applies_proposal_to_all_exact_editable_targets():
    payload, source = privileged_plan()
    resolved = resolve_decisions(source, "automated", {}, "manager")
    values = yaml.safe_load(candidate_files(payload, resolved)["values.yaml"])
    assert values == {"api": {"privileged": False}, "worker": {"privileged": False}}
    assert len(resolved["decisions"]) == 2
    assert all(row["approval"] == "automatic" for row in resolved["decisions"])


@pytest.mark.parametrize("mode", ["guided", "automated"])
def test_explicit_target_selection_applies_false_only_to_selected_source(mode):
    payload, source = privileged_plan()
    row = source["configuration_changes"][0]
    assert row["new_value"] is False and row["proposed_value_source"] == "Hardening Policy"
    assert not row["editable"] and len(row["target_options"]) == 2
    with pytest.raises(ValueError, match="exact editable"):
        resolve_decisions(source, mode, {"17": {"action": "proposed"}}, "manager")
    resolved = resolve_decisions(source, mode, {"17": {"action": "proposed", "target_resource": "Deployment/api"}}, "manager")
    assert resolved["decisions"][0]["new_value"] is False
    assert resolved["decisions"][0]["resource"] == "Deployment/api"
    assert resolved["decisions"][0]["approval"] == "manager-approved"
    assert resolved["configuration_changes"][0]["original_value"] is None
    values = yaml.safe_load(candidate_files(payload, resolved)["values.yaml"])
    assert values == {"api": {"privileged": False}, "worker": {}}
    untouched = resolve_decisions(source, mode, {"17": {"action": "unresolved"}}, "manager")
    assert candidate_files(payload, untouched) == payload["helm_source_files"]


def test_unknown_target_and_namespace_collisions_cannot_be_selected():
    payload, source = privileged_plan()
    with pytest.raises(ValueError, match="target from this plan"):
        resolve_decisions(source, "guided", {"17": {"action": "proposed", "target_resource": "Deployment/foreign"}}, "manager")
    payload["rendered_resources"].append(deepcopy(payload["rendered_resources"][0]))
    finding = SimpleNamespace(id=17, finding="privileged container", target="Deployment/api")
    row = build_plan(payload, [finding], "R1")["configuration_changes"][0]
    assert not row["editable"]
    assert all(option["resource"] != "Deployment/api" for option in row["target_options"])


def test_resolved_false_proposal_is_editable_and_materializes():
    payload, source = privileged_plan("Deployment/api")
    assert source["configuration_changes"][0]["editable"]
    resolved = resolve_decisions(source, "guided", {"17": {"action": "proposed"}}, "manager")
    assert yaml.safe_load(candidate_files(payload, resolved)["values.yaml"])["api"]["privileged"] is False
