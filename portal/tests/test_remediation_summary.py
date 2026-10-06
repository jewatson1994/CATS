import json
from hashlib import sha256

import pytest

from app.remediation_summary import artifacts, build_summary


def plan(after=None, decision="proposed", value=False):
    return {"configuration_changes": [{"rule_id": "KSV1", "resource": "Deployment/api",
              "original_value": True, "new_value": value, "decision": decision,
              "actor": "manager", "approval": "manager-approved", "reason": "Hardening policy",
              "source_mapping": {"values_file": "values.yaml", "values_key": "option"}}],
            "after": after or {}}


def build(p=None, before=None, after=None):
    return build_summary(p or plan(), before or {"values.yaml": "option: true\n"},
                         after or {"values.yaml": "option: false\n"}, {"status": "FAIL"}, [], [])


def scan(failures=None):
    return {"policy_validation": "FAIL" if failures else "PASS", "configuration_findings": len(failures or []),
            "configuration_scan_findings": failures or []}


def test_mutation_does_not_mean_resolution_and_preserves_types():
    row = build()["configuration_changes"][0]
    assert row["accepted"] and row["source_modified"] and not row["verified"]
    assert row["original_value"] is True and row["proposed_value"] is False and row["actual_value"] is False
    assert row["actor"] == "manager"


def test_final_scan_and_actual_value_required():
    assert build(plan(scan()))["configuration_changes"][0]["verified"]
    assert not build(plan(scan()), after={"values.yaml": 'option: "false"\n'})["configuration_changes"][0]["verified"]
    assert not build(plan(scan([{"rule_id": "KSV1", "target": "manifest.yaml"}])))["configuration_changes"][0]["verified"]


def test_unresolved_decision_is_not_resolved_by_clean_scan():
    result = build(plan(scan(), decision="unresolved"))
    assert result["unresolved"][0]["status"] == "UNRESOLVED"
    assert result["configuration_changes"] == []
    assert not result["configuration_decisions"][0]["accepted"]


def test_exact_target_and_resolution_survive_summary_and_artifacts():
    p = plan(scan())
    identity = {"api_version": "apps/v1", "kind": "Deployment", "namespace": "default",
                "name": "api", "container_type": "container", "container_name": "web"}
    p["configuration_changes"][0].update(resource_identity=identity, target_id="exact-target",
                                          target_resolution="user-selected")
    summary = build(p)
    row = summary["configuration_changes"][0]
    assert row["resource_identity"] == identity
    assert row["target_id"] == "exact-target"
    assert row["target_resolution"] == "user-selected"
    documents = artifacts(summary, {"values.yaml": "option: true\n"}, {"values.yaml": "option: false\n"})
    assert "user-selected" in documents["documentation/remediation/summary-of-changes.md"]


@pytest.mark.parametrize("check", ["baseline_render", "change_scope", "intended_changes"])
def test_failed_render_safety_check_prevents_verification(check):
    result = build_summary(plan(scan()), {"values.yaml": "option: true\n"},
                           {"values.yaml": "option: false\n"},
                           {"checks": {check: {"status": "FAIL"}}}, [], [])
    assert not result["configuration_changes"][0]["verified"]


def test_exact_hashes_include_unchanged_files_and_bytes():
    result = build(before={"values.yaml": "option: true\n", "same.txt": b"exact\r\n"},
                   after={"values.yaml": "option: false\n", "same.txt": b"exact\r\n"})
    row = next(r for r in result["source_files"] if r["path"] == "same.txt")
    assert row["before_sha256"] == row["after_sha256"] == sha256(b"exact\r\n").hexdigest()
    assert not row["modified"]


@pytest.mark.parametrize("path", ["../x", "/x", "C:/x", "a/../x", "\\\\host\\x", "a\nx"])
def test_unsafe_paths_rejected(path):
    with pytest.raises(ValueError):
        build(before={path: "content"})


@pytest.mark.parametrize("secret", ['password: hush', 'env: [{name: KEY, value: hush}]',
    'kind: Secret\nstringData: {value: hush}', 'url: https://user:hush@example.org',
    'privateKey: hush', 'token: hush'])
def test_sensitive_files_fully_redacted_from_diff(secret):
    before = {"values.yaml": "option: true\n" + secret + "\n"}
    after = {"values.yaml": "option: false\n" + secret + "\n"}
    result = artifacts(build(before=before, after=after), before, after)
    assert "hush" not in json.dumps(result)
    assert "[REDACTED]" in result["documentation/remediation/changes.patch"]


def test_artifacts_include_copa_charts_validation_and_plain_diff():
    p = plan(scan())
    p.update(images=[{"original": "api:1", "candidate": "api:2", "patch_status": "FAILED", "reason": "Copa failed"}],
             charts=[{"path": "Chart.yaml", "original_version": "1.0.0", "remediated_version": "1.0.0-cats"}])
    result = artifacts(build(p), {"values.yaml": "option: true\n"}, {"values.yaml": "option: false\n"})
    assert len(result) == 4
    assert "-option: true" in result["documentation/remediation/changes.patch"]
    assert "Copa failed" in result["documentation/remediation/summary-of-changes.md"]
    assert "1.0.0-cats" in result["documentation/remediation/summary-of-changes.md"]


def test_frontend_summary_preserves_typed_collections_and_omits_private_fields():
    from app.frontend_remediations import project_remediations
    summary = build(plan(scan(), value=["ALL"]), after={"values.yaml": "option: [ALL]\n"})
    summary["configuration_changes"][0]["internal_worker_payload"] = "hidden"
    data = {"next_path": "/"}
    project_remediations(data, "remediation_report.html", {"job": {"validation_results": {"summary_of_changes": summary}}}, None, {})
    row = data["job"]["summary_of_changes"]["configuration_changes"][0]
    assert row["proposed_value"] == row["actual_value"] == ["ALL"]
    assert "internal_worker_payload" not in row


def test_frontend_preserves_exact_target_without_private_identity_fields():
    from app.frontend_remediations import project_remediations
    change = {"target_id": "exact-app", "target_resolution": "retained_lineage", "container_name": "app",
              "container_type": "container", "resource_identity": {"api_version": "apps/v1", "kind": "Deployment",
              "namespace": "production", "name": "api", "private": "hidden"},
              "source_mapping": {"source_file": "templates/api.yaml", "values_key": "app.privileged"}}
    data = {"next_path": "/"}
    project_remediations(data, "remediation_report.html", {"job": {"configuration_changes": [change],
        "validation_results": {"summary_of_changes": {"schema_version": 1, "configuration_changes": [change]}}}}, None, {})
    for row in (data["job"]["configuration_changes"][0], data["job"]["summary_of_changes"]["configuration_changes"][0]):
        assert row["target_id"] == "exact-app"
        assert row["container_name"] == "app"
        assert row["resource_identity"]["namespace"] == "production"
        assert "private" not in row["resource_identity"]
        assert row["source_mapping"]["source_file"] == "templates/api.yaml"


@pytest.mark.parametrize("release_namespace", [False, True])
def test_exact_namespaced_source_and_named_container_are_read(release_namespace):
    source = """kind: Deployment
metadata: {name: api, namespace: production}
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext: {privileged: false}
      - name: sidecar
        securityContext: {privileged: true}
"""
    p = plan(scan())
    row = p["configuration_changes"][0]
    row.update(resource="production/Deployment/api", field_path="securityContext.privileged",
               source_mapping={"template": "deployment.yaml", "resource_identity": ["Deployment", "production", "api"],
                               "mutation_path": ["spec", "template", "spec", "containers", {"name": "app"}, "securityContext", "privileged"]})
    if release_namespace:
        source = source.replace(", namespace: production", "")
        row["source_mapping"]["source_resource_identity"] = ["Deployment", "", "api"]
    result = build(p, before={"deployment.yaml": source.replace("privileged: false", "privileged: true")}, after={"deployment.yaml": source})
    assert result["configuration_changes"][0]["actual_value"] is False
    assert result["configuration_changes"][0]["verified"]


def test_policy_payload_preserves_exact_lineage_evidence():
    from app.schemas import PolicyFindingPayload
    evidence = {"resource_lineage": {"kind": "Deployment", "name": "api", "container_name": "sidecar"}}
    payload = PolicyFindingPayload(finding="KSV-0106", evidence=evidence)
    assert payload.model_dump()["evidence"] == evidence
