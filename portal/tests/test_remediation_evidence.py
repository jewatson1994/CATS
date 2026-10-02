from types import SimpleNamespace

import pytest

from app.remediation import (
    DECISION_REQUIRED, MANUAL_ONLY, SAFE_AUTOMATIC,
    build_plan, classify_policy_finding, summarize_configuration_report, summarize_grype_reports,
)


def policy(rule):
    return SimpleNamespace(id=1, finding=rule, title=rule, description="", remediation="",
                           severity="High", target="Deployment/api")


def payload(field):
    return {"helm_source_files": {"values.yaml": "security: {}"},
            "service_overview": {"rendered_resources": [
                {"kind": "Deployment", "metadata": {"name": "api"},
                 "_cats_source_mappings": [{"field_path": field, "values_file": "values.yaml",
                                            "values_key": "security.option", "ambiguous": False}]}]}}


@pytest.mark.parametrize("rule,field,category", [
    ("allowPrivilegeEscalation", "securityContext.allowPrivilegeEscalation", SAFE_AUTOMATIC),
    ("readOnlyRootFilesystem", "securityContext.readOnlyRootFilesystem", DECISION_REQUIRED),
    ("runAsNonRoot", "securityContext.runAsNonRoot", DECISION_REQUIRED),
    ("application resource limits", "resources.limits", MANUAL_ONLY),
])
def test_policy_action_categories(rule, field, category):
    assert classify_policy_finding(policy(rule), payload(field))["category"] == category


def test_plan_does_not_report_forecast_as_observed_clean():
    plan = build_plan(payload("securityContext.allowPrivilegeEscalation"), [policy("allowPrivilegeEscalation")], "R1")
    assert plan["forecast_configuration_findings"] == 0
    assert plan["after"]["configuration_findings"] is None
    assert plan["after"]["policy_validation"] == "NOT RUN"


def test_completed_scan_counts_actual_failed_rules():
    summary = summarize_configuration_report({"SchemaVersion": 2, "Results": [
        {"Target": "deployment.yaml", "Misconfigurations": [
            {"ID": "KSV1", "Status": "FAIL", "Severity": "HIGH"},
            {"ID": "KSV2", "Status": "PASS"}]}]})
    assert summary["configuration_findings"] == 1
    assert summary["policy_validation"] == "FAIL"
    assert summary["configuration_scan_findings"][0]["rule_id"] == "KSV1"


@pytest.mark.parametrize("report", [{}, {"SchemaVersion": 2}, {"SchemaVersion": 1, "Results": []},
                                    {"SchemaVersion": 2, "Results": [{"Misconfigurations": [{}]}]}])
def test_missing_or_invalid_scan_is_not_clean(report):
    with pytest.raises(ValueError):
        summarize_configuration_report(report)


def test_explicit_empty_completed_results_are_clean():
    assert summarize_configuration_report({"SchemaVersion": 2, "Results": []})["configuration_findings"] == 0


@pytest.mark.parametrize("report", [{}, {"matches": None}, {"matches": [{}]}, {"matches": [None]}])
def test_invalid_vulnerability_evidence_is_not_clean(report):
    with pytest.raises(ValueError):
        summarize_grype_reports([report], lambda _: (False, None))


def test_completed_empty_vulnerability_report_is_clean():
    assert summarize_grype_reports([{"matches": []}], lambda _: (False, None))["cve_count"] == 0


def test_candidate_validation_applies_ordered_helm_overrides(tmp_path, monkeypatch):
    from app import main
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: api\nversion: 1.0.0\n")
    for name, replicas in [("base.yaml", 2), ("service.yaml", 3)]:
        (tmp_path / name).write_text(f"replicas: {replicas}\n")
    monkeypatch.setattr(main.shutil, "which", lambda name: "helm" if name == "helm" else None)
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        assert args[-4:] == ["--values", str(tmp_path / "base.yaml"), "--values", str(tmp_path / "service.yaml")]
        return SimpleNamespace(returncode=0, stdout="kind: Pod\nmetadata: {name: api}\n", stderr="")
    monkeypatch.setattr(main.subprocess, "run", run)
    validation = {"checks": {}, "required_checks": []}
    main._validate_materialized_candidate(tmp_path, {"helm_values_files": ["base.yaml", "service.yaml"]},
        {"before": {"resource_identities": ["Pod/api"]}, "images": []}, validation)
    assert [args[1] for args in calls] == ["lint", "template"]


def test_candidate_validation_rejects_unretained_values(tmp_path, monkeypatch):
    from app import main
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: pytest.fail("must not render"))
    with pytest.raises(ValueError, match="confined"):
        main._validate_materialized_candidate(tmp_path, {"helm_values_files": ["../secret.yaml"]}, {}, {"checks": {}})
