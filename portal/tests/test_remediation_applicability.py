from types import SimpleNamespace

import pytest

from app import candidate_worker
from app.remediation import build_plan, candidate_files, static_validation
from app.remediation_validation import classify_static


def image_payload(kind="image"):
    payload = {"artifact_type": kind, "findings": [{"image": "harbor.example/api:1", "severity": "High"}]}
    if kind == "compose":
        payload["service_overview"] = {"compose": {"services": [
            {"name": "api", "image": "harbor.example/api:1", "configuration": {}}]}}
    return payload


@pytest.mark.parametrize("kind", ["image", "compose"])
def test_non_kubernetes_candidate_does_not_invoke_render_tools(kind, tmp_path, monkeypatch):
    payload = image_payload(kind)
    plan = build_plan(payload, [], "R-IMAGE")
    for image in plan["images"]:
        image.update(candidate="harbor.example/api:patched", patch_status="PATCHED")
    monkeypatch.setattr(candidate_worker.subprocess, "run", lambda *a, **kw: pytest.fail("Must not render, build or start containers"))
    validation = candidate_worker.validate_candidate(tmp_path, payload, plan, static_validation(payload, plan))
    assert candidate_files(payload, plan) == {}
    for check in ("helm_lint", "helm_template", "yaml_parsing", "expected_resources", "kubernetes_schema"):
        assert validation["checks"][check]["status"] == "NOT_APPLICABLE"
    assert validation["checks"]["vulnerability_rescan"]["status"] == "PASS"
    assert plan["before"]["images"] == 1
    assert plan["before"]["helm_render"] == plan["after"]["helm_render"] == "NOT_APPLICABLE"
    if kind == "image":
        assert plan["forecast_configuration_findings"] is None
        assert plan["after"]["policy_validation"] == "NOT_APPLICABLE"
        assert classify_static(validation)["status"] == "PASS"
    else:
        assert plan["after"]["policy_validation"] == "UNAVAILABLE"
        assert classify_static(validation)["status"] == "WARNING_UNVERIFIED"
    assert validation["blockers"] == []


def test_retained_image_configuration_findings_remain_applicable(tmp_path):
    policy = SimpleNamespace(id=1, finding="COMPOSE-ROOT-USER", title="Root execution", description="", remediation="",
                             severity="High", target="api")
    payload = image_payload()
    plan = build_plan(payload, [policy], "R-CONFIG")
    validation = candidate_worker.validate_candidate(tmp_path, payload, plan, static_validation(payload, plan))
    assert plan["before"]["configuration_findings"] == 1
    assert plan["after"]["configuration_findings"] is None
    assert validation["checks"]["candidate_security_evidence"]["status"] == "UNAVAILABLE"
    assert classify_static(validation)["status"] == "WARNING_UNVERIFIED"


@pytest.mark.parametrize("kind", ["helm", "kubernetes"])
def test_missing_expected_deployment_render_is_not_not_applicable(kind, tmp_path, monkeypatch):
    payload = image_payload(kind)
    plan = build_plan(payload, [], "R-MISSING")
    monkeypatch.setattr(candidate_worker.shutil, "which", lambda _: None)
    validation = candidate_worker.validate_candidate(tmp_path, payload, plan, static_validation(payload, plan))
    assert validation["checks"]["expected_resources"]["status"] == "FAIL"
    assert classify_static(validation)["status"] == "BLOCKING"
    assert (validation["checks"]["helm_template"]["status"] == "NOT_APPLICABLE") == (kind == "kubernetes")


def test_actual_chart_cannot_be_marked_inapplicable(tmp_path, monkeypatch):
    payload = image_payload()
    plan = build_plan(payload, [], "R-CHART")
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: api\nversion: 1.0.0\n")
    monkeypatch.setattr(candidate_worker.shutil, "which", lambda _: None)
    validation = candidate_worker.validate_candidate(tmp_path, payload, plan, static_validation(payload, plan))
    assert validation["checks"]["helm_template"]["status"] == "FAIL"
    assert validation["applicability"]["helm"] is True


def test_failed_image_scan_is_not_pass_or_not_applicable(tmp_path):
    payload = image_payload()
    plan = build_plan(payload, [], "R-FAILED")
    plan["images"][0].update(patch_status="FAILED")
    validation = candidate_worker.validate_candidate(tmp_path, payload, plan, static_validation(payload, plan))
    assert validation["checks"]["vulnerability_rescan"]["status"] == "UNAVAILABLE"
    assert classify_static(validation)["status"] == "WARNING_UNVERIFIED"
