from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_service_navigation_is_shared_and_uses_remediations_label():
    partial = (ROOT / "app" / "templates" / "_service_tabs.html").read_text(encoding="utf-8")
    assert partial.count("Overview") == 1
    assert "Remediations" in partial
    assert "?poam=true" not in partial


def test_administration_tabs_consolidate_general_policy_and_hide_configuration():
    tabs = (ROOT / "app" / "templates" / "_admin_tabs.html").read_text(encoding="utf-8")
    assert "General Policy" in tabs
    assert "Configuration</a>" not in tabs
    assert "Evidence Policy" not in tabs
    assert "Workflow Policy" not in tabs


def test_missing_evidence_removal_is_scoped_and_audited():
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert '@app.post("/services/{service_key}/missing-evidence/remove")' in source
    assert 'auth.has("evidence.remove", service.id)' in source
    assert '"missing_evidence.removed"' in source


def test_remediation_revoke_uses_dialog_and_safe_return_context():
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    enterprise = (ROOT / "app" / "templates" / "remediations.html").read_text(encoding="utf-8")
    service = (ROOT / "app" / "templates" / "service_remediations.html").read_text(encoding="utf-8")
    assert "def _safe_remediation_return" in source
    assert "remediation-revoke-dialog" in enterprise
    assert "remediation-revoke-dialog" in service
    assert "Yes, Revoke" in enterprise and "Cancel" in enterprise
    assert "return_to" in enterprise and "return_to" in service
    assert "window.confirm" not in enterprise + service


def test_archival_is_a_service_header_action_not_raw_findings_panel():
    template = (ROOT / "app" / "templates" / "service.html").read_text(encoding="utf-8")
    assert "service-actions-dialog" in template
    assert "ARCHIVAL PENDING" in template
    assert template.count("Request service archival") == 1


def test_assessment_rollup_does_not_invent_image_details():
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert '"evidence_image": ""' in source
    assert "specific_missing_evidence" in source
