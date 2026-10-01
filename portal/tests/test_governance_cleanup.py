from pathlib import Path

from app.frontend_service_secondary import project_secondary
from app.frontend import page_data
from starlette.requests import Request

ROOT = Path(__file__).parents[1]


def test_service_header_preserves_scoped_archive_actions():
    request = Request({"type": "http", "path": "/services/example", "query_string": b"", "headers": []})
    data = page_data(request, "service.html", {
        "view": {"service": {"id": 7, "service_key": "example", "password": "private"}},
        "archive_pending": True,
        "can": lambda permission, service_id=None: permission == "archive.request" and service_id == 7,
    }, formatters={})["data"]
    assert data["archive_pending"] is True
    assert data["can"]["archive.request"] == {"7": True}
    assert data["can"]["service.delete"] == {"7": False}
    assert "password" not in data["view"]["service"]


def test_deployment_validation_contract_is_available_without_a_run():
    data = project_secondary({}, "service_overview.html", {})
    assert data["deployment_validation"]["status"] is None
    assert data["deployment_validation"]["has_observed_topology"] is False
    assert set(data["deployment_validation"]["resource_summary"]) == {"pods", "deployments", "statefulsets"}


def test_missing_evidence_removal_is_scoped_and_audited():
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert '@app.post("/services/{service_key}/missing-evidence/remove")' in source
    assert 'auth.has("evidence.remove", service.id)' in source
    assert '"missing_evidence.removed"' in source


def test_remediation_return_rejects_external_or_unrelated_destinations():
    from app.main import _safe_remediation_return
    assert _safe_remediation_return("https://evil.example", "/remediations") == "/remediations"
    assert _safe_remediation_return("//evil.example", "/remediations") == "/remediations"
    assert _safe_remediation_return("/admin/configuration", "/remediations") == "/remediations"
    assert _safe_remediation_return("/remediations?status=pending", "/remediations") == "/remediations?status=pending"
    assert _safe_remediation_return("/services/example", "/remediations") == "/remediations"
    assert _safe_remediation_return("/services/example?remediations=true", "/remediations") == "/services/example?remediations=true"


def test_assessment_rollup_does_not_invent_image_details():
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert 'row["item"] != "Assessment" else ""' in source
    assert 'for row in missing_evidence' in source
