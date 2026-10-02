from datetime import datetime
from types import SimpleNamespace
import json

from app.frontend_service_secondary import project_secondary


def test_overview_projection_preserves_controls_without_secrets():
    permissions = []
    def can(permission, service_id):
        permissions.append((permission, service_id))
        return True
    context = {"view": {"service": SimpleNamespace(id=7), "active": [1], "policy_findings": [2]},
               "overview_data": {"source": "Scan", "missing_evidence": [{"type": "Image", "item": "app", "removable": True, "password": "secret"}]},
               "latest_execution": SimpleNamespace(id=9, complete=True, raw_payload={"service_overview": {"helm_chart_graph": {"charts": [{"chart": "app", "token": "secret"}]}}}),
               "service_images": [SimpleNamespace(id=3, image_reference="app:1", lifecycle_status="active", password="secret")],
               "architecture_verification": {"state": "VERIFIED", "run": SimpleNamespace(token="secret")},
               "deployment_validation": {"status": "VERIFIED", "resource_summary": {"pods": {"ready": 2, "expected": 2, "token": "secret"}}, "observed_topology": {"nodes": [1], "token": "secret"}}}
    result = project_secondary({}, "service_overview.html", context, can)
    assert result["finding_counts"]["active"] == 2
    assert result["latest_execution"]["id"] == 9
    assert result["can"]["evidence.remove"] == {"7": True}
    assert permissions == [("evidence.remove", 7)]
    assert result["deployment_validation"]["has_observed_topology"] is True
    assert result["deployment_validation"]["static_scan_complete"] is True
    assert "secret" not in json.dumps(result)


def test_activity_projects_actor_display_and_known_detail_only():
    event = SimpleNamespace(action="service.updated", created_at=datetime(2026, 9, 30),
                            actor=SimpleNamespace(display_name="Jane", password_hash="secret"),
                            detail={"version": "2", "token": "secret", "password": "secret", "service_id": 3,
                                    "changed": ["name", "password_hash"]})
    result = project_secondary({}, "service_activity.html", {"events": [event]}, formatters={"cats_datetime": lambda _: "Display date"})
    row = result["events"][0]
    assert row["actor_name"] == "Jane" and row["detail"] == {"version": "2", "changed": ["name"]}
    assert row["created_at_display"] == "Display date"
    assert "secret" not in json.dumps(result)


def test_artifact_provenance_projects_independent_evidence_without_arbitrary_metadata():
    context = {"artifact_provenance": [{"artifact_kind": "image", "digest": "sha256:" + "a" * 64,
        "source_version": "1.5", "revision_number": 1, "post_remediation_scan": "PASS",
        "runtime_verification": "not_verified", "signature": "failed", "password": "secret",
        "release_lineage": True}]}
    result = project_secondary({}, "service_overview.html", context)
    assert result["artifact_provenance"][0]["runtime_verification"] == "not_verified"
    assert result["artifact_provenance"][0]["signature"] == "failed"
    assert "password" not in str(result)
    assert "release_lineage" not in str(result)


def test_history_projects_retained_evidence_fields_without_nested_secrets():
    raw = {"service": {"id": "app", "name": "App", "version": "1", "token": "secret"},
           "findings": [{"cve": "CVE-1", "image": "app:1", "evidence": {"password": "secret"}}],
           "policy_findings": [{"finding": "CFG", "severity": "High", "token": "secret"}],
           "sbom_components": [{"name": "pkg", "purl": "pkg:x", "password": "secret"}],
           "service_overview": {"ports": [{"port": 80, "protocol": "TCP", "token": "secret"}], "credentials": "secret",
                                "images": [{"image": "app:1", "password": "secret"}]}}
    snapshot = {"key": "scan-1", "at": datetime(2026, 9, 30), "scope": "service", "complete": True,
                "source_files": ["Chart.yaml"], "data": raw}
    result = project_secondary({}, "service_history.html", {"service": SimpleNamespace(id=1, service_key="app", name="App"),
                "version": "1", "versions": ["1"], "snapshots": [snapshot], "imported_snapshots": [snapshot]})
    assert result["snapshots"][0]["data"]["findings"][0]["cve"] == "CVE-1"
    assert result["imported_snapshots"][0]["source_files"] == ["Chart.yaml"]
    assert result["snapshots"][0]["data"]["service_overview"]["images"][0]["image"] == "app:1"
    assert "secret" not in json.dumps(result)
