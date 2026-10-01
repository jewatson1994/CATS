from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.frontend_portfolio import cybersecurity_data
from app.security_dashboard import scan_snapshot, service_history


def execution(identifier, version, findings=None, complete=True, scope="service"):
    return SimpleNamespace(id=identifier, scanned_at=datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(hours=identifier),
                           complete=complete, scan_scope=scope,
                           raw_payload={"service": {"version": version}, "findings": findings or []})


def test_snapshot_deduplicates_cves_at_highest_severity_and_preserves_partial_state():
    scan = execution(1, "1.0", [{"cve": "CVE-1", "severity": "Low"},
                               {"cve": "CVE-1", "severity": "Critical"},
                               {"cve": "CVE-2", "severity": "Other"}], complete=False)
    snapshot = scan_snapshot(scan)
    assert snapshot["counts"] == {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Unknown": 1}
    assert snapshot["total"] == 2
    assert snapshot["complete"] is False


def test_history_uses_latest_scans_of_distinct_versions_excluding_image_scans():
    service = SimpleNamespace(service_key="api", name="API", executions=[
        execution(1, "1.0"), execution(2, "2.0"), execution(3, "2.0"),
        execution(4, "3.0", scope="image"), execution(5, "unknown")])
    history = service_history(service)
    assert [scan["execution_id"] for scan in history["versions"]] == [3, 1]
    assert [scan["execution_id"] for scan in history["trend"]] == [1, 2, 3, 5]
    assert history["trend"][-1]["version"] == "Unversioned"


def test_history_is_bounded_and_projection_drops_unrelated_fields():
    service = SimpleNamespace(service_key="api", name="API", executions=[execution(i, "1.0") for i in range(1, 12)])
    history = service_history(service)
    assert len(history["trend"]) == 8
    history["secret"] = "not for frontend"
    history["trend"][0]["raw_payload"] = {"secret": "not for frontend"}
    projected = cybersecurity_data({"history": [history]})["history"][0]
    assert "secret" not in projected
    assert "raw_payload" not in projected["trend"][0]


def test_history_limits_comparison_to_two_versions_with_many_distinct_releases():
    service = SimpleNamespace(service_key="api", name="API", executions=[execution(i, str(i)) for i in range(1, 12)])
    history = service_history(service)
    assert [scan["version"] for scan in history["versions"]] == ["11", "10"]
    assert len(history["trend"]) == 8
