"""SQL-paged Raw Non-Compliant/Warnings pages match the legacy in-memory pages."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.main import active_exception, configuration_for_service, service_view
from app.models import PortalSetting, Service
from test_overview_counts import _expected, _seed
from test_portal import new_client, page_data, setup_function  # noqa: F401

COMPARED = ("noncompliance_items", "warning_items", "total_items", "total_pages", "page", "findings",
            "policy_findings", "finding_counts")


def _pages(client, query):
    new = page_data(client.get(f"/services/payments-service?findings=true&findings_view=raw&{query}"))
    legacy = page_data(client.get(f"/services/payments-service?overview=false&{query}"))
    return new, legacy


@pytest.mark.parametrize("settings", [
    {"incomplete_noncompliant": "true"},
    {"compliance_mode": "raw", "raw_due_rules": '[{"severity":"High","days":80}]', "warning_days": "30"},
    {"compliance_mode": "risk_based", "minimum_severity": "Low", "epss_enabled": "true", "kev_enabled": "true",
     "kev_noncompliant": "true", "epss_rules": '[{"severity":"Any","threshold":0.1}]'},
])
@pytest.mark.parametrize("query", [
    "finding_state=noncompliant&page_size=50",
    "finding_state=noncompliant&page_size=50&page=2",
    "finding_state=overdue&page_size=50&finding_type=configuration",
    "finding_state=noncompliant&page_size=50&finding_type=evidence",
    "finding_state=noncompliant&page_size=50&q=cve-2026-001",
    "finding_state=noncompliant&page_size=50&q=deployment/api-1&resource=ksv",
    "finding_state=noncompliant&page_size=50&severity=High",
    "finding_state=noncompliant&page_size=50&q=%25",
    "finding_state=noncompliant&page_size=50&q=ksv_0",
    "finding_state=noncompliant&page_size=50&q=_&resource=%25",
    "finding_state=noncompliant&page_size=50&page=99",
    "finding_state=warnings&page_size=50",
    "finding_state=warnings&page_size=50&finding_type=vulnerability",
    "finding_state=warnings&page_size=50&finding_type=evidence",
])
def test_raw_noncompliant_and_warnings_match_legacy(settings, query):
    client = new_client()
    _seed(client, complete=False)
    with SessionLocal() as db:
        for key, value in settings.items():
            db.add(PortalSetting(key=key, value=value))
        db.commit()
    new, legacy = _pages(client, query)
    for key in COMPARED:
        assert new.get(key) == legacy.get(key), key


def test_raw_noncompliant_pages_interleave_evidence_rows_in_order():
    client = new_client()
    _seed(client, complete=False)
    with SessionLocal() as db:
        db.add(PortalSetting(key="incomplete_noncompliant", value="true"))
        db.commit()
    collected, legacy_all = [], []
    for page in range(1, 5):
        new, legacy = _pages(client, f"finding_state=noncompliant&page_size=50&page={page}")
        assert new["noncompliance_items"] == legacy["noncompliance_items"]
        collected.extend(new["noncompliance_items"])
    assert any(item["type"] == "Evidence" for item in collected)


def test_raw_severity_options_match_canonical_view():
    client = new_client()
    _seed(client)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        configuration = configuration_for_service(db, service)
        _, view = _expected(db, service, configuration, now)
        service = view["service"]
        raw_active = [f for f in service.findings if f.active and not active_exception(f, now)]
        items = [*raw_active, *view["excepted"], *view["resolved"],
                 *view["policy_findings"], *view["policy_excepted"], *view["policy_resolved"]]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        expected = sorted({str(item.severity) for item in items if item.severity},
                          key=lambda value: (order.get(value.casefold(), 4), value.casefold()))
    new = page_data(client.get("/services/payments-service?findings=true&findings_view=raw&finding_state=noncompliant&page_size=50"))
    assert new["severity_options"] == expected


def test_raw_noncompliant_paging_interleaves_evidence_across_page_boundaries():
    from datetime import timedelta
    from app.models import Execution, Finding
    from test_portal import payload, pipeline_headers
    client = new_client()
    now = datetime.now(timezone.utc)
    body = payload("interleave", now, [f"CVE-2026-{index:04d}" for index in range(140)])
    body["policy_findings"] = [{"type": "Configuration", "finding": f"KSV{index:03d}", "severity": "High",
                                "scanner": "Trivy", "target": f"Deployment/api-{index}"} for index in range(30)]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        for finding in db.scalars(select(Finding)):
            finding.episode_started = now - timedelta(days=200)
        from app.models import PolicyFinding
        for policy in db.scalars(select(PolicyFinding)):
            policy.episode_started = now - timedelta(days=200)
        execution = db.scalar(select(Execution))
        execution.complete = False
        # Evidence rows sort by their type label ("Image") between CVE and KSV rows.
        execution.raw_payload = {**execution.raw_payload,
                                 "skipped_images": ["aaa/first:1", "mid/middle:1", "zzz/last:1"]}
        db.add(PortalSetting(key="incomplete_noncompliant", value="true"))
        db.commit()
    seen = []
    for page in range(1, 6):
        new, legacy = _pages(client, f"finding_state=noncompliant&page_size=50&page={page}")
        assert new["noncompliance_items"] == legacy["noncompliance_items"], page
        assert (new["total_items"], new["total_pages"]) == (legacy["total_items"], legacy["total_pages"])
        seen.extend(item["item"] for item in new["noncompliance_items"])
    assert len([item for item in seen if item]) >= 170
