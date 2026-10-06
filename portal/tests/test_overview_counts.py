"""Service Overview SQL counts match the canonical ``service_view`` evaluation."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import selectinload

from app.database import SessionLocal, engine
from app.main import configuration_for_service, service_view
from app.models import (ExceptionRecord, Execution, Finding, PolicyExceptionRecord, PolicyFinding, PortalSetting,
                        Service)
from app.service_counts import overview_finding_counts
from test_portal import new_client, page_data, payload, pipeline_headers, setup_function  # noqa: F401

SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
# Ages straddle 90-day due dates, the 14-day warning window and raw rules.
AGES = (1, 30, 70, 77, 80, 85, 89, 95, 120, 200)


def _seed(client, *, complete=True):
    now = datetime.now(timezone.utc)
    body = payload("counts-1", now, [f"CVE-2026-{index:04d}" for index in range(60)])
    # Duplicate CVEs on another image exercise the CVE-keyed warning filter.
    body["findings"] += [dict(body["findings"][index], image="registry/other:1") for index in range(0, 60, 7)]
    body["findings"][3]["evidence"] = {"kev": True}
    body["findings"][4]["evidence"] = {"epss": 0.97}
    body["findings"][5]["evidence"] = {"epss_score": "0.2"}
    body["policy_findings"] = [{"type": "Configuration", "finding": f"KSV{index:03d}", "severity": "High",
                                "scanner": "Trivy", "target": f"Deployment/api-{index}", "fingerprint": f"fp-{index}"}
                               for index in range(12)]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        findings = db.scalars(select(Finding).order_by(Finding.id)).all()
        for index, finding in enumerate(findings):
            finding.severity = SEVERITIES[index % len(SEVERITIES)]
            finding.episode_started = now - timedelta(days=AGES[index % len(AGES)], hours=index % 3)
            if index % 11 == 0:
                finding.active = False
            if index % 6 == 1:
                db.add(ExceptionRecord(finding_id=finding.id, justification="x", approved_by="a",
                                       starts_at=now - timedelta(days=5),
                                       expires_at=now + timedelta(days=(3 if index % 12 == 1 else 40))))
            if index % 9 == 2:
                db.add(ExceptionRecord(finding_id=finding.id, justification="revoked", approved_by="a",
                                       starts_at=now - timedelta(days=5), expires_at=now + timedelta(days=2),
                                       revoked_at=now - timedelta(days=1)))
        if not complete:
            # Retained evidence marked incomplete after ingest keeps the finding set.
            db.scalar(select(Execution)).complete = False
        policies = db.scalars(select(PolicyFinding).order_by(PolicyFinding.id)).all()
        for index, policy in enumerate(policies):
            policy.episode_started = now - timedelta(days=AGES[index % len(AGES)])
            if index == 7:
                policy.active = False
            if index % 4 == 1:
                db.add(PolicyExceptionRecord(policy_finding_id=policy.id, justification="x", approved_by="a",
                                             starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=30)))
        db.commit()


def _expected(db, service, configuration, now):
    service = db.scalar(select(Service).where(Service.id == service.id).options(
        selectinload(Service.findings).selectinload(Finding.exceptions),
        selectinload(Service.findings).selectinload(Finding.observations),
        selectinload(Service.policy_findings).selectinload(PolicyFinding.exceptions),
        selectinload(Service.executions)).execution_options(populate_existing=True))
    view = service_view(service, now, configuration)
    return {"active": len(view["active"]) + len(view["policy_findings"]),
            "exceptions": len(view["excepted"]) + len(view["policy_excepted"]),
            "resolved": len(view["resolved"]) + len(view["policy_resolved"]),
            "noncompliant": len(view["noncompliance_items"]),
            "warnings": len(view["warning_items"])}, view


CONFIGURATIONS = [
    {},
    {"compliance_mode": "raw"},
    {"compliance_mode": "raw", "raw_due_rules": '[{"severity":"High","days":80},{"severity":"critical","days":75}]'},
    {"compliance_mode": "risk_based", "minimum_severity": "High", "warning_days": "30"},
    {"compliance_mode": "risk_based", "minimum_severity": "None", "kev_enabled": "true", "kev_noncompliant": "true"},
    {"compliance_mode": "risk_based", "minimum_severity": "Low", "epss_enabled": "true",
     "epss_rules": '[{"severity":"Any","threshold":0.1,"noncompliant":true}]'},
    {"hardening_noncompliant": "false", "overdue_days": "70"},
    {"hardening_overdue_days": "75", "incomplete_noncompliant": "true"},
    {"incomplete_noncompliant": "false"},
    {"compliance_mode": "risk_based", "minimum_severity": "Critical", "epss_enabled": "true", "kev_enabled": "true",
     "epss_rules": '[{"severity":"High","threshold":0.5,"noncompliant":false},{"severity":"Any","threshold":0.15}]'},
]


@pytest.mark.parametrize("settings", CONFIGURATIONS)
@pytest.mark.parametrize("complete", [True, False])
def test_overview_sql_counts_match_service_view(settings, complete):
    client = new_client()
    _seed(client, complete=complete)
    with SessionLocal() as db:
        for key, value in settings.items():
            db.add(PortalSetting(key=key, value=value))
        db.commit()
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        configuration = configuration_for_service(db, service)
        expected, view = _expected(db, service, configuration, now)
        header = {"evidence_noncompliant": view["evidence_noncompliant"],
                  "missing_evidence_count": sum(item["type"] == "Evidence" for item in view["noncompliance_items"])
                  if view["evidence_noncompliant"] else 0,
                  "warning_items": [item for item in view["warning_items"] if item["type"] not in {"CVE", "Exception"}]}
        assert overview_finding_counts(db, service.id, configuration, now, header) == expected
    assert sum(expected.values()) > 0
    page = page_data(client.get("/services/payments-service?overview=true"))
    assert page["finding_counts"] == expected


def test_overview_get_reads_without_writes_or_tracked_payload_mutation():
    client = new_client()
    _seed(client, complete=False)
    with SessionLocal() as db:
        before = db.scalar(select(Execution.raw_payload))
    statements = []
    listener = lambda conn, cursor, statement, *args: statements.append(statement)
    event.listen(engine, "before_cursor_execute", listener)
    try:
        response = client.get("/services/payments-service?overview=true")
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert response.status_code == 200
    assert not [statement for statement in statements
                if statement.lstrip().split(None, 1)[0].upper() in {"INSERT", "UPDATE", "DELETE"}]
    # No statement hydrates every retained finding or observation row.
    assert not any("FROM findings" in statement and "count(" not in statement.lower()
                   and "findings.cve" not in statement and "LIMIT" not in statement
                   and "GROUP BY" not in statement for statement in statements if "SELECT findings.id," in statement)
    with SessionLocal() as db:
        assert db.scalar(select(Execution.raw_payload)) == before
        assert "source" not in (before.get("service_overview") or {})
