"""Service Remediations collections are paged in the database without losing records."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, insert, select

from app.database import SessionLocal, engine
from app.models import (ExceptionRecord, Finding, PoamEntry, PolicyExceptionRecord, PolicyFinding,
                        RemediationExecution, Service, User, WorkflowRequest)
from test_portal import new_client, page_data, payload, pipeline_headers, setup_function  # noqa: F401

BASE = "/services/payments-service?remediations=true"


def _seed():
    client = new_client()
    now = datetime.now(timezone.utc)
    body = payload("paging", now, [f"CVE-2026-{index:04d}" for index in range(80)])
    body["policy_findings"] = [{"type": "Configuration", "finding": f"KSV{index:03d}", "severity": "High",
                                "scanner": "Trivy", "target": f"Deployment/api-{index}"} for index in range(40)]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        user = db.scalar(select(User).where(User.username == "admin"))
        findings = db.scalars(select(Finding).order_by(Finding.id)).all()
        policies = db.scalars(select(PolicyFinding).order_by(PolicyFinding.id)).all()
        for index, finding in enumerate(findings[:70]):
            db.add(ExceptionRecord(finding_id=finding.id, justification=f"v{index}", approved_by="a",
                                   starts_at=now - timedelta(days=2), created_at=now - timedelta(minutes=index % 7),
                                   expires_at=now + timedelta(days=index - 20),
                                   revoked_at=now if index % 9 == 0 else None))
        for index, policy in enumerate(policies[:30]):
            db.add(PolicyExceptionRecord(policy_finding_id=policy.id, justification=f"p{index}", approved_by="a",
                                         starts_at=now - timedelta(days=1), created_at=now - timedelta(minutes=index),
                                         expires_at=now + timedelta(days=30)))
        for index in range(20):
            target = findings[70 + index % 10] if index % 2 else None
            db.add(WorkflowRequest(request_type="exception", status="pending", service_id=service.id,
                                   finding_id=target.id if target else None,
                                   policy_finding_id=None if target else policies[30 + index % 10].id,
                                   requested_by_id=user.id, justification=f"w{index}", created_at=now - timedelta(minutes=index),
                                   requested_expires_at=now + timedelta(days=10)))
        for index in range(130):
            db.add(PoamEntry(service_id=service.id, item_type="mitigation" if index % 3 == 0 else "poam",
                             title=f"Entry {index:03d}", description="d", remediation="r", status="active",
                             created_by_id=user.id, created_at=now - timedelta(minutes=index // 2)))
        db.execute(insert(RemediationExecution), [dict(job_key=f"R-{index:03d}", service_id=service.id,
            requested_by_id=user.id, created_at=now + timedelta(seconds=index)) for index in range(130)])
        db.commit()
    return client


def _legacy_exceptions(now_cutoff=None):
    """The previous unpaged list, built from complete relationship loads."""
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        rows = []
        for record in db.scalars(select(ExceptionRecord).join(Finding).where(Finding.service_id == service.id)
                                 .order_by(ExceptionRecord.created_at.desc(), ExceptionRecord.id.desc())):
            rows.append(("Vulnerability", record.finding.cve, record.justification))
        for record in db.scalars(select(PolicyExceptionRecord).join(PolicyFinding).where(PolicyFinding.service_id == service.id)
                                 .order_by(PolicyExceptionRecord.created_at.desc(), PolicyExceptionRecord.id.desc())):
            rows.append(("Configuration", record.policy_finding.finding, record.justification))
        for workflow in db.scalars(select(WorkflowRequest).where(WorkflowRequest.service_id == service.id,
                WorkflowRequest.request_type == "exception", WorkflowRequest.status == "pending")
                .order_by(WorkflowRequest.created_at.desc(), WorkflowRequest.id.desc())):
            target = workflow.finding or workflow.policy_finding
            if target:
                rows.append(("Vulnerability" if workflow.finding else "Configuration",
                             target.cve if workflow.finding else target.finding, workflow.justification))
        return rows


def _collect(client, tab, key, page_size=25):
    first = page_data(client.get(f"{BASE}&tab={tab}&page_size={page_size}"))
    rows, pages = list(first[key]), first["page_count"]
    assert first["page"] == 1 and len(first[key]) <= page_size
    for page in range(2, pages + 1):
        data = page_data(client.get(f"{BASE}&tab={tab}&page_size={page_size}&page={page}"))
        assert data["page"] == page and data["total_items"] == first["total_items"]
        rows.extend(data[key])
    assert len(rows) == first["total_items"]
    return rows, first


def test_exception_pages_cover_every_record_in_legacy_order():
    client = _seed()
    rows, first = _collect(client, "exceptions", "exceptions")
    expected = _legacy_exceptions()
    assert first["total_items"] == len(expected) == 120
    assert [(row["kind"], row["item"], row["justification"]) for row in rows] == expected
    assert {row["status"] for row in rows} >= {"Active", "Revoked", "Expired", "Pending"}
    assert first["pagination_base"] == "/services/payments-service?remediations=true&tab=exceptions&page_size=25"


@pytest.mark.parametrize("tab,mitigation", [("poams", False), ("mitigations", True)])
def test_poam_and_mitigation_pages_are_disjoint_and_complete(tab, mitigation):
    client = _seed()
    rows, first = _collect(client, tab, tab)
    with SessionLocal() as db:
        expected = [entry.title for entry in db.scalars(select(PoamEntry).order_by(PoamEntry.created_at.desc(), PoamEntry.id.desc()))
                    if (entry.item_type == "mitigation") == mitigation]
    assert [row["title"] for row in rows] == expected
    assert first["total_items"] == (44 if mitigation else 86)


def test_candidate_history_is_paged_instead_of_truncated():
    client = _seed()
    rows, first = _collect(client, "pipeline", "remediation_jobs", page_size=50)
    assert first["total_items"] == 130 and first["page_count"] == 3
    assert [row["job_key"] for row in rows] == [f"R-{index:03d}" for index in reversed(range(130))]


def test_remediation_tabs_load_only_the_selected_page():
    client = _seed()
    statements = []
    listener = lambda conn, cursor, statement, parameters, context, many: statements.append(statement)
    event.listen(engine, "before_cursor_execute", listener)
    try:
        data = page_data(client.get(f"{BASE}&tab=exceptions&page_size=25&page=3"))
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert len(data["exceptions"]) == 25 and data["poams"] == [] and data["remediation_jobs"] == []
    assert not any("FROM poam_entries" in statement for statement in statements)
    assert not any("FROM remediation_executions" in statement for statement in statements)
    # Every statement that reads exception/request rows (not counts) is a page.
    row_reads = [statement for statement in statements if "justification" in statement and "count(" not in statement]
    assert row_reads and all("LIMIT" in statement for statement in row_reads)
    assert client.get(f"{BASE}&tab=poams&page_size=7").status_code == 422
    beyond = page_data(client.get(f"{BASE}&tab=poams&page_size=25&page=999"))
    assert beyond["page"] == beyond["page_count"] and beyond["poams"]
