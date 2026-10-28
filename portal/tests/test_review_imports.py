"""Imported rows remain independently reviewable and use one scoped notification."""
import csv
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO

import pytest
from openpyxl import Workbook
from sqlalchemy import create_engine, func, inspect, select, text

from app.frontend import PAGE_MEDIA_TYPE
from app.models import ExchangePreview, ExceptionRecord, Finding, PolicyExceptionRecord, PolicyFinding, PoamEntry, Service, WorkflowImportBatch, WorkflowRequest
from app.review_imports import parse_upload, upgrade_workflow_imports
from test_portal import setup_function, new_client, csrf, ingest, SessionLocal, add_user
from test_exchange_concurrency import sessions


def csv_file(rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def preview(client, kind, rows, service="payments-service"):
    return client.post(f"/services/{service}/review-imports/{kind}/preview",
        data={"csrf_token": csrf(client)}, files={"upload": ("entries.csv", csv_file(rows))})


def confirm(client, token, service="payments-service"):
    return client.post(f"/services/{service}/review-imports/confirm/{token}", data={"csrf_token": csrf(client)}, headers={"Accept": "application/json"})


def entries():
    return [{"title": "First action", "description": "First description", "remediation": "First remediation"},
            {"title": "Second action", "description": "Second description", "remediation": "Second remediation"}]


@pytest.mark.parametrize("kind", ["poams", "mitigations", "exceptions"])
def test_grouped_import_per_row_decisions_and_notification(kind):
    admin = new_client()
    assert ingest(admin, cves=["CVE-ONE", "CVE-TWO"]).status_code == 201
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id))
        ids = db.scalars(select(Finding.id).order_by(Finding.id)).all()
    add_user("manager", "Service Manager", sid)
    add_user("reviewer", "Cybersecurity", sid)
    manager, reviewer = new_client("manager"), new_client("reviewer")
    rows = entries() if kind != "exceptions" else [{"finding_id": identifier,
        "justification": "Compensating control in place", "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()}
        for identifier in ids]
    response = preview(manager, kind, rows)
    assert response.status_code == 200, response.text
    assert response.json()["errors"] == []
    token = response.json()["token"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(WorkflowRequest)) == 0
        assert db.scalar(select(func.count()).select_from(PoamEntry)) == 0
    imported = confirm(manager, token)
    assert imported.status_code == 200, imported.text
    result = imported.json()
    assert result["count"] == 2
    assert confirm(manager, token).status_code == 409
    detail = reviewer.get(result["href"], headers={"Accept": PAGE_MEDIA_TYPE}).json()["data"]
    assert detail["selected_import_batch"]["pending"] == 2
    assert len(detail["workflows"]) == 2
    assert {row["import_row_number"] for row in detail["workflows"]} == {2, 3}
    inbox = reviewer.get("/requests", headers={"Accept": PAGE_MEDIA_TYPE}).json()
    assert not inbox["data"]["workflows"]
    assert len(inbox["data"]["import_batches"]) == 1
    assert len([notice for notice in inbox["data"]["actionable_notifications"] if notice.get("href") == result["href"]]) == 1
    first, second = [row["id"] for row in detail["workflows"]]
    assert manager.post(f"/requests/{first}/review", data={"csrf_token": csrf(manager), "decision": "approved"}).status_code == 403
    assert reviewer.post(f"/requests/{second}/review", data={"csrf_token": csrf(reviewer), "decision": "rejected", "review_reason": ""}).status_code == 422
    approved = reviewer.post(f"/requests/{first}/review", data={"csrf_token": csrf(reviewer), "decision": "approved"}, follow_redirects=False)
    assert approved.status_code == 303 and approved.headers["location"] == result["href"]
    with SessionLocal() as db:
        assert db.get(WorkflowRequest, second).status == "pending"
    rejected = reviewer.post(f"/requests/{second}/review", data={"csrf_token": csrf(reviewer), "decision": "rejected", "review_reason": "Needs more evidence"}, follow_redirects=False)
    assert rejected.status_code == 303
    assert reviewer.post(f"/requests/{first}/review", data={"csrf_token": csrf(reviewer), "decision": "approved"}).status_code == 409
    detail = reviewer.get(result["href"], headers={"Accept": PAGE_MEDIA_TYPE}).json()["data"]
    assert {key: detail["selected_import_batch"][key] for key in ("pending", "approved", "rejected")} == {"pending": 0, "approved": 1, "rejected": 1}
    with SessionLocal() as db:
        if kind == "exceptions":
            assert db.scalar(select(func.count()).select_from(ExceptionRecord)) == 1
        else:
            assert {entry.status for entry in db.scalars(select(PoamEntry))} == {"active", "rejected"}
            assert {entry.item_type for entry in db.scalars(select(PoamEntry))} == ({"mitigation"} if kind == "mitigations" else {"missing_requirement"})


def test_invalid_rows_and_scope_never_create_requests():
    client = new_client()
    assert ingest(client, cves=["CVE-ONE"]).status_code == 201
    assert ingest(client, execution="other", service_id="other-service", cves=["CVE-PRIVATE"]).status_code == 201
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id).where(Service.service_key == "payments-service"))
        other = db.scalar(select(Finding.id).where(Finding.cve == "CVE-PRIVATE"))
    add_user("manager", "Service Manager", sid)
    manager = new_client("manager")
    rows = [{"finding_id": other, "justification": "Valid explanation", "expires_at": "2000-01-01"}]
    result = preview(manager, "exceptions", rows).json()
    assert result["token"] is None
    assert {item["field"] for item in result["errors"]} == {"finding_id", "expires_at"}
    assert all(item["row"] == 2 for item in result["errors"])
    assert preview(manager, "poams", entries(), service="other-service").status_code == 403
    assert manager.post("/services/payments-service/review-imports/poams/preview", data={"csrf_token": "bad"}, files={"upload": ("test.csv", csv_file(entries()))}).status_code == 403
    duplicate = preview(manager, "poams", [entries()[0], entries()[0]]).json()
    assert duplicate["token"] is None and any("Duplicate" in row["message"] for row in duplicate["errors"])
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(WorkflowRequest)) == 0


def test_importer_with_review_permission_still_needs_another_reviewer_and_individual_actions_remain_separate():
    admin = new_client()
    assert ingest(admin).status_code == 201
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id))
    add_user("cyber", "Cybersecurity", sid)
    reviewer = new_client("cyber")
    token = preview(admin, "mitigations", entries()).json()["token"]
    result = confirm(admin, token).json()
    with SessionLocal() as db:
        workflow_id = db.scalar(select(WorkflowRequest.id))
        assert all(row.status == "pending" for row in db.scalars(select(WorkflowRequest)))
        assert all(row.approved_by_id is None for row in db.scalars(select(PoamEntry)))
    assert admin.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(admin), "decision": "approved"}).status_code == 409
    for number in range(2):
        assert admin.post("/services/payments-service/mitigations", data={"csrf_token": csrf(admin), "title": f"Manual action {number}", "description": "Manual description", "remediation": "Apply controls"}, follow_redirects=False).status_code == 303
    inbox = reviewer.get("/requests", headers={"Accept": PAGE_MEDIA_TYPE}).json()
    assert len(inbox["data"]["workflows"]) == 2
    notices = inbox["data"]["actionable_notifications"]
    assert len([item for item in notices if item["href"].startswith("/requests")]) == 3


def test_confirmation_is_atomic_and_rechecks_targets(monkeypatch):
    from app import review_imports
    client = new_client()
    assert ingest(client, cves=["CVE-ONE"]).status_code == 201
    token = preview(client, "poams", entries()).json()["token"]
    original = review_imports.add_poam_request
    calls = []
    def fail_second(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError("simulated write failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(review_imports, "add_poam_request", fail_second)
    with pytest.raises(RuntimeError, match="simulated"):
        confirm(client, token)
    with SessionLocal() as db:
        assert not db.get(ExchangePreview, token).consumed
        for model in (WorkflowImportBatch, WorkflowRequest, PoamEntry):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        finding = db.scalar(select(Finding))
        identifier = finding.id
    exception_token = preview(client, "exceptions", [{"finding_id": identifier, "justification": "Accept until replacement", "expires_at": (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()}]).json()["token"]
    with SessionLocal() as db:
        db.get(Finding, identifier).active = False
        db.commit()
    assert confirm(client, exception_token).status_code == 409
    with SessionLocal() as db:
        assert not db.get(ExchangePreview, exception_token).consumed


def test_xlsx_parser_and_additive_migration():
    book = Workbook()
    book.active.append(["title", "description", "remediation"])
    book.active.append(["First title", "=1+2", "Apply controls"])
    output = BytesIO()
    book.save(output)
    rows, errors = parse_upload(output.getvalue(), "actions.xlsx", "poams")
    assert len(rows) == 1 and errors == [{"row": 2, "field": "description", "message": "Formulas are not importable"}]
    with pytest.raises(ValueError, match="unique"):
        parse_upload(b"title,title,description,remediation\na,b,c,d", "test.csv", "poams")
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE workflow_requests (id INTEGER PRIMARY KEY, status TEXT)"))
        connection.execute(text("INSERT INTO workflow_requests VALUES (1, 'pending')"))
        upgrade_workflow_imports(connection)
        upgrade_workflow_imports(connection)
        assert {"import_batch_id", "import_row_number"} <= {item["name"] for item in inspect(connection).get_columns("workflow_requests")}
        assert connection.execute(text("SELECT status FROM workflow_requests")).scalar_one() == "pending"


@pytest.mark.parametrize("policy", [False, True])
def test_active_exception_conflicts_at_preview_confirmation_and_review(policy):
    client = new_client()
    assert ingest(client, cves=["CVE-ONE"]).status_code == 201
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id))
        if policy:
            finding = PolicyFinding(service_id=sid, identity_key="policy-import", finding="POL-1",
                first_seen=now, episode_started=now, last_seen=now)
            db.add(finding)
            db.flush()
        else:
            finding = db.scalar(select(Finding))
        identifier = finding.id
        db.commit()
    field, model = ("policy_finding_id", PolicyExceptionRecord) if policy else ("finding_id", ExceptionRecord)
    row = {field: identifier, "justification": "Requested new exception", "expires_at": (now + timedelta(days=30)).isoformat()}
    token = preview(client, "exceptions", [row]).json()["token"]
    with SessionLocal() as db:
        record = model(**{field: identifier}, justification="Existing approved exception", approved_by="cyber",
            starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=10))
        db.add(record)
        db.commit()
        exception_id = record.id
    invalid = preview(client, "exceptions", [row]).json()
    assert invalid["token"] is None and any("already active" in error["message"] for error in invalid["errors"])
    conflict = confirm(client, token)
    assert conflict.status_code == 409 and "already active" in conflict.json()["detail"]
    with SessionLocal() as db:
        db.get(model, exception_id).revoked_at = now
        db.commit()
    result = confirm(client, token)
    assert result.status_code == 200
    with SessionLocal() as db:
        db.get(model, exception_id).revoked_at = None
        workflow_id = db.scalar(select(WorkflowRequest.id))
        db.commit()
    add_user("reviewer", "Cybersecurity", sid)
    reviewer = new_client("reviewer")
    rejected = reviewer.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(reviewer), "decision": "approved"}, headers={"Accept": "application/json"})
    assert rejected.status_code == 409 and "already active" in rejected.json()["detail"]
    with SessionLocal() as db:
        assert db.get(WorkflowRequest, workflow_id).status == "pending"
        assert db.scalar(select(func.count()).select_from(model)) == 1


def test_overdue_import_and_exception_approval_stays_with_selected_finding():
    client = new_client()
    assert ingest(client, cves=["CVE-SAME"]).status_code == 201
    assert ingest(client, service_id="other-service", execution="other", cves=["CVE-SAME"]).status_code == 201
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id).where(Service.service_key == "payments-service"))
        identifier = db.scalar(select(Finding.id).where(Finding.service_id == sid))
    add_user("reviewer", "Cybersecurity", sid)
    reviewer = new_client("reviewer")
    overdue = entries()[0] | {"due_date": "2000-01-01"}
    for kind in ("poams", "mitigations"):
        result = preview(client, kind, [overdue]).json()
        assert not result["errors"] and confirm(client, result["token"]).status_code == 200
    row = {"finding_id": identifier, "justification": "Scope this approval", "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()}
    result = confirm(client, preview(client, "exceptions", [row]).json()["token"]).json()
    with SessionLocal() as db:
        workflow_id = db.scalar(select(WorkflowRequest.id).where(WorkflowRequest.import_batch_id == result["batch_id"]))
    assert reviewer.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(reviewer), "decision": "approved"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.scalars(select(ExceptionRecord.finding_id)).all() == [identifier]


def test_existing_workbook_poam_updates_wait_for_individual_review():
    from test_exchange import seed, xlsx
    client = new_client()
    seed(client)
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id))
    add_user("reviewer", "Cybersecurity", sid)
    reviewer = new_client("reviewer")

    def submit(description):
        rows = [{"finding.identifier": "P-1", "finding.description": description,
            "finding.mitigation": "Apply proposed controls", "finding.due_date": "2000-01-01"}]
        response = client.post("/services/payments-service/exchange/poam/preview",
            data={"csrf_token": csrf(client), "version": "1.4"},
            files={"upload": ("legacy.xlsx", xlsx("poam", rows))}, headers={"Accept": PAGE_MEDIA_TYPE})
        assert response.status_code == 200, response.text
        token = response.json()["data"]["token"]
        return client.post(f"/services/payments-service/exchange/confirm/{token}",
            data={"csrf_token": csrf(client), "conflict_action": "update"}, follow_redirects=False)

    first = submit("Original description")
    assert first.status_code == 303 and "batch_id=" in first.headers["location"]
    with SessionLocal() as db:
        workflow_id = db.scalar(select(WorkflowRequest.id))
        entry_id = db.scalar(select(PoamEntry.id))
    assert submit("Premature update").status_code == 409
    assert reviewer.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(reviewer), "decision": "approved"}, follow_redirects=False).status_code == 303
    second = submit("Proposed description")
    assert second.status_code == 303
    detail = reviewer.get(second.headers["location"], headers={"Accept": PAGE_MEDIA_TYPE}).json()["data"]
    row = detail["workflows"][0]
    assert row["request_type"] == "poam_update" and "Proposed description" in row["justification"]
    with SessionLocal() as db:
        assert db.get(PoamEntry, entry_id).description == "Original description"
    assert reviewer.post(f"/requests/{row['id']}/review", data={"csrf_token": csrf(reviewer), "decision": "rejected", "review_reason": "Needs revision"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.get(PoamEntry, entry_id).description == "Original description"
    third = submit("Approved replacement")
    row = reviewer.get(third.headers["location"], headers={"Accept": PAGE_MEDIA_TYPE}).json()["data"]["workflows"][0]
    assert reviewer.post(f"/requests/{row['id']}/review", data={"csrf_token": csrf(reviewer), "decision": "approved"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.get(PoamEntry, entry_id).description == "Approved replacement"


def test_concurrent_confirm_creates_one_batch(sessions, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi import HTTPException
    from app import exchange_routes, review_imports
    from test_exchange_concurrency import auth
    with sessions() as db:
        db.add(ExchangePreview(token="grouped-preview", service_id=1, user_id=1, version="", dataset="review_poams",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30), payload={"kind": "poams", "filename": "plans.csv",
            "rows": [{"row": i + 2, "values": values} for i, values in enumerate(entries())]}))
        db.commit()
    original = exchange_routes.lock_service
    barrier = Barrier(2)
    def rendezvous(db, service_id):
        barrier.wait(timeout=10)
        original(db, service_id)
    monkeypatch.setattr(exchange_routes, "lock_service", rendezvous)
    def submit():
        with sessions() as db:
            try:
                review_imports.confirm_import("target", "grouped-preview", "csrf-good", db, auth(permissions={"poam.request"}))
                return 200
            except HTTPException as error:
                db.rollback()
                return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit) for _ in range(2)]
        assert sorted(future.result(timeout=20) for future in futures) == [200, 409]
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(WorkflowImportBatch)) == 1
        assert db.scalar(select(func.count()).select_from(WorkflowRequest)) == 2
        assert db.scalar(select(func.count()).select_from(PoamEntry)) == 2
