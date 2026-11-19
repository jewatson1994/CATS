"""Synthetic fixtures for an isolated, already-started GUI acceptance portal.

Run inside the portal container with its DATABASE_URL/PYTHONPATH environment:
  python /workspace/tests/diagnostics/gui_seed.py --allow-isolated-fixtures --url http://127.0.0.1:8080
The URL is optional: omit it to seed only, then use --trigger-only with the URL.
Reads PIPELINE_API_TOKEN and CATS_BOOTSTRAP_PASSWORD without printing either.
Never import pytest fixtures or point this script at an existing installation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

PREFIX = "diagnostics-gui-"
ADMIN = "diagnostics-admin"
VIEWER = "diagnostics-viewer"
CORRELATION = "diagnostics-gui-ownerless"
SENTINEL = "GUI_FAKE_SECRET_MUST_NOT_APPEAR"


def fixture_id(name):
    return uuid.uuid5(uuid.NAMESPACE_URL, PREFIX + name).hex


def seed():
    from sqlalchemy import select
    from app.auth import hash_password
    from app.database import SessionLocal
    from app.diagnostics import build_diagnostic
    from app.diagnostic_store import record_diagnostic
    from app.durable_jobs import DurableJob
    from app.models import Role, Service, User, UserRoleAssignment

    password = os.environ.get("CATS_BOOTSTRAP_PASSWORD")
    if not password or os.environ.get("CATS_BOOTSTRAP_USERNAME") != ADMIN:
        raise SystemExit("Use the dedicated diagnostics-admin bootstrap environment.")
    events = []
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.username.not_in([ADMIN, VIEWER])).limit(1)) is not None:
            raise SystemExit("Refusing fixtures: this database contains unrelated users.")
        if db.scalar(select(Service.id).where(~Service.service_key.startswith(PREFIX)).limit(1)) is not None:
            raise SystemExit("Refusing fixtures: this database contains unrelated services.")
        admin = db.scalar(select(User).where(User.username == ADMIN))
        if admin is None:
            raise SystemExit("Start the isolated portal first so standard bootstrap creates its admin.")
        admin.must_change_password = False
        viewer = db.scalar(select(User).where(User.username == VIEWER))
        if viewer is None:
            viewer = User(username=VIEWER, display_name="Synthetic diagnostics viewer",
                          password_hash=hash_password(os.environ.get("GUI_DIAGNOSTIC_VIEWER_PASSWORD") or password),
                          must_change_password=False)
            db.add(viewer)
            db.flush()
        role = db.scalar(select(Role).where(Role.name == "GUI diagnostics viewer"))
        if role is None:
            role = Role(name="GUI diagnostics viewer", permissions=["service.view"])
            db.add(role)
            db.flush()
        if db.scalar(select(UserRoleAssignment.id).where(UserRoleAssignment.user_id == viewer.id,
                                                        UserRoleAssignment.role_id == role.id)) is None:
            db.add(UserRoleAssignment(user_id=viewer.id, role_id=role.id))
        service = db.scalar(select(Service).where(Service.service_key == PREFIX + "ownerless"))
        if service is None:
            service = Service(service_key=PREFIX + "ownerless", name="SYNTHETIC GUI ownerless service", manual_version="1")
            db.add(service)
            db.flush()
        for index, kind in enumerate(("remediation_plan", "remediation_execute", "remediation_deliver")):
            job_id = fixture_id(kind)
            # Real Python exception frames; all credential values are fake sentinels.
            try:
                raise TimeoutError("Synthetic GUI worker timeout password=" + SENTINEL)
            except TimeoutError as error:
                diagnostic = build_diagnostic(error, component="remediation worker", operation=kind,
                    status="failed", correlation_id=fixture_id("correlation-" + kind),
                    resource={"service_id": service.id, "service_key": service.service_key,
                              "job_id": job_id, "jobs_view_id": job_id},
                    context={"failed_stage": "synthetic dependency check", "last_successful_stage": "synthetic input validation",
                             "worker_id": "gui-fixture-worker", "tool": "synthetic-tool", "exit_code": 23,
                             "attempts": 2, "max_attempts": 3})
            diagnostic["error_id"] = fixture_id("event-" + kind)
            diagnostic["technical"]["api_key"] = SENTINEL
            from app.diagnostics import sanitize
            diagnostic = sanitize(diagnostic)
            if SENTINEL in json.dumps(diagnostic):
                raise AssertionError("Synthetic secret was not sanitized")
            if db.get(DurableJob, job_id) is None:
                db.add(DurableJob(id=job_id, kind=kind, service_id=service.id, requested_by_id=admin.id,
                    payload={}, result={"diagnostic": diagnostic}, status="failed", stage="synthetic dependency check",
                    error=diagnostic["summary"], correlation_id=diagnostic["correlation_id"], attempts=2, max_attempts=3,
                    worker_id="gui-fixture-worker", heartbeat_at=now, created_at=now, started_at=now, completed_at=now))
            events.append(diagnostic)
        service_id = service.id
        db.commit()
    for diagnostic in events:
        if not record_diagnostic(diagnostic):
            raise RuntimeError("Fixture diagnostic persistence failed")
    print(json.dumps({"fixture": "synthetic GUI acceptance", "admin_username": ADMIN, "viewer_username": VIEWER,
                      "service_id": service_id, "service_key": PREFIX + "ownerless",
                      "center": "/admin/diagnostics", "jobs": ["/jobs?job=" + item["resource"]["job_id"] for item in events],
                      "reports": ["/admin/diagnostics?error_id=" + item["error_id"] for item in events]}))


def trigger(base_url):
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.diagnostic_store import DiagnosticEvent

    # A rerun reuses the persisted real HTTP failure instead of growing history.
    with SessionLocal() as db:
        existing = db.scalar(select(DiagnosticEvent).where(DiagnosticEvent.correlation_id == CORRELATION))
        if existing is not None:
            print(json.dumps({"ownerless_error_id": existing.error_id, "correlation_id": CORRELATION, "reused": True}))
            return
    token = os.environ.get("PIPELINE_API_TOKEN")
    if not token:
        raise SystemExit("PIPELINE_API_TOKEN is required for the real ingestion request.")
    body = {"schema_version": "1.0", "execution_id": PREFIX + "ingestion", "scanned_at": datetime.now(timezone.utc).isoformat(),
            "complete": True, "skipped_images": [], "fixable_only": True,
            "service": {"id": PREFIX + "ownerless", "name": "SYNTHETIC GUI ownerless service", "version": "1",
                        "poc": "synthetic@example.invalid", "groups": ["Synthetic GUI group"]}, "findings": []}
    request = Request(base_url.rstrip("/") + "/api/v1/pipeline-results", json.dumps(body).encode(),
                      headers={"Content-Type": "application/json", "Authorization": "Bearer " + token,
                               "X-Correlation-ID": CORRELATION}, method="POST")
    try:
        with urlopen(request, timeout=30) as response:
            raise AssertionError("Expected ownership HTTP 409, received " + str(response.status))
    except HTTPError as error:
        if error.code != 409:
            raise AssertionError("Expected ownership HTTP 409, received " + str(error.code)) from None
        result = json.loads(error.read())
    diagnostic = result["diagnostic"]
    assert diagnostic["code"] == "CAT-SVC-OWNERSHIP-001"
    assert diagnostic["cause"] == "Service has no owning group"
    assert "technical" not in diagnostic
    for _ in range(50):
        with SessionLocal() as db:
            if db.get(DiagnosticEvent, diagnostic["error_id"]):
                break
        time.sleep(0.1)
    else:
        raise AssertionError("HTTP diagnostic did not persist within five seconds")
    print(json.dumps({"ownerless_error_id": diagnostic["error_id"], "correlation_id": diagnostic["correlation_id"],
                      "report": "/admin/diagnostics?error_id=" + diagnostic["error_id"], "status": 409, "persisted": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-isolated-fixtures", action="store_true", required=True)
    parser.add_argument("--url")
    parser.add_argument("--trigger-only", action="store_true")
    args = parser.parse_args()
    if not args.trigger_only:
        seed()
    if args.url:
        trigger(args.url)
    elif args.trigger_only:
        parser.error("--trigger-only requires --url")
