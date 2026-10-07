"""Service Posture read model: parity with the original computations.

Shadow mode recomputes every row directly on each read and logs any
difference; these scenarios assert there is none, and that rows are
invalidated by every class of change that can alter posture.
"""
from datetime import datetime, timedelta, timezone
import logging

import pytest
from sqlalchemy import delete, select, update

from app import main, service_posture
from app.database import SessionLocal
from app.models import (DeploymentValidationRun, Execution, ExceptionRecord, Finding, Group, PortalSetting, Role, Service,
                        ServicePosture, User, UserRoleAssignment, utcnow)
from app.auth import hash_password
from test_portal import new_client, payload, pipeline_headers, setup_function  # noqa: F401

PAGE = {"Accept": "application/vnd.cats.page+json"}


@pytest.fixture
def shadow(monkeypatch, caplog):
    monkeypatch.setenv("CATS_POSTURE_SHADOW", "true")
    caplog.set_level(logging.WARNING, logger="cats.posture")
    yield caplog
    assert not [record for record in caplog.records if "service_posture_shadow_mismatch" in record.getMessage()]


def ingest(client, key, cves, *, when=None, complete=True, scan="run"):
    body = payload(f"{key}-{scan}", when or datetime.now(timezone.utc), cves, service_id=key, complete=complete)
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201


def services(client):
    response = client.get("/api/dashboard/services?page_size=200")
    assert response.status_code == 200, response.text[:300]
    return {row["service"]["service_key"]: row for row in response.json()["views"]}


def cyber(client):
    response = client.get("/api/dashboard/cybersecurity?page_size=200")
    assert response.status_code == 200, response.text[:300]
    return response.json()


def posture_row(key):
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == key))
        return db.get(ServicePosture, service_id)


def test_projection_matches_direct_computation_and_follows_ingest(shadow):
    client = new_client()
    old = datetime.now(timezone.utc) - timedelta(days=200)
    ingest(client, "alpha", ["CVE-2024-0001", "CVE-2024-0002"], when=old)
    ingest(client, "beta", [], complete=False)
    first = services(client)
    assert first["alpha"]["noncompliant_count"] == 2 and not first["alpha"]["compliant"]
    assert first["beta"]["evidence_state"].startswith("Incomplete")
    assert cyber(client)["metrics"]["services"] == 2
    built = posture_row("alpha")
    assert built.services_built_generation == built.data_generation and built.services_row is not None
    # A later scan resolves one finding: the same flush bumps the generation.
    ingest(client, "alpha", ["CVE-2024-0001"], scan="second")
    stale = posture_row("alpha")
    assert stale.data_generation > stale.services_built_generation
    assert services(client)["alpha"]["noncompliant_count"] == 1
    assert cyber(client)["metrics"]["vulnerabilities"] == 1


def test_exceptions_and_their_expiry_invalidate_rows(shadow, monkeypatch):
    client = new_client()
    ingest(client, "gamma", ["CVE-2024-1000"], when=datetime.now(timezone.utc) - timedelta(days=200))
    assert services(client)["gamma"]["noncompliant_count"] == 1
    now = utcnow()
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).join(Service).where(Service.service_key == "gamma"))
        db.add(ExceptionRecord(finding_id=finding.id, justification="accepted", approved_by="admin",
                               starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1)))
        db.commit()
    row = services(client)["gamma"]
    assert row["noncompliant_count"] == 0 and row["excepted_count"] == 1
    until = posture_row("gamma").services_valid_until
    assert until is not None and service_posture._aware(until) <= service_posture._aware(now) + timedelta(hours=1)
    # Two hours later the exception has expired with no write at all: the
    # row's time boundary makes it stale and the reader recomputes it.
    later = now + timedelta(hours=2)
    monkeypatch.setattr(main, "utcnow", lambda: later)
    from app import dashboard_portfolio
    monkeypatch.setattr(dashboard_portfolio, "utcnow", lambda: later)
    row = services(client)["gamma"]
    assert row["noncompliant_count"] == 1 and row["excepted_count"] == 0
    cyber(client)


def test_intelligence_configuration_and_validation_changes_invalidate_rows(shadow, monkeypatch):
    client = new_client()
    with SessionLocal() as db:
        db.add_all([PortalSetting(key="compliance_mode", value="risk_based"), PortalSetting(key="kev_enabled", value="true"),
                    PortalSetting(key="kev_noncompliant", value="true"), PortalSetting(key="minimum_severity", value="Critical")])
        db.commit()
    ingest(client, "delta", ["CVE-2023-7777"], when=datetime.now(timezone.utc) - timedelta(days=200))
    before = services(client)["delta"]
    assert before["active_count"] + before["noncompliant_count"] + before["excepted_count"] == 0  # High, not KEV: ineligible
    # The KEV catalog now lists the CVE: the content token changes.
    monkeypatch.setattr(main, "kev_cves", lambda: frozenset({"CVE-2023-7777"}))
    from app import policy_data
    monkeypatch.setattr(policy_data, "kev_cves", lambda: frozenset({"CVE-2023-7777"}))
    monkeypatch.setattr(policy_data, "epss_scores", lambda: {})
    monkeypatch.setattr(policy_data, "_catalog_snapshot", None)
    assert services(client)["delta"]["noncompliant_count"] == 1
    assert cyber(client)["metrics"]["kev"] == 1
    # Configuration change (no source data change): digest differs.
    with SessionLocal() as db:
        db.execute(update(PortalSetting).where(PortalSetting.key == "kev_noncompliant").values(value="false"))
        db.commit()
    assert services(client)["delta"]["noncompliant_count"] == 0
    # A failed deployment validation changes the Cybersecurity status.
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "delta"))
        execution = db.scalar(select(Execution).where(Execution.service_id == service.id))
        db.add(DeploymentValidationRun(run_key="DV-POSTURE", service_id=service.id, execution_id=execution.id,
                                       status="FAILED", phase="COMPLETE", cleanup_status="COMPLETE"))
        db.commit()
    assert cyber(client)["metrics"]["kind_failed"] == 1


def test_scoped_users_only_see_their_services_and_share_rows_safely(shadow):
    client = new_client()
    for key in ("visible-one", "visible-two", "hidden"):
        ingest(client, key, ["CVE-2024-2000"])
    with SessionLocal() as db:
        group = Group(name="posture-scope")
        db.add(group); db.flush()
        members = [db.scalar(select(Service).where(Service.service_key == key)) for key in ("visible-one", "visible-two")]
        for member in members:
            member.groups.append(group)
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        user = User(username="scoped-posture", display_name="Scoped", password_hash=hash_password("test-password-long"),
                    must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, group_id=group.id)); db.commit()
    assert set(services(client)) == {"visible-one", "visible-two", "hidden"}
    scoped = new_client("scoped-posture")
    assert set(services(scoped)) == {"visible-one", "visible-two"}
    data = cyber(scoped)
    assert data["metrics"]["services"] == 2 and "hidden" not in str(data)


def test_concurrent_write_during_a_build_leaves_the_row_stale(shadow):
    client = new_client()
    ingest(client, "epsilon", ["CVE-2024-3000"])
    services(client)
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == "epsilon"))
        db.execute(update(ServicePosture).where(ServicePosture.service_id == service_id)
                   .values(data_generation=ServicePosture.data_generation + 1))
        db.commit()
    row = posture_row("epsilon")
    assert row.services_built_generation < row.data_generation
    services(client)
    row = posture_row("epsilon")
    assert row.services_built_generation == row.data_generation


def test_portfolio_wide_invalidation_is_bounded_and_served_stale(shadow, monkeypatch):
    client = new_client()
    for index in range(6):
        ingest(client, f"bulk-{index}", ["CVE-2024-4000"])
    services(client)
    monkeypatch.setenv("CATS_POSTURE_SYNC_LIMIT", "3")
    scheduled = []
    monkeypatch.setattr(service_posture, "schedule", lambda bind, ids, kinds=service_posture.KINDS: scheduled.append((set(ids), kinds)))
    with SessionLocal() as db:  # a bulk statement names no service: the epoch is replaced
        db.execute(delete(ExceptionRecord).where(ExceptionRecord.id == -1)); db.commit()
    shadow.clear()  # stale rows are served intentionally on this read
    response = client.get("/api/dashboard/services?page_size=200")
    assert response.status_code == 200 and response.json()["posture_refreshing"] is True
    assert scheduled and len(scheduled[0][0]) == 6
    monkeypatch.setenv("CATS_POSTURE_SYNC_LIMIT", "250")
    assert client.get("/api/dashboard/services").json()["posture_refreshing"] is False


def test_new_services_get_posture_rows_in_the_creating_transaction():
    with SessionLocal() as db:
        service = Service(service_key="born", name="Born", lifecycle_status="active")
        db.add(service); db.commit()
        row = db.get(ServicePosture, service.id)
        assert row is not None and row.data_generation >= 1 and row.services_built_generation == -1
