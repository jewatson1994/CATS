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
    monkeypatch.setattr(service_posture, "background_enabled", lambda bind: True)
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


def test_idempotent_writes_do_not_invalidate_but_real_changes_do():
    client = new_client()
    ingest(client, "zeta", ["CVE-2024-5000"])
    services(client)
    before = posture_row("zeta").data_generation
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).join(Service).where(Service.service_key == "zeta"))
        finding.severity = finding.severity  # touched, unchanged
        db.commit()
    assert posture_row("zeta").data_generation == before
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).join(Service).where(Service.service_key == "zeta"))
        finding.severity = "Low"
        db.commit()
    assert posture_row("zeta").data_generation == before + 1


def test_cybersecurity_evidence_flags_match_with_and_without_current_summaries():
    """SBOM presence and missing evidence read from execution summaries must
    equal the retained-payload reading they replace (used when a summary is
    missing, outdated or lacks the field)."""
    from app.dashboard_portfolio import compute_rows
    from app.models import ExecutionSummary
    client = new_client()
    with_sbom = payload("sbom-run", datetime.now(timezone.utc), ["CVE-2024-6000"], service_id="with-sbom")
    with_sbom["sbom_images"] = ["registry.example/app:1"]
    assert client.post("/api/v1/pipeline-results", json=with_sbom, headers=pipeline_headers).status_code == 201
    skipped = payload("skipped-run", datetime.now(timezone.utc), [], service_id="skipped")
    skipped["skipped_images"] = ["registry.example/private:1"]
    assert client.post("/api/v1/pipeline-results", json=skipped, headers=pipeline_headers).status_code == 201
    ingest(client, "partial", ["CVE-2024-6001"], complete=False)
    ingest(client, "plain", [])

    def rows():
        with SessionLocal() as db:
            found = db.scalars(select(Service)).all()
            base = main.get_global_configuration(db)
            configurations = service_posture.resolve_configurations(db, [s.id for s in found], base)
            computed = compute_rows(db, found, configurations, base, utcnow())
            return {s.service_key: (computed[s.id]["sbom"], computed[s.id]["missing"], computed[s.id]["status"]) for s in found}

    from_summaries = rows()
    assert from_summaries["with-sbom"][0] is True and from_summaries["plain"][0] is False
    assert from_summaries["partial"][1] is True and from_summaries["plain"][1] is False
    for change in ({"summary_version": -1}, {"data": {"legacy": True}}):
        with SessionLocal() as db:
            db.execute(update(ExecutionSummary).values(**change)); db.commit()
        assert rows() == from_summaries


def test_bulk_statements_invalidate_only_the_services_they_name():
    """An ingest's bulk reconciliation (DELETE ... WHERE execution_id = :id)
    must invalidate that service only, not the whole portfolio."""
    from app.models import DependencyWatchlistMatch
    client = new_client()
    ingest(client, "bulk-a", ["CVE-2024-8000"])
    ingest(client, "bulk-b", ["CVE-2024-8001"])
    services(client)
    with SessionLocal() as db:
        epoch = service_posture.current_epoch(db)
        a, b = (db.scalar(select(Service.id).where(Service.service_key == key)) for key in ("bulk-a", "bulk-b"))
        before = {sid: db.get(ServicePosture, sid).data_generation for sid in (a, b)}
    ingest(client, "bulk-a", ["CVE-2024-8000"], scan="again")
    with SessionLocal() as db:
        assert service_posture.current_epoch(db) == epoch
        assert db.get(ServicePosture, b).data_generation == before[b]
        assert db.get(ServicePosture, a).data_generation > before[a]
        execution = db.scalar(select(Execution.id).where(Execution.service_id == b))
        db.execute(delete(DependencyWatchlistMatch).where(DependencyWatchlistMatch.execution_id == execution))
        db.execute(update(Finding).where(Finding.service_id == a).values(severity="Low"))
        db.commit()
        assert db.get(ServicePosture, b).data_generation == before[b] + 1
        db.execute(delete(DependencyWatchlistMatch).where(DependencyWatchlistMatch.execution_id == execution))
        db.rollback()  # nothing published
        assert db.get(ServicePosture, b).data_generation == before[b] + 1
        assert service_posture.current_epoch(db) == epoch
        db.execute(delete(DependencyWatchlistMatch)); db.commit()  # names no service
        assert service_posture.current_epoch(db) != epoch


def test_service_deletion_removes_posture_and_a_reused_id_starts_fresh(monkeypatch):
    """Deleting the newest service and creating another must work on SQLite,
    which can reuse the deleted id (review P1)."""
    from test_portal import csrf
    client = new_client()
    ingest(client, "doomed", ["CVE-2024-9100"])
    services(client)
    with SessionLocal() as db:
        doomed_id = db.scalar(select(Service.id).where(Service.service_key == "doomed"))
        assert db.get(ServicePosture, doomed_id) is not None
    from app.models import ServiceArchiveEvent
    with SessionLocal() as db:
        db.add(ServiceArchiveEvent(service_id=doomed_id, action="archive", reason="test", performed_by="admin")); db.commit()
    monkeypatch.setenv("ALLOW_SERVICE_DELETE", "true")
    response = client.post("/services/doomed/delete", data={"confirmation": "doomed", "reason": "test", "csrf_token": csrf(client)},
                           follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        assert db.get(ServicePosture, doomed_id) is None
        # An orphan left by an earlier release must not block a new service with the same id.
        db.execute(ServicePosture.__table__.insert().values(service_id=doomed_id, data_generation=7,
                                                             services_built_generation=7, services_algorithm=1,
                                                             services_row={"stale": True}))
        db.commit()
    ingest(client, "reborn", ["CVE-2024-9101"])
    with SessionLocal() as db:
        reborn_id = db.scalar(select(Service.id).where(Service.service_key == "reborn"))
        row = db.get(ServicePosture, reborn_id)
        assert row is not None and row.services_row != {"stale": True}
    assert services(client)["reborn"]["active_count"] + services(client)["reborn"]["noncompliant_count"] >= 0
    with SessionLocal() as db:  # startup migration removes orphans of services deleted by bulk statements
        db.execute(ServicePosture.__table__.insert().values(service_id=987654, data_generation=1))
        db.commit()
        service_posture.ensure_rows(db.connection())
        db.commit()
        assert db.get(ServicePosture, 987654) is None


def test_a_write_that_races_the_inline_rebuild_is_never_served_as_current(shadow, monkeypatch):
    """After an inline rebuild the reader re-checks provenance (review P2)."""
    client = new_client()
    ingest(client, "racy", ["CVE-2024-9200"])
    services(client)
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id).where(Service.service_key == "racy"))
        db.execute(update(ServicePosture).where(ServicePosture.service_id == sid)
                   .values(data_generation=ServicePosture.data_generation + 1)); db.commit()
    original = service_posture.rebuild
    calls = []

    def racing_rebuild(bind, kind, ids, now=None):
        result = original(bind, kind, ids, now=now)
        if kind == "services" and not calls:
            # A writer commits right after the rebuild published its rows.
            with SessionLocal() as writer:
                writer.execute(update(ServicePosture).where(ServicePosture.service_id == sid)
                               .values(data_generation=ServicePosture.data_generation + 1)); writer.commit()
        calls.append(kind)
        return result
    monkeypatch.setattr(service_posture, "rebuild", racing_rebuild)
    services(client)
    assert calls.count("services") == 2  # rebuilt again because the first result was already stale
    row = posture_row("racy")
    assert row.services_built_generation == row.data_generation

    def always_raced(bind, kind, ids, now=None):
        result = original(bind, kind, ids, now=now)
        with SessionLocal() as writer:
            writer.execute(update(ServicePosture).where(ServicePosture.service_id == sid)
                           .values(data_generation=ServicePosture.data_generation + 1)); writer.commit()
        return result
    monkeypatch.setattr(service_posture, "rebuild", always_raced)
    with SessionLocal() as db:  # make the row stale again so the read rebuilds it
        db.execute(update(ServicePosture).where(ServicePosture.service_id == sid)
                   .values(data_generation=ServicePosture.data_generation + 1)); db.commit()
    shadow.clear()
    response = client.get("/api/dashboard/services?page_size=200")
    # Still not current after the retry: reported as refreshing, not as current.
    assert response.status_code == 200 and response.json()["posture_refreshing"] is True


def test_poam_due_exactly_now_sets_a_boundary_just_after():
    from app.models import PoamEntry
    now = utcnow()
    client = new_client()
    ingest(client, "due-now", ["CVE-2024-9300"])
    with SessionLocal() as db:
        sid = db.scalar(select(Service.id).where(Service.service_key == "due-now"))
        admin_id = db.scalar(select(User.id).where(User.username == "admin"))
        db.add(PoamEntry(service_id=sid, item_type="vulnerability", title="due", description="d", remediation="r",
                         status="active", due_date=now, created_by_id=admin_id))
        db.commit()
        boundary = service_posture.valid_until(db, [sid], [main.get_configuration(db)], now)[sid]
    assert boundary is not None and service_posture._aware(boundary) <= service_posture._aware(now) + timedelta(milliseconds=1)


def test_services_without_posture_beyond_the_bound_are_reported_as_preparing(monkeypatch):
    client = new_client()
    for index in range(4):
        ingest(client, f"prep-{index}", ["CVE-2024-9400"])
    with SessionLocal() as db:
        db.execute(update(ServicePosture).values(services_row=None, cyber_row=None)); db.commit()
    monkeypatch.setenv("CATS_POSTURE_SYNC_LIMIT", "1")
    monkeypatch.setattr(service_posture, "background_enabled", lambda bind: True)
    scheduled = []
    monkeypatch.setattr(service_posture, "schedule", lambda bind, ids, kinds=service_posture.KINDS: scheduled.append(set(ids)))
    body = client.get("/api/dashboard/services?page_size=200").json()
    assert body["posture_preparing"] == 3 and body["posture_refreshing"] is True
    assert len(body["views"]) == 1  # no invented rows for services not yet prepared
    assert scheduled and len(scheduled[0]) == 3
    cyber_body = client.get("/api/dashboard/cybersecurity?page_size=200").json()
    assert cyber_body["posture_preparing"] == 3 and cyber_body["metrics"]["services"] == 1
