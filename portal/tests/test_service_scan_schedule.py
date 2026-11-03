from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from test_portal import SessionLocal, setup_function
from app import main, scan_coordination as jobs, service_scan_schedule as schedules
from app.auth import AuthContext
from app.models import Role, Service, ServiceImage, User, UserRoleAssignment


OPENING = datetime(2026, 11, 2, 21, tzinfo=timezone.utc)
DIGEST = "sha256:" + "ab" * 32


def dispatch(db, clock):
    schedules.dispatch_due(clock=clock)
    db.expire_all()


def setup_schedule(db):
    service = Service(name="Ledger", service_key="ledger", manual_version="release-7")
    user = User(username="scheduler", display_name="Scheduling owner")
    role = Role(name="Scoped scheduler", permissions=["scan.ingest", "service.edit"])
    db.add_all([service, user, role])
    db.flush()
    db.add_all([UserRoleAssignment(user_id=user.id, role_id=role.id, service_id=service.id),
                ServiceImage(service_id=service.id, image_reference="registry/ledger:v7", image_digest=DIGEST),
                ServiceImage(service_id=service.id, image_reference="registry/cache:1"),
                ServiceImage(service_id=service.id, image_reference="registry/old:1", lifecycle_status="removed")])
    db.commit()
    auth = AuthContext(user, None)
    assert schedules.schedule_view(db, service, "America/Chicago")["timezone"] == "America/Chicago"
    view = schedules.configure_schedule(db, service, auth, "daily", "UTC", 0, clock=OPENING - timedelta(hours=1))
    assert view["next_run_at"] == OPENING.isoformat()
    db.commit()
    return service, auth


@pytest.mark.parametrize("clock,cadence,weekday,opening,closing", [
    ("2026-10-31T19:00", "daily", 0, "2026-11-01T01:00", "2026-11-01T10:00"),
    ("2026-03-08T07:00", "daily", 0, "2026-03-08T02:00", "2026-03-08T09:00"),
    ("2026-11-03T08:00", "weekly", 0, "2026-11-03T02:00", "2026-11-03T10:00"),
    ("2026-11-03T10:00", "weekly", 0, "2026-11-10T02:00", "2026-11-10T10:00"),
])
def test_local_window_uses_opening_weekday_and_dst(clock, cadence, weekday, opening, closing):
    def utc(value):
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    assert schedules._window(utc(clock), cadence, ZoneInfo("America/New_York"), weekday) == (utc(opening), utc(closing))


def test_admission_inventory_version_and_duplicate_recovery(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setattr(jobs, "now", lambda: OPENING)
    with SessionLocal() as db:
        service, auth = setup_schedule(db)
        dispatch(db, OPENING - timedelta(seconds=1))
        assert not db.scalar(select(jobs.ScanJob))
        dispatch(db, OPENING)
        view = schedules.schedule_view(db, service)
        job = db.get(jobs.ScanJob, view["last_job_id"])
        assert view["next_run_at"] == (OPENING + timedelta(days=1)).isoformat()
        assert job.payload["image_list"].splitlines() == ["registry/cache:1", f"registry/ledger:v7@{DIGEST}"]
        assert job.service_key == "ledger" and job.service_version == "release-7"
        assert job.payload["credential_policy"] == "service" and job.payload["owner_user_id"] == auth.user.id
        assert (tmp_path / job.id / "input.tar.gz").is_file()
        # Simulate a committed queue admission followed by a lost schedule checkpoint.
        schedule = db.get(schedules.ServiceScanSchedule, service.id)
        schedule.next_run_at, schedule.last_job_id, schedule.last_run_at = OPENING, None, None
        db.commit()
        dispatch(db, OPENING)
        assert schedules.schedule_view(db, service)["last_job_id"] == job.id
        # A new zone opened an hour earlier and includes the last admission.
        schedules.configure_schedule(db, service, auth, "weekly", "Europe/Paris", 0, clock=OPENING)
        db.commit()
        dispatch(db, OPENING)
        assert db.scalar(select(func.count()).select_from(jobs.ScanJob)) == 1


@pytest.mark.parametrize("condition", ["in-window", "late", "disabled", "revoked", "archived"])
def test_worker_claim_rechecks_window_schedule_and_scope(monkeypatch, tmp_path, condition):
    clock = OPENING
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setattr(jobs, "now", lambda: clock)
    with SessionLocal() as db:
        service, auth = setup_schedule(db)
        dispatch(db, clock)
        job_id = schedules.schedule_view(db, service)["last_job_id"]
        if condition == "late":
            clock += timedelta(hours=8)
        elif condition == "disabled":
            schedules.configure_schedule(db, service, auth, "off", "UTC", 0)
        elif condition == "revoked":
            auth.user.role_assignments[0].role.permissions = ["service.edit"]
        elif condition == "archived":
            service.lifecycle_status = "archived"
        db.commit()
    attempt = jobs.claim("schedule-test-worker")
    with SessionLocal() as db:
        job = db.get(jobs.ScanJob, job_id)
        if condition == "in-window":
            assert attempt["job_id"] == job_id and job.status == "claimed"
        else:
            assert attempt is None and job.status == "cancelled"


def test_queue_full_retries_and_empty_inventory_does_not_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setenv("CATS_SCAN_QUEUE_CAPACITY", "1")
    main.PUBLIC_JOBS["busy"] = {"status": "queued", "owner_user_id": 1}
    with SessionLocal() as db:
        service, _ = setup_schedule(db)
        dispatch(db, OPENING)
        assert schedules.schedule_view(db, service)["last_result"] == "Waiting for scan queue capacity"
        main.PUBLIC_JOBS.update_job("busy", {"status": "complete"})
        dispatch(db, OPENING + timedelta(minutes=5))
        assert schedules.schedule_view(db, service)["last_job_id"]
        job_id = schedules.schedule_view(db, service)["last_job_id"]
        main.PUBLIC_JOBS.update_job(job_id, {"status": "complete"})
        for entry in service.images:
            entry.lifecycle_status = "removed"
        db.commit()
        dispatch(db, OPENING + timedelta(days=1))
        assert schedules.schedule_view(db, service)["last_result"] == "No active registry images to scan"
        assert db.scalar(select(func.count()).select_from(jobs.ScanJob)) == 2


def test_configuration_and_dispatch_require_current_scoped_permissions():
    with SessionLocal() as db:
        service, auth = setup_schedule(db)
        for cadence, zone, day in [("hourly", "UTC", 0), ("daily", "../etc", 0), ("weekly", "UTC", 7)]:
            with pytest.raises(HTTPException) as error:
                schedules.configure_schedule(db, service, auth, cadence, zone, day)
            assert error.value.status_code == 422
        auth.user.role_assignments[0].role.permissions = ["service.edit"]
        db.commit()
        with pytest.raises(HTTPException) as error:
            schedules.configure_schedule(db, service, auth, "weekly", "UTC", 0)
        assert error.value.status_code == 403
        dispatch(db, OPENING)
        assert schedules.schedule_view(db, service)["cadence"] == "off"
        assert not db.scalar(select(jobs.ScanJob))
