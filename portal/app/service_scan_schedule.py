"""Opt-in, local-calendar scheduling for a service's active registry images."""
import logging
import os
import uuid
from datetime import datetime, time, timedelta, timezone as tz
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import HTTPException
from sqlalchemy import DateTime, ForeignKey, Integer, String, select
from sqlalchemy.orm import Mapped, mapped_column

from .auth import AuthContext
from .database import Base, SessionLocal
from .durable_jobs import aware, now
from .models import Service, ServiceImage, User
from .scan_coordination import ScanJob, TERMINAL


class ServiceScanSchedule(Base):
    __tablename__ = "service_scan_schedules"
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    cadence: Mapped[str] = mapped_column(String(12))
    timezone: Mapped[str] = mapped_column(String(100))
    weekday: Mapped[int] = mapped_column(Integer)
    revision: Mapped[str] = mapped_column(String(32))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_job_id: Mapped[str | None] = mapped_column(String(32))
    last_result: Mapped[str | None] = mapped_column(String(250))


def _window(clock, cadence, zone, weekday):
    """The current or next eligible night. A weekly night belongs to its opening date."""
    local = clock.astimezone(zone)
    day = local.date() - timedelta(days=local.hour < 5)
    if cadence == "weekly":
        day += timedelta(days=(weekday - day.weekday()) % 7)
    # Combine local calendar dates independently to handle DST overnight.
    opening = datetime.combine(day, time(21), zone).astimezone(tz.utc)
    closing = datetime.combine(day + timedelta(days=1), time(5), zone).astimezone(tz.utc)
    return opening, closing


def schedule_view(db, service, default_timezone="UTC"):
    item = db.get(ServiceScanSchedule, service.id)
    if item is None:
        return {"cadence": "off", "timezone": default_timezone, "weekday": 0, "next_run_at": None,
                "last_run_at": None, "last_job_id": None, "last_result": None}
    result = item.last_result
    if result == "Queued" and item.last_job_id:
        job = db.get(ScanJob, item.last_job_id)
        if job:
            result = job.status.replace("_", " ").capitalize()
            if job.status in {"error", "cancelled"} and job.payload.get("error"):
                from .scan_access import _public_text
                result += " · " + _public_text(job.payload["error"])[:180]
    return {"cadence": item.cadence, "timezone": item.timezone, "weekday": item.weekday,
            "next_run_at": aware(item.next_run_at).isoformat() if item.next_run_at else None,
            "last_run_at": aware(item.last_run_at).isoformat() if item.last_run_at else None,
            "last_job_id": item.last_job_id, "last_result": result}


def _permitted(auth, service):
    return (auth and service and service.lifecycle_status == "active"
            and all(auth.has(permission, service.id) for permission in ("service.edit", "scan.ingest")))


def configure_schedule(db, service, auth, cadence, timezone, weekday, *, clock=None):
    if not auth.has("service.edit", service.id) or (cadence != "off" and not auth.has("scan.ingest", service.id)):
        raise HTTPException(403, "Scoped service editing and scan ingestion permissions are required")
    if cadence not in ("off", "daily", "weekly") or type(weekday) is not int or not 0 <= weekday <= 6:
        raise HTTPException(422, "Choose off, daily or weekly and a valid weekday")
    if not isinstance(timezone, str) or not 1 <= len(timezone) <= 100:
        raise HTTPException(422, "Choose an IANA time zone")
    try:
        zone = ZoneInfo(timezone)
    except (ValueError, ZoneInfoNotFoundError):
        raise HTTPException(422, "Choose an IANA time zone") from None
    if cadence != "off" and service.lifecycle_status != "active":
        raise HTTPException(409, "Only active services can schedule scans")
    # Serialize first creation with concurrent editors, then with due dispatch.
    db.scalar(select(Service.id).where(Service.id == service.id).with_for_update())
    item = db.get(ServiceScanSchedule, service.id, with_for_update=True, populate_existing=True)
    if item is None:
        if cadence == "off":
            return schedule_view(db, service)
        item = ServiceScanSchedule(service_id=service.id)
        db.add(item)
    if (item.cadence, item.timezone, item.weekday, item.actor_id) != (cadence, timezone, weekday, auth.user.id):
        item.cadence, item.timezone, item.weekday, item.actor_id = cadence, timezone, weekday, auth.user.id
        item.revision = uuid.uuid4().hex
        clock = clock or now()
        item.next_run_at = max(clock, _window(clock, cadence, zone, weekday)[0]) if cadence != "off" else None
        db.flush()
    return schedule_view(db, service)


def _actor(db, item):
    user = db.get(User, item.actor_id) if item.actor_id is not None else None
    return AuthContext(user=user, session=None) if user and user.enabled else None


def claim_error(db, job, clock):
    """Fence late starts, retries, disabled schedules and revoked service grants."""
    context = job.payload["schedule_context"]
    item = db.get(ServiceScanSchedule, job.payload["ingest_service_db_id"])
    if not item or item.cadence == "off" or item.revision != context["revision"]:
        return "Schedule changed before the scan started"
    service = db.get(Service, item.service_id)
    if not _permitted(_actor(db, item), service) or service.service_key != job.service_key:
        return "Schedule owner no longer has access to this active service"
    if not datetime.fromisoformat(context["opening"]) <= clock < datetime.fromisoformat(context["closing"]):
        return "Scheduled scan window closed before a worker was available"
    return None


def _inventory(db, service):
    from . import main
    limit = int(os.getenv("CATS_PUBLIC_MAX_IMAGES", "50"))
    rows = db.execute(select(ServiceImage.image_reference, ServiceImage.image_digest).where(
        ServiceImage.service_id == service.id, ServiceImage.lifecycle_status == "active"
    ).distinct().order_by(ServiceImage.image_reference, ServiceImage.image_digest).limit(limit + 1)).all()
    if not rows:
        raise HTTPException(409, "No active registry images to scan")
    if len(rows) > limit:
        raise HTTPException(413, f"Active inventory exceeds the configured {limit}-image scan limit")
    references = set()
    for reference, digest in rows:
        name, digest = main._image_identity(main._validate_image_reference(reference), digest)
        digest = main._validate_image_digest(digest)
        references.add(f"{name}@{digest}" if digest else name)
    return "\n".join(sorted(references))


def _dispatch(db, item, clock):
    from . import main
    service = db.get(Service, item.service_id)
    if not _permitted(_actor(db, item), service):
        item.cadence, item.next_run_at = "off", None
        item.last_result = "Disabled because the service is inactive or the schedule owner lost access"
        return
    zone = ZoneInfo(item.timezone)
    opening, closing = _window(clock, item.cadence, zone, item.weekday)
    if clock < opening:
        item.next_run_at = opening
        item.last_result = "Missed scan window"
        return
    if item.last_job_id and opening <= aware(item.last_run_at) < closing:
        # Editing the time zone can shift the opening of an overlapping night.
        item.next_run_at = _window(closing, item.cadence, zone, item.weekday)[0]
        return
    # A stable identity recovers an enqueue committed before the schedule checkpoint.
    job_id = uuid.uuid5(uuid.NAMESPACE_URL, f"cats:service-scan:{service.id}:{opening.isoformat()}").hex
    existing = db.get(ScanJob, job_id)
    if existing is None:
        active = db.scalar(select(ScanJob.id).where(ScanJob.service_key == service.service_key,
            ScanJob.status.not_in(TERMINAL)).limit(1))
        if active:
            item.next_run_at = min(clock + timedelta(minutes=5), closing)
            item.last_result = "Waiting for an active service scan to finish"
            return
        try:
            images = _inventory(db, service)
            config = main.configuration_for_service(db, service)
            certificates = main.parse_json(config.get("trusted_ca_certificates"), [])
            main._start_public_scan(images, ingest_service_id=service.service_key, owner_user_id=item.actor_id,
                trusted_ca_certificates=certificates if isinstance(certificates, list) else [],
                schedule_context={"job_id": job_id, "revision": item.revision,
                                  "opening": opening.isoformat(), "closing": closing.isoformat()})
        except HTTPException as exc:
            if exc.status_code == 429:
                item.next_run_at = min(clock + timedelta(minutes=5), closing)
                item.last_result = "Waiting for scan queue capacity"
                return
            item.last_result = str(exc.detail)[:250]
            item.next_run_at = _window(closing, item.cadence, zone, item.weekday)[0]
            return
    item.last_run_at, item.last_job_id, item.last_result = clock, job_id, "Queued"
    item.next_run_at = _window(closing, item.cadence, zone, item.weekday)[0]


def dispatch_due(*, clock=None):
    """Process bounded due rows, checkpointing each occurrence independently."""
    for _ in range(20):
        instant = clock or now()
        with SessionLocal() as db:
            item = db.scalar(select(ServiceScanSchedule).where(ServiceScanSchedule.next_run_at <= instant)
                .order_by(ServiceScanSchedule.next_run_at, ServiceScanSchedule.service_id)
                .with_for_update(skip_locked=True).limit(1))
            if item is None:
                break
            service_id, revision = item.service_id, item.revision
            try:
                _dispatch(db, item, instant)
                db.commit()
            except Exception:
                db.rollback()
                logging.getLogger(__name__).exception("Scheduled scan dispatch failed for service %s", service_id)
                item = db.get(ServiceScanSchedule, service_id, with_for_update=True)
                if item and item.revision == revision and item.next_run_at and aware(item.next_run_at) <= instant:
                    item.last_result = "Scan submission failed. Retrying in five minutes"
                    item.next_run_at = instant + timedelta(minutes=5)
                db.commit()
