"""Atomically assemble large, authenticated runtime inventory snapshots."""
import hashlib
import json
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from sqlalchemy import DateTime, ForeignKey, JSON, String, delete, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .database import Base, get_db
from .runtime_models import now
from .release_validity import utc
from . import runtime_routes as runtime

router = APIRouter(prefix="/api/runtime", tags=["Runtime"])
_REPORT_FIELDS = {"sequence", "observed_at", "complete", "errors", "workloads", "discovery_version"}
_MAX_ROWS = 20000
_MAX_BYTES = 16 * 1024 * 1024
_MAX_PAGES = 64


class RuntimeReportPage(Base):
    __tablename__ = "runtime_report_pages"
    agent_id: Mapped[str] = mapped_column(ForeignKey("runtime_agents.id", ondelete="CASCADE"), primary_key=True)
    sequence: Mapped[int] = mapped_column(primary_key=True)
    page: Mapped[int] = mapped_column(primary_key=True)
    page_count: Mapped[int]
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    metadata_hash: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    rows: Mapped[int]
    byte_count: Mapped[int]
    observations: Mapped[list] = mapped_column(JSON)


def clear_pages(db, agent_id, through_sequence=None):
    query = delete(RuntimeReportPage).where(RuntimeReportPage.agent_id == agent_id)
    if through_sequence is not None:
        query = query.where(RuntimeReportPage.sequence <= through_sequence)
    db.execute(query)


def ensure_pending_matches(db, agent_id, sequence, snapshot_hash, observed):
    """Fence competing delivery paths while the caller holds the agent lock."""
    pending = db.execute(select(RuntimeReportPage.sequence, RuntimeReportPage.snapshot_hash, RuntimeReportPage.observed_at)
                         .where(RuntimeReportPage.agent_id == agent_id).limit(1)).first()
    if pending and (sequence < pending.sequence or
                    observed < utc(pending.observed_at) or
                    (sequence == pending.sequence and snapshot_hash != pending.snapshot_hash)):
        raise HTTPException(409, "Report conflicts with a pending runtime snapshot")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


@router.post("/reports/pages", openapi_extra=runtime.report_body_schema(512, _MAX_PAGES))
async def receive_page(request: Request, db: Session = Depends(get_db)):
    """Keep a single pending snapshot per agent. Publish only a complete set of verified pages."""
    row, token_hash = runtime.authenticate(request, db)
    identity = row.id
    db.rollback()
    data = await runtime.body(request, _REPORT_FIELDS | {"page", "pages", "snapshot_sha256"}, limit=runtime.MAX_BODY)
    try:
        return await run_in_threadpool(_persist_page, db, identity, token_hash, data)
    finally:
        db.rollback()  # Release the page lock on duplicates and discard rejected partial writes.


def _persist_page(db, identity, token_hash, data):
    index, count, snapshot_hash = data.get("page"), data.get("pages"), data.get("snapshot_sha256")
    if (type(index) is not int or type(count) is not int or not 0 <= index < count <= _MAX_PAGES
            or not isinstance(snapshot_hash, str) or not re.fullmatch("[a-f0-9]{64}", snapshot_hash)):
        raise HTTPException(422, "Invalid runtime snapshot page")
    report = {k: v for k, v in data.items() if k in _REPORT_FIELDS}
    timestamp = now()
    observed, _, _ = runtime.validate_report(report, timestamp)
    sequence = report["sequence"]
    observations = report["workloads"]
    empty_snapshot = count == 1 and report.get("discovery_version") == 1 and report["complete"]
    if len(observations) > 512 or (not observations and not empty_snapshot):
        raise HTTPException(422, "Each runtime page requires 1 to 512 observations or a complete empty discovery snapshot")
    meta = {k: v for k, v in report.items() if k != "workloads"}
    meta_hash = digest(meta)

    # A conditional write serializes page admission, finalization and revocation
    # in PostgreSQL and SQLite. Authentication is checked again after the upload.
    row = runtime.lock_reporting_agent(db, identity, token_hash)
    if sequence == row.last_sequence and row.report_hash == snapshot_hash:
        return runtime.reply({"accepted": True, "duplicate": True, "sequence": sequence})
    if sequence <= row.last_sequence or (row.observed_at and observed < utc(row.observed_at)):
        raise HTTPException(409, "Snapshot conflicts with accepted inventory")

    header = db.execute(select(RuntimeReportPage.sequence, RuntimeReportPage.snapshot_hash,
        RuntimeReportPage.page_count, RuntimeReportPage.metadata_hash, RuntimeReportPage.observed_at)
        .where(RuntimeReportPage.agent_id == identity).limit(1)).first()
    if header is not None:
        if sequence < header.sequence or observed < utc(header.observed_at):
            raise HTTPException(409, "A newer runtime snapshot is already arriving")
        if sequence > header.sequence:
            clear_pages(db, identity)
        elif (header.snapshot_hash != snapshot_hash or header.page_count != count or header.metadata_hash != meta_hash):
            raise HTTPException(409, "Page belongs to a different snapshot")

    existing = db.get(RuntimeReportPage, (identity, sequence, index))
    if existing is None:
        page_bytes = len(json.dumps(observations, separators=(",", ":"), ensure_ascii=False).encode())
        db.add(RuntimeReportPage(agent_id=identity, sequence=sequence, page=index, page_count=count,
            snapshot_hash=snapshot_hash, metadata_hash=meta_hash, observed_at=observed, rows=len(observations),
            byte_count=page_bytes, observations=observations))
        db.flush()
    elif existing.observations != observations:
        raise HTTPException(409, "Page already contains different observations")
    selected = RuntimeReportPage.agent_id == identity
    pages, rows, total_bytes = db.execute(select(func.count(), func.sum(RuntimeReportPage.rows),
        func.sum(RuntimeReportPage.byte_count)).where(selected)).one()
    if rows > _MAX_ROWS or total_bytes - (pages - 1) > _MAX_BYTES:
        raise HTTPException(413, "Runtime snapshot exceeds the inventory limit")
    if pages < count:
        db.commit()
        return runtime.reply({"received": True, "page": index, "sequence": sequence})

    inventory = db.scalars(select(RuntimeReportPage.observations).where(selected).order_by(RuntimeReportPage.page))
    report["workloads"] = [item for page in inventory for item in page]
    if len(json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode()) > _MAX_BYTES:
        raise HTTPException(413, "Runtime snapshot exceeds the inventory limit")
    if digest(report) != snapshot_hash:
        raise HTTPException(409, "Assembled runtime snapshot failed its digest check")
    return runtime.accept_report(db, row, token_hash, report, timestamp, max_workloads=_MAX_ROWS)
