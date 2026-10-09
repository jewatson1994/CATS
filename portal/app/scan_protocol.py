"""Authenticated worker protocol and restart-safe authoritative evidence ingestion."""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import shutil
import tempfile
import tarfile
import threading
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import and_, or_, select
from .database import SessionLocal
from . import scan_coordination as jobs
from .scan_artifacts import digest, unpack

router = APIRouter(prefix="/internal/scan-worker", tags=["internal scan worker"])


def verify_image_identity(payload, output):
    """Reject evidence contradicting an immutable submitted image reference."""
    result = output / "portal-result.json"
    if not result.is_file():
        return
    data = json.loads(result.read_text(encoding="utf-8"))
    pinned = {reference: reference.rsplit("@", 1)[1]
              for reference in str(payload.get("image_list") or "").splitlines()
              if "@sha256:" in reference}
    for finding in data.get("findings", []):
        if not isinstance(finding, dict):
            continue
        reference = str(finding.get("image") or "")
        expected = pinned.get(reference)
        if expected:
            actual = str(finding.get("image_digest") or "").rsplit("@", 1)[-1]
            if actual != expected:
                raise ValueError("Evidence image digest differs from immutable input")
        if "@sha256:" in reference and finding.get("image_digest"):
            embedded = reference.rsplit("@", 1)[1]
            actual = str(finding["image_digest"]).rsplit("@", 1)[-1]
            if actual != embedded:
                raise ValueError("Evidence contains conflicting image digest identities")


def _valid_token(value):
    return (isinstance(value, str) and len(value) >= 32 and value.isascii()
            and not any(marker in value.lower() for marker in ("replace", "changeme", "placeholder", "example", "your-token")))


def authenticated(authorization: str = Header(default=""), x_worker_id: str = Header(default="scan-worker")):
    worker = x_worker_id if isinstance(x_worker_id, str) else os.getenv("CATS_SCAN_WORKER_ID", "scan-worker")
    if not worker or len(worker) > 120 or not worker.isascii():
        raise HTTPException(401, "Invalid worker credential")
    configured = os.getenv("CATS_SCAN_WORKER_CREDENTIALS", "").strip()
    if configured:
        try:
            records = json.loads(configured)
            record = records.get(worker)
            if not isinstance(record, dict) or not _valid_token(record.get("current")):
                raise ValueError("Invalid credential record")
            candidates = [record["current"]]
            if record.get("previous"):
                if not _valid_token(record["previous"]):
                    raise ValueError("Invalid rotation credential")
                candidates.append(record["previous"])
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(401, "Invalid worker credential") from None
    else:
        token = os.getenv("CATS_SCAN_WORKER_TOKEN", "").strip()
        if worker != os.getenv("CATS_SCAN_WORKER_ID", "scan-worker") or not _valid_token(token):
            raise HTTPException(401, "Invalid worker credential")
        candidates = [token]
    try:
        supplied = authorization.encode("ascii")
    except (UnicodeEncodeError, AttributeError):
        raise HTTPException(401, "Invalid worker credential") from None
    if not any(secrets.compare_digest(supplied, ("Bearer " + token).encode("ascii")) for token in candidates):
        raise HTTPException(401, "Invalid worker credential")
    return worker


def _identity(value):
    # Direct internal callers do not resolve FastAPI dependencies.
    return value if isinstance(value, str) else None


@router.post("/claim")
def claim(payload: dict, worker_id: str = Depends(authenticated)):
    worker = str(payload.get("worker_id", ""))
    if not worker or len(worker) > 120:
        raise HTTPException(422, "Invalid worker identity")
    if _identity(worker_id) and worker != worker_id:
        raise HTTPException(403, "Worker identity differs from credential")
    return jobs.claim(worker)


@router.post("/{job_id}/{attempt_id}/heartbeat")
def heartbeat(job_id: str, attempt_id: str, payload: dict, x_attempt_token: str = Header(default=""), worker_id: str = Depends(authenticated)):
    return jobs.heartbeat(job_id, attempt_id, x_attempt_token, payload.get("phase", "prepare"), payload.get("log_tail", ""), worker_id=_identity(worker_id))


@router.post("/{job_id}/{attempt_id}/failure")
def failure(job_id: str, attempt_id: str, payload: dict, x_attempt_token: str = Header(default=""), worker_id: str = Depends(authenticated)):
    return jobs.report_failure(job_id, attempt_id, x_attempt_token, payload.get("category"),
                               payload.get("reason", ""), payload.get("log_tail", ""), worker_id=_identity(worker_id))


@router.get("/{job_id}/{attempt_id}/input")
def input_archive(job_id: str, attempt_id: str, x_attempt_token: str = Header(default=""), worker_id: str = Depends(authenticated)):
    from .main import PUBLIC_JOB_ROOT
    with SessionLocal() as db:
        jobs.fenced(db, job_id, attempt_id, x_attempt_token, worker_id=_identity(worker_id))
    return FileResponse(PUBLIC_JOB_ROOT / job_id / "input.tar.gz", media_type="application/x-tar")


@router.put("/{job_id}/{attempt_id}/results")
async def results(job_id: str, attempt_id: str, request: Request, x_attempt_token: str = Header(default=""), worker_id: str = Depends(authenticated)):
    from .main import PUBLIC_JOB_ROOT
    # Authenticate the attempt before accepting any bytes; fence again at commit.
    with SessionLocal() as db:
        job, attempt = jobs.fenced(db, job_id, attempt_id, x_attempt_token, completed=True, worker_id=_identity(worker_id))
        identity = {"job_id": job_id, "attempt_id": attempt_id, "input_digest": job.input_digest,
                    "service_key": job.service_key, "service_version": job.service_version}
        previous = attempt.manifest_digest
    maximum = jobs.setting("CATS_SCAN_DISK_BYTES", 8 * 1024**3)
    base = PUBLIC_JOB_ROOT / job_id
    with tempfile.TemporaryDirectory(prefix="transfer-", dir=base) as temporary:
        archive = Path(temporary) / "results.tar.gz"
        total = 0
        with archive.open("wb") as output:
            async for chunk in request.stream():
                total += len(chunk)
                if total > maximum:
                    raise HTTPException(413, "Result transfer exceeds disk budget")
                await asyncio.to_thread(output.write, chunk)
        checksum = await asyncio.to_thread(digest, archive)
        if previous:
            if not secrets.compare_digest(previous, checksum):
                raise HTTPException(409, "Completed attempt cannot be replaced")
            return {"accepted": True, "duplicate": True}
        extracted = Path(temporary) / "evidence"
        try:
            manifest = await asyncio.to_thread(unpack, archive, extracted, identity)
            if not isinstance(manifest.get("returncode"), int):
                raise ValueError("Scanner exit status is required")
            if not (extracted / "output" / "scan-summary.json").is_file():
                raise ValueError("Scan summary is required")
            # Workers cannot replace immutable Portal input or submission metadata.
            if any(not name.startswith(("output/", "sources/")) for name in manifest["files"]):
                raise ValueError("Result contains an unauthorized artifact path")
        except (ValueError, OSError, tarfile.TarError, json.JSONDecodeError) as exc:
            raise HTTPException(422, "Invalid result envelope") from exc
        with SessionLocal() as db:
            job, attempt = jobs.fenced(db, job_id, attempt_id, x_attempt_token, completed=True, worker_id=_identity(worker_id))
            if attempt.manifest_digest:
                if attempt.manifest_digest != checksum:
                    raise HTTPException(409, "Completed attempt cannot be replaced")
                return {"accepted": True, "duplicate": True}
            destination = base / "attempts" / attempt_id
            destination.parent.mkdir(exist_ok=True)
            if destination.exists():
                shutil.rmtree(destination)  # only this authorized attempt's unpublished transfer
            for retry in range(5):
                try:
                    os.replace(extracted, destination)
                    break
                except PermissionError:
                    if os.name != "nt" or retry == 4:
                        raise
                    # Windows can briefly hold just-closed archive handles.
                    await asyncio.sleep(0.1 * (retry + 1))
            (destination / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            attempt.manifest_digest, attempt.state = checksum, "received"
            job.status, job.lease_until = "evidence_ready", None
            job.payload = {**job.payload, "status": "running", "phase": "ingest", "returncode": manifest["returncode"]}
            db.commit()
    return {"accepted": True}


def ingest_one():
    """Hold a session lock on a pinned connection across ingest commits."""
    from sqlalchemy import text
    with SessionLocal() as lock_db:
        connection = lock_db.connection()
        postgres = connection.dialect.name == "postgresql"
        if postgres and not connection.scalar(text("SELECT pg_try_advisory_lock(73488291)")):
            return
        try:
            return _ingest_one()
        finally:
            if postgres:
                connection.execute(text("SELECT pg_advisory_unlock(73488291)"))


def _ingest_one():
    """One ingest at a time across Portal replicas using a PostgreSQL advisory lock."""
    from . import main
    from .models import ServiceImage
    from sqlalchemy import text
    with SessionLocal() as db:
        jobs.recover(db)
        row = db.scalar(select(jobs.ScanJob).where(jobs.ScanJob.status == "evidence_ready")
                        .order_by(jobs.ScanJob.created_at).with_for_update(skip_locked=True).limit(1))
        if row is None:
            # Lease exhaustion and cancellation may finish without returned evidence.
            # Propagate those terminal outcomes to their definition workflow too.
            pending = list(db.scalars(select(jobs.ScanJob).where(
                jobs.ScanJob.status.in_(jobs.TERMINAL),
                jobs.ScanJob.definition_pending.is_(True),
            ).order_by(jobs.ScanJob.created_at).with_for_update(skip_locked=True).limit(20)))
            from .definition_routes import complete_scan
            for finished in pending:
                complete_scan(finished.id, dict(finished.payload))
                finished.payload = {**finished.payload, "definition_notified": True}
                finished.definition_pending = False
            db.commit()
            return
        job_id, payload = row.id, dict(row.payload)
        attempt_root = main.PUBLIC_JOB_ROOT / job_id / "attempts" / row.attempt_id
        output = main.PUBLIC_JOB_ROOT / job_id / "output"
        fatal = False
        try:
            # Publication is a same-filesystem atomic rename. A crash after the
            # rename reuses the complete immutable directory on the next replay.
            staged_output = attempt_root / "output"
            if staged_output.exists():
                if output.exists():
                    raise ValueError("Conflicting evidence publication")
                os.replace(staged_output, output)
            if not output.is_dir():
                raise ValueError("Verified evidence is unavailable")
            sources = main.PUBLIC_JOB_ROOT / job_id / "input" / "worker-charts"
            staged_sources = attempt_root / "sources"
            if staged_sources.exists():
                sources.parent.mkdir(parents=True, exist_ok=True)
                if sources.exists():
                    raise ValueError("Conflicting worker source publication")
                os.replace(staged_sources, sources)
            if sources.exists():
                payload["worker_sources"] = True
                row.payload = payload
                db.commit()
                # Publication commits release the job lock. Cancellation may
                # win before the next transaction; reacquire before continuing.
                db.refresh(row, with_for_update=True)
                if row.status == "cancelled":
                    return
            fatal = (output / "scan-failure.json").exists()
            summary = json.loads((output / "scan-summary.json").read_text(encoding="utf-8"))
            if (output / "definition-acquisition-failure.json").exists():
                from .definition_routes import _status
                failure = json.loads((output / "definition-acquisition-failure.json").read_text(encoding="utf-8"))
                context = payload["definition_context"]
                _status(context["artifact_id"], context["run_id"], context["index"], "acquisition_failed",
                        failure["reason"], acquisition_diagnostic=failure.get("diagnostic"))
                raise ValueError("Declared chart acquisition failed; evidence was retained")
            if fatal:
                failure = json.loads((output / "scan-failure.json").read_text(encoding="utf-8"))
                phase = jobs.sanitize_diagnostic(failure.get("phase", "unknown"), 64)
                raise ValueError(f"Required scanner phase {phase} failed (exit {failure.get('exit_code', 'unknown')}); evidence retained")
            verify_image_identity(payload, output)
            if payload.get("definition_component"):
                from .definition_routes import finalize_definition_result
                from .definition_acquisition import _collect_helm_source_files
                files = _collect_helm_source_files(sources)
                resolution = json.loads((output / "definition-component.json").read_text(encoding="utf-8"))
                finalize_definition_result(job_id, payload, files, resolution)
                row.payload = payload
                db.commit()
                db.refresh(row, with_for_update=True)
                if row.status == "cancelled":
                    return
            if row.service_key and payload.get("job_kind") == "scan":
                from types import SimpleNamespace
                from .models import Service
                service = db.scalar(select(Service).where(Service.service_key == row.service_key))
                if service is None:
                    raise ValueError("Scan service is no longer available")
                class InternalAuth:
                    user = SimpleNamespace(id=payload.get("owner_user_id"))
                    def accessible_service_ids(self, permission):
                        return {service.id} if permission == "scan.ingest" else set()
                    def has(self, permission, service_id):
                        return permission == "scan.ingest" and service_id == service.id
                # Existing execution ID public:<job> makes crash/replay ingestion idempotent.
                main.ingest_public_scan(job_id=job_id, service_id=row.service_key, request=None, db=db, auth=InternalAuth())
                # The existing ingest path commits its own transaction. Preserve
                # a cancellation recorded after that commit rather than replacing it.
                db.refresh(row, with_for_update=True)
                if row.status == "cancelled":
                    return
            status = "complete" if (payload.get("returncode") == 0
                                    and summary.get("status", "complete") == "complete"
                                    and not summary.get("skipped_images")
                                    and not summary.get("skipped_charts")) else "incomplete"
            row.payload = {**payload, "status": status, "phase": "done", "summary": summary,
                           "finished_at": jobs.now().isoformat(), "ingested": bool(row.service_key and payload.get("job_kind") == "scan")}
            row.status = status
            row.finished_at = jobs.now()
            for image in db.scalars(select(ServiceImage).where(ServiceImage.scan_job_id == job_id)):
                image.scan_status = "scanned" if status == "complete" else "failed"
                image.last_scanned_at = jobs.now()
            db.commit()
        except Exception as exc:
            db.rollback()
            logging.getLogger(__name__).exception("Scan evidence ingestion failed for %s", job_id)
            jobs.DurableJobs().update_job(job_id, {"status": "error", "phase": "ingest",
                                                  "error": jobs.sanitize_diagnostic(str(exc)) if isinstance(exc, ValueError) else "Evidence ingestion failed; retained results require review",
                                                  "failure_category": "scanner_execution" if fatal else "evidence_ingestion",
                                                  "finished_at": jobs.now().isoformat()})
        (main.PUBLIC_JOB_ROOT / job_id / "input.tar.gz").unlink(missing_ok=True)
        final = jobs.DurableJobs().get(job_id, {})
        if final.get("definition_context"):
            from .definition_routes import complete_scan
            complete_scan(job_id, final)
            jobs.DurableJobs().update_job(job_id, {"definition_notified": True})


async def maintenance():
    while True:
        try:
            await asyncio.to_thread(ingest_one)
            await asyncio.to_thread(retention_once)
        except Exception:
            logging.getLogger(__name__).exception("Scan coordinator maintenance failed")
        await asyncio.sleep(2)


_cleanup_lock = threading.Lock()
_cleanup_root = None
_cleanup_job_cursor = None
_cleanup_entries = None


def _orphan_batch(root, limit):
    """Advance a bounded directory scan; close its handle on exhaustion."""
    global _cleanup_entries
    if not root.exists():
        if _cleanup_entries is not None:
            _cleanup_entries.close()
            _cleanup_entries = None
        return []
    if _cleanup_entries is None:
        _cleanup_entries = os.scandir(root)
    batch = []
    for _ in range(limit):
        try:
            batch.append(next(_cleanup_entries))
        except StopIteration:
            _cleanup_entries.close()
            _cleanup_entries = None
            break
    return batch


def retention_once():
    with _cleanup_lock:
        _retention_once()


def _retention_once():
    """Bound each pass and touch only expired job-owned workspace directories."""
    from .main import PUBLIC_JOB_ROOT
    import re
    import time
    global _cleanup_root, _cleanup_job_cursor, _cleanup_entries
    root = PUBLIC_JOB_ROOT.resolve()
    if _cleanup_root != root:
        if _cleanup_entries is not None:
            _cleanup_entries.close()
        _cleanup_root, _cleanup_job_cursor, _cleanup_entries = root, None, None
    cutoff = jobs.now() - timedelta(days=jobs.setting("CATS_SCAN_RETENTION_DAYS", 30))
    limit = jobs.setting("CATS_SCAN_CLEANUP_BATCH_SIZE", 20)
    from .models import Execution, ServiceImage
    with SessionLocal() as db:
        query = (select(jobs.ScanJob).where(
            jobs.ScanJob.status.in_(jobs.TERMINAL), jobs.ScanJob.finished_at < cutoff,
            jobs.ScanJob.definition_pending.is_(False), jobs.ScanJob.service_key == "",
            ~select(Execution.id).where(Execution.execution_key == "public:" + jobs.ScanJob.id).exists(),
            ~select(ServiceImage.id).where(ServiceImage.scan_job_id == jobs.ScanJob.id).exists())
            .order_by(jobs.ScanJob.finished_at, jobs.ScanJob.id)
            .with_for_update(skip_locked=True).limit(limit))
        if _cleanup_job_cursor is not None:
            finished_at, job_id = _cleanup_job_cursor
            query = query.where(or_(jobs.ScanJob.finished_at > finished_at,
                                   and_(jobs.ScanJob.finished_at == finished_at, jobs.ScanJob.id > job_id)))
        expired = list(db.scalars(query))
        # Advance over protected payloads too; wrapping never loads full history.
        _cleanup_job_cursor = (expired[-1].finished_at, expired[-1].id) if expired else None
        for job in expired:
            if job.payload.get("definition_context") or job.payload.get("ingested"):
                continue
            if not re.fullmatch(r"[0-9a-f]{32}", job.id):
                continue
            target = root / job.id
            if target.is_symlink() or target.resolve().parent != root:
                continue
            if target.exists():
                shutil.rmtree(target)
            db.execute(jobs.delete(jobs.ScanAttempt).where(jobs.ScanAttempt.job_id == job.id))
            db.delete(job)
        db.commit()
        # Staging is reserved in the DB first; only old unknown directories qualify.
        if root.exists():
            for entry in _orphan_batch(root, limit * 5):
                if not re.fullmatch(r"[0-9a-f]{32}", entry.name) or entry.is_symlink():
                    continue
                if not entry.is_dir(follow_symlinks=False) or entry.stat(follow_symlinks=False).st_mtime > time.time() - 86400:
                    continue
                if db.get(jobs.ScanJob, entry.name) is None:
                    target = Path(entry.path)
                    # Unknown output may be retained evidence from a historical
                    # deployment; absence of a scheduling row does not authorize deletion.
                    if (target / "output").exists():
                        continue
                    if db.scalar(select(Execution.id).where(Execution.execution_key == "public:" + entry.name).limit(1)) is not None:
                        continue
                    if db.scalar(select(ServiceImage.id).where(ServiceImage.scan_job_id == entry.name).limit(1)) is not None:
                        continue
                    if target.resolve().parent == root:
                        shutil.rmtree(target)
