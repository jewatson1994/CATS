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
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
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


def authenticated(authorization: str = Header(default="")):
    configured = os.getenv("CATS_SCAN_WORKER_TOKEN", "").strip()
    if not configured or len(configured) < 32 or not secrets.compare_digest(authorization, "Bearer " + configured):
        raise HTTPException(401, "Invalid worker credential")


@router.post("/claim", dependencies=[Depends(authenticated)])
def claim(payload: dict):
    worker = str(payload.get("worker_id", ""))
    if not worker or len(worker) > 120:
        raise HTTPException(422, "Invalid worker identity")
    return jobs.claim(worker)


@router.post("/{job_id}/{attempt_id}/heartbeat", dependencies=[Depends(authenticated)])
def heartbeat(job_id: str, attempt_id: str, payload: dict, x_attempt_token: str = Header(default="")):
    return jobs.heartbeat(job_id, attempt_id, x_attempt_token, payload.get("phase", "prepare"), payload.get("log_tail", ""))


@router.get("/{job_id}/{attempt_id}/input", dependencies=[Depends(authenticated)])
def input_archive(job_id: str, attempt_id: str, x_attempt_token: str = Header(default="")):
    from .main import PUBLIC_JOB_ROOT
    with SessionLocal() as db:
        jobs.fenced(db, job_id, attempt_id, x_attempt_token)
    return FileResponse(PUBLIC_JOB_ROOT / job_id / "input.tar.gz", media_type="application/gzip")


@router.put("/{job_id}/{attempt_id}/results", dependencies=[Depends(authenticated)])
async def results(job_id: str, attempt_id: str, request: Request, x_attempt_token: str = Header(default="")):
    from .main import PUBLIC_JOB_ROOT
    # Authenticate the attempt before accepting any bytes; fence again at commit.
    with SessionLocal() as db:
        job, attempt = jobs.fenced(db, job_id, attempt_id, x_attempt_token, completed=True)
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
                output.write(chunk)
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
            job, attempt = jobs.fenced(db, job_id, attempt_id, x_attempt_token, completed=True)
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
                jobs.ScanJob.payload["definition_context"].as_string().is_not(None),
                jobs.ScanJob.payload["definition_notified"].as_boolean().is_(None),
            ).order_by(jobs.ScanJob.created_at).with_for_update(skip_locked=True).limit(20)))
            from .definition_routes import complete_scan
            for finished in pending:
                complete_scan(finished.id, dict(finished.payload))
                finished.payload = {**finished.payload, "definition_notified": True}
            db.commit()
            return
        job_id, payload = row.id, dict(row.payload)
        attempt_root = main.PUBLIC_JOB_ROOT / job_id / "attempts" / row.attempt_id
        output = main.PUBLIC_JOB_ROOT / job_id / "output"
        try:
            # Re-copy immutable verified evidence on replay, including a crash
            # partway through publication; an existing directory is not proof
            # that every artifact was published.
            shutil.copytree(attempt_root / "output", output, dirs_exist_ok=True)
            sources = attempt_root / "sources"
            if sources.exists():
                target = main.PUBLIC_JOB_ROOT / job_id / "input" / "charts"
                shutil.copytree(sources, target, dirs_exist_ok=True)
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
                raise ValueError("A required scanner phase failed; evidence was retained")
            verify_image_identity(payload, output)
            if payload.get("definition_component"):
                from .definition_routes import finalize_definition_result
                from .definition_acquisition import _collect_helm_source_files
                files = _collect_helm_source_files(sources)
                resolution = json.loads((output / "definition-component.json").read_text(encoding="utf-8"))
                finalize_definition_result(job_id, payload, files, resolution)
                row.payload = payload
                db.commit()
            if row.service_key and payload.get("job_kind") == "scan":
                class InternalAuth:
                    def accessible_service_ids(self, *_args): return None
                    def has(self, *_args): return True
                # Existing execution ID public:<job> makes crash/replay ingestion idempotent.
                main.ingest_public_scan(job_id, row.service_key, db, InternalAuth())
                # The existing ingest path commits its own transaction. Preserve
                # a cancellation recorded after that commit rather than replacing it.
                db.refresh(row)
                if row.status == "cancelled":
                    return
            status = "complete" if (payload.get("returncode") == 0
                                    and summary.get("status", "complete") == "complete"
                                    and not summary.get("skipped_images")
                                    and not summary.get("skipped_charts")) else "incomplete"
            row.payload = {**payload, "status": status, "phase": "done", "summary": summary,
                           "finished_at": jobs.now().isoformat(), "ingested": bool(row.service_key and payload.get("job_kind") == "scan")}
            row.status = status
            for image in db.scalars(select(ServiceImage).where(ServiceImage.scan_job_id == job_id)):
                image.scan_status = "scanned" if status == "complete" else "failed"
                image.last_scanned_at = jobs.now()
            db.commit()
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("Scan evidence ingestion failed for %s", job_id)
            jobs.DurableJobs().update_job(job_id, {"status": "error", "phase": "ingest",
                                                  "error": "Evidence ingestion failed; retained results require review",
                                                  "finished_at": jobs.now().isoformat()})
        final = jobs.DurableJobs().get(job_id, {})
        if final.get("definition_context"):
            from .definition_routes import complete_scan
            complete_scan(job_id, final)
            jobs.DurableJobs().update_job(job_id, {"definition_notified": True})


async def maintenance():
    while True:
        try:
            await asyncio.to_thread(ingest_one)
        except Exception:
            logging.getLogger(__name__).exception("Scan coordinator maintenance failed")
        await asyncio.sleep(2)
