"""Dedicated bounded export process: python -m app.export_worker."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import timedelta
from email.message import Message
import errno
from hashlib import sha256
import os
from pathlib import Path
import re
import shutil
import tempfile
import time

from fastapi import HTTPException
from sqlalchemy import select

from .account_models import AccountRetirement
from .auth import AuthContext
from .database import SessionLocal
from .delivery_execution import delivery_lock
from .durable_jobs import DurableJob, JobError, aware, now, run_worker
from .export_jobs import BUILDERS, ScopedExportAuth, assert_access, output_root, snapshots
from .models import User


def limits():
    return (max(1, int(os.getenv("CATS_EXPORT_MAX_BYTES", str(256 * 1024 * 1024)))),
            max(1, int(os.getenv("CATS_EXPORT_DISK_BYTES", str(4 * 1024**3)))),
            max(1, int(os.getenv("CATS_EXPORT_RETENTION_HOURS", "24"))))


def _auth(db, job, payload):
    user = db.get(User, job.requested_by_id)
    if not user or not user.enabled or db.get(AccountRetirement, user.id):
        raise JobError("The requesting account is no longer authorized")
    auth = AuthContext(user, None)
    try:
        assert_access(db, auth, payload)
    except HTTPException:
        raise JobError("Export access was revoked; request a new export with your current permissions") from None
    return ScopedExportAuth(auth, payload["scopes"])


def _safe_root():
    root = output_root()
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise JobError("Export storage path must not contain symlinks")
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def _cleanup(root, session_factory):
    cutoff = now() - timedelta(hours=limits()[2])
    with session_factory() as db:
        jobs = {row.id: row for row in db.scalars(select(DurableJob).where(DurableJob.kind == "export"))}
    for directory in root.iterdir():
        if not re.fullmatch(r"[a-f0-9]{32}", directory.name) or directory.is_symlink() or not directory.is_dir():
            continue
        job = jobs.get(directory.name)
        # Never remove a live builder, even when it has exceeded retention.
        expired = job and job.completed_at and aware(job.completed_at) < cutoff
        abandoned = not job and directory.stat().st_mtime < time.time() - 3600
        terminal_failure = job and job.status in {"cancelled", "failed"}
        if expired or abandoned or terminal_failure:
            if directory.resolve().parent != root:
                raise JobError("Unsafe export cleanup path")
            shutil.rmtree(directory)


def cleanup(session_factory=SessionLocal):
    root = _safe_root()
    with delivery_lock(root, 1) as acquired:
        if acquired:
            _cleanup(root, session_factory)


def _write_response(response, stream, maximum, ctx):
    digest, size, last_check = sha256(), 0, time.monotonic()
    def write(block):
        nonlocal size, last_check
        if isinstance(block, str):
            block = block.encode()
        size += len(block)
        if size > maximum:
            raise JobError("Export exceeds CATS_EXPORT_MAX_BYTES; choose a smaller export")
        if time.monotonic() - last_check > 2:
            ctx.check()
            last_check = time.monotonic()
        digest.update(block)
        stream.write(block)
    async def consume():
        try:
            if hasattr(response, "body"):
                write(response.body)
            else:
                async for block in response.body_iterator:
                    write(block)
        finally:
            if response.background:
                await response.background()
    asyncio.run(consume())
    stream.flush()
    os.fsync(stream.fileno())
    return size, digest.hexdigest()


@contextmanager
def _scratch(directory, maximum):
    """Contain library temporary files; retries also reclaim crash leftovers."""
    scratch = directory / "scratch"
    if scratch.is_symlink():
        raise JobError("Unsafe export scratch path")
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    previous = tempfile.tempdir
    previous_limit = None
    try:
        tempfile.tempdir = str(scratch)
        # Linux production: bound even uncompressed openpyxl scratch files.
        # One builder plus outer archive/member/scratch reservation bounds disk.
        if os.name == "posix":
            import resource
            previous_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
            hard = previous_limit[1]
            soft = maximum if hard == resource.RLIM_INFINITY else min(maximum, hard)
            resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        yield
    finally:
        if previous_limit is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, previous_limit)
        tempfile.tempdir = previous
        shutil.rmtree(scratch)


def generate(ctx, payload):
    # Import registers the original builders, but does not start portal lifecycle.
    from . import main as _routes  # noqa: F401
    from . import exchange_routes as _exchange  # noqa: F401
    root = _safe_root()
    maximum, disk_budget, _ = limits()
    # One generation across all replicas sharing this volume. The kernel releases
    # the lock on process death; the database lease still fences publication.
    with delivery_lock(root, 1) as acquired:
        if not acquired:
            raise RuntimeError("Export worker storage is busy")
        _cleanup(root, ctx.session_factory)
        directory = root / ctx.job.id
        if directory.is_symlink():
            raise JobError("Unsafe export job path")
        directory.mkdir(exist_ok=True)
        partial, output = directory / "output.part", directory / "output"
        for path in (partial, output):
            if path.is_symlink():
                raise JobError("Unsafe export output path")
            path.unlink(missing_ok=True)
        stale_scratch = directory / "scratch"
        if stale_scratch.is_symlink():
            raise JobError("Unsafe export scratch path")
        if stale_scratch.exists():
            shutil.rmtree(stale_scratch)
        used = sum(path.stat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink())
        # Reserve final output plus two bounded packaging/scratch copies. Worker
        # TMPDIR should reside on this same managed volume.
        reserve = maximum * 3
        if used + reserve > disk_budget or shutil.disk_usage(root).free < reserve:
            raise JobError("Export storage budget is full; wait for retention cleanup or increase CATS_EXPORT_DISK_BYTES")
        ctx.stage("Checking assessment snapshot and export permissions", 10)
        try:
            with _scratch(directory, maximum), ctx.session_factory() as db:
                # PostgreSQL snapshots include all lazily loaded builder queries.
                # Export builders may flush audit events but may not commit here.
                if db.get_bind().dialect.name == "postgresql":
                    db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                auth = _auth(db, ctx.job, payload)
                ids = [item["service_id"] for item in payload["snapshot"]]
                if snapshots(db, ids) != payload["snapshot"]:
                    raise JobError("Assessment or service version changed while queued; request a new export")
                builder = BUILDERS.get(payload["builder"])
                if builder is None:
                    raise JobError("Unsupported export type")
                ctx.stage("Generating workbooks and retained evidence", 25)
                response = builder(db=db, auth=auth, **payload["arguments"])
                ctx.stage("Writing complete export", 80)
                with partial.open("xb") as stream:
                    size, digest = _write_response(response, stream, maximum, ctx)
                db.commit()
            # Use fresh authorization after the snapshot transaction, so a role
            # revoked during a long build prevents publication as well as download.
            with ctx.session_factory() as db:
                _auth(db, ctx.job, payload)
            ctx.stage("Publishing completed export", 95)
            ctx.check()
            os.replace(partial, output)
            header = Message()
            header["content-disposition"] = response.headers.get("content-disposition", "")
            default_filename = "sbom-components.json" if response.media_type == "application/json" else "cats-export.zip"
            filename = Path(header.get_filename() or default_filename).name
            return {"download_url": f"/api/v1/exports/{ctx.job.id}/download", "result_url": f"/jobs?job={ctx.job.id}",
                    "filename": filename, "media_type": response.media_type or "application/octet-stream",
                    "bytes": size, "sha256": digest, "snapshot": payload["snapshot"]}
        except HTTPException as exc:
            # Builders' 422 errors may contain source evidence: never echo them.
            raise JobError("Export could not be generated from retained evidence; review the selected export and required fields") from exc
        except ValueError as exc:
            raise JobError("Export exceeds packaging bounds or contains invalid source data; select a smaller export or correct its inputs") from exc
        except OSError as exc:
            if exc.errno in {errno.EFBIG, errno.ENOSPC}:
                raise JobError("Export exceeds CATS_EXPORT_MAX_BYTES or available storage; choose a smaller export") from exc
            raise
        finally:
            partial.unlink(missing_ok=True)


if __name__ == "__main__":
    run_worker(("export",), generate, maintenance=cleanup)
