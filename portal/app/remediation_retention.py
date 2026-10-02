"""Bounded cleanup of terminal remediation content, preserving durable evidence."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat

from sqlalchemy import select

from .models import RemediationExecution


@dataclass(frozen=True)
class RetentionPolicy:
    days: int = 30
    published_days: int = 7
    max_bytes: int = 20 * 1024**3

    def __post_init__(self):
        if not 1 <= self.days <= 3650 or not 1 <= self.published_days <= self.days or self.max_bytes < 1:
            raise ValueError("Invalid remediation retention policy")


def retention_policy():
    days = int(os.getenv("CATS_REMEDIATION_RETENTION_DAYS", "30"))
    return RetentionPolicy(days=days,
        published_days=int(os.getenv("CATS_REMEDIATION_PUBLISHED_RETENTION_DAYS", str(min(7, days)))),
        max_bytes=int(os.getenv("CATS_REMEDIATION_RETENTION_MAX_BYTES", str(20 * 1024**3))))


def _unsafe(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _inventory(folder, root):
    if _unsafe(folder) or folder.resolve().parent != root or not folder.is_dir():
        raise ValueError("Unsafe candidate directory")
    files, folders = [], []
    stack = [folder]
    total = 0
    while stack:
        current = stack.pop()
        if _unsafe(current) or not current.resolve().is_relative_to(folder.resolve()):
            raise ValueError("Unsafe candidate path")
        folders.append(current)
        for path in current.iterdir():
            if _unsafe(path):
                raise ValueError("Candidate contains a link")
            if path.is_dir():
                stack.append(path)
            elif path.is_file():
                files.append(path)
                total += path.stat().st_size
            else:
                raise ValueError("Unsupported candidate file")
    return total, files, folders


def cleanup_remediation_artifacts(db, root: Path, *, now=None, policy=None):
    """Delete only validated terminal job directories; caller commits DB changes.

    Active jobs can temporarily exceed quota. Call before admitting new work and
    after workers finish; over_quota lets callers decline additional work.
    """
    policy = policy or retention_policy()
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    root = Path(root).absolute()
    result = {"removed": [], "removed_bytes": 0, "retained_bytes": 0, "over_quota": False, "skipped": []}
    if not root.exists():
        return result
    if _unsafe(root) or root.resolve() == Path(root.anchor):
        raise ValueError("Unsafe remediation root")
    root = root.resolve()
    rows = list(db.scalars(select(RemediationExecution)))
    entries = []
    known_folders = {row.job_key for row in rows}
    # Unknown content consumes quota but is never deleted without a durable owner.
    for folder in root.iterdir():
        if folder.name in known_folders:
            continue
        try:
            if folder.is_dir():
                size, _, _ = _inventory(folder, root)
            elif folder.is_file() and not _unsafe(folder):
                size = folder.stat().st_size
            else:
                raise ValueError("Unsafe orphan content")
            result["retained_bytes"] += size
        except (OSError, ValueError):
            result["retained_bytes"] += policy.max_bytes + 1
        result["skipped"].append(folder.name)
    active_states = {"queued", "running", "pending", "preparing", "publishing", "delivering"}
    for row in rows:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", row.job_key or ""):
            result["skipped"].append(row.job_key)
            continue
        folder = root / row.job_key
        if not folder.exists():
            continue
        try:
            size, files, folders = _inventory(folder, root)
        except (OSError, ValueError):
            result["skipped"].append(row.job_key)
            result["retained_bytes"] += policy.max_bytes + 1
            continue
        result["retained_bytes"] += size
        active = (str(row.status).lower() in active_states
                  or str(row.delivery_status).lower() in {"running", "queued", "publishing", "delivering", "in_progress"}
                  or str(row.verification_status).lower() in {"running", "queued", "in_progress"})
        if active:
            continue
        stamp = row.completed_at or row.created_at
        stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp
        age = max(0, (now - stamp).total_seconds() / 86400)
        published = str(row.delivery_status).lower() in {"published", "delivered"}
        expired = age >= (policy.published_days if published else policy.days)
        entries.append((not expired, not published, stamp, row, size, files, folders))
    for not_expired, _, _, row, size, files, folders in sorted(entries, key=lambda item: item[:3]):
        if not_expired and result["retained_bytes"] <= policy.max_bytes:
            continue
        try:
            # Revalidate immediately before mutation; never follow links.
            fresh_size, fresh_files, fresh_folders = _inventory(root / row.job_key, root)
            for path in fresh_files:
                if _unsafe(path) or not path.resolve().is_relative_to(root / row.job_key):
                    raise ValueError("Candidate changed during cleanup")
                path.unlink()
            for folder in sorted(fresh_folders, key=lambda path: len(path.parts), reverse=True):
                if _unsafe(folder):
                    raise ValueError("Candidate changed during cleanup")
                folder.rmdir()
        except (OSError, ValueError):
            result["skipped"].append(row.job_key)
            continue
        row.artifact_path = None
        result["removed"].append(row.job_key)
        result["removed_bytes"] += fresh_size
        result["retained_bytes"] -= size
    result["over_quota"] = result["retained_bytes"] > policy.max_bytes
    db.flush()
    return result
