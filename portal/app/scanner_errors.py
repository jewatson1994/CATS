"""Allowlisted scanner diagnostics; never publish native output or input values."""
from __future__ import annotations

import errno


_DETAILS = {
    "process_creation_failed": "The scanner could not create a process or thread. Check worker PID/thread usage and memory limits.",
    "disk_space_exhausted": "The scanner ran out of disk space or disk quota. Check worker scratch storage.",
    "memory_exhausted": "The scanner could not allocate memory. Check worker and host memory usage.",
    "file_descriptor_limit": "The scanner could not open another file. Check worker file descriptor usage and limits.",
    "file_access_denied": "The scanner could not access a required file. Check input and database permissions.",
    "file_unavailable": "A required scanner file is missing. Check retained inputs and the installed scanner tools.",
    "scanner_database_unavailable": "The retained vulnerability database could not be loaded or validated. Check the worker's intelligence snapshot.",
    "scanner_database_expired": "The retained vulnerability database exceeds the configured age policy. Refresh the intelligence snapshot or review the configured offline age policy.",
    "scanner_database_changed": "The retained vulnerability database changed during scanning. Retry with a stable intelligence snapshot.",
    "scanner_database_policy_invalid": "The scanner database age policy is invalid. Check the configured age and validation settings.",
    "invalid_scanner_evidence": "The scanner did not return valid, complete evidence.",
    "invalid_scanner_input": "The supplied scanner input is not a valid native SBOM.",
    "isolation_unavailable": "Worker isolation could not start. Check the host AppArmor and seccomp profiles.",
    "time_limit_exceeded": "The offline scanner exceeded its time limit.",
    "output_limit_exceeded": "The offline scanner exceeded its output limit.",
    "scanner_failed": "The offline scanner failed for an unclassified reason.",
}


def scanner_failure_reason(stderr: str) -> str:
    """Reduce known native errors to a fixed code without retaining their text."""
    text = stderr.lower()
    if any(line.startswith("bwrap:") for line in text.splitlines()):
        return "isolation_unavailable"
    if "no space left on device" in text or "disk quota exceeded" in text:
        return "disk_space_exhausted"
    if ("pthread_create failed" in text or "failed to create new os thread" in text
            or ("resource temporarily unavailable" in text
                and any(word in text for word in ("fork", "clone", "thread")))):
        return "process_creation_failed"
    if "cannot allocate memory" in text or "runtime: out of memory" in text:
        return "memory_exhausted"
    if "too many open files" in text:
        return "file_descriptor_limit"
    if ("database" in text or "vulnerability db" in text) and any(
            marker in text for marker in ("too old", "older than", "exceeds max allowed age")):
        return "scanner_database_expired"
    if any(marker in text for marker in (
            "failed to load vulnerability db", "vulnerability database is invalid",
            "database metadata not found", "database disk image is malformed",
            "failed to read db description")):
        return "scanner_database_unavailable"
    if "permission denied" in text:
        return "file_access_denied"
    return "scanner_failed"


def scanner_failure_message(reason: str | None) -> str:
    reason = reason if reason in _DETAILS else "scanner_failed"
    return f"[{reason}] {_DETAILS[reason]}"


def scanner_failure_detail(error: Exception) -> str:
    """Only codes we own may reach a job log, including for unexpected errors."""
    reason = getattr(error, "reason", None)
    if reason not in _DETAILS:
        if isinstance(error, OSError):
            reason = {
                errno.EAGAIN: "process_creation_failed",
                errno.ENOMEM: "memory_exhausted",
                errno.ENOSPC: "disk_space_exhausted",
                errno.EDQUOT: "disk_space_exhausted",
                errno.EMFILE: "file_descriptor_limit",
                errno.ENFILE: "file_descriptor_limit",
                errno.EACCES: "file_access_denied",
                errno.EPERM: "file_access_denied",
                errno.ENOENT: "file_unavailable",
            }.get(error.errno)
        elif getattr(error, "infrastructure", False):
            reason = "isolation_unavailable"
    return scanner_failure_message(reason)
