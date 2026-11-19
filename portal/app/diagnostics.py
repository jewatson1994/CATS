"""Portable, bounded diagnostics. This module has no database or web dependency.

Raw exceptions remain available to their caller. Only this sanitized projection
may be persisted or sent over a worker/API boundary; never serialize locals,
request bodies, SQL parameters, environment variables, or authentication headers.
"""
from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timezone
from itertools import islice
import re
import subprocess
import traceback
import uuid

correlation = ContextVar("cats_diagnostic_correlation", default=None)
_SECRET = re.compile(r"(?i)(?:password|passwd|secret|token|authorization|cookie|credential|api[_-]?key|private[_-]?key|client[_-]?key|connection[_-]?string|dsn)")
_SAFE_KEYS = {"token_configured", "credentials_configured", "signature_status", "signature_verification", "signature_verified"}
_PUBLIC_CONTEXT = {"stage", "failed_stage", "last_successful_stage", "worker_id", "job_id", "task_id", "attempts", "max_attempts", "exit_code", "tool", "timeout_seconds", "failure_category", "reason_category"}


def _text(value):
    # Redact before truncation: a truncation boundary must not reveal part of a secret.
    value = str(value)[:32768]
    value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)", "[REDACTED PRIVATE KEY]", value, flags=re.S)
    value = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[REDACTED]@", value)
    value = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED AUTHORIZATION]", value)
    value = re.sub(r"(?i)([\"']?(?:password|passwd|secret|access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|client[_-]?secret|authorization|cookie|credential|x-amz-signature|x-amz-security-token)[\"']?\s*[=:]\s*)(?:\"[^\"]*(?:\"|$)|'[^']*(?:'|$)|[^\s&,;\]}]+)", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(--(?:password|passwd|token|secret|api-key|client-secret|registry-password)\s+)(?:\"[^\"]*(?:\"|$)|'[^']*(?:'|$)|\S+)", r"\1[REDACTED]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?", "[REDACTED TOKEN]", value)
    # Signed URLs and arbitrary query parameters are not useful diagnostic evidence.
    value = re.sub(r"((?:https?|oci)://[^\s?#]+)\?[^\s#]*", r"\1?[REDACTED QUERY]", value)
    return value[:4096] + (" … [truncated]" if len(value) > 4096 else "")


def sanitize(value, *, _depth=0, _budget=None):
    """Bound nested hostile data to 128 nodes, six levels and 4 KiB per string."""
    budget = [128] if _budget is None else _budget
    budget[0] -= 1
    if budget[0] < 0 or _depth > 6:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        result = {}
        for key, item in islice(value.items(), 40):
            key = _text(key)[:100]
            result[key] = "[REDACTED]" if _SECRET.search(key) and key not in _SAFE_KEYS else sanitize(item, _depth=_depth + 1, _budget=budget)
            if budget[0] <= 0:
                break
        return result
    if isinstance(value, (list, tuple, set)):
        return [sanitize(item, _depth=_depth + 1, _budget=budget) for item in islice(value, 30) if budget[0] > 0]
    if isinstance(value, bytes):
        return "[binary data omitted]"
    return _text(value)


# Rules match observed evidence, not guesses about the infrastructure.
# code, category, observed terms, summary/cause, resolution, retryable
_RULES = (
    ("CAT-SVC-OWNERSHIP-001", "ownership", ("exactly one owning group", "no owning group", "multiple owning groups"), "Service ownership validation failed", "Assign exactly one owning group in Edit service, save, and retry the operation.", False),
    ("CAT-REGISTRY-TLS-001", "tls", ("certificate verify failed", "certificate verification", "x509:", "certificate signed by unknown", "tls certificate trust failed"), "TLS certificate verification failed", "Install the issuing CA in CATS trusted certificates and verify the registry hostname and certificate chain. Keep certificate verification enabled.", False),
    ("CAT-REGISTRY-AUTH-001", "authentication", ("registry authentication", "unauthorized: authentication required", "401 unauthorized", "insufficient_scope", "pull access denied"), "Registry authentication or repository access was denied", "Check the configured registry credentials, their expiry, and pull/push permissions for this repository.", False),
    ("CAT-OCI-MISSING-001", "not_found", ("manifest unknown", "blob unknown", "manifest_unknown", "blob_unknown", "manifest not found"), "Requested OCI content was not found", "Verify the repository, tag or digest and confirm all manifests and blobs finished publishing or replicating.", False),
    ("CAT-BUNDLE-INVALID-001", "validation", ("invalid service bundle", "invalid bundle", "bundle verification failed", "invalid exchange package"), "Bundle validation failed", "Re-export the complete bundle from the source and verify its schema, checksum and publisher trust before importing it again.", False),
    ("CAT-CHART-INVALID-001", "validation", ("invalid chart", "malformed chart", "unsupported chart", "chart.yaml", "helm template failed"), "Chart validation or rendering failed", "Review the reported chart file and validation errors. Correct the chart, values and dependencies, then package and retry.", False),
    ("CAT-SCAN-CREDENTIALS-001", "configuration", ("scan-worker credentials", "scan worker token is not configured", "scan worker credentials", "cats_scan_worker_token"), "Scan worker credentials are missing or invalid", "Configure matching portal and scan-worker credentials in the deployment, restart the affected services, and retry.", False),
    ("CAT-STORAGE-FULL-001", "capacity", ("no space left on device", "insufficient disk space", "not enough disk space", "disk budget exceeded", "exceeds worker disk budget"), "Available disk capacity is insufficient", "Free space on the affected worker or artifact volume using the configured retention policy; check free bytes and inodes before retrying.", True),
    ("CAT-VALIDATOR-CONNECTION-001", "connectivity", ("validator connectivity", "validator unavailable", "validator connection", "validation worker unavailable"), "The validator could not be reached", "Check validator health, endpoint, network access, CA trust and mutual TLS configuration, then retry validation.", True),
    ("CAT-SIGNATURE-001", "signature", ("signature verification failed", "signature invalid", "invalid signature", "untrusted publisher", "signature_invalid"), "Signature verification failed", "Verify the artifact digest, configured publisher trust and key rotation state. Obtain a valid signed artifact; do not disable verification.", False),
    ("CAT-RELEASE-APPROVAL-001", "approval", ("no approved release", "missing approved release", "approved release required", "no active approved"), "An applicable approved release is missing", "Have an authorized reviewer approve and publish the correct service release, then confirm replication and retry the pull.", False),
    ("CAT-WORKER-LOST-001", "worker", ("worker lease expired", "worker stopped", "worker lost", "worker restarted", "worker crash"), "The worker stopped before completing the job", "Check worker availability and resource limits. Review the last completed stage and any partial output before retrying.", True),
    ("CAT-REPLICA-SYNC-001", "replication", ("incomplete release replication", "replica synchronization failed", "local registry sync failed"), "Replica synchronization did not complete", "Inspect the related release diagnostics; verify local registry content, publisher trust, signed sequence and source connectivity, then sync again.", True),
    ("CAT-TIMEOUT-001", "timeout", ("timed out", "timeout", "deadline exceeded"), "The operation exceeded its time limit", "Check the failed stage, worker capacity and external dependency response time. Adjust the configured timeout only when the workload requires it, then retry.", True),
    ("CAT-CONNECTION-001", "connectivity", ("connection refused", "name resolution", "could not resolve", "network is unreachable", "connection reset"), "A required dependency could not be reached", "Verify the reported endpoint, DNS, network rules and dependency health, then retry.", True),
)


def _exception_details(error):
    details, seen = [], set()
    current = error if isinstance(error, BaseException) else None
    database_chain = False
    while current is not None and id(current) not in seen and len(details) < 5:
        seen.add(id(current))
        # SQLAlchemy includes SQL and bound parameters in __str__. Never copy those.
        sql_error = type(current).__module__.startswith("sqlalchemy")
        database_chain = database_chain or sql_error
        message = (type(current.orig).__name__ if sql_error and getattr(current, "orig", None) else type(current).__name__) if database_chain else str(current)
        # subprocess exception strings serialize argv with Python repr, which
        # can separate an option from its secret value. Never retain argv,
        # stdin, stdout or stderr from these exception objects.
        if isinstance(current, subprocess.TimeoutExpired):
            message = f"External tool timed out after {current.timeout} seconds"
        elif isinstance(current, subprocess.CalledProcessError):
            message = f"External tool exited with code {current.returncode}"
        if type(current).__name__ == "RequestValidationError":
            message = "Request validation failed; see validation_errors (submitted values omitted)."
        frames = [{"file": frame.filename.replace("\\", "/").split("/")[-1], "line": frame.lineno, "function": frame.name}
                  for frame in traceback.extract_tb(current.__traceback__)[-12:]]
        details.append({"type": type(current).__name__, "message": sanitize(message), "frames": frames})
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    return details


def _tool_rule(error, observed, context):
    tool = getattr(error, "tool", None) or (context.get("tool") if isinstance(context, dict) else None)
    if tool == "trivy" and ("the first run cannot skip downloading db" in observed or
                            "--skip-db-update cannot be specified on the first run" in observed):
        return ("CAT-SCANNER-DB-001", "configuration", (), "The scanner vulnerability database is unavailable",
                "Publish a valid scanner database snapshot to the affected worker, verify its configured cache path, and retry the scan.", False)
    if tool in {"trivy", "grype", "syft", "dockle", "copa"} and (
            ("no such file or directory" in observed and any(term in observed for term in
                ("unable to open", "opening file", "unable to initialize archive image"))) or
            (tool == "copa" and re.search(r"report path [^\n]+ does not exist", observed))):
        return ("CAT-TOOL-INPUT-001", "not_found", (), "A required tool input file is missing",
                "Restore or regenerate the referenced image archive, SBOM or scan report. Verify the worker's input mount and retry the operation.", False)
    return None


def build_diagnostic(error, *, component, operation, status=None, correlation_id=None,
                     resource=None, context=None, summary=None, code=None, retryable=None):
    details = _exception_details(error)
    observed = (details[0]["message"] if isinstance(error, (subprocess.TimeoutExpired, subprocess.CalledProcessError))
                else str(getattr(error, "detail", error)))[:32768].lower()
    if type(error).__module__.startswith("sqlalchemy"):
        observed = type(error).__name__.lower()
    else:
        # Wrapped dependency errors retain useful, sanitized evidence. Never
        # classify from SQL parameters or provider response bodies.
        observed += " " + " ".join(str(item["message"]) for item in details).lower()
    rule = _tool_rule(error, observed, context) or next((rule for rule in _RULES if any(term in observed for term in rule[2])), None)
    if type(error).__name__ in {"OperationalError", "DisconnectionError", "InterfaceError"} and type(error).__module__.startswith("sqlalchemy"):
        rule = ("CAT-DATABASE-001", "database", (), "Database connection or operation failed", "Check database health, connectivity and connection limits. Use the correlation ID to inspect the database failure; retry once connectivity is restored.", True)
    cause = rule[3] if rule else None
    if rule and rule[0] == "CAT-SVC-OWNERSHIP-001":
        if "no owning group" in observed:
            cause = "Service has no owning group"
        elif "multiple owning groups" in observed:
            cause = "Service has multiple owning groups"
    if rule:
        default_code, category, _, title, resolution, may_retry = rule
    else:
        category = "authorization" if status in (401, 403) else "validation" if status in (400, 409, 422) else "not_found" if status == 404 else "internal"
        default_code = {"authorization": "CAT-AUTH-001", "validation": "CAT-VALIDATION-001", "not_found": "CAT-NOT-FOUND-001"}.get(category, "CAT-UNKNOWN-001")
        title = {"authorization": "Authentication or authorization failed", "validation": "The submitted operation could not be accepted", "not_found": "The requested resource was not found"}.get(category, "The operation failed")
        resolution = "Review the technical evidence and related events using the correlation ID. The root cause has not been determined."
        if category == "authorization":
            resolution = "Sign in with the correct account and ask an administrator to verify your access to this operation."
        elif category == "validation":
            resolution = "Review the reported validation message, correct the submitted data and retry."
        elif category == "not_found":
            resolution = "Verify the resource identifier and your access to it, then retry."
        may_retry = status in (429, 502, 503, 504)
    return {
        "schema_version": 1, "error_id": uuid.uuid4().hex,
        "correlation_id": valid_correlation(correlation_id or correlation.get()),
        "timestamp": datetime.now(timezone.utc).isoformat(), "component": sanitize(component),
        "operation": sanitize(operation), "code": code or default_code, "category": category,
        "severity": "warning" if isinstance(status, int) and 400 <= status < 500 else "error",
        "status": status if status is not None else "failed", "summary": sanitize(summary or title), "cause": cause,
        "resolution": [resolution], "resource": sanitize(resource or {}),
        "retryable": may_retry if retryable is None else bool(retryable),
        "context": sanitize(context or {}), "technical": {"exceptions": details},
    }


def valid_correlation(value=None):
    # Existing durable-job correlation columns are VARCHAR(32). Normalize at
    # ingress so one identity survives both HTTP and PostgreSQL job boundaries.
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{8,32}", value) else uuid.uuid4().hex


def request_correlation(request):
    value = getattr(request.state, "diagnostic_correlation_id", None)
    if value is None:
        value = valid_correlation(request.headers.get("x-correlation-id"))
        request.state.diagnostic_correlation_id = value
    return value


def public_diagnostic(diagnostic, technical=False):
    result = sanitize(diagnostic)
    if not isinstance(result, dict):
        return {}
    if not technical:
        result.pop("technical", None)
        context = result.get("context")
        result["context"] = {key: value for key, value in context.items() if key in _PUBLIC_CONTEXT} if isinstance(context, dict) else {}
    return result


def record_diagnostic(diagnostic, session_factory=None):
    """Best effort only; durable job state is the authoritative failure record."""
    try:
        from .diagnostic_store import record_diagnostic as record
        return record(diagnostic, session_factory=session_factory)
    except Exception:
        return False


def enqueue_diagnostic(diagnostic):
    try:
        from .diagnostic_store import enqueue_diagnostic as enqueue
        return enqueue(diagnostic)
    except Exception:
        return False


def capture_failure(error, **kwargs):
    """Record a swallowed/partial failure without changing its business outcome."""
    item = build_diagnostic(error, **kwargs)
    enqueue_diagnostic(item)
    return public_diagnostic(item)
