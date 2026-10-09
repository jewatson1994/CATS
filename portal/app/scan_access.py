"""Admission and capability checks shared by every public scan-job route."""
import hashlib
import os
import re
import secrets

from fastapi import HTTPException


def anonymous_enabled():
    return os.getenv("CATS_SCAN_ALLOW_ANONYMOUS", "false").lower() in {"true", "1", "yes"}


def admission_policy(owner, service=None):
    """Return job security fields after validating the submission principal.

    Pass AuthContext to validate service permission here. An integer owner ID
    supports internal submissions whose service permission is already checked.
    """
    owner_id = getattr(getattr(owner, "user", None), "id", owner)
    service_id = getattr(service, "id", service) if service is not None else None
    if owner_id is None:
        if not anonymous_enabled():
            raise HTTPException(401, "Sign in to submit a scan")
        if service_id is not None:
            raise HTTPException(403, "Anonymous scans cannot use service credentials")
    if service_id is not None and hasattr(owner, "has") and not owner.has("scan.ingest", service_id):
        raise HTTPException(403, "Scan permission is required for this service")
    return {"owner_user_id": owner_id, "ingest_service_db_id": service_id,
            "credential_policy": "service" if owner_id is not None and service_id is not None else "public"}


def cookie_name(job_id):
    if not re.fullmatch(r"[0-9a-f]{32}", str(job_id)):
        raise ValueError("Invalid scan job identifier")
    return "cats_scan_access_" + str(job_id)


def issue_access(job):
    """Store only a capability hash; deliver the raw token in the response/cookie."""
    if job.get("owner_user_id") is not None:
        return None
    if not anonymous_enabled():
        raise HTTPException(401, "Sign in to submit a scan")
    if job.get("ingest_service_id") or job.get("ingest_service_db_id") is not None:
        raise HTTPException(403, "Anonymous scans cannot use service credentials")
    token = secrets.token_urlsafe(32)
    job["access_token_hash"] = hashlib.sha256(token.encode()).hexdigest()
    job["credential_policy"] = "public"
    return token


def authorize_job(job, auth, request=None, service_id=None):
    """Authorize owner, service-scoped scanner, or anonymous job capability."""
    owner = job.get("owner_user_id")
    if auth is not None:
        if owner is not None and auth.user.id == owner:
            return
        service_id = service_id if service_id is not None else job.get("ingest_service_db_id")
        if service_id is not None and auth.has("scan.ingest", service_id):
            return
    # Capabilities never bypass authentication/service scope on owned jobs.
    expected = job.get("access_token_hash")
    if owner is None and expected and not job.get("ingest_service_id") and job.get("ingest_service_db_id") is None:
        supplied = ""
        if request is not None:
            supplied = request.headers.get("X-Scan-Access-Token", "")
            if not supplied:
                supplied = request.cookies.get(cookie_name(job["job_id"]), "")
            if not supplied:
                supplied = request.scope.get("session", {}).get("scan_access", {}).get(job["job_id"], "")
        if (isinstance(supplied, str) and 20 <= len(supplied) <= 256
                and secrets.compare_digest(str(expected), hashlib.sha256(supplied.encode()).hexdigest())):
            return
    raise HTTPException(403, "Scan job access denied")


def _counts(value, depth=0):
    if not isinstance(value, dict) or depth > 3:
        return {}
    result = {}
    for key, count in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_ -]{1,64}", key):
            continue
        if isinstance(count, (int, float, bool)):
            result[key] = count
        elif isinstance(count, dict):
            result[key] = _counts(count, depth + 1)
    return result


def public_projection(job, provenance=None):
    """Explicit public status schema; arbitrary job payload never reaches clients."""
    fields = {"job_id", "job_kind", "status", "phase", "created_at", "started_at", "finished_at",
              "completed_at", "attempts", "error_code", "retryable"}
    result = {key: job[key] for key in fields if key in job}
    result["summary"] = _counts(job.get("summary", {}))
    formats = job.get("summary", {}).get("formats", []) if isinstance(job.get("summary"), dict) else []
    allowed_formats = {"syft-json", "spdx-json", "spdx-tag-value", "cyclonedx-json", "cyclonedx-xml"}
    if isinstance(formats, list):
        result["summary"]["formats"] = [value for value in formats if isinstance(value, str) and value in allowed_formats]
    if isinstance(job.get("skipped_charts"), list):
        result["skipped_charts"] = [_public_text(value) for value in job["skipped_charts"][:100]]
    if job.get("error"):
        result["error"] = _public_text(job["error"])
    else:
        result["error"] = ""
    if provenance is not None:
        result["intelligence"] = intelligence_projection(provenance)
    return result


def intelligence_projection(provenance):
    """Compare pinned worker identities with administrator sources; expose no paths."""
    from .scan_intelligence import intelligence_status
    databases = provenance.get("databases", {}) if isinstance(provenance, dict) else {}
    if not isinstance(databases, dict):
        databases = {}
    sources = {"CATS_SCAN_GRYPE_SOURCE": os.getenv("GRYPE_DB_CACHE_DIR", "/opt/catscan/grype-db"),
               "CATS_SCAN_TRIVY_SOURCE": os.getenv("TRIVY_CACHE_DIR", "/opt/catscan/trivy-cache")}
    selected = {key: value for key, value in databases.items() if key in {"grype", "trivy"} and isinstance(value, dict)}
    freshness = intelligence_status(selected, sources)
    result = {}
    for scanner in ("grype", "trivy"):
        pinned = selected.get(scanner, {})
        state = freshness.get(scanner, {}).get("status", "unavailable")
        state = {"unavailable": "missing", "invalid": "mismatch"}.get(state, state)
        if pinned.get("status") == "unavailable" or not pinned:
            state = "missing"
        item = {"status": state}
        for source, target in (("version", "version"), ("built_at", "built")):
            value = pinned.get(source)
            if isinstance(value, (str, int, float)):
                item[target] = _public_text(str(value))[:240]
        result[scanner] = item
    statuses = {item["status"] for item in result.values()}
    overall = next((state for state in ("mismatch", "missing", "superseded", "unversioned", "current") if state in statuses), "missing")
    return {"status": overall, "databases": result}


def _public_text(value):
    from .patching import redact
    text = redact(value)
    text = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text, flags=re.I)
    text = re.sub(r"(?i)Bearer\s+[^\s,;]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:key|secret|api_key|access_token)=)[^&\s]+", r"\1[REDACTED]", text)
    return text[:1000]
