"""Historical dashboard counts from immutable scan payloads, not live findings."""
from datetime import timezone

SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")


def scan_snapshot(execution):
    payload = execution.raw_payload or {}
    findings = {}
    for item in payload.get("findings", []):
        cve = str(item.get("cve") or "").strip()
        if not cve:
            continue
        severity = str(item.get("severity") or "Unknown").title()
        severity = severity if severity in SEVERITIES else "Unknown"
        # Count a CVE once per service scan, taking its highest observed severity.
        if cve not in findings or SEVERITIES.index(severity) < SEVERITIES.index(findings[cve]):
            findings[cve] = severity
    counts = {level: sum(value == level for value in findings.values()) for level in SEVERITIES}
    version = str((payload.get("service") or {}).get("version") or "").strip()
    if not version or version.lower() in {"unknown", "unversioned"}:
        version = "Unversioned"
    return {"execution_id": execution.id, "version": version,
            "scanned_at": execution.scanned_at.isoformat(), "complete": bool(execution.complete),
            "counts": counts, "total": len(findings)}


def service_history(service):
    # Image-only scans are not comparable service-wide snapshots.
    scans = sorted((item for item in service.executions if item.scan_scope == "service"),
                   key=lambda item: (item.scanned_at.replace(tzinfo=timezone.utc) if item.scanned_at.tzinfo is None
                                     else item.scanned_at, item.id), reverse=True)
    snapshots = []
    versions = []
    seen = set()
    for index, execution in enumerate(scans):
        snapshot = scan_snapshot(execution)
        if index < 8:
            snapshots.append(snapshot)
        if len(versions) < 2 and snapshot["version"] not in seen and snapshot["version"] != "Unversioned":
            seen.add(snapshot["version"])
            versions.append(snapshot)
        if len(versions) == 2 and index >= min(7, len(scans) - 1):
            break
    return {"service_key": service.service_key, "name": service.name,
            "trend": list(reversed(snapshots[:8])), "versions": versions}
