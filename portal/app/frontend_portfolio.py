"""Explicit security portfolio projection; never serialize service relationships."""
from collections.abc import Mapping
from datetime import date, datetime


def _value(source, key, default=None):
    return source.get(key, default) if isinstance(source, Mapping) else getattr(source, key, default)


def _scalar(value):
    return value if value is None or isinstance(value, (str, int, float, bool)) else None


def cybersecurity_data(context, format_date=None):
    """Return only fields rendered by cybersecurity.html, with configured dates."""
    data = {key: _scalar(context.get(key, "")) for key in
            ("q", "status", "attention", "severity", "component", "since")}
    metrics = context.get("metrics", {})
    data["metrics"] = {key: _scalar(_value(metrics, key, 0)) for key in
        ("attention", "services", "scanned", "vulnerabilities", "critical_high", "kev",
         "watchlist", "patchable", "poam", "poam_overdue", "sbom_coverage", "missing", "kind_failed",
         "critical", "high", "medium", "low", "unknown", "green", "yellow", "red")}
    data["history"] = []
    for service in context.get("history", []):
        history = {key: _scalar(_value(service, key)) for key in ("service_key", "name")}
        for key in ("trend", "versions"):
            history[key] = []
            for scan in _value(service, key, []):
                snapshot = {field: _scalar(_value(scan, field)) for field in
                            ("execution_id", "version", "scanned_at", "complete", "total")}
                snapshot["counts"] = {level: _scalar(_value(_value(scan, "counts", {}), level, 0))
                                      for level in ("Critical", "High", "Medium", "Low", "Unknown")}
                history[key].append(snapshot)
        data["history"].append(history)
    data["rows"] = []
    for source in context.get("rows", []):
        service = _value(source, "service")
        row = {key: _scalar(_value(source, key)) for key in
            ("status", "critical", "high", "medium", "low", "kev", "watchlist", "patchable", "poam",
             "poam_overdue", "missing", "sbom", "kind")}
        row["service"] = {key: _scalar(_value(service, key)) for key in ("service_key", "name")}
        scanned = _value(source, "last_scan")
        if scanned is None:
            row["last_scan"] = None
            row["last_scan_display"] = "—"
        elif isinstance(scanned, (date, datetime)):
            row["last_scan"] = scanned.isoformat()
            row["last_scan_display"] = str(format_date(scanned)) if format_date else scanned.strftime("%d %b %Y")
        else:
            row["last_scan"] = _scalar(scanned)
            row["last_scan_display"] = _scalar(scanned) or "—"
        data["rows"].append(row)
    return data
