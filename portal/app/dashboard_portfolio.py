"""Permission-scoped portfolio summaries, without historical payload graphs."""
from datetime import datetime, timedelta
from math import ceil

from fastapi import HTTPException
from sqlalchemy import and_, case, false, func, or_, select

from .frontend_portfolio import cybersecurity_data
from .sql_sets import catalog_subset, member_of
from .models import (DependencyWatchlistMatch, DeploymentValidationRun, ExceptionRecord, ExecutionSummary,
                     Execution, Finding, FindingObservation, PoamEntry, PolicyExceptionRecord,
                     PolicyFinding, Service, ServiceImage, utcnow)


def compute_rows(db, services, configs, configuration, now):
    """Per-service Cybersecurity posture rows (without the service object).

    The exact historical portfolio computation, restricted to ``services``;
    the Service Posture projection stores its output and recomputes only
    services whose evidence, intelligence, configuration or time window
    changed.
    """
    from . import main as m
    ids = [service.id for service in services]
    if not ids:
        return {}
    warning_policy = m.parse_json(configuration.get("cyber_warning_policy"), {})
    def latest_scans(current=False):
        query = select(Execution.id.label("id"), Execution.service_id.label("service_id"),
                       func.row_number().over(partition_by=Execution.service_id,
                           order_by=(Execution.scanned_at.desc(), Execution.id.desc())).label("rank")).where(member_of(Execution.service_id, ids, numeric=True))
        if current:
            query = query.join(Service, Service.id == Execution.service_id).where(or_(Service.current_version_id.is_(None), Execution.service_version_id == Service.current_version_id))
        return query.subquery()

    latest = latest_scans()
    latest_current = latest_scans(True)
    # Evidence presence comes from the execution summary when it is current
    # for that exact payload (digest, version, completeness); otherwise from
    # the retained payload itself, exactly as before. Parsing whole retained
    # payloads only to test two flags dominated this computation.
    from .execution_summaries import SUMMARY_VERSION
    current_summary = and_(ExecutionSummary.execution_id == Execution.id,
                           ExecutionSummary.payload_digest == Execution.payload_digest,
                           ExecutionSummary.summary_version == SUMMARY_VERSION,
                           ExecutionSummary.source_complete == Execution.complete)
    scans = {row.service_id: row for row in db.execute(select(
        Execution.service_id, Execution.id, Execution.scanned_at,
        ExecutionSummary.data["has_sbom_images"].label("has_sbom")
    ).join(latest, and_(latest.c.id == Execution.id, latest.c.rank == 1)).outerjoin(ExecutionSummary, current_summary))}
    sbom = {sid: row.has_sbom for sid, row in scans.items() if isinstance(row.has_sbom, bool)}
    pending = [row.id for sid, row in scans.items() if sid not in sbom]
    for chunk in range(0, len(pending), 100):
        for row in db.execute(select(Execution.service_id, Execution.raw_payload["sbom_images"].label("sbom_images"))
                              .where(Execution.id.in_(pending[chunk:chunk + 100]))):
            sbom[row.service_id] = bool(row.sbom_images)
    evidence_rows = db.execute(select(
        Execution.service_id, Execution.id, Execution.complete,
        ExecutionSummary.data["missing_evidence_count"].label("missing_count")
    ).join(latest_current, and_(latest_current.c.id == Execution.id, latest_current.c.rank == 1))
     .outerjoin(ExecutionSummary, current_summary)).all()
    missing_evidence = {}
    pending = []
    for row in evidence_rows:
        if not row.complete:
            missing_evidence[row.service_id] = True
        elif isinstance(row.missing_count, int) and not isinstance(row.missing_count, bool):
            missing_evidence[row.service_id] = row.missing_count > 0
        else:
            pending.append(row.id)
    for chunk in range(0, len(pending), 100):
        for ev in db.execute(select(
                Execution.service_id, Execution.complete,
                Execution.raw_payload["service_overview"].label("overview"),
                Execution.raw_payload["skipped_images"].label("images"),
                Execution.raw_payload["skipped_charts"].label("charts")).where(Execution.id.in_(pending[chunk:chunk + 100]))):
            missing_evidence[ev.service_id] = bool(not ev.complete or m.normalize_overview(
                ev.overview or {}, skipped_images=ev.images or [], skipped_charts=ev.charts or [],
                incomplete=not ev.complete)["missing_evidence"])
    observation_ids = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("id")).join(Finding, Finding.id == FindingObservation.finding_id).where(member_of(Finding.service_id, ids, numeric=True), Finding.active.is_(True)).group_by(FindingObservation.finding_id).subquery()
    exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id,
        ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
    catalog_kev = m.kev_cves()
    kev = or_(member_of(Finding.cve, catalog_kev) if catalog_kev else false(),
        func.coalesce(FindingObservation.evidence["kev"].as_boolean(), FindingObservation.evidence["known_exploited"].as_boolean(), False))
    catalog_epss = m.epss_scores()
    epss = func.coalesce(FindingObservation.evidence["epss"].as_float(), FindingObservation.evidence["epss_score"].as_float())
    noncompliant_parts, warning_parts = [], []
    def raw_overdue(cfg, when):
        default_days = max(1, int(cfg.get("overdue_days", "90")))
        rules = m.parse_json(cfg.get("raw_due_rules"), [])
        due_days = {str(rule.get("severity", "")).lower(): max(1, int(rule.get("days", default_days))) for rule in rules}
        level = func.lower(Finding.severity)
        return or_(*[and_(level == name, Finding.episode_started <= when - timedelta(days=days)) for name, days in due_days.items()],
                   and_(~level.in_(list(due_days)), Finding.episode_started <= when - timedelta(days=default_days)))
    configuration_groups = {}
    for sid, cfg in configs.items():
        configuration_groups.setdefault(tuple(sorted(cfg.items())), []).append(sid)
    for configuration_key, group_ids in configuration_groups.items():
        cfg = dict(configuration_key)
        raw = cfg.get("compliance_mode", "risk_based") == "raw"
        days = max(1, int(cfg.get("overdue_days", "90")))
        overdue = raw_overdue(cfg, now) if raw else Finding.episode_started <= now - timedelta(days=days)
        eligible, failing = ([member_of(Finding.service_id, group_ids, numeric=True)], [overdue]) if raw else ([], [])
        ranks = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        minimum = cfg.get("minimum_severity", "None").lower()
        if not raw and minimum in ranks:
            match = (Finding.id.is_not(None) if ranks[minimum] == 0 else
                     func.lower(Finding.severity).in_([key for key, rank in ranks.items() if rank >= ranks[minimum]]))
            eligible.append(match)
            failing.append(and_(match, overdue))
        if not raw and cfg.get("kev_enabled") == "true":
            eligible.append(kev)
            if cfg.get("kev_noncompliant") == "true":
                failing.append(and_(kev, overdue))
        if not raw and cfg.get("epss_enabled") == "true":
            rules = m.parse_json(cfg.get("epss_rules"), []) or [{"severity": "Any", "threshold": float(cfg.get("epss_threshold", ".90")), "noncompliant": True}]
            prior = false()
            for rule in rules:
                level = str(rule.get("severity", "Any")).lower()
                threshold = float(rule.get("threshold", 1))
                catalog_match = catalog_subset(catalog_epss, ("epss>=", threshold), lambda score, threshold=threshold: score >= threshold)
                score_match = or_(epss >= threshold, and_(epss.is_(None), member_of(Finding.cve, catalog_match) if catalog_match else threshold <= 0))
                match = and_(score_match, (func.lower(Finding.severity) == level if level != "any" else True))
                eligible.append(match)
                if bool(rule.get("noncompliant", True)):
                    failing.append(and_(match, ~prior, overdue))
                prior = or_(prior, match)
        scope = member_of(Finding.service_id, group_ids, numeric=True)
        visible = or_(*eligible) if eligible else false()
        noncompliant_parts.append(and_(scope, or_(*failing) if failing else false(), ~exception))
        warning_days = max(1, int(cfg.get("warning_days", "14")))
        approaching = and_(Finding.episode_started > now - timedelta(days=days), Finding.episode_started <= now - timedelta(days=days-warning_days))
        if raw:
            approaching = and_(~overdue, raw_overdue(cfg, now + timedelta(days=warning_days)))
        expiry = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now, ExceptionRecord.expires_at <= now + timedelta(days=warning_days)).exists()
        warning_parts.append(and_(scope, visible, or_(and_(~exception, approaching), expiry)))
    severity_lower = func.lower(Finding.severity)
    levels = ("critical", "high", "medium", "low")
    columns = [func.count(Finding.id).label("vulnerabilities")]
    columns += [func.sum(case((severity_lower == level, 1), else_=0)).label(level) for level in levels]
    columns += [func.sum(case((~severity_lower.in_(levels), 1), else_=0)).label("unknown"),
        func.sum(case((kev, 1), else_=0)).label("kev"),
        func.sum(case((and_(FindingObservation.fixed_version.is_not(None), FindingObservation.fixed_version != ""), 1), else_=0)).label("patchable"),
        func.sum(case((or_(*noncompliant_parts), 1), else_=0)).label("noncompliant"),
        func.sum(case((or_(*warning_parts), 1), else_=0)).label("warning")]
    counts = {row.service_id: row._mapping for row in db.execute(select(Finding.service_id, *columns).outerjoin(observation_ids, observation_ids.c.finding_id == Finding.id).outerjoin(FindingObservation, FindingObservation.id == observation_ids.c.id).where(member_of(Finding.service_id, ids, numeric=True), Finding.active.is_(True)).group_by(Finding.service_id))} if ids else {}
    policy_exception = select(PolicyExceptionRecord.id).where(PolicyExceptionRecord.policy_finding_id == PolicyFinding.id, PolicyExceptionRecord.revoked_at.is_(None), PolicyExceptionRecord.starts_at <= now, PolicyExceptionRecord.expires_at > now).exists()
    policy_fails = {sid: int(count) for sid, count in db.execute(select(PolicyFinding.service_id, func.count()).where(member_of(PolicyFinding.service_id, ids, numeric=True), PolicyFinding.active.is_(True), m._hardening_overdue_expression(configs, now), ~policy_exception).group_by(PolicyFinding.service_id))} if ids else {}
    poams = {row.service_id: row for row in db.execute(select(PoamEntry.service_id, func.count().label("count"), func.sum(case((PoamEntry.due_date < now, 1), else_=0)).label("overdue")).where(member_of(PoamEntry.service_id, ids, numeric=True), PoamEntry.status == "active").group_by(PoamEntry.service_id))} if ids else {}
    watches = {sid: count for sid, count in db.execute(select(DependencyWatchlistMatch.service_id, func.count()).join(latest, and_(latest.c.id == DependencyWatchlistMatch.execution_id, latest.c.rank == 1)).group_by(DependencyWatchlistMatch.service_id))} if ids else {}
    ranked_validations = select(DeploymentValidationRun.service_id, DeploymentValidationRun.status, func.row_number().over(partition_by=DeploymentValidationRun.service_id, order_by=(DeploymentValidationRun.created_at.desc(), DeploymentValidationRun.id.desc())).label("rank")).where(member_of(DeploymentValidationRun.service_id, ids, numeric=True)).subquery()
    validations = dict(db.execute(select(ranked_validations.c.service_id, ranked_validations.c.status).where(ranked_validations.c.rank == 1)).all()) if ids else {}
    rows = {}
    failed_statuses = {"FAILED", "COULD_NOT_VALIDATE", "ERROR"}
    for service in services:
        row = {key: int(counts.get(service.id, {}).get(key, 0) or 0) for key in (*levels, "unknown", "vulnerabilities", "kev", "patchable", "noncompliant", "warning")}
        scan, poam = scans.get(service.id), poams.get(service.id)
        missing = missing_evidence.get(service.id, False)
        row.update(service_id=service.id, watchlist=int(watches.get(service.id, 0)), poam=int(poam.count if poam else 0), poam_overdue=int(poam.overdue or 0) if poam else 0, missing=missing, sbom=bool(scan and sbom.get(service.id)), kind=validations.get(service.id, "NOT_ATTEMPTED"), last_scan=scan.scanned_at if scan else None)
        kind_failed = row["kind"] in failed_statuses
        warning = row["warning"] or missing or any(warning_policy.get(key, True) and value for key, value in (("critical_high", row["critical"] + row["high"]), ("kev", row["kev"]), ("watchlist", row["watchlist"]), ("poam", row["poam"]), ("kind", kind_failed), ("missing_evidence", missing)))
        compliant = not row["noncompliant"] and not policy_fails.get(service.id) and not (missing and configs[service.id].get("incomplete_noncompliant") == "true")
        row["status"] = "RED" if not compliant else "YELLOW" if warning else "GREEN"
        row["attention"] = row["critical"] + row["high"] + row["kev"] + row["watchlist"] + row["poam"] + int(missing) + int(kind_failed)
        rows[service.id] = row
    return rows


def portfolio(db, auth, q="", status="all", attention="all", severity="all", component="", since="", page=1, page_size=50):
    from . import main as m
    try:
        since_date = datetime.fromisoformat(since).date() if since else None
    except ValueError as exc:
        raise HTTPException(422, detail="Invalid since date") from exc
    page_size = max(1, min(int(page_size), 200))
    page = max(1, int(page))
    now = utcnow()
    configuration = m.get_global_configuration(db)
    services, configs = m._overview_services_and_configurations(db, auth, configuration, projected=True)
    services = [service for service in services if service.lifecycle_status == "active"]
    ids = [service.id for service in services]
    configs = {sid: configs[sid] for sid in ids}

    from .service_posture import cyber_rows
    rows_by_id, posture = cyber_rows(db, services, configs, configuration, now)
    rows = [{**rows_by_id[service.id], "service": service} for service in services]
    latest = select(Execution.id.label("id"), Execution.service_id.label("service_id"),
                    func.row_number().over(partition_by=Execution.service_id,
                        order_by=(Execution.scanned_at.desc(), Execution.id.desc())).label("rank")).where(member_of(Execution.service_id, ids, numeric=True)).subquery()
    severity_lower = func.lower(Finding.severity)
    levels = ("critical", "high", "medium", "low")
    failed_statuses = {"FAILED", "COULD_NOT_VALIDATE", "ERROR"}
    component_ids = None
    if component and ids:
        needle = component.casefold()
        component_ids = set(db.scalars(select(Finding.service_id).join(FindingObservation).where(member_of(Finding.service_id, ids, numeric=True), Finding.active.is_(True), func.lower(FindingObservation.package).contains(needle, autoescape=True)).distinct()))
        component_ids.update(db.scalars(select(ServiceImage.service_id).where(member_of(ServiceImage.service_id, ids, numeric=True), func.lower(ServiceImage.image_reference).contains(needle, autoescape=True)).distinct()))
        component_ids.update(db.scalars(select(DependencyWatchlistMatch.service_id).join(latest, and_(latest.c.id == DependencyWatchlistMatch.execution_id, latest.c.rank == 1)).where(or_(func.lower(DependencyWatchlistMatch.component_name).contains(needle, autoescape=True), func.lower(DependencyWatchlistMatch.image).contains(needle, autoescape=True))).distinct()))
    severity_ids = set(db.scalars(select(Finding.service_id).where(member_of(Finding.service_id, ids, numeric=True), Finding.active.is_(True), severity_lower == severity.casefold()).distinct())) if severity != "all" and ids else None
    metrics = {key: sum(row[key] for row in rows) for key in (*levels, "unknown", "vulnerabilities", "kev", "patchable", "watchlist", "poam", "poam_overdue", "missing", "attention")}
    metrics.update(services=len(rows), scanned=sum(row["last_scan"] is not None for row in rows), critical_high=metrics["critical"] + metrics["high"], sbom_coverage=sum(row["sbom"] for row in rows), kind_failed=sum(row["kind"] in failed_statuses for row in rows))
    metrics.update({color.lower(): sum(row["status"] == color for row in rows) for color in ("GREEN", "YELLOW", "RED")})
    filtered = [row for row in rows if (not q or q.casefold() in row["service"].name.casefold() or q.casefold() in row["service"].service_key.casefold()) and (status == "all" or row["status"] == status) and (severity_ids is None or row["service"].id in severity_ids) and (component_ids is None or row["service"].id in component_ids) and (not since_date or row["last_scan"] and m.aware(row["last_scan"]).date() >= since_date) and (attention == "all" or (attention in {"kev", "watchlist", "poam", "missing"} and row[attention]) or (attention == "kind" and row["kind"] in failed_statuses))]
    total = len(filtered)
    pages = max(1, ceil(total / page_size))
    page = min(page, pages)
    data = cybersecurity_data(dict(rows=filtered[(page-1)*page_size:page*page_size], metrics=metrics, q=q, status=status, attention=attention, severity=severity, component=component, since=since), format_date=lambda value: m.configured_time(value, configuration=configuration))
    data.pop("history", None)
    data["services"] = [{"service_key": service.service_key, "name": service.name} for service in services]
    data["pagination"] = {"page": page, "page_size": page_size, "total": total, "pages": pages, "has_previous": page > 1, "has_next": page < pages}
    data["posture_refreshing"] = posture["refreshing"]
    return data
