"""Bounded contributors to the permission-scoped Cybersecurity metric cards."""
from fastapi import HTTPException
from sqlalchemy import and_, case, false, func, literal, or_, select, union_all

from .models import DependencyWatchlistMatch, Execution, Finding, FindingObservation, PoamEntry, utcnow
from .risk_sql import evidence_key_boolean
from .sql_sets import member_of


TITLES = {
    "attention": "Attention score", "services": "Services", "scanned": "Scanned services",
    "vulnerabilities": "Vulnerabilities", "critical_high": "Critical and high vulnerabilities",
    "patchable": "Patchable vulnerabilities", "missing": "Missing evidence",
    "critical": "Critical vulnerabilities", "high": "High vulnerabilities",
    "medium": "Medium vulnerabilities", "low": "Low vulnerabilities", "unknown": "Other or unknown severity",
    "green": "Green services", "yellow": "Yellow services", "red": "Red services",
    "sbom_coverage": "SBOM coverage", "kev": "Known exploited vulnerabilities",
    "watchlist": "Dependency watchlist matches", "poam": "Active POA&M entries",
    "poam_overdue": "Overdue POA&M entries", "kind_failed": "Failed deployment validations",
}
FINDING_METRICS = {"vulnerabilities", "critical_high", "patchable", "critical", "high", "medium", "low", "unknown", "kev"}
FAILED = {"FAILED", "COULD_NOT_VALIDATE", "ERROR"}


def _count(row, metric):
    if metric == "services":
        return 1
    if metric == "scanned":
        return int(row["last_scan"] is not None)
    if metric == "critical_high":
        return row["critical"] + row["high"]
    if metric == "sbom_coverage":
        return int(row["sbom"])
    if metric == "kind_failed":
        return int(row["kind"] in FAILED)
    if metric in {"green", "yellow", "red"}:
        return int(row["status"] == metric.upper())
    return int(row[metric])


def metric_details(db, auth, metric):
    """Use posture for exact service contributions and SQL for top-ten evidence."""
    if metric not in TITLES:
        raise HTTPException(422, detail="Unknown Cybersecurity metric")
    from . import main as m
    from .service_posture import cyber_rows

    now = utcnow()
    configuration = m.get_global_configuration(db)
    services, configs = m._overview_services_and_configurations(db, auth, configuration, projected=True)
    services = [service for service in services if service.lifecycle_status == "active"]
    rows, _ = cyber_rows(db, services, {service.id: configs[service.id] for service in services}, configuration, now)
    contributors = [(service, _count(rows[service.id], metric)) for service in services if service.id in rows]
    contributors = [(service, count) for service, count in contributors if count > 0]
    contributors.sort(key=lambda item: (-item[1], item[0].name.casefold(), item[0].service_key))
    description = "Top 10 contributors across the active services you can view. Counts use the same scope as the dashboard metric."
    if metric == "attention":
        description += " The score adds critical/high findings, KEV findings, watchlist matches, active POA&Ms, missing evidence and failed validations; a finding can contribute twice."
    result = dict(title=TITLES[metric], description=description,
                  services=[dict(service_key=service.service_key, name=service.name, count=count)
                            for service, count in contributors[:10]], cves=[], packages=[])
    ids = [service.id for service, _ in contributors]
    if not ids:
        return result

    parts = []
    # One observation per active finding, matching dashboard_portfolio.compute_rows.
    observations = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("id")).join(
        Finding, Finding.id == FindingObservation.finding_id).where(
        member_of(Finding.service_id, ids, numeric=True), Finding.active.is_(True)).group_by(FindingObservation.finding_id).subquery()
    observation_join = and_(observations.c.finding_id == Finding.id)
    severity = func.lower(Finding.severity)
    catalog = m.kev_cves()
    kev = or_(member_of(Finding.cve, catalog) if catalog else false(), func.coalesce(
        evidence_key_boolean(FindingObservation.evidence, "kev"),
        evidence_key_boolean(FindingObservation.evidence, "known_exploited"), False))
    if metric in FINDING_METRICS or metric == "attention":
        condition = literal(True)
        weight = literal(1)
        if metric in {"critical", "high", "medium", "low"}:
            condition = severity == metric
        elif metric == "unknown":
            condition = ~severity.in_(("critical", "high", "medium", "low"))
        elif metric == "critical_high":
            condition = severity.in_(("critical", "high"))
        elif metric == "kev":
            condition = kev
        elif metric == "patchable":
            condition = and_(FindingObservation.fixed_version.is_not(None), FindingObservation.fixed_version != "")
        elif metric == "attention":
            weight = case((severity.in_(("critical", "high")), 1), else_=0) + case((kev, 1), else_=0)
            condition = weight > 0
        parts.append(select(Finding.cve.label("cve"), FindingObservation.package.label("package"), weight.label("weight"))
                     .outerjoin(observations, observation_join).outerjoin(FindingObservation, FindingObservation.id == observations.c.id)
                     .where(member_of(Finding.service_id, ids, numeric=True), Finding.active.is_(True), condition))
    if metric in {"watchlist", "attention"}:
        latest = select(Execution.id.label("id"), func.row_number().over(partition_by=Execution.service_id,
            order_by=(Execution.scanned_at.desc(), Execution.id.desc())).label("rank")).where(
                member_of(Execution.service_id, ids, numeric=True)).subquery()
        parts.append(select(literal(None).label("cve"), DependencyWatchlistMatch.component_name.label("package"), literal(1).label("weight"))
                     .join(latest, and_(latest.c.id == DependencyWatchlistMatch.execution_id, latest.c.rank == 1))
                     .where(member_of(DependencyWatchlistMatch.service_id, ids, numeric=True)))
    if metric in {"poam", "poam_overdue", "attention"}:
        # POA&Ms count once per active entry, including multiple entries for a finding.
        query = select(Finding.cve.label("cve"), FindingObservation.package.label("package"), literal(1).label("weight"))
        query = query.select_from(PoamEntry).outerjoin(Finding, Finding.id == PoamEntry.finding_id)
        # POA&M findings may be inactive; use their latest retained observation.
        latest_poam = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("id")).join(
            Finding, Finding.id == FindingObservation.finding_id).where(member_of(Finding.service_id, ids, numeric=True)).group_by(FindingObservation.finding_id).subquery()
        query = query.outerjoin(latest_poam, latest_poam.c.finding_id == Finding.id).outerjoin(FindingObservation, FindingObservation.id == latest_poam.c.id)
        query = query.where(member_of(PoamEntry.service_id, ids, numeric=True), PoamEntry.status == "active",
                            or_(Finding.id.is_(None), Finding.service_id == PoamEntry.service_id))
        if metric == "poam_overdue":
            query = query.where(PoamEntry.due_date < now)
        parts.append(query)
    if parts:
        evidence = (union_all(*parts) if len(parts) > 1 else parts[0]).subquery()
        for column, output, key in ((evidence.c.cve, "cves", "cve"), (evidence.c.package, "packages", "package")):
            count = func.sum(evidence.c.weight)
            query = select(column, count).where(column.is_not(None), column != "").group_by(column).order_by(count.desc(), column).limit(10)
            result[output] = [{key: value, "count": int(total)} for value, total in db.execute(query)]
    return result
