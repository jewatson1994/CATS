"""Scalar projections for the findings page, without loading evidence history.

Risk and compliance still require one scalar row per finding. This is an
intentional service-sized scan, not a paginated risk evaluation. Evidence is
bounded to the latest observation per finding; page support loads only the
selected findings' relevant execution.
"""
from types import SimpleNamespace
import json

from sqlalchemy import func, select, tuple_, text

from .models import (
    ExceptionRecord, Execution, Finding, FindingObservation, Group,
    PoamEntry, PolicyExceptionRecord, PolicyFinding, ServiceArchiveEvent,
    ServiceGroup, ServiceVersion,
)

# Pair predicates bind two values per finding. Leave room below SQLite's
# historical 999-variable limit for service and window predicates.
SUPPORT_BATCH_SIZE = 400


def _rows(db, model, *conditions, order_by=None):
    statement = select(*model.__table__.columns).where(*conditions)
    if order_by is not None:
        statement = statement.order_by(order_by)
    return [SimpleNamespace(**dict(row)) for row in db.execute(statement).mappings()]


def prepare_findings_view(db, service, now, configuration, service_view_callback, *, include_global_latest=True):
    """Return the existing view contract backed by scalar, history-free adapters."""
    proxy = SimpleNamespace(**{
        column.key: getattr(service, column.key) for column in service.__table__.columns
    })
    proxy.findings = _rows(db, Finding, Finding.service_id == service.id, order_by=Finding.id)
    proxy.policy_findings = _rows(db, PolicyFinding, PolicyFinding.service_id == service.id,
                                  order_by=PolicyFinding.id)
    findings = {finding.id: finding for finding in proxy.findings}
    policies = {finding.id: finding for finding in proxy.policy_findings}
    for finding in findings.values():
        finding.exceptions = []
        finding.observations = []
    for finding in policies.values():
        finding.exceptions = []
        finding.type = "Configuration"

    for model, parent_model, foreign_key, parents in (
        (ExceptionRecord, Finding, ExceptionRecord.finding_id, findings),
        (PolicyExceptionRecord, PolicyFinding, PolicyExceptionRecord.policy_finding_id, policies),
    ):
        statement = (select(*model.__table__.columns)
                     .join(parent_model, foreign_key == parent_model.id)
                     .where(parent_model.service_id == service.id, model.revoked_at.is_(None),
                            model.starts_at <= now, model.expires_at > now)
                     .order_by(model.id))
        for row in db.execute(statement).mappings():
            exception = SimpleNamespace(**dict(row))
            parents[getattr(exception, foreign_key.key)].exceptions.append(exception)

    latest_ids = (select(func.max(FindingObservation.id).label("id"))
                  .join(Finding, Finding.id == FindingObservation.finding_id)
                  .where(Finding.service_id == service.id)
                  .group_by(FindingObservation.finding_id).subquery())
    for observation in _rows(db, FindingObservation, FindingObservation.id.in_(select(latest_ids.c.id))):
        findings[observation.finding_id].observations = [observation]

    execution_query = select(Execution).where(Execution.service_id == service.id)
    if service.current_version_id is not None:
        execution_query = execution_query.where(Execution.service_version_id == service.current_version_id)
    latest_execution = db.scalar(execution_query.order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    # The header evaluates the current version, while detail-page evidence has
    # historically used the newest scan across every version. Keep both bounded
    # candidates so callers can retain that distinction without scan history.
    global_latest = db.scalar(select(Execution).where(Execution.service_id == service.id)
                              .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1)) if include_global_latest else latest_execution
    proxy.executions = list({execution.id: execution for execution in (latest_execution, global_latest)
                             if execution is not None}.values())
    archive_query = (select(*ServiceArchiveEvent.__table__.columns)
                     .where(ServiceArchiveEvent.service_id == service.id)
                     .order_by(ServiceArchiveEvent.created_at.desc(), ServiceArchiveEvent.id.desc()).limit(1))
    proxy.archive_events = [SimpleNamespace(**dict(row)) for row in db.execute(archive_query).mappings()]
    group_query = (select(*Group.__table__.columns)
                   .join(ServiceGroup, ServiceGroup.group_id == Group.id)
                   .where(ServiceGroup.service_id == service.id).order_by(Group.id))
    proxy.groups = [SimpleNamespace(**dict(row)) for row in db.execute(group_query).mappings()]
    versions = _rows(db, ServiceVersion, ServiceVersion.id == service.current_version_id) if service.current_version_id else []
    proxy.current_version = versions[0] if versions else None
    proxy.poam_entries = _rows(db, PoamEntry, PoamEntry.service_id == service.id, PoamEntry.status == "active")
    return service_view_callback(proxy, now, configuration), proxy, latest_execution


def load_page_support(db, service_id, findings, latest_execution):
    """Attach relevant scalar observations and return images for selected rows.

    Active findings use the current execution. Historical findings use the
    execution containing their latest observation, matching the legacy page.
    """
    selected = {finding.id: finding for finding in findings}
    if not selected:
        return {}
    if len(selected) > SUPPORT_BATCH_SIZE:
        items = list(selected.values())
        images = {}
        for start in range(0, len(items), SUPPORT_BATCH_SIZE):
            images.update(load_page_support(db, service_id,
                                            items[start:start + SUPPORT_BATCH_SIZE],
                                            latest_execution))
        return images
    latest = (select(FindingObservation.finding_id,
                     func.max(FindingObservation.id).label("id"))
              .join(Finding, Finding.id == FindingObservation.finding_id)
              .where(Finding.service_id == service_id, Finding.id.in_(selected))
              .group_by(FindingObservation.finding_id).subquery())
    execution_by_finding = dict(db.execute(
        select(FindingObservation.finding_id, FindingObservation.execution_id)
        .join(latest, latest.c.id == FindingObservation.id)
    ).all())
    for finding in selected.values():
        # A complete scan observed every active finding. An incomplete one may
        # not have, so its active findings keep their own latest observation.
        if finding.active and latest_execution and getattr(latest_execution, "complete", True):
            execution_by_finding[finding.id] = latest_execution.id
    observations_by_finding = {finding_id: [] for finding_id in selected}
    # Match exact pairs so a page containing several historical executions does
    # not accidentally retrieve each selected finding's history across them.
    if execution_by_finding:
        observations = _rows(
            db, FindingObservation,
            tuple_(FindingObservation.finding_id, FindingObservation.execution_id)
            .in_(list(execution_by_finding.items())),
            order_by=FindingObservation.id,
        )
        for observation in observations:
            if execution_by_finding.get(observation.finding_id) == observation.execution_id:
                observations_by_finding[observation.finding_id].append(observation)
    for finding in selected.values():
        if isinstance(finding, SimpleNamespace):
            finding.observations = observations_by_finding[finding.id]
    return {finding_id: sorted({observation.image for observation in observations})
            for finding_id, observations in observations_by_finding.items()}


def load_filter_support(db, service_id, findings):
    """Load at most twenty scalar observations per projected search candidate.

    Call only when query/resource filters are present. The window is evaluated
    in SQL, preserving the legacy latest-twenty search surface without fetching
    the history into application memory.
    """
    selected = {finding.id: finding for finding in findings}
    if not selected:
        return
    if len(selected) > SUPPORT_BATCH_SIZE:
        items = list(selected.values())
        for start in range(0, len(items), SUPPORT_BATCH_SIZE):
            load_filter_support(db, service_id, items[start:start + SUPPORT_BATCH_SIZE])
        return
    ranked = (select(FindingObservation.id,
                     func.row_number().over(partition_by=FindingObservation.finding_id,
                                            order_by=FindingObservation.id.desc()).label("position"))
              .join(Finding, Finding.id == FindingObservation.finding_id)
              .where(Finding.service_id == service_id, Finding.id.in_(selected)).subquery())
    observations = _rows(db, FindingObservation,
                         FindingObservation.id.in_(select(ranked.c.id).where(ranked.c.position <= 20)),
                         order_by=FindingObservation.id.desc())
    for finding in selected.values():
        if isinstance(finding, SimpleNamespace):
            finding.observations = []
    for observation in observations:
        finding = selected[observation.finding_id]
        if isinstance(finding, SimpleNamespace):
            finding.observations.append(observation)


def load_simplified_support(db, service_id, findings, latest_execution):
    """Load current evidence before grouping, with latest-ever fallback.

    Unlike page images, simplified remediation uses the latest-ever observation
    when a finding has no current execution evidence. Current image sets still
    remain empty in that case because the fallback retains its execution ID.
    """
    selected = {finding.id: finding for finding in findings if finding.active}
    if not selected:
        return
    # Preserve latest-ever evidence already supplied by the risk projection or
    # bounded search support before replacing observations with current rows.
    fallbacks = {finding.id: max(finding.observations, key=lambda row: row.id, default=None)
                 for finding in selected.values()}
    load_page_support(db, service_id, selected.values(), latest_execution)
    for finding in selected.values():
        if isinstance(finding, SimpleNamespace) and not finding.observations and fallbacks[finding.id]:
            finding.observations = [fallbacks[finding.id]]


def group_simplified_findings(findings, latest_execution, due_dates):
    """Preserve remediation groups while deduplicating CVEs in linear time."""
    simplified_groups = {}
    seen_cves = {}
    for finding in findings:
        observations = [o for o in finding.observations if latest_execution and o.execution_id == latest_execution.id]
        observation = max(observations or finding.observations, key=lambda item: item.id, default=None)
        evidence = observation.evidence if observation else {}
        package = (observation.package if observation else None) or "Package update"
        fixed = (observation.fixed_version if observation else None) or "Latest fixed version"
        remediation = evidence.get("remediation") or evidence.get("recommendation") or "Update the affected package to the fixed version."
        key = (package, str(remediation))
        group = simplified_groups.setdefault(key, {
            "package": package, "fixed_versions": set(), "remediation": str(remediation),
            "cves": [], "images": set(), "severities": [], "finding_ids": [],
            "due": due_dates.get(finding.id),
        })
        cve = str(finding.cve or "").strip().upper()
        seen = seen_cves.setdefault(key, set())
        if cve and cve not in seen:
            seen.add(cve)
            group["cves"].append(cve)
            group["finding_ids"].append(finding.id)
        group["fixed_versions"].add(str(fixed))
        group["severities"].append(finding.severity)
        group["due"] = min(group["due"], due_dates.get(finding.id)) if group["due"] and due_dates.get(finding.id) else group["due"]
        group["images"].update(o.image for o in observations if o.image)
    severity_rank = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    simplified_findings = []
    for group in simplified_groups.values():
        ordered_findings = sorted(zip(group["cves"], group["finding_ids"]))
        group["cves"] = [cve for cve, _ in ordered_findings]
        group["finding_ids"] = [finding_id for _, finding_id in ordered_findings]
        group["images"] = sorted(group["images"])
        group["fixed_versions"] = sorted(group["fixed_versions"])
        group["fixed_version"] = ", ".join(group["fixed_versions"])
        group["severity"] = max(group["severities"], key=lambda value: severity_rank.get(str(value).lower(), 0), default="Unknown")
        simplified_findings.append(group)
    simplified_findings.sort(key=lambda item: (str(item["package"]).casefold(), str(item["fixed_version"]).casefold()))
    return simplified_findings


def _group_evidence_value(db, evidence, key):
    """Retain JSON booleans instead of SQLite JSON_EXTRACT's integer coercion."""
    if db.get_bind().dialect.name != 'sqlite':
        return evidence[key]
    from sqlalchemy import case, type_coerce
    path = '$.' + key
    return type_coerce(case(
        (func.json_type(evidence, path) == 'true', 'true'),
        (func.json_type(evidence, path) == 'false', 'false'),
        else_=func.json_quote(func.json_extract(evidence, path))), FindingObservation.evidence.type)


def page_simplified_findings(db, service_id, findings, latest_execution, due_dates, page, page_size, *, grouping_metadata=None):
    """Page scalar group keys in SQL before loading current observation details.

    Canonical risk/search eligibility and Python JSON/Unicode grouping semantics
    still require service-sized scalar work. Images, complete evidence rows and
    display groups are assembled only for selected groups. Complete CVE lists
    require all member scalars, but never require full observation hydration.
    """
    selected = {finding.id: finding for finding in findings}
    latest_current = (select(FindingObservation.finding_id,
                             func.max(FindingObservation.id).label('observation_id'))
                      .join(Finding, Finding.id == FindingObservation.finding_id)
                      .where(Finding.service_id == service_id,
                             FindingObservation.execution_id == (latest_execution.id if latest_execution else -1))
                      .group_by(FindingObservation.finding_id).subquery())
    # Only grouping columns cross the boundary; current image sets stay unloaded.
    current = dict(grouping_metadata or {})
    statement = select(FindingObservation.finding_id, FindingObservation.package,
                       FindingObservation.fixed_version, _group_evidence_value(db, FindingObservation.evidence, 'remediation'),
                       _group_evidence_value(db, FindingObservation.evidence, 'recommendation')).join(
                           latest_current, latest_current.c.observation_id == FindingObservation.id)
    if grouping_metadata is None:
        ids_json = json.dumps(list(selected))
        id_source = ('SELECT CAST(value AS INTEGER) FROM json_each(:candidate_ids)'
                     if db.get_bind().dialect.name == 'sqlite' else
                     'SELECT CAST(value AS INTEGER) FROM json_array_elements_text(CAST(:candidate_ids AS JSON))')
        statement = statement.where(FindingObservation.finding_id.in_(text(id_source)))
    for finding_id, package, fixed, remediation, recommendation in ([] if grouping_metadata is not None else db.execute(statement, {'candidate_ids': ids_json})):
        if finding_id in selected:
            current[finding_id] = (package, fixed, remediation, recommendation)
    groups = {}
    grouping_rows = {}
    for finding in findings:
        if finding.id in current:
            package, fixed, remediation, recommendation = current[finding.id]
        else:
            observation = max(finding.observations, key=lambda item: item.id, default=None)
            evidence = observation.evidence if observation else {}
            package = observation.package if observation else None
            fixed = observation.fixed_version if observation else None
            remediation, recommendation = evidence.get('remediation'), evidence.get('recommendation')
        package = package or 'Package update'
        remediation = str(remediation or recommendation or 'Update the affected package to the fixed version.')
        key = (package, remediation)
        grouping_rows[finding.id] = (package, fixed, remediation)
        group = groups.setdefault(key, {'ids': [], 'fixed': set()})
        group['ids'].append(finding.id)
        group['fixed'].add(str(fixed or 'Latest fixed version'))
    metadata = [[index, str(key[0]).casefold(), ', '.join(sorted(group['fixed'])).casefold()]
                for index, (key, group) in enumerate(groups.items())]
    encoded = json.dumps(metadata, ensure_ascii=False)
    if db.get_bind().dialect.name == 'sqlite':
        source = "SELECT CAST(json_extract(value, '$[0]') AS INTEGER) AS idx, json_extract(value, '$[1]') AS package, json_extract(value, '$[2]') AS fixed FROM json_each(:metadata)"
        collation = 'BINARY'
    else:
        source = "SELECT CAST(value->>0 AS INTEGER) AS idx, value->>1 AS package, value->>2 AS fixed FROM json_array_elements(CAST(:metadata AS JSON))"
        collation = 'C'
    total = db.scalar(text('SELECT count(*) FROM (' + source + ') AS groups'), {'metadata': encoded}) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, pages))
    indexes = db.scalars(text('SELECT idx FROM (' + source + ') AS groups ORDER BY package COLLATE "'
        + collation + '", fixed COLLATE "' + collation + '", idx LIMIT :limit OFFSET :offset'),
        {'metadata': encoded, 'limit': page_size, 'offset': (page - 1) * page_size}).all()
    group_values = list(groups.values())
    page_ids = {finding_id for index in indexes for finding_id in group_values[index]['ids']}
    page_findings = [finding for finding in findings if finding.id in page_ids]
    # Group metadata already identifies the exact remediation and fixed version.
    # Rehydrating every member's full evidence repeats that work and can load an
    # entire service when only a few large groups exist. Keep the complete CVE
    # membership, but build groups from lightweight adapters instead.
    def adapters():
        for finding in page_findings:
            package, fixed, remediation = grouping_rows[finding.id]
            yield SimpleNamespace(
                id=finding.id, cve=finding.cve, severity=finding.severity,
                observations=[SimpleNamespace(id=0, execution_id=-1, package=package,
                    fixed_version=fixed, evidence={'remediation': remediation}, image=None)])
    result = group_simplified_findings(adapters(), latest_execution, due_dates)
    if page_ids and latest_execution:
        encoded_ids = json.dumps(sorted(page_ids))
        if db.get_bind().dialect.name == 'sqlite':
            selected_ids = 'SELECT CAST(value AS INTEGER) FROM json_each(:ids)'
        else:
            selected_ids = 'SELECT CAST(value AS INTEGER) FROM json_array_elements_text(CAST(:ids AS JSON))'
        # The server filters members and deduplicates images before transfer.
        # No full observations, evidence documents or history cross this boundary.
        image_rows = db.execute(select(FindingObservation.finding_id, FindingObservation.image)
            .where(FindingObservation.finding_id.in_(text(selected_ids)),
                   FindingObservation.execution_id == latest_execution.id,
                   FindingObservation.image.is_not(None), FindingObservation.image != '')
            .distinct(), {'ids': encoded_ids})
        images_by_key = {(group['package'], group['remediation']): set() for group in result}
        for finding_id, image in image_rows:
            package, _, remediation = grouping_rows[finding_id]
            images_by_key[(package, remediation)].add(image)
        for group in result:
            group['images'] = sorted(images_by_key[(group['package'], group['remediation'])])
    return result, {'page': page, 'total_items': total, 'total_pages': pages}


def prepare_simplified_candidates(db, service, now, configuration, latest_execution):
    """Transfer eligible member scalars and exact JSON grouping keys once.

    Exceptions and canonical risk membership are evaluated by the database.
    Python retains arbitrary JSON truth/string semantics and Unicode ordering.
    """
    from datetime import timedelta
    from sqlalchemy import case
    from sqlalchemy.orm import aliased
    from .main import _risk_finding_expressions, aware
    exception = select(ExceptionRecord.id).where(
        ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None),
        ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
    eligible, noncompliant, _ = _risk_finding_expressions({service.id: configuration}, now, exception)
    latest_ids = (select(FindingObservation.finding_id,
        func.max(FindingObservation.id).label('id')).join(Finding,
        Finding.id == FindingObservation.finding_id).where(Finding.service_id == service.id)
        .group_by(FindingObservation.finding_id).subquery())
    current_ids = (select(FindingObservation.finding_id,
        func.max(FindingObservation.id).label('id')).join(Finding,
        Finding.id == FindingObservation.finding_id).where(Finding.service_id == service.id,
        FindingObservation.execution_id == (latest_execution.id if latest_execution else -1))
        .group_by(FindingObservation.finding_id).subquery())
    current = aliased(FindingObservation)
    # JSON CASE returns raw JSON on SQLite; apply SQLAlchemy's JSON result
    # processor to preserve nested values and booleans without SQL coercion.
    from sqlalchemy import type_coerce
    def chosen(column):
        value = case((current.id.is_not(None), getattr(current, column)),
                     else_=getattr(FindingObservation, column))
        return type_coerce(value, FindingObservation.evidence.type) if column == 'evidence' else value
    evidence = chosen('evidence')
    statement = (select(Finding.id, Finding.cve, Finding.severity, Finding.episode_started,
        chosen('package'), chosen('fixed_version'), _group_evidence_value(db, evidence, 'remediation'),
        _group_evidence_value(db, evidence, 'recommendation'))
        .outerjoin(latest_ids, latest_ids.c.finding_id == Finding.id)
        .outerjoin(FindingObservation, FindingObservation.id == latest_ids.c.id)
        .outerjoin(current_ids, current_ids.c.finding_id == Finding.id)
        .outerjoin(current, current.id == current_ids.c.id)
        .where(Finding.service_id == service.id, Finding.active.is_(True), eligible,
               ~noncompliant, ~exception).order_by(Finding.id))
    overdue_days = max(1, int(configuration.get('overdue_days', '90')))
    try:
        rules = json.loads(configuration.get('raw_due_rules', '[]'))
    except (TypeError, ValueError):
        rules = []
    raw_due = {str(rule.get('severity', '')).lower(): max(1, int(rule.get('days', overdue_days)))
               for rule in rules}
    findings, keys, due = [], {}, {}
    for finding_id, cve, severity, started, package, fixed, remediation, recommendation in db.execute(statement):
        findings.append(SimpleNamespace(id=finding_id, cve=cve, severity=severity, active=True, observations=[]))
        keys[finding_id] = (package, fixed, remediation, recommendation)
        days = raw_due.get(severity.lower(), overdue_days) if configuration.get('compliance_mode') == 'raw' else overdue_days
        due[finding_id] = aware(started) + timedelta(days=days)
    # Same visibility set used by the legacy severity dropdown: active eligible
    # compliant, eligible exceptions, resolved, plus every policy lifecycle.
    severity_statement = select(Finding.severity).outerjoin(latest_ids, latest_ids.c.finding_id == Finding.id).outerjoin(
        FindingObservation, FindingObservation.id == latest_ids.c.id).where(Finding.service_id == service.id,
        (Finding.active.is_(False)) | (eligible & (exception | ~noncompliant))).distinct()
    values = set(db.scalars(severity_statement)) | set(db.scalars(select(PolicyFinding.severity)
        .where(PolicyFinding.service_id == service.id).distinct()))
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
    severity_options = sorted({str(value) for value in values if value},
        key=lambda value: (order.get(value.casefold(), 4), value.casefold()))
    return findings, keys, due, severity_options
