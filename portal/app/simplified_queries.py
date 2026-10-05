"""Database grouped findings. Members are never hydrated by a group request.

Grouping strings are derived at observation write time, preserving Python JSON
truth/string and Unicode casefold semantics without reading evidence on GET.
"""
import hashlib
import json
from datetime import timedelta
from sqlalchemy import case, event, func, literal, select, update, inspect
from sqlalchemy.orm import aliased, Session
from .models import Finding, FindingObservation, ExceptionRecord, PolicyFinding


def observation_metadata(values):
    evidence = values.get('evidence') or {}
    package = str(values.get('package') or 'Package update')
    remediation = str(evidence.get('remediation') or evidence.get('recommendation') or
                      'Update the affected package to the fixed version.')
    fixed = str(values.get('fixed_version') or 'Latest fixed version')
    return dict(simplified_key=hashlib.sha256(json.dumps([package, remediation],
        ensure_ascii=False).encode()).hexdigest(), simplified_package=package,
        simplified_remediation=remediation, simplified_fixed=fixed,
        simplified_package_sort=package.casefold(), simplified_fixed_sort=fixed.casefold(),
        search_folded=' '.join(str(values[key])[:500] for key in
            ('image', 'package', 'installed_version', 'fixed_version') if values.get(key)).casefold())


def finding_metadata(values):
    return dict(severity_folded=str(values.get('severity') or '').casefold(),
        cve_normalized=str(values.get('cve') or '').strip().upper(),
        search_folded=' '.join(str(values[key])[:500] for key in ('cve', 'severity') if values.get(key)).casefold())


POLICY_SEARCH_FIELDS = ('finding', 'severity', 'scanner', 'framework', 'target', 'namespace', 'title', 'description')


def policy_metadata(values):
    return dict(severity_folded=str(values.get('severity') or '').casefold(),
        search_folded=' '.join(str(values[key]) for key in POLICY_SEARCH_FIELDS if values.get(key)).casefold()[:5000])


@event.listens_for(Session, 'before_flush')
def normalize_observations(db, context, instances):
    for obj in db.new.union(db.dirty):
        if isinstance(obj, Finding):
            for key, value in finding_metadata({'cve': obj.cve, 'severity': obj.severity}).items():
                setattr(obj, key, value)
        if isinstance(obj, PolicyFinding):
            for key, value in policy_metadata({key: getattr(obj, key) for key in POLICY_SEARCH_FIELDS}).items():
                setattr(obj, key, value)
        if isinstance(obj, FindingObservation):
            state = inspect(obj)
            if obj in db.new or any(state.attrs[key].history.has_changes() for key in
                ('evidence', 'package', 'fixed_version', 'image', 'installed_version')):
                for key, value in observation_metadata({key: getattr(obj, key) for key in
                    ('evidence', 'package', 'fixed_version', 'image', 'installed_version')}).items():
                    setattr(obj, key, value)


def upgrade_projection(connection):
    from sqlalchemy import text
    names = {column['name'] for column in inspect(connection).get_columns('findings')}
    for column in ('severity_folded', 'cve_normalized', 'search_folded'):
        if column not in names:
            connection.execute(text(f'ALTER TABLE findings ADD COLUMN {column} TEXT'))
    while True:
        rows = connection.execute(select(Finding.id, Finding.cve, Finding.severity)
            .where(Finding.search_folded.is_(None)).order_by(Finding.id).limit(250)).mappings().all()
        if not rows: break
        for row in rows:
            connection.execute(update(Finding).where(Finding.id == row['id']).values(**finding_metadata(row)))
    names = {column['name'] for column in inspect(connection).get_columns('policy_findings')}
    for column in ('severity_folded', 'search_folded'):
        if column not in names:
            connection.execute(text(f'ALTER TABLE policy_findings ADD COLUMN {column} TEXT'))
    while True:
        rows = connection.execute(select(PolicyFinding.id, *(getattr(PolicyFinding, key) for key in POLICY_SEARCH_FIELDS))
            .where(PolicyFinding.search_folded.is_(None)).order_by(PolicyFinding.id).limit(250)).mappings().all()
        if not rows: break
        for row in rows:
            connection.execute(update(PolicyFinding).where(PolicyFinding.id == row['id']).values(**policy_metadata(row)))
    names = {column['name'] for column in inspect(connection).get_columns('finding_observations')}
    for column in ('simplified_key', 'simplified_package', 'simplified_remediation',
                   'simplified_fixed', 'simplified_package_sort', 'simplified_fixed_sort', 'search_folded'):
        if column not in names:
            from sqlalchemy import text
            connection.execute(text(f'ALTER TABLE finding_observations ADD COLUMN {column} TEXT'))
    # One-time bounded migration, not an endpoint fallback. Retained evidence is
    # unchanged and remains authoritative. Core/bulk importers may call rebuild.
    while True:
        rows = connection.execute(select(FindingObservation.id, FindingObservation.evidence,
            FindingObservation.package, FindingObservation.fixed_version, FindingObservation.image,
            FindingObservation.installed_version).where(FindingObservation.simplified_key.is_(None))
            .order_by(FindingObservation.id).limit(250)).mappings().all()
        if not rows:
            break
        for row in rows:
            connection.execute(update(FindingObservation).where(FindingObservation.id == row['id'])
                .values(**observation_metadata(row)))
    from sqlalchemy import text
    connection.execute(text('CREATE INDEX IF NOT EXISTS ix_obs_finding_execution_id ON finding_observations (finding_id, execution_id, id)'))


def candidates(db, service, latest, now, configuration, *, state='active', finding_type='all',
               severities=(), query='', resource=''):
    from .main import _risk_finding_expressions
    current = select(func.max(FindingObservation.id)).where(
        FindingObservation.finding_id == Finding.id,
        FindingObservation.execution_id == (latest.id if latest else -1)).correlate(Finding).scalar_subquery()
    ever = select(func.max(FindingObservation.id)).where(
        FindingObservation.finding_id == Finding.id).correlate(Finding).scalar_subquery()
    chosen = aliased(FindingObservation)
    exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id,
        ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now,
        ExceptionRecord.expires_at > now).exists()
    eligible, noncompliant, needs = _risk_finding_expressions({service.id: configuration}, now, exception)
    clauses = [Finding.service_id == service.id]
    if state == 'resolved': clauses.append(Finding.active.is_(False))
    elif state == 'exceptions': clauses.extend((Finding.active.is_(True), eligible, exception))
    elif state in {'noncompliant', 'overdue'}: clauses.extend((Finding.active.is_(True), noncompliant, ~exception))
    elif state == 'active': clauses.extend((Finding.active.is_(True), eligible, ~noncompliant, ~exception))
    elif state == 'warnings': clauses.append(literal(False))
    else: raise ValueError('Unknown finding state')
    if finding_type not in {'all', 'vulnerability', 'configuration', 'evidence', 'watchlist'}:
        raise ValueError('Unknown finding type')
    if finding_type not in {'all', 'vulnerability'}: clauses.append(literal(False))
    if severities: clauses.append(Finding.severity_folded.in_([s.casefold() for s in severities]))
    # Search uses persisted observation text; no JSON/evidence hydration. EXISTS
    # keeps membership and pagination inside the database on both platforms.
    for needle in (query.strip().casefold(), resource.strip().casefold()):
        if needle:
            recent = select(FindingObservation.search_folded.label('text_value')).where(
                FindingObservation.finding_id == Finding.id).order_by(FindingObservation.id.desc())
            recent = recent.limit(20).correlate(Finding).subquery()
            aggregate = (func.group_concat(recent.c.text_value, ' ') if db.get_bind().dialect.name == 'sqlite'
                         else func.string_agg(recent.c.text_value, ' '))
            history = select(aggregate).select_from(recent).where(recent.c.text_value != '').scalar_subquery()
            surface = Finding.search_folded + case((func.coalesce(history, '') != '', literal(' ') + history), else_='')
            clauses.append(surface.contains(needle, autoescape=True))
    rank = case(*[(func.lower(Finding.severity) == name, value) for value, name in
        enumerate(('unknown', 'negligible', 'low', 'medium', 'high', 'critical'))], else_=0)
    statement = select(Finding.id.label('id'), Finding.cve.label('cve'), Finding.cve_normalized.label('cve_normalized'), Finding.severity.label('severity'),
        Finding.active.label('active'), Finding.episode_started.label('started'), rank.label('rank'),
        func.coalesce(chosen.simplified_key, observation_metadata({})['simplified_key']).label('group_id'),
        func.coalesce(chosen.simplified_package, 'Package update').label('package'),
        func.coalesce(chosen.simplified_remediation, 'Update the affected package to the fixed version.').label('remediation'),
        func.coalesce(chosen.simplified_fixed, 'Latest fixed version').label('fixed'),
        func.coalesce(chosen.simplified_package_sort, 'package update').label('package_sort'),
        func.coalesce(chosen.simplified_fixed_sort, 'latest fixed version').label('fixed_sort'))
    statement = statement.select_from(Finding).outerjoin(chosen, chosen.id == func.coalesce(current, ever))
    if needs:
        statement = statement.outerjoin(FindingObservation, FindingObservation.id == ever)
    return statement.where(*clauses).cte('members')


def group_page(db, service, latest, now, configuration, *, page=1, page_size=50, **filters):
    from datetime import datetime, timezone
    from sqlalchemy import String, cast, text
    members = candidates(db, service, latest, now, configuration, **filters)
    # Explicit reuse prevents candidate/risk evaluation for every aggregate.
    members = members.prefix_with('MATERIALIZED', dialect='postgresql').prefix_with('MATERIALIZED', dialect='sqlite')
    dialect = db.get_bind().dialect.name
    default_days = max(1, int(configuration.get('overdue_days', '90')))
    try:
        rules = json.loads(configuration.get('raw_due_rules', '[]'))
    except (TypeError, ValueError):
        rules = []
    due_by_severity = {str(rule.get('severity', '')).lower(): max(1, int(rule.get('days', default_days)))
                       for rule in rules}
    days = (case(*[(func.lower(members.c.severity) == severity, value)
                   for severity, value in due_by_severity.items()], else_=default_days)
            if configuration.get('compliance_mode') == 'raw' and due_by_severity else literal(default_days))
    if dialect == 'postgresql':
        due = func.to_char(members.c.started + days * text("INTERVAL '1 day'"), 'YYYY-MM-DD HH24:MI:SS.US')
        identity = func.lpad(cast(members.c.id, String), 20, '0')
    else:
        due = cast(func.datetime(members.c.started, literal('+') + cast(days, String) + literal(' days')), String) + func.substr(cast(members.c.started, String), 20, 7)
        identity = func.printf('%020d', members.c.id)
    severity_key = cast(5 - members.c.rank, String) + literal(':') + identity + literal(':') + members.c.severity
    cve = members.c.cve_normalized
    groups = select(members.c.group_id, func.min(members.c.package).label('package'),
        func.min(members.c.remediation).label('remediation'), func.min(members.c.package_sort).label('package_sort'),
        func.min(members.c.id).label('first_id'),
        func.count(func.distinct(func.nullif(cve, ''))).label('member_count'),
        func.min(func.nullif(cve, '')).label('representative_cve'),
        func.min(severity_key).label('severity_key'),
        func.min(case((members.c.active.is_(True), due), else_=None)).label('due'))
    groups = groups.group_by(members.c.group_id).cte('groups')
    versions = select(members.c.group_id, members.c.fixed, members.c.fixed_sort).distinct().subquery()
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import aggregate_order_by
        joined_fixed = func.string_agg(versions.c.fixed, aggregate_order_by(literal(', '), versions.c.fixed))
        joined_sort = func.string_agg(versions.c.fixed_sort, aggregate_order_by(literal(', '), versions.c.fixed))
    else:
        versions = select(versions).order_by(versions.c.group_id, versions.c.fixed).subquery()
        joined_fixed = func.group_concat(versions.c.fixed, ', ')
        joined_sort = func.group_concat(versions.c.fixed_sort, ', ')
    fixed_groups = select(versions.c.group_id, joined_fixed.label('fixed_version'),
        joined_sort.label('fixed_sort')).group_by(versions.c.group_id).cte('fixed_groups')
    ordered = select(groups, fixed_groups.c.fixed_sort, func.substr(fixed_groups.c.fixed_version, 1, 1200).label('fixed_version'),
        func.count().over().label('total_items')).join(fixed_groups, fixed_groups.c.group_id == groups.c.group_id)
    ordered = ordered.order_by(groups.c.package_sort, fixed_groups.c.fixed_sort, groups.c.first_id)
    page = max(1, page)
    def statement(selected_page):
        selected = ordered.limit(page_size).offset((selected_page - 1) * page_size).cte('selected_groups')
        representatives = select(members.c.group_id, func.min(members.c.id).label('representative_id')).join(selected,
            (selected.c.group_id == members.c.group_id) & (selected.c.representative_cve == cve))
        representatives = representatives.group_by(members.c.group_id).cte('representatives')
        images = select(members.c.group_id, func.count(func.distinct(FindingObservation.image)).label('image_count'))
        images = images.join(selected, selected.c.group_id == members.c.group_id).join(FindingObservation,
            FindingObservation.finding_id == members.c.id).where(
                FindingObservation.execution_id == (latest.id if latest else -1),
                FindingObservation.image.is_not(None), FindingObservation.image != '')
        images = images.group_by(members.c.group_id).cte('group_images')
        return select(selected.c.group_id, func.substr(selected.c.package, 1, 500).label('package'),
            func.substr(selected.c.remediation, 1, 1200).label('remediation'), selected.c.fixed_version,
            selected.c.member_count, selected.c.representative_cve, representatives.c.representative_id,
            selected.c.severity_key, selected.c.due, selected.c.total_items,
            func.coalesce(images.c.image_count, 0).label('image_count')).select_from(selected).outerjoin(
                representatives, representatives.c.group_id == selected.c.group_id).outerjoin(
                    images, images.c.group_id == selected.c.group_id).order_by(
                        selected.c.package_sort, selected.c.fixed_sort, selected.c.first_id)
    rows = db.execute(statement(page)).mappings().all()
    total = rows[0]['total_items'] if rows else 0
    if not rows and page > 1:
        total = db.scalar(select(func.count()).select_from(groups)) or 0
        page = max(1, (total + page_size - 1) // page_size)
        rows = db.execute(statement(page)).mappings().all() if total else []
    pages = max(1, (total + page_size - 1) // page_size)
    items = []
    for row in rows:
        due_value = datetime.fromisoformat(row['due']).replace(tzinfo=timezone.utc) if row['due'] else None
        items.append(dict(group_id=row['group_id'], package=row['package'], remediation=row['remediation'],
            fixed_version=row['fixed_version'], severity=row['severity_key'].split(':', 2)[2],
            member_count=row['member_count'], representative_finding_id=row['representative_id'],
            representative_cve=row['representative_cve'], image_count=row['image_count'], due=due_value))
    severities = db.scalars(select(Finding.severity).where(Finding.service_id == service.id).distinct()).all()
    return items, dict(page=page, total_pages=pages, total_items=total), sorted(severities)


def member_page(db, service, latest, now, configuration, group_id, *, page=1, page_size=50, **filters):
    """Canonical CVE members, independently paged without observation hydration."""
    members = candidates(db, service, latest, now, configuration, **filters)
    statement = members.element
    members = statement.where(statement.selected_columns.group_id == group_id).cte('members')
    members = members.prefix_with('MATERIALIZED', dialect='postgresql').prefix_with('MATERIALIZED', dialect='sqlite')
    identities = select(members.c.cve_normalized.label('cve'), func.min(members.c.id).label('id')).where(
        members.c.group_id == group_id, members.c.cve_normalized != '').group_by(members.c.cve_normalized).cte('identities')
    total = db.scalar(select(func.count()).select_from(identities)) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, pages))
    selected = select(identities).order_by(identities.c.cve, identities.c.id).limit(page_size).offset(
        (page - 1) * page_size).cte('selected_members')
    images = select(FindingObservation.finding_id, func.count(func.distinct(FindingObservation.image)).label('image_count')).join(
        selected, selected.c.id == FindingObservation.finding_id).where(
            FindingObservation.execution_id == (latest.id if latest else -1),
            FindingObservation.image.is_not(None), FindingObservation.image != '').group_by(FindingObservation.finding_id).subquery()
    rows = db.execute(select(members.c.id, selected.c.cve, members.c.severity, members.c.active,
        func.substr(members.c.package, 1, 500).label('package'), func.substr(members.c.fixed, 1, 1200).label('fixed'),
        func.coalesce(images.c.image_count, 0).label('image_count')).join(selected, selected.c.id == members.c.id).outerjoin(
            images, images.c.finding_id == members.c.id).order_by(selected.c.cve, selected.c.id)).mappings().all()
    return dict(group_id=group_id, items=[dict(id=row['id'], cve=row['cve'], severity=row['severity'],
        active=row['active'], package=row['package'], fixed_version=row['fixed'], image_count=row['image_count']) for row in rows],
        page=page, page_size=page_size, total_pages=pages, total_items=total)
