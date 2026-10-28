"""Complete POA&M projections with SQL ordering and bounded page hydration."""
from types import SimpleNamespace
from urllib.parse import quote, urlencode

from fastapi import HTTPException
from sqlalchemy import select, func, case, literal, union_all, and_
from sqlalchemy.orm import selectinload

from .models import (PoamEntry, Finding, PolicyFinding, ExceptionRecord,
                     PolicyExceptionRecord, WorkflowRequest, utcnow)


FILTERS = {'all', 'active', 'pending_approval', 'overdue', 'completed', 'rejected',
           'expired', 'revoked', 'scheduled', 'cancelled'}


def exception_status(exception, now):
    current = now.replace(tzinfo=None)
    if exception.revoked_at:
        return 'revoked'
    if exception.expires_at and exception.expires_at.replace(tzinfo=None) <= current:
        return 'expired'
    if exception.starts_at and exception.starts_at.replace(tzinfo=None) > current:
        return 'scheduled'
    return 'active'


def poam_rows_query(now):
    """Scalar keys only: approved requests are represented by their actual records.

    Requests linked to a POA&M already have a row, and must not appear twice.
    Existing remediation entries, including mitigations, retain their identities.
    """
    severity = case((Finding.id.is_not(None), Finding.severity), else_=PolicyFinding.severity)
    entries = select(literal('poam').label('source_type'), PoamEntry.id.label('id'),
        PoamEntry.service_id.label('service_id'), PoamEntry.title.label('title'),
        PoamEntry.status.label('status'), PoamEntry.due_date.label('due_date'),
        PoamEntry.created_at.label('created_at'), severity.label('severity')).outerjoin(
        Finding, Finding.id == PoamEntry.finding_id).outerjoin(
        PolicyFinding, PolicyFinding.id == PoamEntry.policy_finding_id)
    sources = [entries]
    for model, target, key, identifier, source in (
        (ExceptionRecord, Finding, 'finding_id', Finding.cve, 'exception'),
        (PolicyExceptionRecord, PolicyFinding, 'policy_finding_id', PolicyFinding.finding, 'policy_exception'),
    ):
        status = case((model.revoked_at.is_not(None), 'revoked'),
            (model.expires_at <= now, 'expired'), (model.starts_at > now, 'scheduled'), else_='active')
        sources.append(select(literal(source), model.id, target.service_id,
            literal('Exception: ') + identifier, status, model.expires_at, model.created_at,
            target.severity).join(target, target.id == getattr(model, key)))
    sources.append(select(literal('workflow'), WorkflowRequest.id, WorkflowRequest.service_id,
        literal('Exception: ') + func.coalesce(Finding.cve, PolicyFinding.finding, literal('Unlinked finding')),
        case((WorkflowRequest.status == 'pending', 'pending_approval'), else_=WorkflowRequest.status),
        WorkflowRequest.requested_expires_at, WorkflowRequest.created_at, severity).outerjoin(
        Finding, Finding.id == WorkflowRequest.finding_id).outerjoin(
        PolicyFinding, PolicyFinding.id == WorkflowRequest.policy_finding_id).where(
        WorkflowRequest.request_type == 'exception', WorkflowRequest.status != 'approved',
        WorkflowRequest.poam_id.is_(None)))
    return union_all(*sources).subquery('service_poam_rows')


def _conditions(rows, status_filter, now, service_ids=None, due_overdue=False):
    if status_filter not in FILTERS:
        raise HTTPException(422, detail='Unknown POA&M filter')
    conditions = []
    if service_ids is not None:
        conditions.append(rows.c.service_id.in_(service_ids))
    if status_filter == 'overdue' or due_overdue:
        conditions.extend((rows.c.status == 'active', rows.c.due_date < now))
    if status_filter not in {'all', 'overdue'}:
        conditions.append(rows.c.status == status_filter)
    return conditions


def _exception_entry(record, source, now, service=None):
    workflow = source == 'workflow'
    finding = getattr(record, 'finding', None)
    policy = getattr(record, 'policy_finding', None)
    target = finding or policy
    service = service or (record.service if workflow else target.service)
    identifier = finding.cve if finding else policy.finding if policy else 'Unlinked finding'
    state = ('pending_approval' if record.status == 'pending' else record.status) if workflow else exception_status(record, now)
    approved = record.reviewed_by if workflow and record.status == 'approved' else None
    if not workflow and record.approved_by:
        approved = SimpleNamespace(display_name=record.approved_by)
    return SimpleNamespace(
        id=f'{source}:{record.id}', source_type=source, source_id=record.id,
        service_id=service.id, service=service, service_version=None,
        finding_id=finding.id if finding else None, policy_finding_id=policy.id if policy else None,
        finding=finding, policy_finding=policy, item_type='exception',
        title=f'Exception: {identifier}', description=record.justification,
        remediation='', ticket=record.ticket, status=state, exception_status=state.replace('_', ' ').title(),
        revoked_at=getattr(record, "revoked_at", None),
        created_at=record.created_at, due_date=record.requested_expires_at if workflow else record.expires_at,
        created_by=record.requested_by if workflow else None, approved_by=approved,
        approved_at=record.reviewed_at if workflow and approved else record.starts_at if not workflow else None,
        detail_url=(f'/services/{quote(service.service_key, safe="")}/findings/{finding.id}' if finding else
                    f'/services/{quote(service.service_key, safe="")}?finding_type=configuration&finding_state=exceptions'),
    )


def _hydrate(db, keys, now):
    keys = list(keys)
    grouped = {kind: [row.id for row in keys if row.source_type == kind]
               for kind in ('poam', 'exception', 'policy_exception', 'workflow')}
    objects = {}
    if grouped['poam']:
        entries = db.scalars(select(PoamEntry).where(PoamEntry.id.in_(grouped['poam'])).options(
            selectinload(PoamEntry.service), selectinload(PoamEntry.finding),
            selectinload(PoamEntry.policy_finding), selectinload(PoamEntry.created_by),
            selectinload(PoamEntry.approved_by))).all()
        for entry in entries:
            entry.source_type = 'poam'
            entry.detail_url = f'/poam/entries/{entry.id}'
            objects[('poam', entry.id)] = entry
    for source, model, relation in (
        ('exception', ExceptionRecord, ExceptionRecord.finding),
        ('policy_exception', PolicyExceptionRecord, PolicyExceptionRecord.policy_finding),
        ('workflow', WorkflowRequest, None),
    ):
        if not grouped[source]:
            continue
        if source == 'workflow':
            options = [selectinload(WorkflowRequest.service), selectinload(WorkflowRequest.finding),
                selectinload(WorkflowRequest.policy_finding), selectinload(WorkflowRequest.requested_by),
                selectinload(WorkflowRequest.reviewed_by)]
        else:
            target = Finding if source == 'exception' else PolicyFinding
            options = [selectinload(relation).selectinload(target.service)]
        records = db.scalars(select(model).where(model.id.in_(grouped[source])).options(*options)).all()
        for record in records:
            objects[(source, record.id)] = _exception_entry(record, source, now)
    return [objects[(key.source_type, key.id)] for key in keys]


def service_poam_page(db, service_id, now, status_filter, sort_by, page, page_size):
    if sort_by not in {'newest', 'due', 'severity'}:
        raise HTTPException(422, detail='Unknown POA&M sort')
    if page < 1 or page_size not in {25, 50, 100}:
        raise HTTPException(422, detail='Invalid POA&M pagination')
    rows = poam_rows_query(now)
    conditions = _conditions(rows, status_filter, now, [service_id])
    total = db.scalar(select(func.count()).select_from(rows).where(*conditions)) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    ordering = []
    if sort_by != 'newest':
        if db.get_bind().dialect.name == 'sqlite':
            db.connection().connection.driver_connection.create_function(
                'cats_python_lower', 1, lambda value: value.lower(), deterministic=True)
            title_key = func.cats_python_lower(rows.c.title).collate('BINARY')
        else:
            # Preserve Python Unicode lower semantics while hydrating only this page.
            titles = db.scalars(select(rows.c.title).where(*conditions).distinct()).all()
            title_key = (case({title: title.lower() for title in titles},
                              value=rows.c.title, else_=literal('')) if titles else literal('')).collate('C')
        if sort_by == 'due':
            ordering.extend((rows.c.due_date.asc().nulls_last(), title_key))
        else:
            ordering.extend((case({'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Negligible': 4},
                                  value=rows.c.severity, else_=5), title_key))
    keys = db.execute(select(rows.c.source_type, rows.c.id).where(*conditions).order_by(
        *ordering, rows.c.created_at.desc(), rows.c.source_type, rows.c.id.asc())
        .offset((page - 1) * page_size).limit(page_size)).all()
    return _hydrate(db, keys, now), {'page': page, 'page_size': page_size, 'page_count': pages, 'total_items': total}


def poam_export_entries(db, service_ids=None, *, status_filter='all', due_overdue=False, now=None):
    now = now or utcnow()
    rows = poam_rows_query(now)
    keys = db.execute(select(rows.c.source_type, rows.c.id).where(
        *_conditions(rows, status_filter, now, service_ids, due_overdue)).order_by(
        rows.c.service_id, rows.c.created_at.desc(), rows.c.source_type, rows.c.id)).all()
    return _hydrate(db, keys, now)


def poam_service_summaries(db, service_ids, now):
    rows = poam_rows_query(now)
    return db.execute(select(rows.c.service_id, func.count().label('total'),
        func.sum(case((rows.c.status == 'active', 1), else_=0)).label('active'),
        func.sum(case((rows.c.status == 'pending_approval', 1), else_=0)).label('pending'),
        func.sum(case((and_(rows.c.status == 'active', rows.c.due_date < now), 1), else_=0)).label('overdue'))
        .where(rows.c.service_id.in_(service_ids)).group_by(rows.c.service_id)).mappings()


def pagination_base(service_key, status_filter, sort_by, page_size):
    return '/services/' + quote(service_key, safe='') + '?' + urlencode({
        'poam': 'true', 'status_filter': status_filter, 'sort_by': sort_by, 'page_size': page_size})
