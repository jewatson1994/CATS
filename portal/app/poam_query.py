"""Scoped POA&M SQL ordering and bounded relationship hydration."""
from urllib.parse import quote, urlencode
from fastapi import HTTPException
from sqlalchemy import select, func, case, literal
from sqlalchemy.orm import selectinload
from .models import PoamEntry, Finding, PolicyFinding


def service_poam_page(db, service_id, now, status_filter, sort_by, page, page_size):
    if status_filter not in {'all', 'active', 'pending_approval', 'overdue', 'completed', 'rejected'}:
        raise HTTPException(422, detail='Unknown POA&M filter')
    if sort_by not in {'newest', 'due', 'severity'}:
        raise HTTPException(422, detail='Unknown POA&M sort')
    if page < 1 or page_size not in {25, 50, 100}:
        raise HTTPException(422, detail='Invalid POA&M pagination')
    conditions = [PoamEntry.service_id == service_id]
    if status_filter == 'overdue':
        conditions.extend((PoamEntry.status == 'active', PoamEntry.due_date < now))
    elif status_filter != 'all':
        conditions.append(PoamEntry.status == status_filter)
    total = db.scalar(select(func.count(PoamEntry.id)).where(*conditions)) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    query = select(PoamEntry).where(*conditions)
    ordering = []
    if sort_by != 'newest':
        if db.get_bind().dialect.name == 'sqlite':
            db.connection().connection.driver_connection.create_function(
                'cats_python_lower', 1, lambda value: value.lower(), deterministic=True)
            title_key = func.cats_python_lower(PoamEntry.title).collate('BINARY')
        else:
            # Database locale lower() differs from Python for some Unicode titles.
            # Read scalar keys only; full entries and relationships stay page bounded.
            titles = db.scalars(select(PoamEntry.title).where(*conditions).distinct()).all()
            title_key = (case({title: title.lower() for title in titles},
                              value=PoamEntry.title, else_=literal('')) if titles else literal('')).collate('C')
        if sort_by == 'due':
            ordering.extend((PoamEntry.due_date.asc().nulls_last(), title_key))
        else:
            query = query.outerjoin(Finding, Finding.id == PoamEntry.finding_id).outerjoin(
                PolicyFinding, PolicyFinding.id == PoamEntry.policy_finding_id)
            severity = case((Finding.id.is_not(None), Finding.severity), else_=PolicyFinding.severity)
            ordering.extend((case({'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Negligible': 4},
                                  value=severity, else_=5), title_key))
    query = query.order_by(*ordering, PoamEntry.created_at.desc(), PoamEntry.id.asc())
    entries = db.scalars(query.options(selectinload(PoamEntry.finding), selectinload(PoamEntry.policy_finding),
        selectinload(PoamEntry.created_by), selectinload(PoamEntry.approved_by))
        .offset((page - 1) * page_size).limit(page_size)).all()
    return entries, {'page': page, 'page_size': page_size, 'page_count': pages, 'total_items': total}


def pagination_base(service_key, status_filter, sort_by, page_size):
    return '/services/' + quote(service_key, safe='') + '?' + urlencode({
        'poam': 'true', 'status_filter': status_filter, 'sort_by': sort_by, 'page_size': page_size})
