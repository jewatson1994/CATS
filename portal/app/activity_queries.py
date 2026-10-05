"""Bounded service audit pages; authorization is applied by the route first."""
from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import selectinload
from .models import AuditEvent


def global_activity_page(db, *, cutoff=None, action='', page=1, page_size=50):
    """Global audit permission is checked by the route before this query."""
    page_size = max(1, min(int(page_size), 200))
    scope = []
    if cutoff is not None:
        scope.append(AuditEvent.created_at >= cutoff)
    if action:
        scope.append(AuditEvent.action == action)
    total = db.scalar(select(func.count()).select_from(AuditEvent).where(*scope)) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(int(page), pages))
    events = db.scalars(select(AuditEvent).where(*scope).options(selectinload(AuditEvent.actor))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size).limit(page_size)).all()
    return dict(events=events, page=page, page_size=page_size, page_count=pages,
                retained_count=total, shown_count=len(events))


def service_activity_page(db, service_id, page=1, page_size=50):
    page_size = max(1, min(int(page_size), 200))
    scalar_id = AuditEvent.detail["service_id"]
    if db.get_bind().dialect.name == "postgresql":
        scalar_type = func.json_typeof(scalar_id)
        types = ("string", "number")
    else:
        scalar_type = func.json_type(AuditEvent.detail, "$.service_id")
        types = ("text", "integer", "real")
    scope = (scalar_type.in_(types), cast(scalar_id.as_string(), String) == str(service_id))
    total = db.scalar(select(func.count()).select_from(AuditEvent).where(*scope)) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(int(page), pages))
    events = db.scalars(select(AuditEvent).where(*scope)
        .options(selectinload(AuditEvent.actor))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size).limit(page_size)).all()
    return dict(events=events, page=page, page_size=page_size,
                page_count=pages, total_items=total)


def latest_evidence_execution(db, service_id, *, architecture=False):
    """Select retained evidence identity in SQL before loading its payload."""
    from sqlalchemy import or_
    from .models import Execution
    query = select(Execution).where(Execution.service_id == service_id)
    if architecture:
        fields = [Execution.raw_payload['service_overview']['rendered_resources'],
                  Execution.raw_payload['rendered_resources'], Execution.raw_payload['helm_source_files']]
        # Mirrors Python's empty container/false/null checks for retained JSON.
        query = query.where(or_(*(cast(field.as_string(), String).not_in(
            ('', '[]', '{}', 'null', 'false', '0')) for field in fields)))
    return db.scalar(query.order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
