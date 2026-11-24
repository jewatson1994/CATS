"""Read-only HQ views of component events received into the operational database."""
from datetime import timezone

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .audit_forward_routes import administrator
from .audit_forward_store import ComponentOperationalEvent
from .database import get_db


router = APIRouter(prefix="/api/admin/log-forwarding/components", tags=["log forwarding"],
                   dependencies=[Depends(administrator)])


def _utc(stamp):
    return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


@router.get("")
def components(response: Response, limit: int = Query(100, ge=1, le=200), db: Session = Depends(get_db)):
    event = ComponentOperationalEvent
    # Use the receipt time assigned here. A remote clock must not move another reporter off the list.
    recent = (select(event.source_id, func.max(event.received_at).label("last_received_at"))
              .group_by(event.source_id).order_by(func.max(event.received_at).desc(), event.source_id)
              .limit(limit).subquery())
    last_id = (select(event.id).where(event.source_id == recent.c.source_id,
                                      event.received_at == recent.c.last_received_at)
               .order_by(event.id.desc()).limit(1).correlate(recent).scalar_subquery())
    rows = db.execute(select(event.source_id, event.source_name, event.received_at, event.event_id)
                      .select_from(recent).join(event, event.id == last_id)
                      .order_by(event.received_at.desc(), event.source_id))
    response.headers["Cache-Control"] = "no-store"
    return {"components": [{"source_id": row.source_id, "source_name": row.source_name,
                            "last_received_at": _utc(row.received_at), "last_event_id": row.event_id}
                           for row in rows], "limit": limit}


@router.get("/events")
def events(response: Response, source_id: str = Query(min_length=1, max_length=100),
           before_id: int | None = Query(None, ge=1), limit: int = Query(25, ge=1, le=100),
           db: Session = Depends(get_db)):
    event = ComponentOperationalEvent
    query = select(event).where(event.source_id == source_id)
    if before_id is not None:
        query = query.where(event.id < before_id)
    rows = db.scalars(query.order_by(event.id.desc()).limit(limit + 1)).all()
    page = rows[:limit]
    response.headers["Cache-Control"] = "no-store"
    return {"events": [{"id": row.id, "source_id": row.source_id, "source_name": row.source_name,
                        "event_id": row.event_id, "timestamp": _utc(row.timestamp),
                        "received_at": _utc(row.received_at), "data": row.data} for row in page],
            "next_before_id": page[-1].id if len(rows) > limit else None}
