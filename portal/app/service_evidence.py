"""Select retained evidence for the current service version."""
from sqlalchemy import case, select

from .models import Execution


def _current_execution_query(service):
    """Prefer service coverage; allow image-only evidence when no service scan exists.

    Never cross versions or hide an incomplete scan behind an older complete one.
    An image rescan must not silently replace a whole-service inventory.
    """
    # Legacy exports may have no version; only their unversioned scans match.
    return (select(Execution).where(
        Execution.service_id == service.id,
        Execution.service_version_id == service.current_version_id,
        Execution.scan_scope.in_(("service", "image")),
    ).order_by(case((Execution.scan_scope == "service", 0), else_=1),
               Execution.scanned_at.desc(), Execution.id.desc()).limit(1)
        .execution_options(populate_existing=True))


def current_execution(db, service):
    return db.scalar(_current_execution_query(service))


def current_execution_id(db, service):
    # Findings exports stream observations without loading the full scan payload.
    return db.scalar(_current_execution_query(service).with_only_columns(Execution.id))
