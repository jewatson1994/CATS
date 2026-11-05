"""Select retained evidence for the current service version."""
from sqlalchemy import case, select

from .models import Execution


def _current_execution_query(service):
    """Prefer service coverage; allow image-only evidence when no service scan exists.

    Never cross versions or hide an incomplete scan behind an older complete one.
    An image rescan must not silently replace a whole-service inventory.
    """
    from .operating_mode import is_replica
    if is_replica():
        from .replica_models import ReplicaServiceState
        return (select(Execution).where(Execution.service_id == service.id,
            Execution.id == select(ReplicaServiceState.active_execution_id).where(
                ReplicaServiceState.service_id == service.id).scalar_subquery()).limit(1)
                .execution_options(populate_existing=True))
    # Legacy exports may have no version; only their unversioned scans match.
    return (select(Execution).where(
        Execution.service_id == service.id,
        Execution.service_version_id.is_not_distinct_from(service.current_version_id),
        Execution.scan_scope.in_(("service", "image")),
    ).order_by(case((Execution.scan_scope == "service", 0), else_=1),
               Execution.scanned_at.desc(), Execution.id.desc()).limit(1)
        .execution_options(populate_existing=True))


def current_execution(db, service, *, defer_payload=False):
    query = _current_execution_query(service)
    if defer_payload:
        from sqlalchemy.orm import defer
        query = query.options(defer(Execution.raw_payload))
    return db.scalar(query)


def view_executions(executions, configuration):
    """Keep current replica views on the signed approval's exact scan.

    Explicit history readers retain all executions. Missing approval context
    must not silently substitute another scan, even if it is newer or complete.
    """
    from .operating_mode import is_replica
    if is_replica():
        identity = configuration.get('_replica_execution_id')
        return [execution for execution in executions if execution.id == identity]
    return executions


def current_execution_id_query(service):
    return _current_execution_query(service).with_only_columns(Execution.id)


def current_execution_id(db, service):
    # Findings exports stream observations without loading the full scan payload.
    return db.scalar(current_execution_id_query(service))
