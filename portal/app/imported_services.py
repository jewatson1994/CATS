"""Service provenance selects evidence authority independently of deployment mode."""
from sqlalchemy import or_, select, union

# Register the referenced upstream table before standalone consumers create
# metadata; ReplicaSource contains its foreign key even without portal startup.
from . import oci_models as _oci_models
from .replica_models import ReplicaRecordMap, ReplicaRelease, ReplicaServiceState


_PROVENANCE = (ReplicaServiceState, ReplicaRelease, ReplicaRecordMap)


def imported_service_predicate(service_id):
    """Correlated SQL predicate; damaged current state cannot restore local authority."""
    return or_(*(select(model.service_id).where(model.service_id == service_id)
                 .correlate_except(model).exists() for model in _PROVENANCE))


def is_imported_service(db, service_id):
    if service_id is None:
        return False
    return bool(db.scalar(select(imported_service_predicate(service_id))))


def imported_service_ids(db, service_ids=None):
    """Read imported identities once when a page contains local and imported services."""
    identities = None if service_ids is None else set(service_ids)
    if identities == set():
        return set()
    queries = [select(model.service_id) for model in _PROVENANCE]
    if identities is not None:
        from .sql_sets import member_of
        queries = [query.where(member_of(model.service_id, identities, numeric=True))
                   for model, query in zip(_PROVENANCE, queries)]
    return set(db.scalars(union(*queries)))


def uses_imported_evidence(db, service_id):
    from .operating_mode import is_replica
    return is_replica() or is_imported_service(db, service_id)


def require_local_service(db, service_id):
    """Reject commands that would replace publisher-managed service evidence."""
    if is_imported_service(db, service_id):
        from fastapi import HTTPException
        raise HTTPException(409, 'Imported service evidence is managed by its OCI publisher')
