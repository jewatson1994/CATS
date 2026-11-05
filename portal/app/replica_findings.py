"""Read signed publisher classifications without local policy or intelligence work."""
from copy import deepcopy
from datetime import datetime

from sqlalchemy import DateTime, delete, select

from . import models as m
from .replica_models import ReplicaFindingDecision as Decision, ReplicaObservationDecision, ReplicaServiceState


def project(db, service_id, release, maps):
    extension = release.evidence_state.get('extension', {})
    db.execute(delete(Decision).where(Decision.service_id == service_id))
    db.execute(delete(ReplicaObservationDecision).where(ReplicaObservationDecision.service_id == service_id))
    db.execute(delete(m.FindingClassification).where(m.FindingClassification.service_id == service_id))
    for original in extension.get('finding_classifications', []):
        row = deepcopy(original)
        row['finding_id'] = maps[('findings', row['finding_id'])]
        row['service_id'] = service_id
        for key, table in (('current_observation_id', 'finding_observations'),
                           ('latest_observation_id', 'finding_observations'),
                           ('current_execution_id', 'executions')):
            if row.get(key) is not None:
                row[key] = maps[(table, row[key])]
        for column in m.FindingClassification.__table__.columns:
            if isinstance(column.type, DateTime) and isinstance(row.get(column.name), str):
                row[column.name] = datetime.fromisoformat(row[column.name])
        db.add(m.FindingClassification(**row))
    for original in extension.get('finding_decisions', []):
        row = deepcopy(original)
        row['finding_id'] = maps[('findings', row['finding_id'])]
        db.add(Decision(service_id=service_id, release_id=release.id, **row))
    for row in extension.get('observation_decisions', []):
        db.add(ReplicaObservationDecision(service_id=service_id, release_id=release.id,
            observation_id=maps[('finding_observations', row['observation_id'])], excluded=row['excluded']))


def predicate(finding_id, field):
    """Correlated scalar preserves the publisher's nullable SQL decision."""
    return select(getattr(Decision, field)).join(ReplicaServiceState,
        ReplicaServiceState.active_release_id == Decision.release_id).where(
        Decision.finding_id == finding_id).correlate_except(Decision, ReplicaServiceState).scalar_subquery()


def configuration(db, service_id, defaults):
    from .replica_views import active
    release = active(db, service_id)
    display = release.evidence_state.get('extension', {}).get('display', {}) if release else {}
    result = dict(defaults)
    result.update(display.get('configuration', {}))
    state = db.get(ReplicaServiceState, service_id)
    result['_replica_execution_id'] = state.active_execution_id if state else None
    result['_replica_captured_at'] = display.get('captured_at') or (release.approved_at.isoformat() if release else None)
    result['_replica_findings'] = {row.finding_id: {
        key: getattr(row, key) for key in ('eligible', 'noncompliant', 'excepted', 'vex_excluded', 'kev', 'epss')}
        for row in db.scalars(select(Decision).where(Decision.service_id == service_id))}
    return result


def evidence_time(configuration, now):
    value = configuration.get('_replica_captured_at')
    return datetime.fromisoformat(value) if value else now


def available(db, service_id):
    from .replica_views import active
    release = active(db, service_id)
    return bool(release and 'finding_classifications' in release.evidence_state.get('extension', {}))
