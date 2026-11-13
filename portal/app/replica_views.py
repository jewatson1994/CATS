"""Read the publisher's captured assessment without local policy recomputation."""
from copy import deepcopy
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import inspect, select
from sqlalchemy.orm import object_session

from .replica_models import ReplicaRelease, ReplicaServiceState, ReplicaEvidenceRecord, ReplicaRecordMap
from .replica_integrity import verify_record, digest
from .release_validity import utc


def active(db, service_id):
    state = db.get(ReplicaServiceState, service_id)
    release = db.get(ReplicaRelease, state.active_release_id) if state else None
    if release and (not verify_record(release) or digest(release.evidence_state) != release.evidence_state_digest):
        raise HTTPException(409, 'Imported evidence integrity check failed')
    return release


def actor_labels(rows, relationships=('created_by', 'approved_by'), *, service_id=None):
    """Resolve display identities from frozen evidence, never local actor FKs.

    Nonnullable imported user references use the importer for database integrity.
    They are not attribution. Batch the source mappings for each rendered page.
    """
    from .imported_services import uses_imported_evidence
    grouped, result = {}, {}
    for row in rows:
        mapper = inspect(row, raiseerr=False)
        if mapper is None or not hasattr(mapper, 'mapper'):
            continue
        db = object_session(row)
        identity = service_id if service_id is not None else getattr(row, 'service_id', None)
        if db is not None and identity is not None:
            grouped.setdefault((db, identity), []).append(row)
    for (db, identity), items in grouped.items():
        if not uses_imported_evidence(db, identity):
            continue
        # Missing mappings or a retained row absent from the active snapshot do
        # not turn the local database placeholder into the original author.
        for item in items:
            result[id(item)] = {relation: 'Unavailable original identity' for relation in relationships}
        release = active(db, identity)
        if release is None:
            continue
        tables = {item.__tablename__ for item in items}
        maps = {(row.table_name, row.local_id): row.source_id for row in db.scalars(
            select(ReplicaRecordMap).where(ReplicaRecordMap.service_id == identity,
                ReplicaRecordMap.table_name.in_(tables), ReplicaRecordMap.local_id.in_([item.id for item in items])))}
        evidence = release.evidence_state
        originals = {(table, row['id']): row for table in tables
                     for row in evidence.get('records', {}).get(table, [])}
        for item in items:
            source_id = maps.get((item.__tablename__, item.id))
            original = originals.get((item.__tablename__, source_id))
            if original is None:
                continue
            labels = {}
            for relation in relationships:
                actor_id = original.get('actor_user_id' if relation == 'actor' else relation + '_id')
                labels[relation] = (evidence.get('actors', {}).get(str(actor_id), 'Unavailable original identity')
                                    if actor_id is not None else None)
            result[id(item)] = labels
    return result


def service_activity(db, service_id, *, page=1, page_size=50):
    """Page original publisher events without issuing them as local audit events."""
    release = active(db, service_id)
    evidence = release.evidence_state if release else {}
    events = deepcopy(evidence.get('activity', []))
    for row in events:
        try:
            row['created_at'] = utc(datetime.fromisoformat(row.get('created_at')))
        except (TypeError, ValueError):
            row['created_at'] = None
    events.sort(key=lambda row: (row['created_at'] or datetime.min.replace(tzinfo=timezone.utc),
                                row.get('id') or 0), reverse=True)
    page_size = max(1, min(int(page_size), 200))
    pages = max(1, (len(events) + page_size - 1) // page_size)
    page = max(1, min(int(page), pages))
    selected = []
    for row in events[(page - 1) * page_size:page * page_size]:
        actor_id = row.get('actor_user_id')
        row['actor'] = {'display_name': (evidence.get('actors', {}).get(str(actor_id), 'Unavailable original identity')
                                      if actor_id is not None else 'System')}
        selected.append(row)
    return dict(events=selected, page=page, page_size=page_size, page_count=pages,
                total_items=len(events), imported=True, replica_release_id=release.id if release else None)


def captured_assessment(db, item):
    release = db.get(ReplicaRelease, item.release_id)
    if not verify_record(release) or digest(release.evidence_state) != release.evidence_state_digest:
        raise HTTPException(409, 'Imported evidence integrity check failed')
    original = next((r for r in release.evidence_state.get('extension', {}).get('risk_assessments', [])
                     if r['id'] == item.source_id), None)
    if original != item.record:
        raise HTTPException(409, 'Imported assessment integrity check failed')
    result = deepcopy(original)
    result.update(id=item.id, source_assessment_id=item.source_id, service_id=release.service_id,
                  replica_release_id=release.id, imported=True, stale=False, stale_reasons=[])
    return result


def risk_service(db, service):
    release = active(db, service.id)
    extension = release.evidence_state.get('extension', {}) if release else {}
    records = list(db.scalars(select(ReplicaEvidenceRecord).where(ReplicaEvidenceRecord.release_id == release.id,
        ReplicaEvidenceRecord.kind == 'risk_assessments').order_by(ReplicaEvidenceRecord.source_id.desc()))) if release else []
    assessments = [captured_assessment(db, item) for item in records if not item.record.get('provenance', {}).get('preview')]
    latest = assessments[0] if assessments else None
    policy = next((p for p in extension.get('risk_policy_versions', []) if latest and p['id'] == latest['policy_id']), None)
    addresses = {r.source_id: r.id for r in records}
    decisions = deepcopy(extension.get('risk_decisions', []))
    for decision in decisions:
        decision['source_assessment_id'] = decision['assessment_id']
        decision['assessment_id'] = addresses.get(decision['assessment_id'])
        expiry = datetime.fromisoformat(decision['expires_at']) if decision.get('expires_at') else None
        decision['expired'] = bool(expiry and utc(expiry) <= datetime.now(timezone.utc))
    display = extension.get('display', {})
    return {'service': {'id': service.id, 'service_key': service.service_key, 'name': service.name},
        'assessment': latest, 'policy': policy, 'assignment': (latest or {}).get('provenance', {}).get('assignment'),
        'compliance': display.get('cyber_row', display.get('cyber', {})).get('status'),
        'compliance_cached_at': release.approved_at if release else None,
        'history': [{k: a.get(k) for k in ('id','policy_id','as_of','valid_until','summary')} for a in assessments],
        'decisions': decisions, 'can_assess': False, 'decision_kinds': [], 'imported': True,
        'release_id': release.id if release else None}


def posture_rows(db, kind, service_ids):
    rows = {}
    for identity in service_ids:
        release = active(db, identity)
        display = release.evidence_state.get('extension', {}).get('display', {}) if release else {}
        value = display.get(kind + '_row', display.get(kind))
        if value:
            rows[identity] = deepcopy(value)
    return rows, {'total': len(service_ids), 'cached': len(rows), 'stale': 0,
                  'recomputed': 0, 'refreshing': False, 'preparing': 0, 'imported': True}


def native_vex(db, service_id, after=0, finding_id=None):
    release = active(db, service_id)
    extension = release.evidence_state.get('extension', {}) if release else {}
    evaluations = extension.get('vex_disposition_evaluations', [])
    context = extension.get('native_vex_context', {})
    evaluation = next((row for row in evaluations if row['id'] == context.get('evaluation_id')), None)
    # Older captures lack the authoritative current/enabled fence. Show their
    # historical evidence without claiming a historical verdict is effective.
    if not context and evaluations:
        evaluation = max(evaluations, key=lambda r: r['id'])
    maps = {(row.table_name, row.source_id): row.local_id for row in db.scalars(select(ReplicaRecordMap).where(
        ReplicaRecordMap.service_id == service_id,
        ReplicaRecordMap.table_name.in_(('findings', 'finding_observations'))))}
    finding_map = {identity: local for (table, identity), local in maps.items() if table == 'findings'}
    findings = {row['id']: row for row in (release.evidence_state.get('records', {}).get('findings', []) if release else [])}
    decisions = {row['finding_id']: row for row in extension.get('finding_decisions', [])}
    excluded = {row['observation_id'] for row in extension.get('observation_decisions', []) if row.get('excluded')}
    def disposition(source_id, observation_id=None):
        finding, decision = findings.get(source_id), decisions.get(source_id, {})
        if finding is None:
            return None
        if not finding.get('active') or finding.get('resolved_at') is not None:
            return 'resolved'
        if decision.get('excepted'):
            return 'exception'
        if observation_id is not None:
            return 'vex_not_affected' if observation_id in excluded else 'actionable'
        if decision.get('vex_excluded'):
            return 'vex_not_affected'
        mixed = any(row['finding_id'] == source_id and row['observation_id'] in excluded
                    for row in extension.get('vex_observation_dispositions', [])
                    if evaluation and row['evaluation_id'] == evaluation['id'])
        return 'mixed_vex' if mixed else 'active'
    observations = [r for r in extension.get('vex_observation_dispositions', [])
        if evaluation and r['evaluation_id'] == evaluation['id'] and r['id'] > after
        and (finding_id is None or finding_map.get(r['finding_id']) == finding_id)]
    page = sorted(observations, key=lambda r: r['id'])[:100]
    source_finding = next((identity for identity, local in finding_map.items() if local == finding_id), None)
    return {'imported': True, 'current': bool(context.get('current')), 'enabled': bool(context.get('enabled')),
        'pending': bool(context.get('pending', not context)),
        'finding_disposition': disposition(source_finding) if source_finding is not None else None,
        'evaluation': evaluation,
        'items': [{**r, 'source_finding_id': r['finding_id'], 'source_observation_id': r['observation_id'],
            'finding_id': finding_map.get(r['finding_id']),
            'observation_id': maps.get(('finding_observations', r['observation_id'])),
            'verified_not_affected': bool(context.get('current') and r.get('excluded')),
            'effective_disposition': disposition(r['finding_id'], r['observation_id'])} for r in page],
        'next_after': page[-1]['id'] if len(observations) > len(page) else None}
