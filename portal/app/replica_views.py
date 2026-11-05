"""Read the publisher's captured assessment without local policy recomputation."""
from copy import deepcopy
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import select

from .replica_models import ReplicaRelease, ReplicaServiceState, ReplicaEvidenceRecord, ReplicaRecordMap
from .replica_integrity import verify_record, digest
from .release_validity import utc


def active(db, service_id):
    state = db.get(ReplicaServiceState, service_id)
    release = db.get(ReplicaRelease, state.active_release_id) if state else None
    if release and (not verify_record(release) or digest(release.evidence_state) != release.evidence_state_digest):
        raise HTTPException(409, 'Imported evidence integrity check failed')
    return release


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
    evaluation = max(evaluations, key=lambda r: r['id']) if evaluations else None
    finding_map = {row.source_id: row.local_id for row in db.scalars(select(ReplicaRecordMap).where(
        ReplicaRecordMap.service_id == service_id, ReplicaRecordMap.table_name == 'findings'))}
    observations = [r for r in extension.get('vex_observation_dispositions', [])
        if evaluation and r['evaluation_id'] == evaluation['id'] and r['id'] > after
        and (finding_id is None or finding_map.get(r['finding_id']) == finding_id)]
    page = sorted(observations, key=lambda r: r['id'])[:100]
    return {'imported': True, 'current': bool(evaluation), 'enabled': bool(evaluation), 'pending': False,
        'finding_disposition': None, 'evaluation': evaluation,
        'items': [{**r, 'finding_id': finding_map.get(r['finding_id']),
            'verified_not_affected': bool(r.get('excluded')), 'effective_disposition':
                'vex_not_affected' if r.get('excluded') else 'actionable'} for r in page],
        'next_after': page[-1]['id'] if len(observations) > len(page) else None}
