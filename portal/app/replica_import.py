"""Atomic reconstruction of previously approved evidence; never starts assessment work."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re

from sqlalchemy import DateTime, select, update

from . import models as m, service_transfer
from .auth import record_audit
from .replica_integrity import digest, seal_record
from .replica_models import ReplicaEvent, ReplicaRecordMap, ReplicaRelease, ReplicaServiceState, ReplicaEvidenceRecord
from .release_validity import utc


class ReplicaImportError(ValueError):
    """Safe actionable import failure; the caller must roll back the transaction."""


def _timestamp(value, field, optional=False):
    if value is None and optional:
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else value
        if not isinstance(result, datetime) or result.tzinfo is None:
            raise ValueError()
        return utc(result)
    except (ValueError, AttributeError):
        raise ReplicaImportError('Invalid signed ' + field) from None


def _retain(data):
    """Content-addressed storage becomes reachable only after the DB commit."""
    if not isinstance(data, bytes) or not data:
        raise ReplicaImportError('Complete evidence archive is required')
    from .cyber_approvals import root
    storage = Path(os.getenv('CATS_REPLICA_STORAGE', str(root() / 'replica'))).resolve()
    storage.mkdir(parents=True, exist_ok=True)
    checksum = hashlib.sha256(data).hexdigest()
    target = storage / (checksum + '.zip')
    if target.is_symlink():
        raise ReplicaImportError('Evidence storage path is unsafe')
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
            raise ReplicaImportError('Retained evidence integrity failed')
    else:
        import tempfile
        with tempfile.NamedTemporaryFile(dir=storage, delete=False) as output:
            output.write(data)
            temporary = Path(output.name)
        os.replace(temporary, target)
    return str(target)


def _projection(db, service, state, importer_id):
    """Reuse transfer ownership/schema, while explicitly retaining trusted assessments."""
    records = deepcopy(state.get('records'))
    if not isinstance(records, dict):
        raise ReplicaImportError('Relational service evidence is missing')
    manifest = dict(schema_version=2, counts={k: len(v) for k, v in records.items()},
                    service_key=service.service_key)
    service_transfer.validate_state({**state, 'records': records}, manifest)
    source_service = records['services'][0]
    maps = {(r.table_name, r.source_id): r.local_id for r in db.scalars(
        select(ReplicaRecordMap).where(ReplicaRecordMap.service_id == service.id))}
    maps['services', source_service['id']] = service.id
    execution_keys = {row['execution_key']: 'replica-' + hashlib.sha256(
        f'{service.id}:{row["execution_key"]}'.encode()).hexdigest() for row in records['executions']}
    deferred = []
    for model in service_transfer.MODELS:
        name = model.__tablename__
        for original in sorted(records[name], key=lambda r: r.get('id', 0)):
            values = dict(original)
            source_id = values.pop('id', values.get('service_id'))
            for column in model.__table__.columns:
                if column.name not in values:
                    continue
                value = values[column.name]
                if isinstance(column.type, DateTime) and value:
                    values[column.name] = datetime.fromisoformat(value)
                if column.foreign_keys and value is not None:
                    parent = next(iter(column.foreign_keys)).column.table.name
                    if parent == 'users':
                        values[column.name] = None if column.nullable else importer_id
                    elif parent == 'groups':
                        values[column.name] = None
                    elif (parent, value) in maps:
                        values[column.name] = maps[parent, value]
                    elif column.nullable:
                        values[column.name] = None
                        deferred.append((name, source_id, column.name, parent, value))
                    else:
                        raise ReplicaImportError('Unresolved evidence reference in ' + name)
            if name == 'services':
                values['service_key'] = service.service_key
                values['assessment_status'] = 'assessed'
                values['lifecycle_status'] = 'active'
            if name == 'executions':
                values['execution_key'] = execution_keys[original['execution_key']]
                values['raw_payload'] = deepcopy(values['raw_payload'])
                values['raw_payload']['service']['id'] = service.service_key
            for field in ('source_reference', 'artifact_reference'):
                if values.get(field) in execution_keys:
                    values[field] = execution_keys[values[field]]
            for field in ('job_key', 'run_key'):
                if field in values:
                    values[field] = hashlib.sha256(f'{service.id}:{name}:{values[field]}'.encode()).hexdigest()
            if name == 'dependency_watchlist_entries':
                values['enabled'] = False
            if name == 'remediation_executions' and values.get('finding_id') is not None:
                parent = {'configuration': 'policy_findings', 'vulnerability': 'findings'}[values['finding_type']]
                values['finding_id'] = maps[parent, original['finding_id']]
            # Local workers must never treat foreign execution state as queued work.
            if name in {'patch_executions', 'remediation_executions'} and values.get('status', '').lower() in {'queued', 'running'}:
                values.update(status='failed', phase='imported_evidence')
            if name == 'deployment_validation_runs':
                values.update(cluster_name=None, cleanup_status='NOT_STARTED')
                if values['status'] not in {'VERIFIED', 'PARTIALLY_VERIFIED', 'COULD_NOT_VALIDATE',
                        'NOT_ATTEMPTED', 'FAILED', 'ERROR', 'CANCELLED', 'TIMED_OUT'}:
                    values.update(status='NOT_ATTEMPTED', phase='IMPORTED_EVIDENCE')
            local_id = maps.get((name, source_id))
            existing = db.get(model, local_id) if local_id else None
            if existing is None:
                existing = model(**values)
                db.add(existing)
                db.flush()
                local_id = existing.service_id if name == 'service_metadata' else existing.id
                maps[name, source_id] = local_id
                db.add(ReplicaRecordMap(service_id=service.id, table_name=name,
                                        source_id=source_id, local_id=local_id))
            else:
                for key, value in values.items():
                    setattr(existing, key, value)
            db.flush()
    for name, identity, column, parent, value in deferred:
        if (parent, value) not in maps:
            raise ReplicaImportError('Dangling evidence relationship')
        setattr(db.get(service_transfer.TABLES[name], maps[name, identity]), column, maps[parent, value])
    for original in records['service_artifacts']:
        artifact = db.get(m.ServiceArtifact, maps['service_artifacts', original['id']])
        metadata = deepcopy(artifact.source_metadata or {})
        if 'definition_artifact_id' in metadata:
            identity = metadata['definition_artifact_id']
            local_id = maps.get(('service_artifacts', identity)) if type(identity) is int else None
            if local_id is None:
                metadata.pop('definition_artifact_id')
            else:
                metadata['definition_artifact_id'] = local_id
        if isinstance(metadata.get('components'), list):
            for component in metadata['components']:
                if isinstance(component, dict) and 'chart_artifact_id' in component:
                    identity = component['chart_artifact_id']
                    component['chart_artifact_id'] = maps.get(('service_artifacts', identity)) if type(identity) is int else None
        artifact.source_metadata = metadata
    for original in records['deployment_validation_runs']:
        match = re.fullmatch(r'artifact:(\d+):r(\d+)', original.get('artifact_reference') or '')
        if match:
            local_id = maps.get(('service_artifacts', int(match[1])))
            if local_id is None:
                raise ReplicaImportError('Invalid validation artifact reference')
            db.get(m.DeploymentValidationRun, maps['deployment_validation_runs', original['id']]).artifact_reference = f'artifact:{local_id}:r{match[2]}'
    # Keep historical rows but remove them from the active service projection.
    for model in (m.ServiceImage, m.ServiceArtifact):
        active_ids = [maps[model.__tablename__, r['id']] for r in records[model.__tablename__]]
        db.execute(update(model).where(model.service_id == service.id, model.id.not_in(active_ids))
                   .values(lifecycle_status='superseded'))
    for model in (m.Finding, m.PolicyFinding):
        if 'active' in model.__table__.columns:
            current_ids = [maps[model.__tablename__, r['id']] for r in records[model.__tablename__]]
            db.execute(update(model).where(model.service_id == service.id, model.id.not_in(current_ids)).values(active=False))
    db.add(m.ServiceTransferProvenance(service_id=service.id, detail={
        'kind': 'verified_approved_release', 'actors': state.get('actors', {}),
        'activity': state.get('activity', [])}))
    return maps


def reconcile(db, source, verified, *, now=None):
    """Called only with portable_release.fetch_release output. Caller owns commit."""
    now = now or datetime.now(timezone.utc)
    # SQLite ignores FOR UPDATE. Acquire its writer reservation before reading
    # source/trust state so concurrent arrivals cannot regress the retained chain.
    if db.get_bind().dialect.name == 'sqlite':
        connection = db.connection()
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql('BEGIN IMMEDIATE')
    from .replica_models import ReplicaSource
    source = db.scalar(select(ReplicaSource).where(ReplicaSource.id == source.id)
                       .with_for_update().execution_options(populate_existing=True))
    if source is None:
        raise ReplicaImportError('Configured replica source is unavailable')
    manifest = verified.get('manifest')
    if not isinstance(manifest, dict) or not verified.get('verified') or not verified.get('complete'):
        raise ReplicaImportError('Release has not passed cryptographic and completeness verification')
    metadata = manifest.get('portable', manifest.get('portable_release', {}))
    signer = verified.get('key_fingerprint')
    publisher = verified.get('publisher_root', signer)
    if not source.enabled or publisher not in source.trusted_publishers:
        raise ReplicaImportError('Publisher is not trusted by this source')
    source_id = metadata.get('service_uuid')
    sequence = metadata.get('release_sequence')
    release_id = metadata.get('release_uuid')
    if (metadata.get('format') != 'cats-replica-release-v1' or not isinstance(source_id, str)
            or not 1 <= len(source_id) <= 120 or not isinstance(release_id, str)
            or type(sequence) is not int or sequence < 1):
        raise ReplicaImportError('Invalid signed release identity or sequence')
    # Serialize all imports for this publisher/service, including first import.
    if db.get_bind().dialect.name == 'postgresql':
        from sqlalchemy import text
        key = int.from_bytes(hashlib.sha256((publisher + ':' + source_id).encode()).digest()[:8], 'big', signed=True)
        db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': key})
    event_digest = digest(manifest)
    kind = metadata.get('kind', 'release')
    events = db.scalars(select(ReplicaEvent).where(ReplicaEvent.publisher == publisher,
                        ReplicaEvent.source_service_id == source_id).order_by(ReplicaEvent.sequence.desc())).all()
    same = next((event for event in events if event.sequence == sequence), None)
    from .release_key_rotation import reconcile_trust
    identity = {**verified, 'publisher_root': publisher}
    if same:
        if same.manifest_digest != event_digest:
            raise ReplicaImportError('Signed sequence collision; release quarantine required')
        reconcile_trust(db, source, identity, source_id, sequence, replay=True)
        if kind == 'release':
            from .replica_integrity import verify_record
            retained = db.scalar(select(ReplicaRelease).where(ReplicaRelease.publisher == publisher,
                ReplicaRelease.source_release_id == release_id, ReplicaRelease.manifest_digest == event_digest))
            retained_state = db.get(ReplicaServiceState, retained.service_id) if retained else None
            if (not retained_state or retained_state.source_id != source.id
                    or retained_state.source_service_id != source_id
                    or not verify_record(retained)
                    or digest(retained.evidence_state) != retained.evidence_state_digest
                    or digest(verified.get('state')) != retained.evidence_state_digest
                    or verified.get('artifacts') != retained.artifacts):
                raise ReplicaImportError('Existing release evidence integrity check failed')
            # A fresh fully verified package may repair absent retained bytes.
            # It never reprojects history or changes the active release pointer.
            retained.evidence_path = _retain(verified.get('evidence'))
        return {'status': 'unchanged', 'sequence': sequence}
    if kind != 'revocation' and events and sequence <= events[0].sequence:
        raise ReplicaImportError('Rollback rejected by durable signed sequence high-water mark')
    state = db.scalar(select(ReplicaServiceState).where(ReplicaServiceState.publisher == publisher,
                      ReplicaServiceState.source_service_id == source_id).with_for_update()
                      .execution_options(populate_existing=True))
    if state and state.source_id != source.id:
        raise ReplicaImportError('Service is bound to another configured replica source')
    if kind != 'revocation' and state and sequence <= state.high_sequence:
        raise ReplicaImportError('Rollback rejected by service high-water mark')
    reconcile_trust(db, source, identity, source_id, sequence)
    if kind == 'revocation':
        target = metadata.get('target_release_uuid')
        if not isinstance(target, str) or not target:
            raise ReplicaImportError('Revocation target is missing')
        revoked_at = _timestamp(manifest.get('revoked_at', metadata.get('revoked_at')), 'revoked_at')
        if revoked_at > now:
            raise ReplicaImportError('Revocation timestamp is in the future')
        if state:
            release = db.scalar(select(ReplicaRelease).where(ReplicaRelease.service_id == state.service_id,
                                 ReplicaRelease.source_release_id == target))
            if release:
                from .replica_integrity import verify_record
                if not verify_record(release):
                    raise ReplicaImportError('Existing release integrity check failed')
                if release.revoked_at is None or utc(release.revoked_at) > revoked_at:
                    release.revoked_at = revoked_at
                    release.revocation_reason = str(manifest.get('reason', metadata.get('reason', 'Publisher revoked release')))[:4000]
                seal_record(release)
            state.high_sequence, state.last_sync_at = max(state.high_sequence, sequence), now
        db.add(ReplicaEvent(publisher=publisher, source_service_id=source_id, sequence=sequence,
                            kind=kind, manifest_digest=event_digest, manifest=manifest))
        record_audit(db, None, 'replica.revoked', 'service', state.service_id if state else None,
                     publisher=publisher, source_service_id=source_id, sequence=sequence, target_release_id=target)
        db.flush()
        return {'status': 'revoked', 'sequence': sequence}
    if kind != 'release':
        raise ReplicaImportError('Unsupported signed event kind')
    approved_at = _timestamp(manifest.get('approved_at', metadata.get('approved_at')), 'approved_at')
    expires_at = _timestamp(manifest.get('expires_at', metadata.get('expires_at')), 'expires_at', optional=True)
    if approved_at > now or (expires_at and expires_at <= approved_at):
        raise ReplicaImportError('Invalid signed approval validity interval')
    evidence = verified.get('state')
    if not isinstance(evidence, dict) or evidence.get('records', {}).get('services', [{}])[0].get('service_key') != source_id:
        raise ReplicaImportError('Signed service identity does not match retained evidence')
    evidence_path = _retain(verified.get('evidence'))
    if state is None:
        if db.scalar(select(m.Service.id).where(m.Service.service_key == source_id)) is not None:
            raise ReplicaImportError('Stable service identity conflicts with an existing service or publisher')
        original = evidence['records']['services'][0]
        service = m.Service(service_key=source_id, name=original['name'], description=original.get('description'))
        db.add(service)
        db.flush()
        state = ReplicaServiceState(service_id=service.id, source_id=source.id, publisher=publisher,
                    source_service_id=source_id, upstream_id=source.upstream_id, high_sequence=0)
        db.add(state)
    else:
        service = db.get(m.Service, state.service_id)
    if db.scalar(select(ReplicaRelease.id).where(ReplicaRelease.service_id == service.id,
                 ReplicaRelease.source_release_id == release_id)):
        raise ReplicaImportError('Release identity was reused with another sequence')
    previous_release = db.get(ReplicaRelease, state.active_release_id) if state.active_release_id else None
    supersedes = metadata.get('supersedes_release_uuid')
    if previous_release and sequence == state.high_sequence + 1 and supersedes != previous_release.source_release_id:
        raise ReplicaImportError('Signed supersession does not match the preceding release')
    if previous_release and supersedes == release_id:
        raise ReplicaImportError('Release cannot supersede itself')
    maps = _projection(db, service, evidence, source.created_by_id)
    release = ReplicaRelease(service_id=service.id, publisher=publisher, source_release_id=release_id,
        sequence=sequence, manifest=manifest, manifest_digest=event_digest, artifacts=verified['artifacts'],
        evidence_state=evidence, evidence_path=evidence_path, key_fingerprint=signer,
        verified=True, complete=True, approved_at=approved_at, expires_at=expires_at,
        source_reference=verified['reference'])
    db.add(release)
    db.flush()
    seal_record(release)
    from .replica_findings import project as project_findings
    project_findings(db, service.id, release, maps)
    for evidence_kind in ('risk_assessments',):
        for record in evidence.get('extension', {}).get(evidence_kind, []):
            db.add(ReplicaEvidenceRecord(release_id=release.id, kind=evidence_kind, source_id=record['id'], record=record))
    from .replica_authorization import ensure_repository_mappings
    ensure_repository_mappings(db, state, release.artifacts)
    previous = state.active_release_id
    state.active_release_id, state.high_sequence, state.last_sync_at = release.id, sequence, now
    approved_execution = evidence.get('extension', {}).get('approval_context', {}).get('source_execution_id')
    if approved_execution is not None:
        state.active_execution_id = maps.get(('executions', approved_execution))
        if state.active_execution_id is None:
            raise ReplicaImportError('Approved scan evidence is missing from captured service')
    db.add(ReplicaEvent(publisher=publisher, source_service_id=source_id, sequence=sequence,
                        kind=kind, manifest_digest=event_digest, manifest=manifest))
    record_audit(db, None, 'replica.imported', 'service', service.id, release_id=release.id,
                 publisher=publisher, manifest_digest=event_digest, evidence_state_digest=release.evidence_state_digest)
    record_audit(db, None, 'replica.activated', 'service', service.id, release_id=release.id,
                 source_release_id=release_id, sequence=sequence, previous_release_id=previous,
                 publisher=publisher, manifest_digest=event_digest)
    db.flush()
    return {'status': 'activated', 'service_id': service.id, 'release_id': release.id, 'sequence': sequence}
