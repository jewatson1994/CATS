"""Full-mode workers and permissions preserve publisher-managed evidence."""
from datetime import timedelta
from types import SimpleNamespace

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main, auth, definition_routes, durable_jobs, scan_coordination, scan_protocol
from app.database import Base
from app.models import Role, Service, ServiceArtifact, ServiceImage, User, UserRoleAssignment
from app.replica_models import ReplicaRecordMap
from test_replica_import import replica_import
from test_release_key_rotation import rotation_keys


@pytest.fixture
def mixed(monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        local = Service(service_key='local', name='Local')
        imported = Service(service_key='imported', name='Imported')
        user = User(username='manager', display_name='Manager')
        role = Role(name='All service capabilities', permissions=list(auth.PERMISSIONS))
        db.add_all([local, imported, user, role])
        db.flush()
        db.add(UserRoleAssignment(user=user, role=role))
        # Retained provenance must keep an imported service protected even if
        # its current state row is missing or damaged.
        db.add(ReplicaRecordMap(service_id=imported.id, table_name='services', source_id=91, local_id=imported.id))
        db.commit()
        identities = dict(local=local.id, imported=imported.id, user=user.id)
    for module in (scan_coordination, scan_protocol, definition_routes):
        monkeypatch.setattr(module, 'SessionLocal', sessions)
    yield SimpleNamespace(sessions=sessions, **identities)
    engine.dispose()


@pytest.mark.parametrize('permission', ['scan.ingest', 'service.edit', 'service.delete', 'remediation.execute',
    'approval.decide', 'exception.review', 'risk.decide', 'bundle.import'])
def test_imported_mutations_denied_without_disabling_local_capabilities(mixed, permission):
    with mixed.sessions() as db:
        actor = auth.AuthContext(db.get(User, mixed.user), None)
        assert actor.has(permission, mixed.local)
        assert not actor.has(permission, mixed.imported)
        # Global permission continues to allow feature access / creation of
        # future local services; existing targets must still pass has().
        assert actor.accessible_service_ids(permission) is None


@pytest.mark.parametrize('permission', ['service.view', 'service.export', 'evidence.view',
    'local_override.create', 'local_override.revoke', 'local_override.view_audit'])
def test_imported_reads_and_separate_local_overrides_remain_authorized(mixed, permission):
    with mixed.sessions() as db:
        actor = auth.AuthContext(db.get(User, mixed.user), None)
        assert actor.has(permission, mixed.imported)


def test_scoped_permission_sets_exclude_imported_write_targets(mixed):
    with mixed.sessions() as db:
        user = db.get(User, mixed.user)
        user.role_assignments[0].service_id = mixed.local
        db.add(UserRoleAssignment(user=user, role=user.role_assignments[0].role, service_id=mixed.imported))
        db.commit()
        db.expire(user, ['role_assignments'])
        actor = auth.AuthContext(user, None)
        assert actor.accessible_service_ids('scan.ingest') == {mixed.local}
        assert actor.accessible_service_ids('service.view') == {mixed.local, mixed.imported}


def test_scan_queue_rejects_imported_target_and_keeps_local_scan(mixed):
    queue = scan_coordination.DurableJobs()
    with pytest.raises(HTTPException) as failure:
        queue['imported-job'] = {'status': 'queued', 'ingest_service_id': 'imported'}
    assert failure.value.status_code == 409
    queue['local-job'] = {'status': 'queued', 'ingest_service_id': 'local'}
    assert scan_coordination.claim('worker')['job_id'] == 'local-job'


def legacy_scan(db, service_key, *, status='queued', job_id='old-job'):
    row = scan_coordination.ScanJob(id=job_id, status=status, payload={'status': status},
        service_key=service_key, available_at=scan_coordination.now() - timedelta(seconds=1),
        attempt_id='old-attempt')
    db.add(row)
    db.commit()
    return row


def test_already_queued_imported_scan_never_reaches_worker(mixed):
    with mixed.sessions() as db:
        legacy_scan(db, 'imported')
    assert scan_coordination.claim('worker') is None
    with mixed.sessions() as db:
        assert db.get(scan_coordination.ScanJob, 'old-job').status == 'cancelled'
        assert db.scalar(select(scan_coordination.ScanAttempt.id)) is None


def test_completed_imported_scan_is_rejected_before_file_or_inventory_mutation(mixed, monkeypatch):
    with mixed.sessions() as db:
        legacy_scan(db, 'imported', status='evidence_ready')
        image = ServiceImage(service_id=mixed.imported, image_reference='registry/image:tag',
            scan_job_id='old-job', scan_status='scanning')
        db.add(image)
        db.commit()
        identity = image.id
    scan_protocol._ingest_one()
    with mixed.sessions() as db:
        assert db.get(scan_coordination.ScanJob, 'old-job').status == 'error'
        assert db.get(ServiceImage, identity).scan_status == 'scanning'


def test_scan_failure_repairs_only_local_images_with_shared_foreign_job_ids(mixed):
    with mixed.sessions() as db:
        legacy_scan(db, 'local')
        images = [ServiceImage(service_id=identity, image_reference='registry/image:tag',
            scan_job_id='old-job', scan_status='scanning') for identity in (mixed.local, mixed.imported)]
        db.add_all(images)
        db.commit()
        local, imported = [row.id for row in images]
    scan_coordination.DurableJobs().update_job('old-job', {'status': 'error', 'error': 'Failed'})
    with mixed.sessions() as db:
        assert db.get(ServiceImage, local).scan_status == 'failed'
        assert db.get(ServiceImage, imported).scan_status == 'scanning'


def test_durable_mutations_are_blocked_but_local_work_and_imported_exports_run(mixed):
    with mixed.sessions() as db:
        with pytest.raises(HTTPException):
            durable_jobs.submit(db, kind='remediation_execute', payload={}, service_id=mixed.imported)
        local = durable_jobs.submit(db, kind='remediation_plan', payload={}, service_id=mixed.local)
        export = durable_jobs.submit(db, kind='export', payload={}, service_id=mixed.imported)
    for kind, expected in [('remediation_plan', local.id), ('export', export.id)]:
        claimed = durable_jobs.claim([kind], 'worker', mixed.sessions)
        assert claimed.id == expected
        durable_jobs.execute(claimed, lambda *_: {'complete': True}, mixed.sessions)
    with mixed.sessions() as db:
        assert all(db.get(durable_jobs.DurableJob, identity).status == 'completed' for identity in (local.id, export.id))


def test_already_queued_mutation_is_cancelled_without_invoking_handler(mixed):
    with mixed.sessions() as db:
        row = durable_jobs.DurableJob(id='old-mutation', kind='remediation_execute',
            payload={}, service_id=mixed.imported, status='queued')
        db.add(row)
        db.commit()
    assert durable_jobs.claim(['remediation_execute'], 'worker', mixed.sessions) is None
    with mixed.sessions() as db:
        assert db.get(durable_jobs.DurableJob, 'old-mutation').status == 'cancelled'


def test_definition_completion_does_not_rewrite_imported_source(mixed):
    with mixed.sessions() as db:
        rows = [ServiceArtifact(service_id=identity, artifact_type='definition', artifact_name='source',
            source_metadata={'run_id': 'run', 'components': [{'status': 'scanning'}]})
            for identity in (mixed.local, mixed.imported)]
        db.add_all(rows)
        db.commit()
        local, imported = [row.id for row in rows]
    for identity in (local, imported):
        definition_routes._status(identity, 'run', 0, 'complete')
    with mixed.sessions() as db:
        assert db.get(ServiceArtifact, local).source_metadata['components'][0]['status'] == 'complete'
        assert db.get(ServiceArtifact, imported).source_metadata['components'][0]['status'] == 'scanning'


def test_automatic_native_vex_discovery_skips_imported_evidence(mixed):
    from app.native_vex_worker import maintenance
    from app.native_vex_models import VexDispositionService
    with mixed.sessions() as db:
        db.add(VexDispositionService(service_id=mixed.imported, generation=8))
        db.commit()
    assert maintenance(mixed.sessions) == 1
    with mixed.sessions() as db:
        assert db.get(VexDispositionService, mixed.local) is not None
        assert db.get(VexDispositionService, mixed.imported).generation == 8
        assert set(db.scalars(select(durable_jobs.DurableJob.service_id))) == {mixed.local}


def test_risk_assessment_and_decisions_cannot_rewrite_imported_evidence(mixed):
    from app.risk_profiles import enqueue_assessment, record_decision
    from app.risk_worker import refresh_assessment
    with mixed.sessions() as db:
        for operation in (lambda: enqueue_assessment(db, mixed.imported),
                          lambda: refresh_assessment(db, mixed.imported),
                          lambda: record_decision(db, mixed.imported, {}, 'manager')):
            with pytest.raises(HTTPException) as failure:
                operation()
            assert failure.value.status_code == 409
        assert enqueue_assessment(db, mixed.local).service_id == mixed.local


def test_direct_pipeline_ingestion_cannot_replace_imported_service(mixed):
    from test_portal import payload
    from app.models import Execution
    data = main.ExecutionPayload.model_validate(payload('new-local-scan', scan_coordination.now(), [], 'imported'))
    with mixed.sessions() as db:
        before = db.get(Service, mixed.imported).name
        with pytest.raises(HTTPException) as failure:
            main.ingest_payload(data, db)
        assert failure.value.status_code == 409
        assert db.get(Service, mixed.imported).name == before
        assert db.scalar(select(Execution.id).where(Execution.service_id == mixed.imported)) is None


def test_durable_guard_checks_payload_scope_when_queue_scope_is_missing_or_different(mixed):
    with mixed.sessions() as db:
        image = ServiceImage(service_id=mixed.imported, image_reference='registry/image:tag')
        db.add(image)
        db.commit()
        with pytest.raises(HTTPException):
            durable_jobs.submit(db, kind='risk_assessment', payload={'service_id': mixed.imported})
        with pytest.raises(HTTPException):
            durable_jobs.submit(db, kind='patch_campaign_item', payload={'image_id': image.id},
                service_id=mixed.local)
        db.add(durable_jobs.DurableJob(id='payload-target', kind='patch_campaign_item',
            payload={'image_id': image.id}, service_id=None, status='queued'))
        db.commit()
    assert durable_jobs.claim(['patch_campaign_item'], 'worker', mixed.sessions) is None
    with mixed.sessions() as db:
        assert db.get(durable_jobs.DurableJob, 'payload-target').status == 'cancelled'


def test_publication_recovery_and_payload_dispatch_preserve_imported_receipts(mixed):
    from app.cyber_approvals import CyberApproval, reconcile_jobs
    with mixed.sessions() as db:
        rows = [CyberApproval(service_id=identity, source_execution_id=41, variant='current_service',
            snapshot={}, snapshot_digest='snapshot', status='approved', publish_status='publishing',
            publication={'publisher_receipt': 'retained'}) for identity in (mixed.local, mixed.imported)]
        db.add_all(rows)
        db.commit()
        local, imported = rows
        with pytest.raises(HTTPException):
            durable_jobs.submit(db, kind='cyber_release_publish', payload={'approval_id': imported.id})
        reconcile_jobs(db)
        assert local.publish_status == 'failed'
        assert imported.publish_status == 'publishing'
        assert imported.publication == {'publisher_receipt': 'retained'}


def test_shared_artifact_reconciliation_only_associates_local_services(mixed):
    from app import artifact_catalog as catalog
    from app.models import DeploymentValidationRun
    with mixed.sessions() as db:
        artifact = catalog.register_artifact(db, digest='sha256:' + 'a' * 64,
            media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
        db.add_all([ServiceImage(service_id=identity, image_reference='registry/image:tag',
            image_digest=artifact.digest) for identity in (mixed.local, mixed.imported)])
        validation = DeploymentValidationRun(service_id=mixed.imported, run_key='publisher-run', status='VERIFIED')
        db.add(validation)
        db.flush()
        assignments = catalog.associate_known_source_images(db, artifact_id=artifact.id)
        assert [row.service_id for row in assignments] == [mixed.local]
        assert catalog.enqueue_recommendation_reconciliation(db, validation_run_id=validation.id) is None
        with pytest.raises(HTTPException):
            catalog.assign_artifact(db, service_id=mixed.imported, artifact_id=artifact.id)
        assert db.scalar(select(catalog.ServiceArtifactAssignment.id).where(
            catalog.ServiceArtifactAssignment.service_id == mixed.imported)) is None


def test_permission_origin_cache_is_limited_to_the_current_transaction(mixed, monkeypatch):
    from app import imported_services
    original = imported_services.is_imported_service
    calls = []
    def observe(db, identity):
        calls.append(identity)
        return original(db, identity)
    monkeypatch.setattr(imported_services, 'is_imported_service', observe)
    with mixed.sessions() as db:
        actor = auth.AuthContext(db.get(User, mixed.user), None)
        assert not actor.has('service.edit', mixed.imported)
        assert not actor.has('scan.ingest', mixed.imported)
        assert calls == [mixed.imported]
        db.commit()
        assert not actor.has('service.edit', mixed.imported)
        assert calls == [mixed.imported, mixed.imported]


def test_local_signing_rotation_ignores_foreign_publication_state(replica_import, rotation_keys):
    from app import release_key_rotation
    from app.cyber_approvals import CyberApproval
    from app.replica_models import ReleasePublicationSequence
    fixture = replica_import
    foreign = Service(service_key='foreign-publisher', name='Foreign service')
    fixture.origin.add(foreign)
    fixture.origin.flush()
    fixture.origin.add_all([
        ReplicaRecordMap(service_id=foreign.id, table_name='services', source_id=91, local_id=foreign.id),
        ReleasePublicationSequence(service_id=foreign.id, sequence=88),
        CyberApproval(service_id=foreign.id, source_execution_id=fixture.execution.id,
            variant='current_service', status='approved', publish_status='publishing',
            snapshot={'portable_release': {'publisher': 'foreign'}}, snapshot_digest='foreign'),
    ])
    fixture.origin.flush()
    first, second, _ = rotation_keys
    result = release_key_rotation.prepare_configuration(fixture.origin, first, second)
    assert result['signing_key_chain'][-1]['certificate']['service_cutovers'] == {fixture.service.service_key: 2}


@pytest.mark.parametrize('finding_kind', ['vulnerability', 'policy'])
@pytest.mark.parametrize('scope', ['global', 'service'])
def test_exception_review_propagates_only_to_authorized_local_services(mixed, finding_kind, scope):
    from app.models import (ExceptionRecord, Finding, Group, PolicyExceptionRecord,
        PolicyFinding, ServiceGroup, WorkflowRequest)
    with mixed.sessions() as db:
        requester = User(username='requester', display_name='Requester')
        other = Service(service_key='other-local', name='Other local')
        group = Group(name='Mixed origin group')
        db.add_all([requester, other, group])
        db.flush()
        identities = (mixed.local, mixed.imported, other.id)
        db.add_all([ServiceGroup(service_id=identity, group_id=group.id) for identity in identities])
        timestamp = main.utcnow()
        model = Finding if finding_kind == 'vulnerability' else PolicyFinding
        identity_fields = ({'cve': 'CVE-2026-12345'} if finding_kind == 'vulnerability'
            else {'identity_key': 'shared-policy-identity', 'finding': 'shared-policy'})
        findings = [model(service_id=identity, severity='High', active=True,
            first_seen=timestamp, episode_started=timestamp, last_seen=timestamp,
            **identity_fields) for identity in identities]
        db.add_all(findings)
        db.flush()
        target_field = 'finding_id' if finding_kind == 'vulnerability' else 'policy_finding_id'
        workflow = WorkflowRequest(request_type='exception', service_id=mixed.local,
            requested_by_id=requester.id, justification='Reviewed shared exception',
            requested_expires_at=timestamp + timedelta(days=7), bulk_group_id=group.id,
            **{target_field: findings[0].id})
        db.add(workflow)
        manager = db.get(User, mixed.user)
        if scope == 'service':
            manager.role_assignments[0].service_id = mixed.local
        db.commit()
        actor = auth.AuthContext(manager, SimpleNamespace(csrf_token='test-csrf'))
        response = main.review_request(workflow.id, decision='approved', review_reason='Reviewed',
            apply_bulk='yes', csrf_token='test-csrf', db=db, auth=actor)
        assert response.status_code == 303
        assert workflow.status == 'approved'
        exception_model = ExceptionRecord if finding_kind == 'vulnerability' else PolicyExceptionRecord
        targets = set(db.scalars(select(getattr(exception_model, target_field))))
        expected = {findings[0].id, findings[2].id} if scope == 'global' else {findings[0].id}
        assert targets == expected
        assert findings[1].id not in targets
