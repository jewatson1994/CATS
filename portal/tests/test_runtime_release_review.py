"""A runtime draft only gains authority through an independent, signed Cyber release."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import cyber_approvals as approvals, cyber_release_publication, release_revisions, signing
from app.auth import AuthContext, SYSTEM_ROLES
from app.database import Base
from app.durable_jobs import DurableJob
from app.models import Group, Role, Service, User, UserRoleAssignment, utcnow
from app.oci_models import OCIRepository, OCIUpstream
from app.runtime_candidates import reconcile
from app.runtime_models import RuntimeEnvironment
from app.scan_coordination import ScanJob
from test_cyber_approvals import auth, request
from test_cyber_release_publication import environment as publication_environment
from test_runtime_candidates import complete


def system_actor(db, username, service, *role_names):
    user = User(username=username, display_name=username)
    db.add(user)
    for name in role_names:
        role = db.scalar(select(Role).where(Role.name == name))
        if role is None:
            role = Role(name=name, system=True, permissions=SYSTEM_ROLES[name])
        db.add(UserRoleAssignment(user=user, role=role, service=service))
    db.flush()
    return AuthContext(user=user, session=SimpleNamespace(csrf_token='csrf'))


@pytest.fixture
def case(tmp_path, monkeypatch, publication_environment):
    from app.runtime_candidate_assessment import process
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    registry = publication_environment
    material, _ = signing.job_material({}, 'push')
    monkeypatch.setattr(signing, 'configuration', lambda _: {'enabled': True, 'fingerprint': registry.fingerprint,
        'public_key': material['signing_public_key'], 'private_key': 'fixture'})
    monkeypatch.setattr(approvals, 'root', lambda: tmp_path / 'approvals')
    monkeypatch.setattr(release_revisions, 'root', approvals.root)
    with Session(engine) as db:
        group = Group(name='Payments owners')
        service = Service(service_key='payments', name='Payments', groups=[group])
        db.add_all([service, Service(service_key='other', name='Other')])
        db.flush()
        dest = approvals.ApprovedReleaseDestination(name='Cyber', endpoint='https://approved.example', namespace='team')
        upstream = OCIUpstream(name='Source', endpoint='https://source.example')
        db.add_all([dest, OCIRepository(public_repository='apps/payments', upstream=upstream,
            upstream_repository='app', service_id=service.id)])
        env = RuntimeEnvironment(name='Validation', kind='kubernetes', cluster_role='validation', service_ids=[service.id])
        db.add(env)
        db.flush()
        digest = registry.approval.snapshot['artifacts'][0]['digest']
        ref = 'source.example/app@' + digest
        component = {'workload_kind':'Deployment', 'workload':'api', 'workload_uid':'abc',
                     'container_kind':'container', 'container':'web', 'image_id':ref, 'desired_image':ref, 'app_version':'2'}
        app = SimpleNamespace(id=1, identity='payments-application', name='Payments', components=[component])
        draft = reconcile(db, env, service, [app], 'payments')
        job = ScanJob(id='scan', status='running', service_key=service.service_key, service_version='2',
            available_at=utcnow(), payload={'runtime_candidate_artifact':ref, 'credential_policy':'public',
                'pipeline_input_kind':'image', 'image_list':ref,
                'ingest_service_db_id':service.id, 'pipeline_owning_group_id':group.id})
        db.add(job)
        execution = complete(db, job, service, ref)
        draft.jobs = {ref:'scan'}
        db.flush()
        process(db, draft)
        db.commit()
        submitter = system_actor(db, 'manager', service, 'Service Manager', 'Cybersecurity')
        cyber = system_actor(db, 'cyber', service, 'Cybersecurity')
        db.commit()
        yield SimpleNamespace(db=db, service=service, draft=draft, manager=submitter, cyber=cyber, source=execution, ref=ref)
    engine.dispose()


def review(case):
    return approvals.readiness_api(case.service.service_key, db=case.db, auth=case.manager, runtime_candidate_id=case.draft.id)


def submit(case, token, actor=None, **extra):
    return asyncio.run(approvals.request_approval(request({'service_key':case.service.service_key,
        'runtime_candidate_id':case.draft.id, 'review_digest':token, **extra}), case.db, actor or case.manager))


def decision(case, approval_id, choice, actor=None, reason='Reviewed the retained runtime inventory'):
    return asyncio.run(approvals.decide(approval_id, request({'decision':choice, 'rationale':reason}), case.db, actor or case.cyber))


def test_openapi_documents_runtime_submission_and_review_alongside_classic_requests():
    app = FastAPI()
    app.include_router(approvals.router)
    paths = app.openapi()['paths']
    submission = paths['/api/cyber-approvals']['post']['requestBody']['content']['application/json']
    assert submission['schema']['dependentRequired']['runtime_candidate_id'] == ['review_digest']
    assert submission['schema']['properties']['variant']['enum'] == ['current_service', 'cats_remediated']
    assert {'runtime_candidate_id', 'review_digest', 'service_key'} == set(submission['examples']['Runtime candidate']['value'])
    decision = paths['/api/cyber-approvals/{identity}/decision']['post']['requestBody']['content']['application/json']['schema']
    assert set(decision['required']) == {'decision', 'rationale'}
    assert set(decision['properties']['decision']['enum']) == {'approved', 'denied', 'returned'}


def test_return_and_resubmit_through_signed_activation(case):
    ready = review(case)
    assert ready['ready'], ready['blockers']
    with pytest.raises(HTTPException) as stale:
        submit(case, 'earlier evidence')
    assert stale.value.status_code == 409
    with pytest.raises(HTTPException) as forbidden:
        submit(case, ready['review_digest'], case.cyber)
    assert forbidden.value.status_code == 403
    first = submit(case, ready['review_digest'])
    assert first['can_decide'] is False and case.draft.status == 'submitted'
    assert approvals.runtime_review_notifications(case.db, case.manager) == []
    assert approvals.runtime_review_notifications(case.db, case.cyber)[0]['href'].endswith(f"id={first['id']}")
    with pytest.raises(HTTPException) as self_decision:
        decision(case, first['id'], 'approved', case.manager)
    assert self_decision.value.status_code == 403
    with pytest.raises(HTTPException) as empty:
        decision(case, first['id'], 'returned', reason=' ')
    assert empty.value.status_code == 422
    decision(case, first['id'], 'returned', reason='Review the component SBOM')
    assert case.draft.status == 'returned' and not case.db.scalars(select(DurableJob)).first()
    assert 'runtime_candidate_id=' in approvals.runtime_review_notifications(case.db, case.manager)[0]['href']
    second = submit(case, review(case)['review_digest'])
    assert second['id'] != first['id'] and second['snapshot']['previous_review_id'] == first['id']
    assert approvals.approval(first['id'], case.db, case.cyber)['status'] == 'returned'
    path = Path(approvals.download(second['id'], 'submission', case.db, case.manager).path)
    original = path.read_bytes()
    snapshot = json.loads(original)
    assert snapshot['runtime_evidence']['images'][0]['reference'] == case.ref
    assert snapshot['runtime_evidence']['assessments'][0]['execution_id'] == case.source.id
    row = case.db.get(approvals.CyberApproval, second['id'])
    with ZipFile(row.snapshot['evidence']['path']) as archive:
        assert json.loads(archive.read('runtime-candidate.json')) == snapshot['runtime_evidence']
        assert f'assessments/{case.source.id}/scanner.zip' in archive.namelist()
    changed = dict(case.draft.inventory['applications'][0]['components'][0], image_id='source.example/app@sha256:'+'a'*64)
    observed = SimpleNamespace(id=1, identity='payments-application', name='Payments', components=[changed])
    newer = reconcile(case.db, case.db.get(RuntimeEnvironment, case.draft.environment_id), case.service, [observed], 'payments')
    case.db.commit()
    assert newer.current and not case.draft.current and newer.status == 'draft'
    assert approvals.runtime_review_notifications(case.db, case.cyber)[0]['href'].endswith(f"id={second['id']}")
    decided = decision(case, second['id'], 'approved')
    assert (decided['status'], decided['publish_status']) == ('approved', 'queued')
    outcome = approvals.runtime_review_notifications(case.db, case.manager)[0]
    assert outcome['label'] == 'Runtime release approved' and outcome['href'].endswith(f"id={second['id']}")
    assert path.read_bytes() == original and len(case.db.scalars(select(DurableJob)).all()) == 1
    revision = case.db.scalar(select(release_revisions.ReleaseRevision))
    assert case.db.get(release_revisions.ServiceActiveRelease, case.service.id).revision_id is None
    with pytest.raises(ValueError):
        release_revisions.activate(case.db, case.cyber, revision.id, 0)
    receipt = cyber_release_publication.publish(case.db, row, row.destination, lambda _: None)
    assert receipt['status'] == 'published' and receipt['revision_signature']['signature_status'] == 'verified'
    row.publish_status, row.publication = 'published', receipt
    case.db.flush()
    assert not approvals.release_revision(second['id'], case.db, case.manager)['can_manage']
    with pytest.raises(PermissionError):
        release_revisions.activate(case.db, case.manager, revision.id, 0)
    release_revisions.activate(case.db, case.cyber, revision.id, 0)
    assert case.db.get(release_revisions.ServiceActiveRelease, case.service.id).revision_id == revision.id
    assert newer.status == 'draft' and newer.approval_id is None


def test_scope_rejection_and_retained_snapshot_integrity(case):
    with pytest.raises(HTTPException) as inaccessible:
        approvals.readiness_api('other', db=case.db, auth=auth(2), runtime_candidate_id=case.draft.id)
    assert inaccessible.value.status_code == 404
    first = submit(case, review(case)['review_digest'])
    assert approvals.runtime_review_notifications(case.db, auth(2)) == []
    path = Path(approvals.download(first['id'], 'submission', case.db, case.manager).path)
    original = path.read_bytes()
    path.write_bytes(b'{}')
    with pytest.raises(HTTPException) as changed:
        decision(case, first['id'], 'approved')
    assert changed.value.status_code == 409
    path.write_bytes(original)
    decision(case, first['id'], 'denied', reason='Required configuration changes remain open')
    assert case.draft.status == 'denied' and review(case)['can_request'] is False
    assert not case.db.scalars(select(DurableJob)).first()
    assert case.db.get(release_revisions.ServiceActiveRelease, case.service.id).revision_id is None


def test_manager_cannot_submit_when_a_constituent_scan_loses_integrity(case):
    previous = review(case)
    case.source.raw_payload = {**case.source.raw_payload, 'evidence_documents': []}
    case.db.commit()
    blocked = review(case)
    assert not blocked['ready'] and blocked['blockers']
    for token in (previous['review_digest'], blocked['review_digest']):
        with pytest.raises(HTTPException) as error:
            submit(case, token)
        assert error.value.status_code == 409
    assert not case.db.scalars(select(approvals.CyberApproval)).first()
    assert case.draft.status == 'draft' and not case.db.scalars(select(DurableJob)).first()


def test_return_notification_opens_frozen_decision_after_deployment_changes(case):
    submitted = submit(case, review(case)['review_digest'])
    application = SimpleNamespace(**case.draft.inventory['applications'][0])
    application.components = [dict(application.components[0], app_version='next')]
    reconcile(case.db, case.db.get(RuntimeEnvironment, case.draft.environment_id), case.service, [application], 'payments')
    case.db.commit()
    decision(case, submitted['id'], 'returned', reason='Additional supporting evidence required')
    outcome = approvals.runtime_review_notifications(case.db, case.manager)[0]
    assert outcome == {'label': 'Runtime release returned for changes', 'service': case.service.name,
                       'href': f"/cyber-approvals?id={submitted['id']}"}
    assert not approvals.approval(submitted['id'], case.db, case.manager)['can_resubmit']


def test_superseded_unsubmitted_draft_shows_retained_inventory_and_original_events(case, monkeypatch):
    original = review(case)
    changed = dict(case.draft.inventory['applications'][0]['components'][0], workload='replacement')
    app = SimpleNamespace(id=2, name='Replacement', identity='replacement', components=[changed])
    newer = reconcile(case.db, case.db.get(RuntimeEnvironment, case.draft.environment_id), case.service, [app], 'payments')
    case.db.commit()
    assert newer.id != case.draft.id
    with pytest.raises(HTTPException) as forbidden:
        submit(case, original['review_digest'])
    assert forbidden.value.status_code == 409
    monkeypatch.setattr(approvals, '_runtime_assessment', lambda *args: pytest.fail('Historical read recomputed evidence'))
    view = review(case)
    assert not view['can_request'] and not view['ready']
    assert 'runtime_evidence' not in view and 'review_digest' not in view
    history = view['historical_inventory']
    assert history['applications'] == original['runtime_evidence']['applications']
    assert history['fingerprint'] == case.draft.fingerprint and history['revision'] == 1
    assert [event['action'] for event in history['history']] == [
        'runtime.candidate.created', 'runtime.candidate.assessment_changed', 'runtime.candidate.superseded']
    assert all(event['recorded_at'] and event['actor'] == 'System' for event in history['history'])
    with pytest.raises(HTTPException) as unauthorized:
        approvals.readiness_api('payments', db=case.db, auth=case.cyber, runtime_candidate_id=case.draft.id)
    assert unauthorized.value.status_code == 403


def test_runtime_queue_and_release_actions_require_scoped_system_roles(case):
    manager = system_actor(case.db, 'manager-only', case.service, 'Service Manager')
    admin = system_actor(case.db, 'administrator', None, 'Administrator')
    assessor = system_actor(case.db, 'assessor', case.service, 'Assessor')
    other_service = case.db.scalar(select(Service).where(Service.service_key == 'other'))
    other_cyber = system_actor(case.db, 'other-cyber', other_service, 'Cybersecurity')
    ready = approvals.readiness_api('payments', db=case.db, auth=manager, runtime_candidate_id=case.draft.id)
    assert ready['can_request'] and ready['ready']
    for actor in (case.cyber, admin, assessor, other_cyber):
        with pytest.raises(HTTPException) as unavailable:
            approvals.readiness_api('payments', db=case.db, auth=actor, runtime_candidate_id=case.draft.id)
        assert unavailable.value.status_code in (403, 404)
        with pytest.raises(HTTPException) as forbidden:
            submit(case, ready['review_digest'], actor)
        assert forbidden.value.status_code in (403, 404)
    submitted = submit(case, ready['review_digest'], manager)
    identity = submitted['id']
    assert approvals.approvals(db=case.db, auth=manager)['items'][0]['can_decide'] is False
    assert approvals.approvals(db=case.db, auth=case.cyber)['items'][0]['can_decide']
    for actor in (admin, assessor, other_cyber):
        assert approvals.approvals(db=case.db, auth=actor)['items'] == []
        assert not approvals.runtime_review_notifications(case.db, actor)
        with pytest.raises(HTTPException) as hidden:
            approvals.approval(identity, case.db, actor)
        assert hidden.value.status_code == 404
    for actor in (manager, admin, assessor, other_cyber):
        with pytest.raises(HTTPException) as forbidden:
            decision(case, identity, 'approved', actor)
        assert forbidden.value.status_code in (403, 404)
    decision(case, identity, 'approved')
    assert approvals.runtime_review_notifications(case.db, manager)
    assert not approvals.runtime_review_notifications(case.db, case.cyber)
    assert approvals.release_revision(identity, case.db, case.cyber)['can_manage']
    revision = case.db.scalar(select(release_revisions.ReleaseRevision))
    for actor in (manager, admin, assessor):
        assert not approvals.release_revision(identity, case.db, actor)['can_manage']
        with pytest.raises(HTTPException) as forbidden:
            asyncio.run(approvals.release_revision_action(identity, 'activate', request({'expected_version':0}), case.db, actor))
        assert forbidden.value.status_code == 403
        with pytest.raises(PermissionError):
            release_revisions.activate(case.db, actor, revision.id, 0)
