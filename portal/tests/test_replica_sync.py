"""Durable sync boundaries, original-evidence views and source administration."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import durable_jobs, replica_sync, replica_routes, replica_views
from app.models import AuditEvent, Service
from app.replica_import import reconcile
from app.replica_integrity import seal_record
from app.replica_models import ReplicaRelease, ReplicaServiceState, ReplicaSource, upgrade_connection
from app.service_evidence import current_execution
from test_replica_import import replica_import, verified


def worker(f, monkeypatch, incoming):
    sessions = sessionmaker(f.db.get_bind(), expire_on_commit=False)
    @contextmanager
    def environment(*args, **kwargs):
        yield {}
    monkeypatch.setattr(replica_sync, 'registry_environment', environment)
    monkeypatch.setattr(replica_sync.portable_release, 'discover_release_references', lambda *args: iter([incoming['reference']]))
    monkeypatch.setattr(replica_sync.portable_release, 'fetch_release', lambda *args: incoming)
    return sessions


def test_durable_sync_restart_idempotence_and_disabled_source(replica_import, monkeypatch):
    f = replica_import
    sessions = worker(f, monkeypatch, verified(f))
    first = replica_sync.enqueue(f.db, f.source)
    assert replica_sync.enqueue(f.db, f.source).id == first.id
    f.db.commit()
    abandoned = durable_jobs.claim([replica_sync.KIND], 'dead-worker', sessions)
    with sessions() as db:
        row = db.get(durable_jobs.DurableJob, abandoned.id)
        row.lease_until = durable_jobs.now() - timedelta(seconds=1)
        db.commit()
    assert durable_jobs.claim([replica_sync.KIND], 'restarted-worker', sessions) is None
    with sessions() as db:
        row = db.get(durable_jobs.DurableJob, abandoned.id)
        assert row.status == 'queued' and row.lease_token is None
        row.available_at = durable_jobs.now() - timedelta(seconds=1)
        db.commit()
    recovered = durable_jobs.claim([replica_sync.KIND], 'restarted-worker', sessions)
    assert recovered.id == first.id and recovered.lease_token != abandoned.lease_token
    durable_jobs.execute(recovered, replica_sync.sync, sessions)
    f.db.expire_all()
    assert f.db.get(durable_jobs.DurableJob, first.id).status == 'completed'
    assert len(list(f.db.scalars(select(ReplicaRelease)))) == 1
    actions = set(f.db.scalars(select(AuditEvent.action)))
    assert {'replica.discovered', 'replica.verified', 'replica.imported', 'replica.activated'} <= actions
    repeat = replica_sync.enqueue(f.db, f.source)
    f.db.commit()
    durable_jobs.execute(durable_jobs.claim([replica_sync.KIND], 'another-worker', sessions), replica_sync.sync, sessions)
    f.db.expire_all()
    assert f.db.get(durable_jobs.DurableJob, repeat.id).result['unchanged'] == 1
    assert len(list(f.db.scalars(select(ReplicaRelease)))) == 1
    f.source.enabled = False
    job = replica_sync.enqueue(f.db, f.source)
    f.db.commit()
    durable_jobs.execute(durable_jobs.claim([replica_sync.KIND], 'worker', sessions), replica_sync.sync, sessions)
    f.db.expire_all()
    assert f.db.get(durable_jobs.DurableJob, job.id).status == 'failed'


def test_incomplete_sync_preserves_active_and_retries(replica_import, monkeypatch):
    f = replica_import
    result = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    incoming = verified(f, 2)
    incoming['reference'] = 'approved/service@sha256:' + 'b' * 64
    incoming['complete'] = False
    sessions = worker(f, monkeypatch, incoming)
    job = replica_sync.enqueue(f.db, f.source)
    f.db.commit()
    durable_jobs.execute(durable_jobs.claim([replica_sync.KIND], 'worker', sessions), replica_sync.sync, sessions)
    f.db.expire_all()
    retained = f.db.get(ReplicaServiceState, result['service_id'])
    assert retained.active_release_id == result['release_id'] and retained.high_sequence == 1
    assert f.db.get(durable_jobs.DurableJob, job.id).status == 'queued'
    assert 'rejected or incomplete' in f.db.get(ReplicaSource, f.source.id).last_error
    rejection = f.db.scalar(select(AuditEvent).where(AuditEvent.action == 'replica.rejected'))
    assert rejection.detail['failure_type'] == 'ReplicaImportError'
    assert rejection.detail['correlation_id'] == job.correlation_id


def test_captured_risk_and_exact_approved_scan_without_local_evaluation(replica_import, monkeypatch):
    f = replica_import
    incoming = verified(f)
    original = dict(id=37, service_id=f.service.id, policy_id=12, source_execution_id=f.execution.id,
        as_of=f.now.isoformat(), valid_until=(f.now + timedelta(days=4)).isoformat(),
        provenance={'assignment': 'original'}, summary={'total': 123}, details=[{'cve': 'CVE-2026-1234'}])
    incoming['state']['extension'] = {'approval_context': {'source_execution_id': f.execution.id},
        'risk_assessments': [original], 'risk_policy_versions': [{'id': 12, 'name': 'Original policy'}],
        'risk_decisions': [], 'display': {'cyber': {'status': 'GREEN'}}}
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    service = f.db.get(Service, result['service_id'])
    assert current_execution(f.db, service).execution_key.startswith('replica-')
    view = replica_views.risk_service(f.db, service)
    assert view['assessment']['summary'] == {'total': 123}
    assert view['assessment']['source_assessment_id'] == 37
    assert view['policy']['name'] == 'Original policy'
    assert view['can_assess'] is False and view['decision_kinds'] == []
    assert view['assessment']['details'] == original['details']
    release = f.db.get(ReplicaRelease, result['release_id'])
    damaged = deepcopy(release.evidence_state)
    damaged['extension']['risk_assessments'][0]['summary'] = {'total': 0}
    release.evidence_state = damaged
    f.db.flush()
    with pytest.raises(HTTPException, match='409'):
        replica_views.risk_service(f.db, service)


def test_source_validation_rbac_and_repeatable_additive_schema(replica_import):
    f = replica_import
    denied = SimpleNamespace(has=lambda *args: False)
    with pytest.raises(HTTPException) as error:
        replica_routes.require(denied, 'replica.admin')
    assert error.value.status_code == 403
    auth = SimpleNamespace(user=f.user, has=lambda *args: True)
    payload = dict(name='another', upstream_id=f.source.upstream_id, repository='approved/*',
        trusted_publishers=['sha256:' + 'a' * 64], poll_seconds=300, enabled=True)
    created = replica_routes.configure(f.db, auth, payload)
    assert created['repository'] == 'approved/*'
    assert 'password' not in created
    with pytest.raises(HTTPException):
        replica_routes.configure(f.db, auth, {**payload, 'trusted_publishers': []})
    with f.db.get_bind().begin() as connection:
        upgrade_connection(connection)
        upgrade_connection(connection)
    assert f.db.get(Service, 51).name == 'Unrelated'


def test_frozen_finding_views_never_consult_local_policy_or_intelligence(replica_import, monkeypatch):
    from app import models as m, main, finding_classification, policy_data
    from app.portable_release_capture import _finding_decisions
    from app.replica_findings import configuration, evidence_time
    from app.replica_models import ReplicaFindingDecision
    from app.native_vex import finding_excluded
    f = replica_import
    finding = m.Finding(service_id=f.service.id, cve='CVE-2026-12345', severity='Low',
        first_seen=f.now-timedelta(days=100), episode_started=f.now-timedelta(days=100), last_seen=f.now)
    f.origin.add(finding)
    f.origin.flush()
    f.origin.add(m.FindingObservation(finding_id=finding.id, execution_id=f.execution.id,
        image='example/app@sha256:'+'a'*64, package='sample', installed_version='1', fixed_version='2',
        evidence={'kev': True, 'epss': 0.98}))
    f.origin.flush()
    original_policy = {**main.CONFIG_DEFAULTS, 'kev_enabled': 'true', 'kev_noncompliant': 'true',
        'minimum_severity': 'None', 'overdue_days': '30', 'compliance_mode': 'risk_based'}
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'kev_cves', lambda: set())
    monkeypatch.setattr(policy_data, 'risk_metadata', lambda cve: (None, None))
    decisions = _finding_decisions(f.origin, f.service.id, original_policy, f.now, f.execution.id)
    assert decisions['finding_decisions'][0]['noncompliant'] is True
    incoming = verified(f)
    incoming['state']['extension'].update(decisions)
    incoming['state']['extension']['display'] = {'captured_at': f.now.isoformat(),
        'configuration': original_policy, 'services_row': {'compliant': False}, 'cyber_row': {'status': 'RED'}}
    monkeypatch.setenv('CATS_MODE', 'replica')
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    service = f.db.get(Service, result['service_id'])
    saved = f.db.scalar(select(ReplicaFindingDecision))
    def forbidden(*args, **kwargs):
        raise AssertionError('Replica attempted authoritative evaluation')
    monkeypatch.setattr(policy_data, 'risk_metadata', forbidden)
    monkeypatch.setattr(main, 'risk_metadata', forbidden)
    monkeypatch.setattr(finding_classification, 'refresh', forbidden)
    config = configuration(f.db, service.id, {**main.CONFIG_DEFAULTS, 'kev_enabled': 'false'})
    later = f.now+timedelta(days=500)
    assert evidence_time(config, later) == f.now
    assert finding_classification.ensure_current(f.db, service.id, config, later)
    view = main.service_view(service, later, config)
    assert view['risk_eligible'] == {saved.finding_id} and view['risk_findings'] == {saved.finding_id}
    assert view['risk_metadata'][saved.finding_id] == {'kev': True, 'epss': 0.98}
    eligible, noncompliant, joins = main._risk_finding_expressions(f.db, {service.id: config}, later, False)
    assert not joins
    assert f.db.execute(select(eligible, noncompliant, finding_excluded(m.Finding.id, later)).where(
        m.Finding.id == saved.finding_id)).one() == (True, True, False)
    assert replica_views.posture_rows(f.db, 'services', [service.id])[0][service.id]['compliant'] is False
    assert replica_views.risk_service(f.db, service)['compliance'] == 'RED'


def test_delayed_revocation_applies_without_rolling_back_newer_release(replica_import):
    f = replica_import
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    delayed = verified(f, 2)
    delayed['manifest']['portable'].update(kind='revocation', target_release_uuid='release-1')
    delayed['manifest'].update(revoked_at=f.now.isoformat(), reason='Publisher withdrew older release')
    newer = reconcile(f.db, f.source, verified(f, 3), now=f.now)
    f.db.commit()
    assert reconcile(f.db, f.source, delayed, now=f.now)['status'] == 'revoked'
    f.db.commit()
    state = f.db.get(ReplicaServiceState, first['service_id'])
    assert state.high_sequence == 3 and state.active_release_id == newer['release_id']
    assert f.db.get(ReplicaRelease, first['release_id']).revoked_at is not None
    assert reconcile(f.db, f.source, delayed, now=f.now)['status'] == 'unchanged'
