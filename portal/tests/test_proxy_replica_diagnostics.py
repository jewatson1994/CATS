"""Failure boundaries preserve evidence without exposing registry authorization data."""
import json
import pytest

from app import oci_proxy as proxy, replica_sync, durable_jobs, release_oci
from app.oci_authorization import AuthorizationDecision
from test_oci_proxy import registry, setup
from test_replica_import import replica_import, verified
from test_replica_sync import worker


@pytest.mark.parametrize('mode', ['approved_release', 'compliance', 'both'])
def test_denied_pull_preserves_admin_context_without_exposing_policy(setup, monkeypatch, mode):
    events = []
    monkeypatch.setattr(proxy, 'enqueue_diagnostic', lambda event: events.append(event))
    monkeypatch.setattr(proxy, 'authorize', lambda db, mapping, value: AuthorizationDecision(
        allowed=False, reason='compliance_blocked_by_critical_finding', service_id=1,
        artifact_digest=value, execution_id=82,
        effective_policy={'group_pull_policy': {'mode': mode, 'blocked_severity': 'Critical'}}))
    response = setup.client.get('/v2/project/1/image/manifests/latest',
                                headers={'X-Correlation-ID': 'pull-correlation-123'})
    assert response.status_code == 403
    error = response.json()['errors'][0]
    event = events[-1]
    assert error['code'] == 'DENIED'
    assert error['detail']['error_id'] == event['error_id'] == response.headers['X-Error-ID']
    assert response.headers['X-Correlation-ID'] == event['correlation_id'] == 'pull-correlation-123'
    assert event['context']['parsed_service_id'] == 1
    assert event['context']['requested_tag'] == 'latest'
    assert event['context']['resolved_digest'] == setup.image
    assert event['context']['matched_repository_id'] == setup.mapping_id
    assert event['context']['enforcement_mode'] == mode
    assert event['context']['requested_image'] == 'project/1/image:latest'
    assert event['code'] == 'CAT-OCI-POLICY-001'
    assert event['cause'] == 'compliance_blocked_by_critical_finding'
    assert 'blocking findings' in event['resolution'][0]
    assert event['context']['decision']['execution_id'] == 82
    assert 'effective_policy' not in response.text
    assert 'execution_id' not in response.text
    assert 'compliance_blocked' not in response.text


def test_unexpected_proxy_failure_is_sanitized_and_keeps_distribution_envelope(setup, monkeypatch):
    events = []
    monkeypatch.setattr(proxy, 'enqueue_diagnostic', lambda event: events.append(event))
    def broken(*args):
        raise RuntimeError('connection refused password=private-value')
    monkeypatch.setattr(proxy, 'mapping_for', broken)
    response = setup.client.get('/v2/project/1/image/manifests/latest')
    assert response.status_code == 500
    assert response.json()['errors'][0]['code'] == 'UNKNOWN'
    assert response.headers['Docker-Distribution-Api-Version'] == 'registry/2.0'
    assert 'private-value' not in json.dumps(events)
    assert 'private-value' not in response.text
    assert events[0]['technical']['exceptions'][0]['type'] == 'RuntimeError'


def test_replica_partial_failures_each_recorded_with_bounded_job_projection(replica_import, monkeypatch):
    fixture = replica_import
    sessions = worker(fixture, monkeypatch, verified(fixture))
    references = ['registry.example/release@sha256:' + f'{index:064x}' for index in range(23)]
    monkeypatch.setattr(replica_sync.portable_release, 'discover_release_references', lambda *args: iter(references))
    def rejected(*args):
        raise ValueError('Signature verification failed password=private-value')
    monkeypatch.setattr(replica_sync.portable_release, 'fetch_release', rejected)
    events = []
    monkeypatch.setattr(replica_sync, 'record_diagnostic', lambda event, **kwargs: events.append(event))
    job = replica_sync.enqueue(fixture.db, fixture.source)
    fixture.db.commit()
    durable_jobs.execute(durable_jobs.claim([replica_sync.KIND], 'diagnostic-worker', sessions), replica_sync.sync, sessions)
    fixture.db.expire_all()
    pending = fixture.db.get(durable_jobs.DurableJob, job.id)
    assert pending.status == 'queued'
    assert pending.result['failed'] == 23
    assert len(events) == 23
    assert len(pending.result['diagnostics']) == 20
    assert pending.result['diagnostics_truncated'] == 3
    assert {event['resource']['reference'] for event in events} == set(references)
    assert all(event['correlation_id'] == job.correlation_id for event in events)
    assert 'private-value' not in json.dumps(events)
    assert all('technical' not in event for event in pending.result['diagnostics'])


def test_offline_documentation_retains_swallowed_verification_failure(monkeypatch):
    events = []
    monkeypatch.setattr(release_oci, 'enqueue_diagnostic', lambda event: events.append(event))
    subject = 'registry.example/team/image@sha256:' + 'a' * 64
    def broken(*args, **kwargs):
        raise OSError('certificate verify failed password=private-value')
    monkeypatch.setattr(release_oci, '_Client', broken)
    result = release_oci.verify_documentation(subject, subject, {})
    assert result['status'] == 'failed'
    assert result['diagnostic']['error_id'] == events[0]['error_id']
    assert events[0]['operation'] == 'verify_documentation'
    assert events[0]['category'] == 'tls'
    assert 'technical' not in result['diagnostic']
    assert 'private-value' not in json.dumps(events)
