from datetime import timedelta
import pytest
from sqlalchemy import select

from test_portal import SessionLocal, setup_function, new_client, add_user, csrf
from app.durable_jobs import DurableJob, JobContext, LeaseLost, claim, execute, now, recover, submit
from app.models import Service, User, UserRoleAssignment


def enqueue(**kwargs):
    with SessionLocal() as db:
        return submit(db, kind='remediation_plan', payload={}, **kwargs)


def test_duplicate_admission_claim_and_stale_owner_are_fenced():
    original = enqueue(dedupe_key='exact-source-plan')
    assert enqueue(dedupe_key='exact-source-plan').id == original.id
    owner = claim(('remediation_plan',), 'one', SessionLocal)
    assert claim(('remediation_plan',), 'two', SessionLocal) is None
    stale = JobContext(owner, SessionLocal)
    stale.checkpoint({'receipt': 'retained'})
    with SessionLocal() as db:
        row = db.get(DurableJob, owner.id)
        row.lease_until = now() - timedelta(seconds=1)
        db.commit()
        recover(db, ('remediation_plan',))
        db.refresh(row)
        assert row.status == 'queued'
        assert row.available_at.replace(tzinfo=now().tzinfo) > now()
        row.available_at = now() - timedelta(seconds=1)
        db.commit()
    replacement = claim(('remediation_plan',), 'two', SessionLocal)
    assert replacement.result['receipt'] == 'retained'
    assert replacement.result['diagnostic']['code'] == 'worker_lease_expired'
    assert replacement.lease_token != owner.lease_token
    for operation in (stale.check, stale.heartbeat, lambda: stale.finish({'bad': True})):
        with pytest.raises(LeaseLost):
            operation()
    execute(replacement, lambda ctx, payload: {'ok': True}, SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, owner.id)
        assert row.status == 'completed' and row.attempts == 2
        assert row.result['receipt'] == 'retained' and row.result['ok'] is True


def test_repeated_worker_death_is_bounded():
    job = enqueue(max_attempts=1)
    claim(('remediation_plan',), 'one', SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        row.lease_until = now() - timedelta(seconds=1)
        db.commit()
        recover(db, ('remediation_plan',))
        db.refresh(row)
        assert row.status == 'failed'
    assert claim(('remediation_plan',), 'two', SessionLocal) is None


def test_worker_diagnostic_survives_history_unavailable(monkeypatch):
    from app import durable_jobs
    monkeypatch.setattr(durable_jobs, 'record_diagnostic', lambda *args, **kwargs: False)
    job = enqueue(max_attempts=1)
    claimed = claim(('remediation_plan',), 'diagnostic-worker', SessionLocal)
    def fail(ctx, payload):
        from app.diagnostics import build_diagnostic
        assert build_diagnostic(RuntimeError('nested'), component='nested', operation='nested')['correlation_id'] == claimed.correlation_id
        ctx.stage('Loading evidence', 10)
        ctx.stage('Running tool', 30)
        raise TimeoutError('Tool timed out; password=hidden-value')
    execute(claimed, fail, SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        diagnostic = row.result['diagnostic']
        assert row.status == 'failed' and row.lease_until is None and row.lease_token is None
        assert diagnostic['context']['stage'] == 'Running tool'
        assert diagnostic['context']['last_successful_stage'] == 'Loading evidence'
        assert diagnostic['context']['worker_id'] == 'diagnostic-worker'
        assert diagnostic['category'] == 'timeout' and diagnostic['correlation_id'] == row.correlation_id
        assert 'hidden-value' not in str(diagnostic)
        from app.jobs_view import dto
        public = dto(db, row, None)
        assert public['diagnostic']['error_id'] == diagnostic['error_id']
        assert 'technical' not in public['diagnostic']
        assert 'diagnostic' not in public['result']


def test_missing_lease_is_recovered_and_terminalized():
    job = enqueue(max_attempts=1)
    claim(('remediation_plan',), 'missing-lease-worker', SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        row.lease_until = None
        db.commit()
        recover(db, ('remediation_plan',))
        db.refresh(row)
        assert row.status == 'failed' and row.lease_token is None
        assert row.result['diagnostic']['status'] == 'failed'
        assert row.result['diagnostic']['code'] == 'worker_lease_expired'


@pytest.mark.parametrize('failure', ['exit', 'timeout'])
def test_tool_metadata_survives_durable_failure(failure):
    import subprocess
    from app.patching import ToolCommandError
    from app.diagnostics import public_diagnostic
    job = enqueue(max_attempts=1)
    claimed = claim(('remediation_plan',), 'tool-worker', SessionLocal)
    error = (ToolCommandError('Tool exited with code 7', tool='/usr/local/bin/grype', exit_code=7,
                              timeout_seconds=42) if failure == 'exit' else
             subprocess.TimeoutExpired(['/usr/local/bin/grype', 'token=not-public'], timeout=42))

    def fail(ctx, payload):
        ctx.stage('Scanning evidence')
        raise error

    execute(claimed, fail, SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        diagnostic = public_diagnostic(row.result['diagnostic'])
        assert row.status == 'failed' and row.lease_token is None
        assert diagnostic['context']['tool'] == 'grype'
        assert diagnostic['context']['timeout_seconds'] == 42
        assert diagnostic['context']['exit_code'] == (7 if failure == 'exit' else None)
        assert 'not-public' not in str(diagnostic)


def test_configured_runtime_limit_fences_late_completion(monkeypatch):
    monkeypatch.setenv('CATS_JOB_MAX_RUNTIME_SECONDS', '1')
    job = enqueue(max_attempts=1)
    claimed = claim(('remediation_plan',), 'timeout-worker', SessionLocal)
    def delayed(ctx, payload):
        ctx.stage('Waiting for external tool')
        assert ctx.lost.wait(5)
        return {'late_result': True}
    execute(claimed, delayed, SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        assert row.status == 'failed' and row.lease_until is None
        assert row.result['diagnostic']['code'] == 'worker_timeout'
        assert row.result['diagnostic']['context']['timeout_seconds'] == 1
        assert 'late_result' not in row.result


def test_untrusted_errors_are_sanitized_and_retried_with_backoff(caplog):
    job = enqueue()
    claimed = claim(('remediation_plan',), 'one', SessionLocal)
    def fail(ctx, payload):
        raise RuntimeError('password=secret-do-not-log')
    execute(claimed, fail, SessionLocal)
    with SessionLocal() as db:
        row = db.get(DurableJob, job.id)
        assert row.status == 'queued'
        assert 'secret-do-not-log' not in row.error + caplog.text
        assert row.correlation_id in row.error
    assert claim(('remediation_plan',), 'two', SessionLocal) is None


def test_job_scope_counts_details_revocation_and_cancel():
    with SessionLocal() as db:
        service = Service(service_key='permitted', name='Permitted')
        hidden = Service(service_key='hidden', name='Hidden')
        db.add_all([service, hidden]); db.commit()
        sid, other = service.id, hidden.id
    add_user('scoped-jobs', 'Service Manager', service_id=sid)
    client = new_client('scoped-jobs')
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == 'scoped-jobs'))
        visible = submit(db, kind='remediation_plan', payload={'secret': 'private'}, service_id=sid, requested_by_id=user.id)
        invisible = submit(db, kind='remediation_plan', payload={}, service_id=other, requested_by_id=user.id)
        portfolio = submit(db, kind='export', payload={'scopes': {str(sid): ['service.export'], str(other): ['service.export']}}, requested_by_id=user.id)
        owned = submit(db, kind='export', payload={'scopes': {str(sid): ['service.export']}}, service_id=sid, requested_by_id=user.id)
        ids = [visible.id, invisible.id, portfolio.id, owned.id]
    listing = client.get('/api/v1/jobs')
    assert listing.status_code == 200, listing.text
    assert {row['id'] for row in listing.json()['jobs']} == {ids[0], ids[3]}
    assert listing.json()['counts']['queued'] == 2
    assert 'private' not in listing.text
    assert client.get('/api/v1/jobs/' + ids[1]).status_code == 404
    assert client.get('/api/v1/jobs/' + ids[2]).status_code == 404
    assert client.post('/api/v1/jobs/' + ids[0] + '/cancel', json={'csrf_token': 'wrong'}).status_code == 403
    assert client.post('/api/v1/jobs/' + ids[0] + '/cancel', json={'csrf_token': csrf(client)}).status_code == 200
    with SessionLocal() as db:
        grants = db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id)).all()
        unrelated = Service(service_key='unrelated-access', name='Unrelated access')
        db.add(unrelated); db.flush()
        role_id = grants[0].role_id
        for grant in grants: db.delete(grant)
        db.add(UserRoleAssignment(user_id=user.id, role_id=role_id, service_id=unrelated.id))
        db.commit()
    assert client.get('/api/v1/jobs/' + ids[0]).status_code == 404
    assert client.get('/api/v1/jobs/' + ids[3]).status_code == 404
    assert client.get('/api/v1/jobs').json()['counts']['queued'] == 0
    with SessionLocal() as db:
        for grant in db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id)):
            db.delete(grant)
        db.commit()
    assert client.get('/api/v1/jobs').status_code == 403
    assert client.get('/api/v1/jobs/' + ids[0]).status_code == 403


def test_jobs_page_envelope_and_no_unsafe_execute_cancellation():
    client = new_client()
    page = client.get('/jobs', headers={'Accept': 'application/vnd.cats.page+json'})
    assert page.status_code == 200 and page.json()['page'] == 'jobs'
    with SessionLocal() as db:
        service = Service(service_key='side-effect', name='Side effect')
        db.add(service); db.commit()
        row = submit(db, kind='remediation_execute', service_id=service.id, payload={})
    detail = client.get('/api/v1/jobs/' + row.id).json()
    assert not detail['can_cancel'] and not detail['can_retry']


def test_deleted_account_fences_work_and_deleted_service_hides_portfolio(monkeypatch):
    admin = new_client()
    with SessionLocal() as db:
        service = Service(service_key='job-delete', name='Job Delete')
        db.add(service); db.commit(); sid = service.id
    add_user('job-requester', 'Service Manager', service_id=sid)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == 'job-requester'))
        user_id = user.id
        row = submit(db, kind='remediation_plan', payload={}, service_id=sid, requested_by_id=user_id)
        owner = db.scalar(select(User).where(User.username == 'admin'))
        portfolio = submit(db, kind='export', requested_by_id=owner.id,
            payload={'scopes': {str(sid): ['service.export']}})
    claimed = claim(('remediation_plan',), 'old-worker', SessionLocal)
    assert admin.post(f'/admin/users/{user_id}/delete', data={'csrf_token': csrf(admin)}, follow_redirects=False).status_code == 303
    with pytest.raises(LeaseLost):
        JobContext(claimed, SessionLocal).finish({'stale': True})
    with SessionLocal() as db:
        assert db.get(DurableJob, row.id).requested_by_id is None
        assert db.get(DurableJob, row.id).status == 'cancelled'
    monkeypatch.setenv('ALLOW_SERVICE_DELETE', 'true')
    response = admin.post('/services/job-delete/delete', data={'confirmation': 'delete Job Delete',
        'reason': 'Test deletion', 'csrf_token': csrf(admin)}, follow_redirects=False)
    assert response.status_code == 303, response.text
    assert admin.get('/api/v1/jobs/' + portfolio.id).status_code == 404
    assert portfolio.id not in {job['id'] for job in admin.get('/api/v1/jobs').json()['jobs']}
