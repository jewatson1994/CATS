from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import durable_jobs as jobs, gitlab_topic_poll as polling, polling_worker, topic_intake_processing
from app.database import Base
from app.models import Group, Role, Service, User, UserRoleAssignment
from app.topic_intake_models import GitLabTopicSource, TopicProject, TopicRevision


@pytest.fixture
def source_db(monkeypatch, tmp_path):
    monkeypatch.setenv('CATS_MODE', 'full')
    engine = create_engine(f"sqlite:///{(tmp_path / 'topic.db').as_posix()}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as db:
        actor = User(username='operator', display_name='Operator', password_hash='!')
        group = Group(name='Intake')
        role = Role(name='operator', permissions=['config.manage'])
        db.add_all([actor, group, role])
        db.flush()
        db.add(UserRoleAssignment(user_id=actor.id, role_id=role.id))
        source = GitLabTopicSource(name='GitLab team', origin='https://gitlab.example', namespace='group',
            topic='cats', authorized_by_id=actor.id, claim_group_id=group.id, enabled=True)
        db.add(source)
    yield sessions, source.id
    engine.dispose()


def test_manual_and_due_polls_coalesce_and_reconfigure_safely(source_db, monkeypatch):
    sessions, source_id = source_db
    polling.schedule_due(sessions)
    polling.schedule_due(sessions)
    with sessions.begin() as db:
        source = db.get(GitLabTopicSource, source_id)
        first = polling.enqueue(db, source)
        assert first.id == source.latest_job_id
        source.config_revision = 'f' * 32
    with sessions.begin() as db:
        current = polling.enqueue(db, db.get(GitLabTopicSource, source_id))
        assert current.id != first.id
    monkeypatch.setattr(polling.gitlab, 'iter_topic_projects', lambda *a, **kw: pytest.fail('Stale poll made a request'))
    claimed = jobs.claim([polling.KIND], 'polling-worker', sessions)
    assert claimed.id == first.id
    jobs.execute(claimed, polling.poll, sessions)
    with sessions() as db:
        assert db.get(jobs.DurableJob, first.id).status == 'failed'
        assert db.get(GitLabTopicSource, source_id).latest_job_id == current.id
        assert db.get(GitLabTopicSource, source_id).last_attempt_at is None


def test_partial_project_failure_commits_other_revisions_and_replays_cleanly(source_db, monkeypatch):
    sessions, source_id = source_db
    broken = True
    def projects(origin, namespace, topic, *, check, on_project_error, **kwargs):
        check()
        if broken:
            on_project_error(11, 'GitLab returned an invalid default branch revision.')
        yield dict(project_id=12, path_with_namespace='group/valid', web_url=origin + '/group/valid',
                   default_branch='main', commit_sha='a' * 40)
    monkeypatch.setattr(polling.gitlab, 'iter_topic_projects', projects)
    polling.schedule_due(sessions)
    claimed = jobs.claim([polling.KIND], 'first-worker', sessions)
    jobs.execute(claimed, polling.poll, sessions)
    with sessions.begin() as db:
        failed = db.get(jobs.DurableJob, claimed.id)
        assert failed.status == 'queued' and failed.result['project_errors'][0]['gitlab_project_id'] == 11
        source = db.get(GitLabTopicSource, source_id)
        assert source.last_error and source.last_success_at is None
        assert db.scalars(select(TopicRevision)).one().commit_sha == 'a' * 40
        failed.available_at = jobs.now() - timedelta(seconds=1)
    broken = False
    retried = jobs.claim([polling.KIND], 'restarted-worker', sessions)
    assert retried.id == claimed.id
    jobs.execute(retried, polling.poll, sessions)
    with sessions() as db:
        assert db.scalars(select(TopicRevision)).one().commit_sha == 'a' * 40
        assert db.scalars(select(jobs.DurableJob).where(jobs.DurableJob.kind == topic_intake_processing.KIND)).one()
        result = db.get(jobs.DurableJob, claimed.id)
        assert result.status == 'completed' and result.result['failed_projects'] == 0
        source = db.get(GitLabTopicSource, source_id)
        assert source.last_success_at and source.last_error is None
    polling.schedule_due(sessions)
    assert jobs.claim([polling.KIND], 'too-soon', sessions) is None


def test_disabled_authorizer_never_sends_the_source_token(source_db, monkeypatch):
    sessions, source_id = source_db
    polling.schedule_due(sessions)
    with sessions.begin() as db:
        db.get(User, db.get(GitLabTopicSource, source_id).authorized_by_id).enabled = False
    monkeypatch.setattr(polling.gitlab, 'iter_topic_projects', lambda *a, **kw: pytest.fail('Unprivileged network request'))
    job = jobs.claim([polling.KIND], 'poll', sessions)
    jobs.execute(job, polling.poll, sessions)
    with sessions() as db:
        assert db.get(jobs.DurableJob, job.id).status == 'failed'
        assert 'administrator' in db.get(GitLabTopicSource, source_id).last_error


def test_only_complete_poll_withdraws_absent_projects_and_same_sha_can_opt_back_in(source_db, monkeypatch):
    sessions, source_id = source_db
    ids, broken = [11, 12], False
    def listing(origin, namespace, topic, *, on_project_error, **kwargs):
        if broken:
            on_project_error(90, 'GitLab returned incomplete project status metadata.')
        for identity in ids:
            path = f'{namespace}/p{identity}'
            yield dict(project_id=identity, path_with_namespace=path, web_url=f'{origin}/{path}',
                       default_branch='main', commit_sha='a' * 40)
    monkeypatch.setattr(polling.gitlab, 'iter_topic_projects', listing)

    def run():
        with sessions.begin() as db:
            poll = polling.enqueue(db, db.get(GitLabTopicSource, source_id))
            poll.available_at = jobs.now() - timedelta(seconds=1)
        claimed = jobs.claim([polling.KIND], 'polling-worker', sessions)
        jobs.execute(claimed, polling.poll, sessions)

    run()
    with sessions.begin() as db:
        rows = db.scalars(select(TopicProject).order_by(TopicProject.gitlab_project_id)).all()
        assert all(row.eligible and row.last_seen_poll_id for row in rows)
        revision_ids = [row.latest_revision_id for row in rows]
        owned = Service(service_key='retained', name='Retained')
        db.add(owned)
        db.flush()
        rows[0].service_id = owned.id
    ids, broken = [11], True
    run()
    with sessions() as db:
        assert all(row.eligible for row in db.scalars(select(TopicProject)))
    ids, broken = [], False
    run()  # Same durable job retries. An incomplete attempt's marker must not count.
    with sessions() as db:
        assert not any(row.eligible for row in db.scalars(select(TopicProject)))
        assert db.get(Service, owned.id)
    ids = [11]
    run()
    with sessions() as db:
        rows = db.scalars(select(TopicProject).order_by(TopicProject.gitlab_project_id)).all()
        assert [row.eligible for row in rows] == [True, False]
        assert [row.latest_revision_id for row in rows] == revision_ids
        assert rows[0].service_id == owned.id and len(db.scalars(select(TopicRevision)).all()) == 2


@pytest.mark.parametrize('oci_enabled', [True, False])
def test_full_worker_always_consumes_topic_work_on_its_own_slot(monkeypatch, oci_enabled):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setenv('CATS_REPLICA_SYNC_ENABLED', str(oci_enabled))
    monkeypatch.setattr(polling_worker.signal, 'signal', lambda *args: None)
    roles = []
    def observe(kinds, handler, **settings):
        roles.append(kinds)
        if polling.KIND in kinds:
            monkeypatch.setattr(polling, 'poll', lambda ctx, payload: 'poll')
            monkeypatch.setattr(topic_intake_processing, 'handler', lambda ctx, payload: 'process')
            for kind, result in [(polling.KIND, 'poll'), (topic_intake_processing.KIND, 'process')]:
                assert handler(SimpleNamespace(job=SimpleNamespace(kind=kind)), {}) == result
    monkeypatch.setattr(jobs, 'run_worker', observe)
    polling_worker._run()
    assert (polling.KIND, topic_intake_processing.KIND) in roles
    assert (('replica_sync',) in roles) == oci_enabled
