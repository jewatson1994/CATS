"""Durable namespace-scoped GitLab topic polling for authoritative portals."""
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import extract, or_, select, update
from sqlalchemy.exc import DataError, IntegrityError

from . import discovery_gitlab as gitlab, durable_jobs as jobs
from .auth import AuthContext
from .database import SessionLocal
from .models import User
from .operating_mode import is_replica
from .replica_models import reserve_sqlite_writer
from .secrets import decrypt_secret
from .topic_intake_models import GitLabTopicSource, TopicProject
from .trusted_ca import configured_certificates


KIND = 'gitlab_topic_poll'


def _active_job(source_id, revision):
    job = jobs.DurableJob
    return select(job).where(job.kind == KIND, job.status.in_(('queued', 'running')),
                             job.payload['source_id'].as_integer() == source_id,
                             job.payload['config_revision'].as_string() == revision)


def enqueue(db, source, actor_id=None):
    """Manual and scheduled requests coalesce for one source configuration."""
    reserve_sqlite_writer(db)
    source = db.get(GitLabTopicSource, source.id, with_for_update=True, populate_existing=True)
    if is_replica() or source is None or not source.enabled:
        raise jobs.JobError('GitLab topic polling requires an enabled source on the full portal.')
    job = db.scalar(_active_job(source.id, source.config_revision).limit(1))
    if job is None:
        job = jobs.submit(db, kind=KIND, payload={'source_id': source.id, 'config_revision': source.config_revision},
                          requested_by_id=actor_id, commit=False)
    source.latest_job_id = job.id
    return job


def schedule_due(session_factory=SessionLocal):
    if is_replica():
        return
    timestamp = jobs.now().timestamp()
    source = GitLabTopicSource
    for _ in range(16):
        with session_factory() as db:
            reserve_sqlite_writer(db)
            due = db.scalar(select(source).where(
                source.enabled.is_(True),
                or_(source.last_attempt_at.is_(None), extract('epoch', source.last_attempt_at) + source.poll_seconds <= timestamp),
                ~_active_job(source.id, source.config_revision).exists()
            ).order_by(source.last_attempt_at.asc().nulls_first(), source.id)
                .limit(1).with_for_update(skip_locked=True))
            if due is None:
                return
            enqueue(db, due)
            db.commit()


def _current_source(ctx, db, payload, *, lock=False):
    if lock:
        reserve_sqlite_writer(db)
    source = db.get(GitLabTopicSource, payload['source_id'], with_for_update=lock)
    if ctx._owned(db).cancel_requested:
        raise jobs.JobCancelled()
    if source is None or not source.enabled or source.config_revision != payload['config_revision']:
        raise jobs.JobError('GitLab topic source was disabled or reconfigured. Poll the current configuration.')
    return source


def _check_authority(db, source):
    principal = db.get(User, source.authorized_by_id)
    if not principal or not principal.enabled or not AuthContext(principal, None).can_manage_group(None):
        raise jobs.JobError('The source administrator no longer has global configuration access.')


def poll(ctx, payload):
    from .topic_intake_processing import IntakeError, observe_project

    if is_replica():
        raise jobs.JobError('GitLab topic polling is available only on the full portal.')
    ctx.stage('Checking opted-in GitLab projects', 5)
    # Each retry gets a new enumeration marker: observations from an earlier
    # partial attempt cannot keep an absent project eligible on the next run.
    poll_id = uuid4().hex
    observed, skipped, problem_count, problems = 0, 0, 0, []

    def problem(project_id, message):
        nonlocal problem_count
        problem_count += 1
        if len(problems) < 20:
            problems.append({'gitlab_project_id': project_id, 'message': message})

    def check():
        with ctx.session_factory() as db:
            _check_authority(db, _current_source(ctx, db, payload))

    try:
        with ctx.session_factory() as db:
            source = _current_source(ctx, db, payload, lock=True)
            source.last_attempt_at, source.last_error = jobs.now(), None
            origin, namespace, topic = source.origin, source.namespace, source.topic
            token = source.token
            db.commit()
        with ctx.session_factory() as db:
            _check_authority(db, _current_source(ctx, db, payload))
            try:
                trusted = configured_certificates(db)
                token = decrypt_secret(token) if token else None
            except ValueError:
                raise jobs.JobError('Check GitLab source credentials and the configured trusted certificates.') from None
        for project in gitlab.iter_topic_projects(origin, namespace, topic, token=token,
                trusted_ca_certificates=trusted, check=check, on_project_error=problem):
            try:
                with ctx.session_factory() as db:
                    source = _current_source(ctx, db, payload, lock=True)
                    _check_authority(db, source)
                    revision = observe_project(db, source, gitlab_project_id=project['project_id'],
                                               project_path=project['path_with_namespace'], web_url=project['web_url'],
                                               default_branch=project['default_branch'], commit_sha=project['commit_sha'])
                    if revision is not None:
                        db.execute(update(TopicProject).where(
                            TopicProject.id == revision.project_id, TopicProject.source_id == source.id
                        ).values(eligible=True, last_seen_poll_id=poll_id))
                    db.commit()
                if revision is None:
                    skipped += 1
                else:
                    observed += 1
            except (jobs.JobCancelled, jobs.LeaseLost):
                raise
            except jobs.JobError:
                # A superseded source must stop making requests immediately.
                check()
                problem(project['project_id'], 'CATS could not admit this project revision.')
            except (DataError, IntegrityError, IntakeError):
                problem(project['project_id'], 'CATS could not bind this GitLab project revision.')
            except HTTPException as exc:
                if exc.status_code == 429 or exc.status_code >= 500:
                    raise
                problem(project['project_id'], 'CATS could not admit this project revision.')
        result = {'observed': observed, 'skipped': skipped, 'project_errors': problems, 'failed_projects': problem_count}
        ctx.checkpoint(result)
        if problem_count:
            raise gitlab.GitLabSourceError(f'{problem_count} GitLab project(s) could not be polled. See job details.')
        with ctx.session_factory() as db:
            source = _current_source(ctx, db, payload, lock=True)
            _check_authority(db, source)
            absent = db.execute(update(TopicProject).where(
                TopicProject.source_id == source.id, TopicProject.eligible.is_(True),
                or_(TopicProject.last_seen_poll_id.is_(None), TopicProject.last_seen_poll_id != poll_id)
            ).values(eligible=False))
            result['no_longer_eligible'] = absent.rowcount
            source.last_success_at, source.last_error = jobs.now(), None
            db.commit()
        return result
    except (jobs.LeaseLost, jobs.JobCancelled):
        raise
    except Exception as exc:
        safe = str(exc) if isinstance(exc, (gitlab.GitLabSourceError, jobs.JobError)) else 'GitLab topic polling failed. Check job diagnostics.'
        with ctx.session_factory() as db:
            source = _current_source(ctx, db, payload, lock=True)
            source.last_error = safe
            db.commit()
        ctx.checkpoint({'observed': observed, 'skipped': skipped, 'project_errors': problems, 'failed_projects': problem_count})
        if isinstance(exc, gitlab.GitLabSourceError) and exc.status_code < 500:
            raise jobs.JobError(safe) from None
        raise
