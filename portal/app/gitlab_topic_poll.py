"""Preview and reconcile GitLab topic sources in the polling worker."""
from itertools import islice
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import extract, or_, select, update
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import joinedload

from . import discovery_gitlab as gitlab, durable_jobs as jobs
from .auth import AuthContext
from .database import SessionLocal
from .models import User, UserRoleAssignment
from .operating_mode import is_replica
from .replica_models import reserve_sqlite_writer
from .secrets import decrypt_secret
from .topic_intake_models import GitLabTopicSource, TopicProject, TopicRevision
from .topic_scope_rules import resolve_route, scope_sources
from .trusted_ca import configured_certificates


KIND = 'gitlab_topic_poll'
PREVIEW_KIND = 'gitlab_topic_preview'
BATCH_SIZE = 20
DETAIL_LIMIT = 100


def _active_job(source_id, revision, kind=KIND):
    job = jobs.DurableJob
    return select(job).where(job.kind == kind, job.status.in_(('queued', 'running')),
                             job.payload['source_id'].as_integer() == source_id,
                             job.payload['config_revision'].as_string() == revision)


def enqueue(db, source, actor_id=None, *, preview=False):
    """Manual and scheduled requests coalesce for one source configuration."""
    reserve_sqlite_writer(db)
    source = db.get(GitLabTopicSource, source.id, with_for_update=True, populate_existing=True)
    if is_replica() or source is None or (not preview and not source.enabled):
        raise jobs.JobError('GitLab topic polling requires an enabled source on the full portal.')
    kind = PREVIEW_KIND if preview else KIND
    job = db.scalar(_active_job(source.id, source.config_revision, kind).limit(1))
    if job is None:
        job = jobs.submit(db, kind=kind, payload={'source_id': source.id, 'config_revision': source.config_revision},
                          requested_by_id=actor_id, commit=False)
    if preview:
        source.latest_preview_job_id = job.id
    else:
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
    if (source is None or (not source.enabled and ctx.job.kind != PREVIEW_KIND)
            or source.config_revision != payload['config_revision']):
        raise jobs.JobError('GitLab topic source was disabled or reconfigured. Poll the current configuration.')
    return source


def _check_authority(db, source):
    # Keep the live authorization check before each credentialed request. Fetch
    # its usual role and mapping inputs with the principal in one round trip.
    assignments = joinedload(User.role_assignments)
    principal = db.execute(select(User).where(User.id == source.authorized_by_id)
        .options(assignments.joinedload(UserRoleAssignment.role),
                 assignments.joinedload(UserRoleAssignment.oidc_mapping))).unique().scalar_one_or_none()
    if not principal or not principal.enabled or not AuthContext(principal, None).can_manage_group(None):
        raise jobs.JobError('The source administrator no longer has global configuration access.')


def _known_projects(db, origin, projects):
    ids = [item['project_id'] for item in projects]
    rows = db.execute(select(TopicProject, TopicRevision.commit_sha, GitLabTopicSource.name, TopicRevision.status)
                      .join(GitLabTopicSource, GitLabTopicSource.id == TopicProject.source_id)
                      .outerjoin(TopicRevision, (TopicRevision.id == TopicProject.latest_revision_id)
                                 & (TopicRevision.project_id == TopicProject.id))
                      .where(TopicProject.origin == origin, TopicProject.gitlab_project_id.in_(ids)))
    return {row[0].gitlab_project_id: row for row in rows}


def _classify(source, item, sources, known):
    route = resolve_route(source, item, sources)
    bound, head, owner_name, _ = known or (None, None, None, None)
    if route.conflict_sources:
        names = ', '.join(route.conflict_sources[:3])
        more = len(route.conflict_sources) - 3
        if more > 0:
            names += f' and {more} more'
        groups = ', '.join(str(g) for g in route.conflict_group_ids[:5])
        if len(route.conflict_group_ids) > 5:
            groups += ', …'
        return 'conflict', None, f'Conflicting claim groups ({groups}) in {names}. Review the matching rules.'
    if route.claim_group_id is None:
        return 'skipped', None, 'The project is outside the configured namespaces.'
    if bound is not None and bound.source_id != source.id:
        return 'conflict', route.claim_group_id, f'Already tracked by {owner_name}.'
    if head == item['commit_sha']:
        return 'unchanged', route.claim_group_id, 'The default branch still points to the recorded commit.'
    return 'new_commit', route.claim_group_id, ('First observation of this project.' if not bound
                                                else 'The default branch points to a different commit.')


def _remember(result, detail):
    # Highlight actionable conflicts even if they occur after the sample filled.
    details = result['details']
    if len(details) < DETAIL_LIMIT:
        details.append(detail)
        return
    result['truncated'] = True
    if detail['status'] == 'conflict':
        for i in range(len(details) - 1, -1, -1):
            if details[i]['status'] != 'conflict':
                details[i] = detail
                break


def _process_batch(db, source, batch, *, preview, poll_id, result, problem):
    from .topic_intake_processing import IntakeError, observe_project, queue_observed

    sources = scope_sources(db, source)
    known = _known_projects(db, source.origin, batch)
    seen = []
    pending = []
    for item in batch:
        project_id = item['project_id']
        binding = known.get(project_id)
        bound = binding[0] if binding else None
        status, group_id, reason = _classify(source, item, sources, binding)
        result['matched'] += 1
        if not preview:
            if status in ('conflict', 'skipped'):
                # Another source can be first to see a newly conflicting topic.
                # Withdraw eligibility on that positive evidence without moving
                # ownership. Same-group duplicate matches keep their binding.
                ambiguity = status == 'conflict' and group_id is None
                if bound is not None and (bound.source_id == source.id or ambiguity):
                    if ambiguity:
                        bound.observed_topics = item.get('topics', [source.topic])
                    if bound.eligible:
                        bound.eligible = False
                        result['no_longer_eligible'] += 1
            else:
                topics = item.get('topics', [source.topic])
                if status == 'unchanged' and bound.eligible and binding.status != 'failed':
                    # Refresh renames, routing metadata and legacy rows without
                    # revisiting revision admission. ORM flushes only dirty values.
                    bound.claim_group_id, bound.observed_topics = group_id, topics
                    bound.project_path, bound.web_url = item['path_with_namespace'], item['web_url']
                    bound.default_branch = item['default_branch']
                    seen.append(bound.id)
                else:
                    try:
                        with db.begin_nested():
                            revision = observe_project(db, source, gitlab_project_id=project_id,
                                project_path=item['path_with_namespace'], web_url=item['web_url'],
                                default_branch=item['default_branch'], commit_sha=item['commit_sha'],
                                claim_group_id=group_id, observed_topics=topics, defer_queue=True)
                        if revision is None:
                            status, reason = 'conflict', 'Another source already tracks this project.'
                        else:
                            seen.append(revision.project_id)
                            if revision.status == 'pending' and revision.processing_job_id is None:
                                pending.append(revision)
                    except (DataError, IntegrityError, IntakeError):
                        problem(project_id, 'CATS could not bind this GitLab project revision.')
                        continue
                    except HTTPException as exc:
                        if exc.status_code == 429 or exc.status_code >= 500:
                            raise
                        problem(project_id, 'CATS could not admit this project revision.')
                        continue
        counter = {'conflict': 'conflicts', 'skipped': 'skipped', 'unchanged': 'unchanged_commits',
                   'new_commit': 'new_commits'}[status]
        result[counter] += 1
        if status in ('unchanged', 'new_commit'):
            result['observed'] += 1
        _remember(result, {'gitlab_project_id': project_id, 'project_path': item['path_with_namespace'],
                           'web_url': item['web_url'], 'default_branch': item['default_branch'],
                           'commit_sha': item['commit_sha'], 'claim_group_id': group_id,
                           'status': status, 'reason': reason})
    if seen:
        db.execute(update(TopicProject).where(
            TopicProject.source_id == source.id, TopicProject.id.in_(seen)).values(last_seen_poll_id=poll_id))
    if pending:
        # Finish project inserts/updates before acquiring the database-wide
        # PostgreSQL queue lock. Peer polls may be binding overlapping projects.
        db.flush()
        for revision in pending:
            if not queue_observed(db, source, revision):
                break


def poll(ctx, payload):
    if is_replica():
        raise jobs.JobError('GitLab topic polling is available only on the full portal.')
    preview = ctx.job.kind == PREVIEW_KIND
    ctx.stage('Previewing GitLab topic matches' if preview else 'Checking opted-in GitLab projects', 5)
    # A retry must never inherit membership observations from a partial attempt.
    poll_id = uuid4().hex
    result = dict(observed=0, skipped=0, matched=0, new_commits=0, unchanged_commits=0, conflicts=0,
                  excluded=0, excluded_by_reason={},
                  failed_projects=0, no_longer_eligible=0, project_errors=[], details=[], truncated=False)

    def excluded(reason):
        result['excluded'] += 1
        reasons = result['excluded_by_reason']
        reasons[reason] = reasons.get(reason, 0) + 1

    def problem(project_id, message):
        result['failed_projects'] += 1
        if len(result['project_errors']) < 20:
            result['project_errors'].append({'gitlab_project_id': project_id, 'message': message})

    def check():
        with ctx.session_factory() as db:
            _check_authority(db, _current_source(ctx, db, payload))

    try:
        with ctx.session_factory() as db:
            source = _current_source(ctx, db, payload, lock=not preview)
            origin, namespace, topic = source.origin, source.namespace, source.topic
            options = {} if namespace else {'namespaces': [route['namespace'] for route in source.namespace_routes]}
            token = source.token
            if not preview:
                source.last_attempt_at, source.last_error = jobs.now(), None
                db.commit()
        with ctx.session_factory() as db:
            _check_authority(db, _current_source(ctx, db, payload))
            try:
                trusted = configured_certificates(db)
                token = decrypt_secret(token) if token else None
            except ValueError:
                raise jobs.JobError('Check GitLab source credentials and the configured trusted certificates.') from None
        projects = iter(gitlab.iter_topic_projects(origin, namespace, topic, token=token,
                        trusted_ca_certificates=trusted, check=check, on_project_error=problem,
                        on_excluded=excluded, **options))
        # Network waits happen outside every write transaction. Stable projects
        # take one joined lookup and one membership update per bounded batch.
        while batch := list(islice(projects, BATCH_SIZE)):
            with ctx.session_factory() as db:
                source = _current_source(ctx, db, payload, lock=not preview)
                _check_authority(db, source)
                _process_batch(db, source, batch, preview=preview, poll_id=poll_id, result=result, problem=problem)
                if not preview:
                    db.commit()
        if result['failed_projects']:
            raise gitlab.GitLabSourceError(f"{result['failed_projects']} GitLab project(s) could not be polled. See job details.")
        with ctx.session_factory() as db:
            source = _current_source(ctx, db, payload, lock=not preview)
            _check_authority(db, source)
            if not preview:
                absent = db.execute(update(TopicProject).where(
                    TopicProject.source_id == source.id, TopicProject.eligible.is_(True),
                    or_(TopicProject.last_seen_poll_id.is_(None), TopicProject.last_seen_poll_id != poll_id)
                ).values(eligible=False))
                result['no_longer_eligible'] += absent.rowcount
                source.last_success_at, source.last_error = jobs.now(), None
                db.commit()
        return result
    except (jobs.LeaseLost, jobs.JobCancelled):
        raise
    except Exception as exc:
        safe = str(exc) if isinstance(exc, (gitlab.GitLabSourceError, jobs.JobError)) else 'GitLab topic polling failed. Check job diagnostics.'
        if not preview:
            with ctx.session_factory() as db:
                source = _current_source(ctx, db, payload, lock=True)
                source.last_error = safe
                db.commit()
        ctx.checkpoint(result)
        if isinstance(exc, gitlab.GitLabSourceError) and exc.status_code < 500:
            raise jobs.JobError(safe) from None
        raise
