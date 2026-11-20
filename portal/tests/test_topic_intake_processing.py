"""Revision identity, coverage and durable handoff failures."""
from types import SimpleNamespace

from fastapi import HTTPException
import pytest
from sqlalchemy import select

from app import durable_jobs, topic_intake_processing as intake
from app.models import Group, User
from app.topic_intake_claims import ensure_intake_service
from app.topic_intake_models import GitLabTopicSource, TopicProject, TopicRevision
from test_portal import SessionLocal, setup_function


SHA = "a" * 40


def add_source(db, name="source", namespace="team"):
    group = Group(name=name)
    db.add(group)
    db.flush()
    source = GitLabTopicSource(name=name, enabled=True, origin="https://gitlab.example", namespace=namespace,
        topic="cats", claim_group_id=group.id, authorized_by_id=db.scalar(select(User.id).where(User.username == "admin")))
    db.add(source)
    db.flush()
    return source


def observe(db, source, sha):
    return intake.observe_project(db, source, gitlab_project_id=42, project_path="team/test",
        web_url="https://gitlab.example/team/test", default_branch="main", commit_sha=sha)


@pytest.mark.parametrize('change,expected', [('rotate', 'queued'), ('revoke', 'failed'), ('opt-out', 'failed')])
def test_archive_stops_sending_token_after_authority_changes_mid_fetch(monkeypatch, tmp_path, change, expected):
    import json
    from io import BytesIO
    from cryptography.fernet import Fernet
    from app import discovery_gitlab
    from app.secrets import encrypt_secret

    origin = 'https://gitlab.example'
    monkeypatch.setenv('CATS_DISCOVERY_GITLAB_SOURCES', origin)
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path))
    with SessionLocal.begin() as db:
        source = add_source(db)
        source.token = encrypt_secret('initial-token')
        revision = observe(db, source, SHA)
        source_id, project_id = source.id, revision.project_id
    requests = []
    def open_request(req, timeout):
        requests.append((req.full_url, req.get_header('Private-token')))
        # This request was authorized. Change authority before GitLab's reply
        # reaches the worker, after the connection for its check was released.
        with SessionLocal.begin() as db:
            source = db.get(GitLabTopicSource, source_id)
            if change == 'rotate':
                source.config_revision, source.token = 'b' * 32, encrypt_secret('replacement-token')
            elif change == 'revoke':
                db.get(User, source.authorized_by_id).enabled = False
            else:
                db.get(TopicProject, project_id).eligible = False
        data = dict(id=42, topics=['cats'], archived=False, path_with_namespace='team/test',
                    web_url=origin + '/team/test', default_branch='main')
        response = BytesIO(json.dumps(data).encode())
        response.status, response.headers = 200, {}
        return response
    monkeypatch.setattr(discovery_gitlab.request, 'build_opener', lambda *args: SimpleNamespace(open=open_request))
    job = durable_jobs.claim((intake.KIND,), 'fetcher')
    durable_jobs.execute(job, intake.handler)
    assert requests == [(origin + '/api/v4/projects/42', 'initial-token')]
    with SessionLocal() as db:
        assert db.get(durable_jobs.DurableJob, job.id).status == expected
        assert not db.scalar(select(durable_jobs.DurableJob.id).where(durable_jobs.DurableJob.kind == 'discovery'))
    assert not list(tmp_path.rglob('*.part')) and not list(tmp_path.rglob('repository.zip'))


def test_overlapping_scopes_cannot_rebind_and_failed_revision_retry_is_explicit():
    with SessionLocal.begin() as db:
        source = add_source(db)
        first = observe(db, source, SHA)
        old_job = first.processing_job_id
        other = add_source(db, "overlap", "team/apps")
        assert observe(db, other, SHA) is None
        assert observe(db, source, SHA).id == first.id
        claimed = db.get(durable_jobs.DurableJob, old_job)
        claimed.status, claimed.error = "failed", "Repository access denied."
    intake.advance_ready()
    with SessionLocal.begin() as db:
        first = db.scalar(select(TopicRevision))
        assert first.status == "failed" and first.error == "Repository access denied."
        assert observe(db, db.scalar(select(GitLabTopicSource).where(GitLabTopicSource.name == "source")), SHA).processing_job_id == old_job
        assert intake.retry_revision(db, first).id != old_job
        assert first.status == "pending"
        with pytest.raises(HTTPException):
            intake.retry_revision(db, first)


def test_lost_administrator_and_archived_service_are_fenced():
    with SessionLocal.begin() as db:
        source = add_source(db)
        revision = observe(db, source, SHA)
        project = db.get(TopicProject, revision.project_id)
        service = ensure_intake_service(db, project)
        project.claimed_at = revision.created_at
        service.lifecycle_status = "archived"
        db.flush()
        with pytest.raises(intake.IntakeError, match="archived"):
            intake._binding(db, revision.id)
        db.get(User, source.authorized_by_id).enabled = False
        db.flush()
        with pytest.raises(intake.IntakeError, match="administrator"):
            intake._binding(db, revision.id)


def test_version_label_changes_never_replace_commit_identity_or_missing_coverage():
    inventory = SimpleNamespace(inventory={"roots": [{"id": "r", "technology": "helm", "chart_version": "1.4.3",
        "completeness": "complete"}], "nodes": [{"kind": "HelmRelease", "provenance": [{"reference": "oci://repo/apps/app",
        "version": "1.4.3", "chart_sha256": "c"*64, "chart_digest_kind": "tree"}]}]})
    assert intake._version(inventory, SHA) == "1.4.3"
    assert intake._chart_provenance(inventory) == [{"reference": "oci://repo/apps/app", "version": "1.4.3",
                                                   "sha256": "c"*64, "digest_kind": "tree"}]
    inventory.inventory["roots"].append({"technology": "kubernetes"})
    assert intake._version(inventory, SHA) == SHA
    for sha in (SHA, "b"*40):
        job = {"image_list": "registry/demo:1\nregistry/sidecar:2", "topic_intake": {"commit_sha": sha},
               "returncode": 0}
        for images, complete in ((["registry/demo:1"], False), (job["image_list"].splitlines(), True),
                                 (job["image_list"].splitlines() + ["registry/unexpected:3"], False)):
            data = {"complete": True, "sbom_images": images}
            intake.bind_result(data, job, {"status": "complete"})
            assert data["complete"] is complete
            assert data["commit_sha"] == sha and data["scan_scope"] == ("service" if complete else "evidence")
        for skipped in ("skipped_images", "skipped_charts"):
            data = {"complete": True, "sbom_images": job["image_list"].splitlines()}
            intake.bind_result(data, job, {"status": "complete", skipped: ["missing"]})
            assert not data["complete"]


def test_superseded_revision_cannot_publish_or_be_manually_retried():
    with SessionLocal.begin() as db:
        source = add_source(db)
        first = observe(db, source, SHA)
        second = observe(db, source, "b"*40)
        db.flush()
        with pytest.raises(intake.IntakeError, match="superseded"):
            intake._binding(db, first.id)
        first.status = "failed"
        with pytest.raises(HTTPException) as denied:
            intake.retry_revision(db, first)
        assert denied.value.status_code == 409
        assert db.get(TopicProject, second.project_id).latest_revision_id == second.id


def test_one_slot_queue_preserves_pending_project_and_encrypted_archive(tmp_path, monkeypatch):
    import base64
    from hashlib import sha256
    from app.discovery_sources import decrypted_source

    monkeypatch.setenv("CATS_JOB_QUEUE_CAPACITY", "1")
    monkeypatch.setenv("CATS_DISCOVERY_UPLOAD_ROOT", str(tmp_path))
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"s"*32).decode())
    body = b"repository contents"
    reads = []

    def download(source, project_id, sha, stream, **kwargs):
        reads.append(sha)
        stream.write(body)
        return sha256(body).hexdigest()

    monkeypatch.setattr(intake, "fetch_project_archive", download)
    with SessionLocal.begin() as db:
        source = add_source(db)
        occupying = durable_jobs.submit(db, kind="topic_poll", payload={}, commit=False)
        revision = observe(db, source, SHA)
        assert revision.processing_job_id is None
        occupying.status = "completed"
        revision_id = revision.id
    intake.advance_ready()
    process = durable_jobs.claim((intake.KIND,), "polling")
    assert process is not None
    durable_jobs.execute(process, intake.handler)
    with SessionLocal() as db:
        stored = db.get(TopicRevision, revision_id)
        assert stored.status == "pending" and stored.discovery_job_id is None
        assert db.get(durable_jobs.DurableJob, process.id).status == "completed"
    intake.advance_ready()
    intake.advance_ready()
    with SessionLocal() as db:
        revision = db.get(TopicRevision, revision_id)
        assert revision.status == "discovering" and reads == [SHA]
        job = db.get(durable_jobs.DurableJob, revision.discovery_job_id)
        staged = tmp_path / job.payload["source_id"] / "repository.zip"
        assert body not in staged.read_bytes()
        with decrypted_source(staged, job.payload["source_id"], job.payload["source_hash"]) as path:
            assert path.read_bytes() == body


def test_retention_cleans_abandoned_encrypted_archive_and_keeps_waiting_handoff(monkeypatch, tmp_path):
    from datetime import timedelta
    from app.discovery_retention import cleanup_sources
    from app.models import utcnow

    monkeypatch.setenv("CATS_DISCOVERY_UPLOAD_ROOT", str(tmp_path))
    monkeypatch.setenv("CATS_DISCOVERY_SOURCE_RETENTION_HOURS", "1")
    with SessionLocal.begin() as db:
        source = add_source(db)
        first = observe(db, source, SHA)
        second = observe(db, source, "b" * 40)
        first.status = "failed"
        for rev in (first, second):
            job = db.get(durable_jobs.DurableJob, rev.processing_job_id)
            job.created_at = utcnow() - timedelta(hours=2)
            job.status = "completed"
            folder = tmp_path / job.id
            folder.mkdir()
            (folder / "repository.zip").write_bytes(b"ciphertext")
            (folder / ("c"*32 + ".part")).write_bytes(b"partial ciphertext")
        waiting_id, abandoned_id = second.processing_job_id, first.processing_job_id
    assert cleanup_sources(SessionLocal) == 2
    assert not list((tmp_path / abandoned_id).glob("*"))
    assert (tmp_path / waiting_id / "repository.zip").is_file()


def test_returning_topic_requeues_the_same_revision_after_an_opt_out():
    with SessionLocal.begin() as db:
        source = add_source(db)
        rev = observe(db, source, SHA)
        project = db.get(TopicProject, rev.project_id)
        project.eligible = False
        rev.status, rev.error = "failed", intake._OPTED_OUT
        old_id = rev.processing_job_id
        db.flush()
        with pytest.raises(intake.IntakeError, match="no longer opted in"):
            intake._binding(db, rev.id)
        assert observe(db, source, SHA).id == rev.id and project.eligible
        assert rev.status == "pending" and rev.processing_job_id is None
    intake.advance_ready()
    with SessionLocal() as db:
        rev = db.scalar(select(TopicRevision))
        assert rev.processing_job_id and rev.processing_job_id != old_id
