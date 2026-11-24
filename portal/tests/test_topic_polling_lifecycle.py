"""Topic-polling acceptance with a GitLab API fixture and scan-worker evidence."""
import base64
import io
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import discovery_gitlab, discovery_worker, durable_jobs, main, scan_artifacts, scan_control, scan_protocol
from app.auth import hash_password
from app.database import SessionLocal
from app.models import Execution, Group, Role, Service, User, UserRoleAssignment, WorkflowRequest, utcnow
from test_portal import csrf, new_client, setup_function  # noqa: F401


ORIGIN = "https://gitlab.example"
PROJECT = "team/apps/payments"
TOPIC = "cats-scan"
SHA1, SHA2, SHA3 = "a" * 40, "b" * 40, "c" * 40
WORKER = "integration-worker"
WORKER_TOKEN = "integration-credential-" + "7" * 40


class GitLab:
    """Only the provider API is simulated. Archive discovery runs against a real ZIP."""

    def __init__(self):
        self.sha = SHA1
        self.archives = []

    @property
    def image(self):
        return "registry.invalid/payments:" + self.sha[:12]

    def open(self, request, timeout):
        url = urlsplit(request.full_url)
        path = unquote(url.path)
        query = parse_qs(url.query)
        assert url.scheme == "https" and url.netloc == "gitlab.example"
        if path.endswith("/projects") and not path.startswith("/api/v4/projects/"):
            assert query["topic"] == [TOPIC]
            payload = [{"id": 47, "path_with_namespace": PROJECT, "web_url": ORIGIN + "/" + PROJECT,
                        "topics": [TOPIC], "default_branch": "main", "archived": False}]
        elif "/repository/branches/" in path:
            payload = {"name": "main", "commit": {"id": self.sha}}
        elif "/repository/commits/" in path:
            payload = {"id": self.sha}
        elif path == "/api/v4/projects/47":
            payload = {"id": 47, "path_with_namespace": PROJECT, "web_url": ORIGIN + "/" + PROJECT,
                       "topics": [TOPIC], "default_branch": "main", "archived": False}
        elif path.endswith("/repository/archive.zip"):
            assert query["sha"] == [self.sha]
            self.archives.append(self.sha)
            contents = io.BytesIO()
            with ZipFile(contents, "w") as archive:
                archive.writestr("payments-" + self.sha + "/deploy.yaml", json.dumps({
                    "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "payments"},
                    "spec": {"containers": [{"name": "api", "image": self.image}]},
                }))
            payload = contents.getvalue()
        else:
            raise AssertionError("Unexpected GitLab read " + request.full_url)
        response = io.BytesIO(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
        response.status = 200
        response.headers = {}
        return response


def run_queued(kind, handler, expected_status="completed"):
    job = durable_jobs.claim((kind,), "acceptance-worker")
    assert job is not None, kind
    durable_jobs.execute(job, handler)
    with SessionLocal() as db:
        row = db.get(durable_jobs.DurableJob, job.id)
        assert row.status == expected_status, (row.kind, row.error, row.result)
    return job.id


def post_json(client, path, body=None):
    return client.post(path, json=body or {}, headers={"X-CSRF-Token": csrf(client)}, follow_redirects=False)


def finish_scan(control, directory, service, version, image):
    """Claim the real job and submit a checksummed, attempt-bound evidence bundle."""
    headers = {"Authorization": "Bearer " + WORKER_TOKEN, "X-Worker-ID": WORKER}
    result = control.post("/internal/scan-worker/claim", json={"worker_id": WORKER}, headers=headers)
    assert result.status_code == 200, result.text
    claim = result.json()
    assert claim["service_key"] == service and claim["service_version"] == version
    assert image in claim["job"]["image_list"].splitlines()
    endpoint = f"/internal/scan-worker/{claim['job_id']}/{claim['attempt_id']}"
    headers["X-Attempt-Token"] = claim["attempt_token"]
    download = control.get(endpoint + "/input", headers=headers)
    assert download.status_code == 200
    inputs = directory / (claim["job_id"] + "-inputs.tar.gz")
    inputs.write_bytes(download.content)
    assert scan_artifacts.digest(inputs) == claim["input_digest"]

    root = directory / claim["job_id"]
    output = root / "output"
    output.mkdir(parents=True)
    (output / "scan-summary.json").write_text(json.dumps({"status": "complete", "images": 1, "findings": 0}))
    (output / "portal-result.json").write_text(json.dumps({
        "schema_version": "1.0", "execution_id": "scanner-report", "scanned_at": utcnow().isoformat(),
        "complete": True, "sbom_images": [image], "service": {"id": service, "name": service, "version": version}, "findings": [],
    }))
    archive = directory / (claim["job_id"] + "-result.tar.gz")
    identity = {key: claim[key] for key in ("job_id", "attempt_id", "input_digest", "service_key", "service_version")}
    scan_artifacts.pack(root, archive, {**identity, "returncode": 0})
    receipt = control.put(endpoint + "/results", headers=headers, content=archive.read_bytes())
    assert receipt.status_code == 200, receipt.text
    assert receipt.json()["accepted"] is True
    scan_protocol.ingest_one()
    scan_protocol.ingest_one()
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == "public:" + claim["job_id"]))
        assert execution and execution.complete
        assert execution.commit_sha == version and execution.service_version.version == version
        return execution.id


def poll_source(admin, source_id):
    from app import gitlab_topic_poll

    queued = post_json(admin, f"/api/admin/topic-polling/sources/{source_id}/poll")
    assert queued.status_code == 202, queued.text
    assert run_queued(gitlab_topic_poll.KIND, gitlab_topic_poll.poll) == queued.json()["job_id"]


def add_group_manager(db, username, group):
    role = db.scalar(select(Role).where(Role.name == "Service Manager"))
    user = User(username=username, display_name=username, password_hash=hash_password("fixture-password"))
    db.add(user)
    db.flush()
    db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, group_id=group.id))


@pytest.mark.parametrize("cross_group", [False, True], ids=["group", "instance"])
def test_polled_project_reuses_evidence_and_keeps_its_owner_across_versions(monkeypatch, tmp_path, cross_group):
    from app import topic_intake_processing
    from app.topic_intake_models import TopicProject, TopicRevision

    gitlab = GitLab()
    monkeypatch.setenv("CATS_DISCOVERY_GITLAB_SOURCES", ORIGIN)
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"t" * 32).decode())
    monkeypatch.setenv("CATS_DISCOVERY_UPLOAD_ROOT", str(tmp_path / "discovery"))
    monkeypatch.setenv("CATS_DISCOVERY_RENDER_CACHE", "false")
    monkeypatch.setenv("CATS_SCAN_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv("CATS_SCAN_WORKER_ID", WORKER)
    monkeypatch.delenv("CATS_SCAN_WORKER_CREDENTIALS", raising=False)
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path / "jobs")
    monkeypatch.setattr(discovery_gitlab.request, "build_opener", lambda *handlers: gitlab)
    with SessionLocal.begin() as db:
        group = Group(name="Payments")
        foreign = Group(name="Other")
        db.add_all([group, foreign])
        db.flush()
        group_id, foreign_id = group.id, foreign.id
        add_group_manager(db, "payments-manager", group)
        add_group_manager(db, "other-manager", foreign)
        db.add(User(username="directory-user", display_name="Directory user", auth_source="oidc",
                    password_hash=hash_password("fixture-password")))

    admin = new_client()
    manager = new_client("payments-manager", "fixture-password")
    other = new_client("other-manager", "fixture-password")
    directory_user = new_client("directory-user", "fixture-password")
    control = TestClient(scan_control.app)
    scope = {"namespace": "team", "claim_group_id": group_id}
    if cross_group:
        scope = {"scope_mode": "instance", "namespace_routes": [
            {"namespace": "other", "claim_group_id": foreign_id}, {"namespace": "team", "claim_group_id": group_id},
        ]}
    source_path = "/api/admin/topic-polling/sources"
    config = {"name": "Topic source", "origin": ORIGIN, "topic": TOPIC, "enabled": not cross_group, **scope}
    source = post_json(admin, source_path, config)
    assert source.status_code == 201, source.text
    source_id = source.json()["id"]
    if cross_group:
        from app import gitlab_topic_poll

        saved = f"{source_path}/{source_id}"
        preview = post_json(admin, saved + "/preview")
        assert preview.status_code == 202, preview.text
        run_queued(gitlab_topic_poll.PREVIEW_KIND, gitlab_topic_poll.poll)
        results = admin.get(saved + "/results").json()
        assert results["latest_job"] is None
        [match] = results["latest_preview"]["details"]
        assert (match["project_path"], match["claim_group_id"], match["commit_sha"]) == (PROJECT, group_id, SHA1)
        assert gitlab.archives == [] and admin.get(saved + "/projects").json()["total"] == 0
        assert durable_jobs.claim(("topic_intake_process", "discovery"), "preview-only") is None
        enabled = admin.put(saved, json={**config, "enabled": True}, headers={"X-CSRF-Token": csrf(admin)})
        assert enabled.status_code == 200, enabled.text

    def poll():
        poll_source(admin, source_id)

    def discover():
        run_queued("topic_intake_process", topic_intake_processing.handler)
        run_queued("discovery", discovery_worker.handle)
        topic_intake_processing.advance_ready()

    poll()
    discover()
    with SessionLocal() as db:
        project = db.scalars(select(TopicProject)).one()
        project_id, service_id = project.id, project.service_id
        service_key = db.get(Service, service_id, execution_options={"include_topic_intake": True}).service_key
    claim_path = f"/api/unclaimed-services/{project_id}/claim"
    pending = post_json(manager, claim_path, {"group_id": group_id, "execution_id": 1, "csrf_token": csrf(manager)})
    assert pending.status_code == 409, pending.text
    # A generic admin edit must not bypass evidence or the scoped claim transaction.
    direct_edit = admin.post(f"/admin/services/{service_key}", data={
        "csrf_token": csrf(admin), "name": "Other", "group_ids": foreign_id,
    }, follow_redirects=False)
    assert direct_edit.status_code in {403, 404, 409}, direct_edit.text

    first = finish_scan(control, tmp_path, service_key, SHA1, gitlab.image)
    topic_intake_processing.advance_ready()
    poll()
    assert durable_jobs.claim(("topic_intake_process",), "no-duplicate") is None
    assert gitlab.archives == [SHA1]
    [candidate] = manager.get("/api/unclaimed-services").json()["items"]
    assert candidate["scanned"] and candidate["execution_id"] == first
    assert not other.get("/api/unclaimed-services").json()["items"]
    hidden = directory_user.post("/account/access/service", data={"service_id": service_id, "csrf_token": csrf(directory_user)},
                                 follow_redirects=False)
    assert hidden.status_code == 404, hidden.text
    with SessionLocal() as db:
        from app import access_requests, oci_authorization
        user_id = db.scalar(select(User.id).where(User.username == "directory-user"))
        assert service_id not in [row.id for row in access_requests.service_directory(db, user_id)]
        mapping = SimpleNamespace(enabled=True, suspended=False, service_id=service_id, upstream=SimpleNamespace(enabled=True))
        assert not oci_authorization.authorize(db, mapping, "sha256:" + "d"*64).allowed
    gitlab.sha = SHA2
    poll()
    assert not manager.get("/api/unclaimed-services").json()["items"]
    assert admin.get(f"/api/admin/topic-polling/sources/{source_id}/projects").json()["total"] == 1
    reviewed = {"group_id": group_id, "execution_id": candidate["execution_id"], "csrf_token": csrf(manager)}
    assert post_json(manager, claim_path, reviewed).status_code == 409
    discover()
    second = finish_scan(control, tmp_path, service_key, SHA2, gitlab.image)
    topic_intake_processing.advance_ready()
    with SessionLocal() as db:
        revision = db.get(TopicRevision, db.get(TopicProject, project_id).latest_revision_id)
        discovery_detail = f"/api/discovery/{revision.discovery_job_id}"
    assert manager.get(discovery_detail).status_code == 404
    stale = post_json(manager, claim_path, reviewed)
    assert stale.status_code == 409 and "refresh" in stale.json()["detail"].lower()
    [updated] = manager.get("/api/unclaimed-services").json()["items"]
    assert updated["execution_id"] == second and updated["execution_id"] != reviewed["execution_id"]
    reviewed["execution_id"] = updated["execution_id"]
    foreign_claim = post_json(other, claim_path, {**reviewed, "group_id": foreign_id, "csrf_token": csrf(other)})
    assert foreign_claim.status_code in {403, 404}
    wrong_destination = post_json(manager, claim_path, {**reviewed, "group_id": foreign_id})
    assert wrong_destination.status_code in {403, 404}
    claimed = post_json(manager, claim_path, reviewed)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["service_id"] == service_id
    assert manager.get(f"/services/{service_key}").status_code == 200
    assert other.get(f"/services/{service_key}", follow_redirects=False).status_code in {403, 404}
    inventory = manager.get(discovery_detail)
    assert inventory.status_code == 200 and inventory.json()["inventory"]
    assert other.get(discovery_detail).status_code == 404
    assert post_json(manager, discovery_detail + "/cancel", {"csrf_token": csrf(manager)}).status_code == 404

    gitlab.sha = SHA3
    poll()
    discover()
    third = finish_scan(control, tmp_path, service_key, SHA3, gitlab.image)
    topic_intake_processing.advance_ready()
    assert post_json(manager, claim_path, reviewed).json() == claimed.json()
    assert post_json(manager, claim_path, {**reviewed, "execution_id": third}).status_code == 409
    poll()
    assert durable_jobs.claim(("topic_intake_process",), "no-duplicate") is None
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(TopicProject)) == 1
        assert db.scalar(select(func.count()).select_from(TopicRevision)) == 3
        service = db.get(Service, service_id)
        assert [g.id for g in service.groups] == [group_id]
        assert {run.id for run in service.executions} == {first, second, third}
        assert {run.service_version.version for run in service.executions} == {SHA1, SHA2, SHA3}
    # A force-pushed or reverted branch can point back to an already-scanned commit.
    gitlab.sha = SHA1
    poll()
    assert durable_jobs.claim(("topic_intake_process",), "no-repeated-work") is None
    with SessionLocal() as db:
        project = db.get(TopicProject, project_id)
        current = db.get(TopicRevision, project.latest_revision_id)
        assert (current.commit_sha, current.execution_id, current.status) == (SHA1, first, "ready")
    assert gitlab.archives == [SHA1, SHA2, SHA3]

    # The standard archive workflow keeps evidence and stops any later auto-ingest.
    archive = manager.post(f"/services/{service_key}/archive", data={
        "csrf_token": csrf(manager), "reason": "Retire test service",
    }, follow_redirects=False)
    assert archive.status_code == 303, archive.text
    with SessionLocal() as db:
        request_id = db.scalar(select(WorkflowRequest.id).where(WorkflowRequest.service_id == service_id,
                                                                WorkflowRequest.request_type == "archive"))
    review = admin.post(f"/requests/{request_id}/review", data={
        "csrf_token": csrf(admin), "decision": "approved", "review_reason": "Retirement verified",
    }, follow_redirects=False)
    assert review.status_code == 303, review.text
    gitlab.sha = "d" * 40
    poll()
    run_queued("topic_intake_process", topic_intake_processing.handler, expected_status="failed")
    topic_intake_processing.advance_ready()
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Execution).where(Execution.service_id == service_id)) == 3
        rev = db.get(TopicRevision, db.get(TopicProject, project_id).latest_revision_id)
        assert rev.status == "failed" and rev.execution_id is None
        retry_url = f"/api/admin/topic-polling/sources/{source_id}/revisions/{rev.id}/retry"
    assert post_json(admin, retry_url).status_code == 409
    assert gitlab.archives == [SHA1, SHA2, SHA3]



def test_conflicting_namespace_routes_hold_new_intake_until_resolved(monkeypatch):
    from app.topic_intake_models import TopicProject, TopicRevision

    gitlab = GitLab()
    monkeypatch.setenv("CATS_DISCOVERY_GITLAB_SOURCES", ORIGIN)
    monkeypatch.setattr(discovery_gitlab.request, "build_opener", lambda *handlers: gitlab)
    with SessionLocal.begin() as db:
        owners = Group(name="Primary owners")
        other = Group(name="Overlapping owners")
        db.add_all([owners, other])
        db.flush()
        owners_id, other_id = owners.id, other.id
    admin = new_client()
    sources = []
    for namespace, group_id in [("team", owners_id), ("team/apps", other_id)]:
        config = {
            "name": namespace, "origin": ORIGIN, "namespace": namespace, "topic": TOPIC, "claim_group_id": group_id, "enabled": True,
        }
        source = post_json(admin, "/api/admin/topic-polling/sources", config)
        assert source.status_code == 201, source.text
        sources.append(source.json()["id"])

    for source_id in sources:
        poll_source(admin, source_id)
    with SessionLocal() as db:
        assert not db.scalars(select(TopicProject)).first()
        assert not db.scalars(select(TopicRevision)).first()
    disabled = admin.put(f"/api/admin/topic-polling/sources/{sources[1]}", json={**config, "enabled": False},
                         headers={"X-CSRF-Token": csrf(admin)})
    assert disabled.status_code == 200, disabled.text
    poll_source(admin, sources[0])
    with SessionLocal() as db:
        project = db.scalars(select(TopicProject)).one()
        assert project.source_id == sources[0]
        assert db.scalars(select(TopicRevision.commit_sha)).all() == [SHA1]

def test_portal_navigation_returns_while_gitlab_worker_is_waiting(monkeypatch):
    from app import gitlab_topic_poll

    provider_entered = Event()
    release_provider = Event()
    gitlab = GitLab()

    def slow_provider(request, timeout):
        if urlsplit(request.full_url).path.endswith("/projects"):
            provider_entered.set()
            assert release_provider.wait(20), "Portal navigation was unable to finish during the GitLab poll"
        return gitlab.open(request, timeout)

    monkeypatch.setenv("CATS_DISCOVERY_GITLAB_SOURCES", ORIGIN)
    monkeypatch.setattr(discovery_gitlab.request, "build_opener", lambda *handlers: SimpleNamespace(open=slow_provider))
    with SessionLocal.begin() as db:
        owners = Group(name="Owners")
        db.add(owners)
        db.flush()
        group_id = owners.id

    admin = new_client()
    source = post_json(admin, "/api/admin/topic-polling/sources", {
        "name": "Slow GitLab", "origin": ORIGIN, "namespace": "team", "topic": TOPIC,
        "claim_group_id": group_id, "enabled": True,
    })
    assert source.status_code == 201
    source_id = source.json()["id"]
    admin_path = f"/api/admin/topic-polling/sources/{source_id}"
    admission = post_json(admin, admin_path + "/poll")
    assert admission.status_code == 202

    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(run_queued, gitlab_topic_poll.KIND, gitlab_topic_poll.poll)
        try:
            assert provider_entered.wait(10)
            home = admin.get("/", headers={"Accept": "application/vnd.cats.page+json"}, follow_redirects=False)
            assert home.status_code == 200 and home.json()["page"] == "dashboard"
            for path in (admin_path + "/projects", "/api/unclaimed-services"):
                page = admin.get(path, follow_redirects=False)
                assert page.status_code == 200 and page.json()["total"] == 0
            repeated = post_json(admin, admin_path + "/poll")
            assert repeated.status_code == 202
            assert repeated.json()["job_id"] == admission.json()["job_id"]
            assert not running.done()
        finally:
            release_provider.set()
        assert running.result(timeout=10) == admission.json()["job_id"]
