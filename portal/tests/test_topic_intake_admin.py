import base64
import json
from datetime import datetime, timezone

from sqlalchemy import select

from app.durable_jobs import DurableJob
from app.models import AuditEvent, Group, User
from app.secrets import decrypt_secret
from app.topic_intake_models import GitLabTopicSource, TopicProject
from test_portal import SessionLocal, add_user, csrf, new_client, setup_function  # noqa: F401


API = "/api/admin/topic-polling/sources"
ORIGIN = "https://gitlab.example"


def configure(monkeypatch):
    monkeypatch.setenv("CATS_DISCOVERY_GITLAB_SOURCES", ORIGIN)
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"a" * 32).decode())
    with SessionLocal.begin() as db:
        group = Group(name="Platform")
        db.add(group)
        db.flush()
        group_id = group.id
    admin = new_client()
    return admin, {"X-CSRF-Token": csrf(admin)}, {
        "name": "Platform GitLab", "origin": ORIGIN, "namespace": "platform/apps", "topic": "project-topic",
        "claim_group_id": group_id,
    }


def test_admin_source_credentials_rotation_scope_and_disabled_default(monkeypatch):
    admin, headers, body = configure(monkeypatch)
    token = "example-private-gitlab-token"
    create = admin.post(API, json={**body, "token": token}, headers=headers)
    assert create.status_code == 201, create.text
    source_id = create.json()["id"]
    path = f"{API}/{source_id}"
    assert create.json()["has_token"] and not create.json()["enabled"]
    assert token not in create.text and token not in admin.get(API).text
    assert admin.post(path + "/poll", headers=headers).status_code == 409
    with SessionLocal() as db:
        encrypted = db.get(GitLabTopicSource, source_id).token
        assert encrypted != token and decrypt_secret(encrypted) == token
        assert token not in json.dumps(db.scalar(select(AuditEvent.detail).where(
            AuditEvent.action == "topic.source.configured")))
    assert admin.post(API, json=body, headers=headers).status_code == 409
    assert admin.put(path, json={**body, "topic": "other"}, headers=headers).status_code == 409
    assert admin.put(path, json={**body, "enabled": True, "token": ""}, headers=headers).status_code == 200
    with SessionLocal() as db:
        assert db.get(GitLabTopicSource, source_id).token == encrypted
    for _ in range(2):
        polled = admin.post(path + "/poll", headers=headers)
        assert polled.status_code == 202, polled.text
    with SessionLocal.begin() as db:
        job = db.scalars(select(DurableJob)).one()
        job.result = {"project_errors": [{"gitlab_project_id": 11, "message": "GitLab returned invalid project topics."}]}
    assert admin.get(API).json()["sources"][0]["latest_job"]["project_errors"][0]["gitlab_project_id"] == 11
    monkeypatch.delenv("CATS_DISCOVERY_GITLAB_SOURCES")
    disabled = admin.put(path, json={**body, "enabled": False, "clear_token": True}, headers=headers)
    assert disabled.status_code == 200 and not disabled.json()["has_token"]
    assert admin.put(path, json={**body, "enabled": True}, headers=headers).status_code == 403


def test_source_admin_auth_csrf_mode_and_validation(monkeypatch):
    admin, headers, body = configure(monkeypatch)
    add_user("read-only", "Assessor")
    reader = new_client("read-only")
    assert reader.get(API).status_code == 403
    assert reader.post(API, headers={"X-CSRF-Token": csrf(reader)}, json=body).status_code == 403
    assert admin.post(API, json=body).status_code == 403
    assert admin.post(API, json={**body, "origin": "https://outside.example"}, headers=headers).status_code == 403
    assert admin.post(API, json={**body, "namespace": "group/../admin"}, headers=headers).status_code == 422
    assert admin.post(API, json={**body, "claim_group_id": 9999999}, headers=headers).status_code == 422
    conflict = admin.post(API, json={**body, "token": "sensitive-example", "clear_token": True}, headers=headers)
    assert conflict.status_code == 422 and "sensitive-example" not in conflict.text
    monkeypatch.delenv("CATS_CONFIG_ENCRYPTION_KEY")
    unencrypted = admin.post(API, json={**body, "token": "sensitive-example"}, headers=headers)
    assert unencrypted.status_code == 503 and "sensitive-example" not in unencrypted.text
    monkeypatch.setenv("CATS_MODE", "replica")
    assert admin.get(API).status_code == 403
    assert admin.post(API, json=body, headers=headers).status_code == 403
    assert admin.get("/api/unclaimed-services").status_code == 403


def test_another_configuration_administrator_can_reauthorize_a_source(monkeypatch):
    admin, headers, body = configure(monkeypatch)
    source_id = admin.post(API, json={**body, "enabled": True}, headers=headers).json()["id"]
    add_user("replacement-operator", "Cybersecurity")
    replacement = new_client("replacement-operator")
    with SessionLocal.begin() as db:
        old_operator = db.get(User, db.get(GitLabTopicSource, source_id).authorized_by_id)
        old_operator.enabled = False
    saved = replacement.put(f"{API}/{source_id}", headers={"X-CSRF-Token": csrf(replacement)},
                            json={**body, "enabled": True})
    assert saved.status_code == 200, saved.text
    with SessionLocal() as db:
        authorizer = db.get(GitLabTopicSource, source_id).authorized_by_id
        assert db.get(User, authorizer).username == "replacement-operator"


def test_instance_routes_are_required_validated_and_editable(monkeypatch):
    admin, headers, group_source = configure(monkeypatch)
    group_id = group_source["claim_group_id"]
    body = {"name": "Instance", "origin": ORIGIN, "topic": "project-topic", "scope_mode": "instance", "enabled": True}
    route = {"namespace": "payments", "claim_group_id": group_id}
    for routes in ([], [route, route], [{**route, "namespace": "a/../b"}], [{**route, "claim_group_id": 999999}]):
        assert admin.post(API, headers=headers, json={**body, "namespace_routes": routes}).status_code == 422
    created = admin.post(API, headers=headers, json={**body, "namespace_routes": [route]})
    assert created.status_code == 201, created.text
    source = created.json()
    assert source["scope_mode"] == "instance" and source["claim_group_id"] is None and source["namespace_routes"] == [route]
    path = f"{API}/{source['id']}"
    with SessionLocal.begin() as db:
        db.add(TopicProject(source_id=source["id"], origin=ORIGIN, gitlab_project_id=10,
                            claim_group_id=group_id, project_path="payments/api", web_url=ORIGIN + "/payments/api",
                            default_branch="main"))
    new_routes = [route, {**route, "namespace": "payments-tools"}, {**route, "namespace": "production"}]
    changed = admin.put(path, headers=headers, json={**body, "namespace_routes": new_routes})
    assert changed.status_code == 200, changed.text
    assert changed.json()["namespace_routes"] == new_routes
    with SessionLocal.begin() as db:
        assert db.scalar(select(TopicProject.eligible).where(TopicProject.gitlab_project_id == 10)) is True
        replacement = Group(name="Financial Services")
        db.add(replacement)
        db.flush()
        replacement_id = replacement.id
        for gid, root in ((11, "payments-tools"), (12, "production")):
            repo = f"{root}/api"
            db.add(TopicProject(source_id=source["id"], origin=ORIGIN, gitlab_project_id=gid,
                                claim_group_id=group_id, project_path=repo, web_url=ORIGIN + "/" + repo,
                                default_branch="main"))
    # Reassign payments, remove production, and preserve the similarly named sibling.
    changed = admin.put(path, headers=headers, json={**body, "namespace_routes": [
        {**route, "claim_group_id": replacement_id}, new_routes[1]]})
    assert changed.status_code == 200, changed.text
    with SessionLocal() as db:
        assert set(db.scalars(select(TopicProject.gitlab_project_id).where(TopicProject.eligible.is_(True)))) == {11}
    assert admin.put(path, headers=headers, json=group_source).status_code == 409


def test_new_enabled_overlapping_rule_holds_only_affected_unclaimed_projects(monkeypatch):
    admin, headers, group_source = configure(monkeypatch)
    source_id = admin.post(API, json={**group_source, "enabled": True}, headers=headers).json()["id"]
    with SessionLocal.begin() as db:
        group = Group(name="Mission")
        db.add(group)
        db.flush()
        mission = group.id
        source = db.get(GitLabTopicSource, source_id)
        before_revision = source.config_revision
        source.last_attempt_at = datetime.now(timezone.utc)
        for gid, namespace, topics in ((1, "mission", ["project-topic", "mission-topic"]),
                                       (2, "mission", ["project-topic"]),
                                       (3, "ops", ["project-topic", "mission-topic"]),
                                       (4, "mission", None),
                                       (5, "mission", ["project-topic", "mission-topic"])):
            path = f"platform/apps/{namespace}/p{gid}"
            db.add(TopicProject(source_id=source_id, origin=ORIGIN, gitlab_project_id=gid,
                                project_path=path, web_url=ORIGIN + "/" + path, default_branch="main",
                                observed_topics=topics, claimed_at=datetime.now(timezone.utc) if gid == 5 else None))
    rule = {"name": "Mission", "origin": ORIGIN, "topic": "mission-topic", "scope_mode": "instance",
            "namespace_routes": [{"namespace": "platform/apps/mission", "claim_group_id": mission}]}
    assert admin.post(API, json=rule, headers=headers).status_code == 201
    with SessionLocal() as db:
        assert db.get(GitLabTopicSource, source_id).config_revision == before_revision
    added = next(row for row in admin.get(API).json()["sources"] if row["name"] == "Mission")
    result = admin.put(f"{API}/{added['id']}", json={**rule, "enabled": True}, headers=headers)
    assert result.status_code == 200, result.text
    with SessionLocal() as db:
        peer = db.get(GitLabTopicSource, source_id)
        assert peer.config_revision != before_revision and peer.last_attempt_at is None
        assert set(db.scalars(select(TopicProject.gitlab_project_id).where(TopicProject.eligible.is_(True)))) == {2, 3, 5}


def test_preview_saved_disabled_source_is_admin_only_and_lazily_returns_bounded_details(monkeypatch):
    admin, headers, body = configure(monkeypatch)
    source_id = admin.post(API, json=body, headers=headers).json()["id"]
    path = f"{API}/{source_id}"
    add_user("preview-reader", "Assessor")
    reader = new_client("preview-reader")
    assert reader.get(path + "/results").status_code == 403
    assert reader.post(path + "/preview", headers={"X-CSRF-Token": csrf(reader)}).status_code == 403
    assert admin.post(path + "/preview").status_code == 403
    queued = admin.post(path + "/preview", headers=headers)
    assert queued.status_code == 202, queued.text
    assert admin.post(path + "/preview", headers=headers).json()["job_id"] == queued.json()["job_id"]
    with SessionLocal.begin() as db:
        job = db.get(DurableJob, queued.json()["job_id"])
        job.result = {"matched": 102, "new_commits": 100, "conflicts": 2, "truncated": True,
                      "excluded": 7, "excluded_by_reason": {"outside_namespace": 7},
                      "details": [{"gitlab_project_id": i + 1, "project_path": "platform/a", "status": "new_commit",
                                   "private_debug": "do-not-serialize"} for i in range(102)]}
    summary = admin.get(API).json()["sources"][0]
    assert summary["latest_job"] is None
    assert summary["latest_preview"]["matched"] == 102 and "details" not in summary["latest_preview"]
    details = admin.get(path + "/results")
    assert "do-not-serialize" not in details.text
    preview = details.json()["latest_preview"]
    assert preview["excluded_by_reason"] == {"outside_namespace": 7}
    assert preview["truncated"] and len(preview["details"]) == 100
    assert not admin.put(path, json=body, headers=headers).json()["latest_preview"]
    assert admin.get(path + "/results").json()["latest_preview"] is None


def test_new_credentials_require_fresh_results_and_keep_job_history(monkeypatch):
    admin, headers, body = configure(monkeypatch)
    body["enabled"] = True
    source_id = admin.post(API, json=body, headers=headers).json()["id"]
    path = f"{API}/{source_id}"
    poll_id = admin.post(path + "/poll", headers=headers).json()["job_id"]
    preview_id = admin.post(path + "/preview", headers=headers).json()["job_id"]
    with SessionLocal.begin() as db:
        db.add(TopicProject(source_id=source_id, origin=ORIGIN, gitlab_project_id=42,
                            project_path="platform/apps/service", web_url=ORIGIN + "/platform/apps/service",
                            default_branch="main"))
        db.get(GitLabTopicSource, source_id).last_attempt_at = datetime.now(timezone.utc)
    rotated = admin.put(path, headers=headers, json={**body, "token": "replacement-private-token"})
    assert rotated.status_code == 200
    assert admin.get(path + "/results").json() == {"latest_job": None, "latest_preview": None}
    with SessionLocal() as db:
        assert db.get(GitLabTopicSource, source_id).last_attempt_at is None
        assert db.get(DurableJob, poll_id) and db.get(DurableJob, preview_id)
        assert db.scalar(select(TopicProject.eligible).where(TopicProject.gitlab_project_id == 42)) is False
