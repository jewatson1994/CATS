import base64
import json

from sqlalchemy import select

from app.durable_jobs import DurableJob
from app.models import AuditEvent, Group, User
from app.secrets import decrypt_secret
from app.topic_intake_models import GitLabTopicSource
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
