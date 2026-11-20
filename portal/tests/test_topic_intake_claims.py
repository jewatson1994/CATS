from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.auth import AuthContext, hash_password
from app.database import Base
from app.models import AuditEvent, Execution, Group, Role, Service, User, UserRoleAssignment, utcnow
from app.scan_coordination import ScanJob
from app.topic_intake_claims import ClaimInput, claim_service, ensure_intake_service
from app.topic_intake_models import GitLabTopicSource, TopicIntakeGroup, TopicProject, TopicRevision
from test_cache_scope import scope
from test_portal import SessionLocal, add_user, csrf, new_client, setup_function


def intake(db):
    group, other = Group(name="Application owners"), Group(name="Other group")
    db.add_all([group, other])
    db.flush()
    admin_id = db.scalar(select(User.id).where(User.username == "admin"))
    source = GitLabTopicSource(name="Internal GitLab", origin="https://gitlab.example", namespace="mission",
        topic="cats", claim_group_id=group.id, authorized_by_id=admin_id, enabled=True)
    db.add(source)
    db.flush()
    project = TopicProject(source_id=source.id, origin=source.origin, gitlab_project_id=17, project_path="mission/test",
        web_url="https://gitlab.example/mission/test", default_branch="main")
    db.add(project)
    db.flush()
    service = ensure_intake_service(db, project)
    scan = ScanJob(id=uuid4().hex, status="complete", payload={}, service_key=service.service_key, available_at=utcnow())
    db.add(scan)
    db.flush()
    sha = "d" * 40
    execution = Execution(execution_key="public:" + scan.id, service_id=service.id, complete=True,
                          scanned_at=utcnow(), commit_sha=sha, raw_payload={"sbom_components": []})
    db.add(execution)
    db.flush()
    revision = TopicRevision(project_id=project.id, commit_sha=sha, ref="main", status="ready",
                             scan_job_id=scan.id, execution_id=execution.id)
    db.add(revision)
    db.flush()
    project.latest_revision_id = revision.id
    return project.id, group.id, other.id, service.id, service.service_key, execution.id


def manager(db, username, group_id):
    user = User(username=username, display_name=username, password_hash=hash_password("test-password-long"),
                must_change_password=False)
    db.add(user)
    db.flush()
    role_id = db.scalar(select(Role.id).where(Role.name == "Service Manager"))
    db.add(UserRoleAssignment(user_id=user.id, role_id=role_id, group_id=group_id))


def test_private_discovery_preserves_page_cache_until_ownership_is_claimed():
    with SessionLocal.begin() as db:
        project_id, group_id, _, _, _, execution_id = intake(db)
        manager(db, "owner", group_id)
    owner = new_client("owner")
    original = scope(owner)
    with SessionLocal.begin() as db:
        first = db.get(TopicProject, project_id)
        holding = db.get(Group, db.get(TopicIntakeGroup, 1).group_id)
        assert [service.id for service in holding.services] == [first.service_id]
        second = TopicProject(source_id=first.source_id, origin=first.origin, gitlab_project_id=18,
                              project_path="mission/second", web_url=first.origin + "/mission/second",
                              default_branch="main")
        db.add(second)
        db.flush()
        held = ensure_intake_service(db, second)
        assert [g.id for g in held.groups] == [db.get(TopicIntakeGroup, 1).group_id]
        assert {service.id for service in holding.services} == {first.service_id, held.id}
    assert scope(owner) == original
    response = owner.post(f"/api/unclaimed-services/{project_id}/claim", json={
        "group_id": group_id, "execution_id": execution_id, "csrf_token": csrf(owner)})
    assert response.status_code == 200, response.text
    assert scope(owner) != original


def test_group_claim_transfers_existing_evidence_once_and_limits_visibility():
    with SessionLocal.begin() as db:
        project, group, other, service_id, key, execution_id = intake(db)
        for name, destination in (("first", group), ("second", group), ("outsider", other)):
            manager(db, name, destination)
    first, second, outsider = (new_client(name) for name in ("first", "second", "outsider"))
    path = f"/api/unclaimed-services/{project}/claim"
    assert outsider.get("/api/unclaimed-services").json()["total"] == 0
    assert outsider.post(path, json={"group_id": other, "execution_id": execution_id, "csrf_token": csrf(outsider)}).status_code == 404
    queue = first.get("/api/unclaimed-services")
    assert queue.status_code == 200, queue.text
    row = queue.json()["items"][0]
    assert row["scanned"] and row["claim_group_ids"] == [group]
    assert key not in str(row)
    assert first.get("/services/" + key).status_code in (403, 404)
    assert first.post(path, json={"group_id": group, "csrf_token": csrf(first)}).status_code == 422
    assert first.post(path, json={"group_id": other, "execution_id": row["execution_id"], "csrf_token": csrf(first)}).status_code == 403
    assert first.post(path, json={"group_id": group, "execution_id": row["execution_id"], "csrf_token": "bad"}).status_code == 403
    def claim(client, reviewed=row["execution_id"]):
        return client.post(path, json={"group_id": group, "execution_id": reviewed, "csrf_token": csrf(client)})
    results = [claim(first), claim(second)]
    assert sorted(response.status_code for response in results) == [200, 409]
    winner = first if results[0].status_code == 200 else second
    assert claim(winner).json() == {"service_id": service_id, "service_key": key}
    assert claim(winner, row["execution_id"] + 1).status_code == 409
    assert first.get("/api/unclaimed-services").json()["total"] == 0
    with SessionLocal() as db:
        service = db.get(Service, service_id)
        assert service.lifecycle_status == "active" and [g.id for g in service.groups] == [group]
        assert db.get(Execution, execution_id).service_id == service.id
        assert db.get(TopicProject, project).claimed_execution_id == execution_id
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == "discovery.service_claimed")) == 1


def test_admin_cannot_edit_held_service_outside_claim_and_wrong_revision_is_rejected():
    with SessionLocal.begin() as db:
        project, group, other, service_id, key, execution_id = intake(db)
        db.get(Execution, execution_id).commit_sha = "c" * 40
        marker = db.get(TopicIntakeGroup, 1).group_id
    client = new_client()
    token = csrf(client)
    assert client.get("/api/unclaimed-services").json()["items"] == []
    assert client.post("/admin/services/" + key, data={"name": "unexpected", "csrf_token": token,
                       "group_ids": [other]}, follow_redirects=False).status_code in (403, 404)
    assert client.post("/admin/services/stage", data={"service_id": "another", "group_id": marker,
                       "csrf_token": token}, follow_redirects=False).status_code == 403
    assert client.post(f"/api/unclaimed-services/{project}/claim", json={
        "csrf_token": token, "group_id": other, "execution_id": execution_id}).status_code == 409
    with SessionLocal() as db:
        assert db.get(Service, service_id).lifecycle_status == "unclaimed"
        assert db.get(TopicProject, project).claimed_at is None


def test_global_cybersecurity_can_assign_another_group_and_assessors_cannot_claim():
    with SessionLocal.begin() as db:
        project, _, other, service_id, key, execution_id = intake(db)
        reserved = db.get(TopicIntakeGroup, 1).group_id
    add_user("reviewer", "Cybersecurity")
    add_user("observer", "Assessor")
    observer, cyber = new_client("observer"), new_client("reviewer")
    assert observer.get("/api/unclaimed-services").status_code == 403
    path = f"/api/unclaimed-services/{project}/claim"
    assert observer.post(path, json={"csrf_token": csrf(observer), "group_id": other, "execution_id": execution_id}).status_code == 403
    eligible_groups = cyber.get("/api/unclaimed-services").json()["items"][0]["claim_group_ids"]
    assert other in eligible_groups and reserved not in eligible_groups
    response = cyber.post(path, json={"csrf_token": csrf(cyber), "group_id": other, "execution_id": execution_id})
    assert response.status_code == 200 and response.json() == {"service_id": service_id, "service_key": key}


def test_polling_opt_out_and_disabled_source_remove_claim_authority():
    with SessionLocal.begin() as db:
        pid, group, _, _, _, execution_id = intake(db)
    client = new_client()
    payload = {"csrf_token": csrf(client), "group_id": group, "execution_id": execution_id}
    for source_enabled, project_eligible in ((False, True), (True, False)):
        with SessionLocal.begin() as db:
            project = db.get(TopicProject, pid)
            project.eligible = project_eligible
            db.get(GitLabTopicSource, project.source_id).enabled = source_enabled
        assert client.get("/api/unclaimed-services").json()["total"] == 0
        assert client.post(f"/api/unclaimed-services/{pid}/claim", json=payload).status_code == 404
    with SessionLocal.begin() as db:
        db.get(TopicProject, pid).eligible = True
    assert client.get("/api/unclaimed-services").json()["total"] == 1
    assert client.post(f"/api/unclaimed-services/{pid}/claim", json=payload).status_code == 200


def test_competing_claims_across_independent_sqlite_connections(tmp_path):
    from types import SimpleNamespace
    engine = create_engine("sqlite:///" + (tmp_path / "claims.db").as_posix())
    try:
        Base.metadata.create_all(engine)
        factory = sessionmaker(engine, expire_on_commit=False)
        with factory.begin() as db:
            admin = User(username="admin", display_name="Admin", password_hash="unused")
            role = Role(name="Service Manager", permissions=["service.edit"])
            db.add_all([admin, role])
            db.flush()
            pid, group, other, service_id, _, execution_id = intake(db)
            for name in ("first", "second"):
                manager(db, name, group)
        def claim_as(name):
            with factory() as db:
                auth = AuthContext(db.scalar(select(User).where(User.username == name)),
                                   SimpleNamespace(csrf_token="token"))
                try:
                    claim_service(pid, ClaimInput(group_id=group, execution_id=execution_id, csrf_token="token"), db, auth)
                    return 200
                except HTTPException as exc:
                    return exc.status_code
        with ThreadPoolExecutor(2) as pool:
            assert sorted(pool.map(claim_as, ("first", "second"))) == [200, 409]
    finally:
        engine.dispose()
