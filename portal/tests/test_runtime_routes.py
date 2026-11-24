"""Exercise enrollment, isolation, replay protection and coverage through HTTP."""
from datetime import timedelta
from types import SimpleNamespace

import pytest
import secrets
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import main as portal_app  # Register the same complete schema as production startup.
from app import runtime_routes as runtime
from app import runtime_report_pages
from app.auth import AuthContext, require_user
from app.database import Base, SessionLocal, get_db
from app.models import AuditEvent, Service
from app.operating_mode import ReplicaModeMiddleware
from app.runtime_models import RuntimeAgent, RuntimeEnvironment, RuntimeLinkToken, now


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    with SessionLocal(bind=engine, expire_on_commit=True) as db:
        db.add(Service(name='Application', service_key='application'))
        db.commit()
        assignment = SimpleNamespace(role=SimpleNamespace(name='Runtime administrator', permissions=['runtime.view', 'runtime.manage']),
                                     service_id=None, group_id=None, group=None)
        auth = AuthContext(user=SimpleNamespace(id=None, username='operator', display_name='Operator', role_assignments=[assignment]),
                           session=SimpleNamespace(csrf_token='csrf'))
        app = FastAPI()
        app.include_router(runtime.router)
        app.include_router(runtime_report_pages.router)
        app.add_middleware(ReplicaModeMiddleware)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[require_user] = lambda: auth
        with TestClient(app) as client:
            yield client, db, auth
    engine.dispose()


def post(client, path, data=None):
    return client.post('/api/runtime/' + path, json=data or {}, headers={'X-CSRF-Token': 'csrf'})


def enroll(client, name='Core Cluster 01', source='stable-source', kind='kubernetes'):
    env = post(client, 'environments', {'name': name, 'kind': kind, 'service_ids': [1]})
    assert env.status_code == 200, env.text
    return link_agent(client, env.json()['id'], source)


def link_agent(client, identity, source):
    key = post(client, f'environments/{identity}/link-tokens').json()['linking_key']
    result = post(client, 'link', {'linking_key': key, 'name': 'Cluster collector', 'source_id': source, 'version': '0.1.0'})
    assert result.status_code == 200, result.text
    return result.json(), key


def snapshot(sequence=1, **changes):
    return {'sequence': sequence, 'observed_at': now().isoformat(), 'complete': True, 'errors': [],
            'workloads': [{'uid': 'pod-id:regular:api', 'namespace': 'default', 'workload': 'api', 'container': 'api',
                           'image_ref': 'registry.example/project/api:latest',
                           'image_id': 'registry.example/project/api@sha256:' + 'a' * 64, 'state': 'running'}], **changes}


def report(client, linked, value):
    return client.post('/api/runtime/reports', json=value, headers={'Authorization': 'Bearer ' + linked['agent_token']})


def test_named_environment_link_secret_lifecycle_and_revoke(context):
    client, db, _ = context
    linked, key = enroll(client)
    agent = db.get(RuntimeAgent, linked['agent_id'])
    assert agent.token_hash == runtime.hashed(linked['agent_token'])
    assert db.scalar(select(RuntimeLinkToken)).token_hash == runtime.hashed(key)
    assert linked['environment_name'] == 'Core Cluster 01'
    assert post(client, 'link', {'linking_key': key, 'name': 'Other', 'source_id': 'other', 'version': '1'}).status_code == 401
    overview = client.get('/api/runtime')
    assert overview.headers['cache-control'] == 'no-store'
    assert overview.json()['agents'][0]['coverage'] == 'never_reported'
    assert 'token_hash' not in overview.text and key not in overview.text and linked['agent_token'] not in overview.text
    audit = str([row.detail for row in db.scalars(select(AuditEvent))])
    assert key not in audit and linked['agent_token'] not in audit
    result = client.put(f"/api/runtime/environments/{linked['environment_id']}", json={'name': 'Core Cluster A'}, headers={'X-CSRF-Token': 'csrf'})
    assert result.status_code == 200
    assert db.get(RuntimeAgent, agent.id).source_id == 'stable-source'
    assert post(client, f'agents/{agent.id}/revoke').status_code == 200
    assert report(client, linked, snapshot()).status_code == 401
    assert client.get('/api/runtime').json()['agents'][0]['coverage'] == 'revoked'


def test_runtime_page_and_application_permissions_are_wired(context, monkeypatch):
    from app.frontend import PAGE_MEDIA_TYPE
    from app.database import portal_tables
    from app.auth import PERMISSIONS, SYSTEM_ROLES
    _, db, auth = context
    assert {'runtime_agents', 'runtime_environments', 'runtime_link_tokens'} <= {table.name for table in portal_tables()}
    assert {'runtime.view', 'runtime.manage'} <= set(PERMISSIONS)
    assert any({'runtime.view', 'runtime.manage'} <= set(permissions) for permissions in SYSTEM_ROLES.values())
    monkeypatch.setattr(portal_app, 'page_context', lambda value: {
        'csrf_token': value.csrf_token, 'can': value.has, 'cats_mode': 'full'})
    portal_app.app.dependency_overrides[get_db] = lambda: db
    portal_app.app.dependency_overrides[require_user] = lambda: auth
    try:
        with TestClient(portal_app.app) as client:
            response = client.get('/runtime', headers={'Accept': PAGE_MEDIA_TYPE})
            assert response.status_code == 200
            assert response.json()['page'] == 'runtime'
            assert response.json()['data']['permissions']['runtime.manage'] is True
            auth.user.role_assignments[0].role.permissions = []
            assert client.get('/runtime', headers={'Accept': PAGE_MEDIA_TYPE}).status_code == 403
    finally:
        portal_app.app.dependency_overrides.clear()


def test_reports_replay_order_incomplete_and_empty_reconciliation(context, monkeypatch):
    client, db, _ = context
    linked, _ = enroll(client)
    first = snapshot()
    assert report(client, linked, first).status_code == 200
    db.expire_all()
    received = db.get(RuntimeAgent, linked['agent_id']).last_seen_at
    retry = report(client, linked, first)
    assert retry.json()['duplicate'] is True
    db.expire_all()
    assert db.get(RuntimeAgent, linked['agent_id']).last_seen_at == received
    assert report(client, linked, snapshot()).status_code == 409
    second = snapshot(2, complete=False, errors=['kubernetes_access_denied'], workloads=[])
    assert report(client, linked, second).status_code == 200
    page = client.get('/api/runtime').json()
    assert page['agents'][0]['coverage'] == 'incomplete'
    assert len(page['workloads']) == 1
    assert page['workloads'][0]['compliance'] == {'status': 'unverified', 'reason': 'coverage_incomplete'}
    assert page['agents'][0]['inventory_observed_at'] == first['observed_at']
    assert report(client, linked, first).status_code == 409
    assert report(client, linked, snapshot(3, workloads=[])).status_code == 200
    page = client.get('/api/runtime').json()
    assert page['agents'][0]['coverage'] == 'fresh' and page['workloads'] == []


def test_current_policy_reevaluated_and_stale_never_green(context, monkeypatch):
    from app import runtime_policy
    client, db, _ = context
    linked, _ = enroll(client)
    assert report(client, linked, snapshot()).status_code == 200
    monkeypatch.setattr(runtime_policy, 'evaluate_observation', lambda *args, **kwargs: {'status': 'approved', 'reason': 'approved_release'})
    assert client.get('/api/runtime').json()['workloads'][0]['compliance']['status'] == 'approved'
    monkeypatch.setattr(runtime_policy, 'evaluate_observation', lambda *args, **kwargs: {'status': 'noncompliant', 'reason': 'revoked'})
    assert client.get('/api/runtime').json()['workloads'][0]['compliance']['reason'] == 'revoked'
    monkeypatch.setattr(runtime, 'now', lambda: now() + timedelta(minutes=6))
    page = client.get('/api/runtime').json()
    assert page['agents'][0]['coverage'] == 'stale'
    assert page['workloads'][0]['compliance']['status'] == 'unverified'


def test_replacement_hides_revoked_agent_inventory_and_preserves_agent_history(context):
    client, _, _ = context
    old, _ = enroll(client)
    retired = snapshot()["workloads"][0]
    assert report(client, old, snapshot(workloads=[{**retired, "namespace": "retired"}])).is_success
    assert post(client, f"agents/{old['agent_id']}/revoke").is_success
    before = client.get("/api/runtime").json()
    assert before["total_workloads"] == 0 and before["namespaces"] == []
    assert [item["reason"] for item in before["issues"]] == ["coverage_revoked"]
    new, _ = link_agent(client, old["environment_id"], "replacement-installation")
    assert report(client, new, snapshot(workloads=[{**retired, "uid": "next:api", "namespace": "current"}])).is_success
    current = client.get("/api/runtime").json()
    assert current["total_workloads"] == current["clusters"][0]["agent_count"] == 1
    assert [ns["name"] for ns in current["namespaces"]] == ["current"]
    assert all(issue["agent_id"] == new["agent_id"] for issue in current["issues"])
    assert {a["coverage"]: a["workload_count"] for a in current["agents"]} == {"revoked": 1, "fresh": 1}


def test_overlapping_kubernetes_collectors_choose_freshest_inventory_in_each_environment(context, monkeypatch):
    client, _, _ = context
    first, _ = enroll(client)
    second, _ = link_agent(client, first["environment_id"], "parallel-installation")
    another, _ = enroll(client, "Other Cluster")
    observed = now() - timedelta(minutes=2)

    def publish(agent, sequence, at, **changes):
        assert report(client, agent, snapshot(sequence, observed_at=at.isoformat(), **changes)).is_success

    def projected(agent):
        page = client.get("/api/runtime", params={"environment_id": first["environment_id"]}).json()
        assert page["total_workloads"] == page["clusters"][0]["workload_count"] == page["namespaces"][0]["workload_count"] == 1
        assert page["workloads"][0]["agent_id"] == agent["agent_id"]
        return page

    publish(first, 1, observed - timedelta(minutes=5))
    publish(second, 1, observed)
    assert any(issue["reason"] == "coverage_stale" for issue in projected(second)["issues"])
    publish(first, 2, observed)
    publish(another, 1, observed)
    projected(max((first, second), key=lambda a: a["agent_id"]))
    assert client.get("/api/runtime").json()["total_workloads"] == 2
    publish(second, 2, observed + timedelta(seconds=10))
    assert projected(second)["total_issues"] == 1
    publish(second, 3, observed + timedelta(seconds=20), complete=False, errors=["api_timeout"], workloads=[])
    mixed = projected(first)
    assert {issue["code"]: issue["agent_id"] for issue in mixed["issues"]} == {
        "coverage": second["agent_id"], "unverified": first["agent_id"]}
    monkeypatch.setattr(runtime, "now", lambda: now() + timedelta(minutes=6))
    stale = projected(second)
    assert stale["workloads"][0]["compliance"] == {"status": "unverified", "reason": "coverage_stale"}
    assert [issue["code"] for issue in stale["issues"]] == ["coverage", "coverage"]


def test_docker_hosts_keep_independent_container_ids(context):
    client, _, _ = context
    first, _ = enroll(client, kind="docker")
    second, _ = link_agent(client, first["environment_id"], "second-host")
    for host in (first, second):
        assert report(client, host, snapshot()).is_success
    page = client.get("/api/runtime").json()
    assert page["total_workloads"] == 2
    assert {row["agent_id"] for row in page["workloads"]} == {first["agent_id"], second["agent_id"]}


def test_security_boundaries_and_scope(context):
    client, _, auth = context
    assert client.post('/api/runtime/environments', json={}).status_code == 403
    assert post(client, 'environments', {'name': 'X', 'kind': 'docker', 'service_ids': [99]}).status_code == 422
    assert post(client, 'environments', {'name': 'X', 'kind': 'docker', 'service_ids': [True]}).status_code == 422
    linked, _ = enroll(client)
    assert client.post('/api/runtime/reports', json=snapshot()).status_code == 401
    assert client.post('/api/runtime/reports', json=snapshot(), headers={'Authorization': 'Bearer csrf'}).status_code == 401
    assert report(client, linked, snapshot(environment_id=999)).status_code == 422
    auth.user.role_assignments[0].service_id = 1
    assert client.get('/api/runtime').status_code == 403
    assert post(client, 'environments', {'name': 'Other', 'kind': 'docker'}).status_code == 403
    auth.user.role_assignments[0].service_id = None
    auth.user.role_assignments[0].role.permissions = ['runtime.view']
    assert client.get('/api/runtime').json()['permissions']['manage'] is False
    assert post(client, f"agents/{linked['agent_id']}/revoke").status_code == 403


def test_excessive_json_nesting_is_rejected(context):
    client, _, _ = context
    linked, _ = enroll(client)
    response = client.post('/api/runtime/reports', content='[' * 2000 + '0' + ']' * 2000,
                           headers={'Authorization': 'Bearer ' + linked['agent_token'], 'Content-Type': 'application/json'})
    assert response.status_code == 422


def test_link_expiry_replacement_and_relink(context):
    client, db, _ = context
    linked, _ = enroll(client)
    env = linked['environment_id']
    key = post(client, f'environments/{env}/link-tokens').json()['linking_key']
    token = db.scalar(select(RuntimeLinkToken).where(RuntimeLinkToken.token_hash == runtime.hashed(key)))
    token.expires_at = now() - timedelta(seconds=1)
    db.commit()
    payload = {'linking_key': key, 'name': 'Agent', 'source_id': 'stable-source', 'version': '0.1'}
    assert post(client, 'link', payload).status_code == 401
    key = post(client, f'environments/{env}/link-tokens').json()['linking_key']
    next_key = post(client, f'environments/{env}/link-tokens').json()['linking_key']
    assert post(client, 'link', {**payload, 'linking_key': key}).status_code == 401
    assert post(client, 'link', {**payload, 'linking_key': next_key}).status_code == 409
    assert post(client, f"agents/{linked['agent_id']}/revoke").status_code == 200
    result = post(client, 'link', {**payload, 'linking_key': next_key})
    assert result.status_code == 200, result.text
    assert result.json()['agent_id'] == linked['agent_id']
    assert report(client, linked, snapshot()).status_code == 401
    assert report(client, result.json(), snapshot()).status_code == 200


@pytest.mark.parametrize('change', [
    {'sequence': True}, {'sequence': 0}, {'complete': 'true'}, {'observed_at': '2026-01-01'},
    {'observed_at': (now() + timedelta(hours=1)).isoformat()}, {'workloads': [None]},
    {'workloads': [{'uid': 'x', 'container': 'a', 'state': 'running', 'env': {'SECRET': 'hidden'}}]},
    {'errors': ['secret with spaces']}, {'errors': ['scan_failed']},
    {'workloads': [{'uid': 'x', 'container': 'a', 'state': 'running'}] * 2},
])
def test_malformed_reports_rejected(context, change):
    client, _, _ = context
    linked, _ = enroll(client)
    assert report(client, linked, snapshot(**change)).status_code == 422


def test_body_limit_and_old_observation_not_fresh(context):
    client, _, _ = context
    linked, _ = enroll(client)
    response = client.post('/api/runtime/reports', content=b' ' * (runtime.MAX_BODY + 1),
                           headers={'Authorization': 'Bearer ' + linked['agent_token']})
    assert response.status_code == 413
    assert report(client, linked, snapshot(observed_at=(now() - timedelta(hours=1)).isoformat())).status_code == 200
    assert client.get('/api/runtime').json()['agents'][0]['coverage'] == 'stale'


def test_replica_has_narrow_local_reporting_boundary(context, monkeypatch):
    client, _, _ = context
    monkeypatch.setenv('CATS_MODE', 'replica')
    linked, _ = enroll(client)
    assert report(client, linked, snapshot(workloads=[])).status_code == 200
    assert client.get('/api/runtime').status_code == 200
    assert client.post('/api/runtime/anything-else', json={}).status_code == 403
    assert client.post('/api/cyber-approvals', json={}).status_code == 403


def test_link_recovery_requires_both_original_secrets_and_live_source(context):
    client, db, _ = context
    env = post(client, "environments", {"name": "Core", "kind": "kubernetes", "service_scope": "all"}).json()
    key_path = f"environments/{env['id']}/link-tokens"
    key_info = post(client, key_path).json()
    assert key_info["service_scope"] == "all" and key_info["service_ids"] == []
    secret = "cats-agent-" + secrets.token_urlsafe(32)
    request = {"linking_key": key_info["linking_key"], "agent_token": secret, "source_id": "installation",
               "name": "Collector", "kind": "kubernetes", "version": "1"}
    assert post(client, "link", {**request, "kind": "docker"}).status_code == 409
    linked = post(client, "link", request).json()
    assert linked["agent_token"] == secret
    assert post(client, "link", request).json() == linked
    assert post(client, "link", {**request, "source_id": "another-installation"}).status_code == 401
    other = "cats-agent-" + secrets.token_urlsafe(32)
    assert post(client, "link", {**request, "agent_token": other}).status_code == 401
    assert secret not in client.get("/api/runtime").text
    audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "runtime.agent.linked")).all()
    assert len(audit) == 1 and secret not in str(audit[0].detail)
    assert post(client, f"agents/{linked['agent_id']}/revoke").status_code == 200
    assert post(client, "link", request).status_code == 401
    replacement = post(client, key_path).json()["linking_key"]
    assert post(client, "link", {**request, "linking_key": replacement}).status_code == 409
    assert post(client, "link", {**request, "agent_token": other, "linking_key": replacement}).status_code == 200
    assert report(client, linked, snapshot()).status_code == 401


def test_scope_changes_and_deletion_expire_enrollment(context):
    from app.runtime_models import forget_service
    client, db, _ = context
    env = post(client, "environments", {"name": "Core", "kind": "kubernetes", "service_ids": [1]}).json()
    assert env["service_scope"] == "selected"
    key_path = f"environments/{env['id']}/link-tokens"
    edit_path = f"/api/runtime/environments/{env['id']}"
    old = post(client, key_path).json()["linking_key"]
    def link_key(key):
        return post(client, "link", {"linking_key": key, "name": "Collector", "source_id": "source", "version": "1"})
    changed = client.put(edit_path, json={"service_scope": "all"}, headers={"X-CSRF-Token": "csrf"})
    assert changed.json()["service_ids"] == [] and link_key(old).status_code == 401
    assert client.put(edit_path, json={"service_scope": "selected", "service_ids": [1]},
                      headers={"X-CSRF-Token": "csrf"}).status_code == 200
    fresh = post(client, key_path).json()["linking_key"]
    forget_service(db, 1)
    db.delete(db.get(Service, 1))
    db.commit()
    db.add(Service(id=1, service_key="replacement", name="Replacement"))
    db.commit()
    assert link_key(fresh).status_code == 401
    assert client.get("/api/runtime").json()["environments"][0]["service_ids"] == []


def test_revoke_between_upload_admission_and_duplicate_ack(context):
    client, db, _ = context
    linked, _ = enroll(client)
    value = snapshot()
    assert report(client, linked, value).is_success
    admitted = db.get(RuntimeAgent, linked["agent_id"])
    admitted_hash = admitted.token_hash
    assert post(client, f"agents/{admitted.id}/revoke").is_success
    with pytest.raises(HTTPException) as denied:
        runtime.accept_report(db, admitted, admitted_hash, value, now())
    assert denied.value.status_code == 401


@pytest.mark.parametrize("identical", [True, False])
def test_concurrent_single_reports_share_one_sequence(tmp_path, identical):
    from concurrent.futures import ThreadPoolExecutor
    import json
    from threading import Barrier

    engine = create_engine("sqlite:///" + str(tmp_path / "reports.db"))
    Base.metadata.create_all(engine, tables=[RuntimeEnvironment.__table__, RuntimeAgent.__table__,
                                             runtime_report_pages.RuntimeReportPage.__table__])
    with Session(engine) as db:
        env = RuntimeEnvironment(name="Core", kind="kubernetes")
        db.add(env)
        db.flush()
        agent = RuntimeAgent(environment_id=env.id, name="Agent", source_id="source", version="1", token_hash="hash")
        db.add(agent)
        db.commit()
        agent_id = agent.id
    admitted = Barrier(2)
    value = snapshot()
    competing = value if identical else {**value, "workloads": []}

    def send(data):
        with Session(engine) as db:
            row = db.get(RuntimeAgent, agent_id)
            db.rollback()  # Both HTTP handlers passed their initial bearer check.
            admitted.wait(timeout=5)
            try:
                response = runtime.accept_report(db, row, "hash", data, now())
                return "duplicate" if json.loads(response.body)["duplicate"] else "accepted"
            except HTTPException as error:
                assert error.status_code == 409
                return "conflict"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(send, [value, competing]))
        assert sorted(outcomes) == ["accepted", "duplicate" if identical else "conflict"]
        accepted = value if outcomes[0] == "accepted" else competing
        with Session(engine) as db:
            row = db.get(RuntimeAgent, agent_id)
            assert row.last_sequence == 1
            assert [item["uid"] for item in row.workloads] == [item["uid"] for item in accepted["workloads"]]
    finally:
        engine.dispose()


def test_scope_migration_does_not_expand_legacy_selection():
    from app.runtime_models import upgrade_connection
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE runtime_environments (id INTEGER PRIMARY KEY, service_ids JSON)"))
        connection.execute(text("INSERT INTO runtime_environments VALUES (1, '[]')"))
        upgrade_connection(connection)
        upgrade_connection(connection)
        assert connection.execute(text("SELECT service_scope FROM runtime_environments")).scalar_one() == "selected"
    engine.dispose()


def test_cluster_issue_namespace_projection_and_page_scope(context, monkeypatch):
    from app import runtime_policy
    client, db, _ = context
    linked, _ = enroll(client)
    first = snapshot()["workloads"][0]
    second = {**first, "uid": "other:sidecar", "image_ref": "unapproved:tag", "container": "sidecar", "namespace": "core",
              "pod": "api-1", "workload_kind": "Deployment", "container_kind": "regular"}
    waiting = {**second, "uid": "pending:sidecar", "state": "waiting"}
    repeated = {**second, "uid": "other:sidecar-2"}
    value = snapshot(workloads=[first, second, waiting, repeated])
    assert report(client, linked, value).status_code == 200
    monkeypatch.setattr(runtime_policy, "evaluate_observation", lambda db, env, row, **kwargs: {
        "status": "approved" if row["image_ref"] == first["image_ref"] else "noncompliant",
        "reason": "test_decision", "service_id": 1})
    other = post(client, "environments", {"name": "Unlinked", "kind": "docker"}).json()
    page = client.get("/api/runtime", params={"environment_id": linked["environment_id"]}).json()
    assert [(item["severity"], item["service_id"]) for item in page["issues"]] == [("error", 1), ("error", 1)]
    cluster = page["clusters"][0]
    assert cluster["coverage"] == "fresh" and cluster["namespace_count"] == 2 and cluster["issue_count"] == 2
    assert {row["name"]: row["issue_count"] for row in page["namespaces"]} == {"core": 2, "default": 0}
    assert page["issues"][0]["pod"] == "api-1"
    first_page = client.get("/api/runtime", params={"environment_id": cluster["id"], "limit": 1, "issue_limit": 1}).json()
    assert first_page["next_offset"] == 1 and first_page["inventory_truncated"]
    assert first_page["workloads"][0]["compliance"]["status"] == "approved"
    assert first_page["clusters"][0]["issue_count"] == first_page["total_issues"] == 2
    assert first_page["issues"][0]["uid"] == second["uid"]
    assert first_page["next_issue_offset"] == 1
    more_issues = client.get("/api/runtime", params={"environment_id": cluster["id"], "issue_offset": 1}).json()
    assert [issue['uid'] for issue in more_issues['issues']] == [repeated['uid']]
    assert more_issues["next_issue_offset"] is None and more_issues["total_issues"] == 2
    more = client.get("/api/runtime", params={"environment_id": cluster["id"], "offset": 1}).json()
    assert more["workloads"][0]["uid"] == second["uid"] and more["next_offset"] is None
    assert client.get("/api/runtime", params={"environment_id": other["id"]}).json()["issues"][0]["reason"] == "coverage_unlinked"
    assert report(client, linked, snapshot(2, observed_at=(now()-timedelta(minutes=1)).isoformat())).status_code == 409
    assert report(client, linked, snapshot(2, complete=False, errors=["collection_failed"], workloads=[])).status_code == 200
    page = client.get("/api/runtime", params={"environment_id": linked["environment_id"]}).json()
    assert [item["reason"] for item in page["issues"]] == ["coverage_incomplete"]
    assert all(item["compliance"]["status"] == "unverified" for item in page["workloads"])


def test_issue_filters_search_all_pages_and_preserve_namespace_counts(context, monkeypatch):
    from app import runtime_policy
    client, _, _ = context
    linked, _ = enroll(client)
    first = snapshot()["workloads"][0]
    target = {**first, "uid": "backend:api", "image_ref": "unapproved:tag", "namespace": "backend"}
    assert report(client, linked, snapshot(workloads=[first, target])).is_success
    monkeypatch.setattr(runtime_policy, "evaluate_observation", lambda db, env, row, **kwargs: {
        "status": "noncompliant" if row["uid"] == target["uid"] else "unverified", "reason": "test_decision"})
    query = {"environment_id": linked["environment_id"], "limit": 1, "issue_limit": 1}
    def fetch(**filters):
        response = client.get("/api/runtime", params={**query, **filters})
        assert response.is_success
        return response.json()

    initial = fetch()
    assert initial["issues"][0]["uid"] == first["uid"] and initial["next_issue_offset"] == 1
    for filters in ({"issue_namespace": "backend"}, {"issue_code": "noncompliant"},
                    {"issue_namespace": "backend", "issue_code": "noncompliant"}):
        matched = fetch(**filters)
        assert [issue["uid"] for issue in matched["issues"]] == [target["uid"]]
        assert matched["next_issue_offset"] is None and matched["total_issues"] == 1
        assert matched["unfiltered_total_issues"] == matched["clusters"][0]["issue_count"] == 2
        assert matched["namespaces"] == initial["namespaces"] and matched["workloads"] == initial["workloads"]
    empty = fetch(issue_namespace="backend", issue_code="coverage")
    assert empty["issues"] == [] and empty["total_issues"] == 0 and empty["next_issue_offset"] is None
    assert {row["name"]: row["issue_count"] for row in empty["namespaces"]} == {"default": 1, "backend": 1}
    assert client.get("/api/runtime", params={**query, "issue_code": "invalid"}).status_code == 422


@pytest.mark.parametrize(("release_status", "codes"), [
    ("approved", ["scan_noncompliant"]),
    ("excepted", ["scan_noncompliant"]),
    ("noncompliant", ["noncompliant", "scan_noncompliant"]),
    ("unverified", ["scan_noncompliant", "unverified"]),
])
def test_exact_scan_violation_counted_once_with_current_release(context, monkeypatch, release_status, codes):
    from app import runtime_policy
    client, _, _ = context
    linked, _ = enroll(client)
    first = snapshot()["workloads"][0]
    waiting = {**first, "uid": "other:waiting", "state": "waiting"}
    assert report(client, linked, snapshot(workloads=[first, waiting])).is_success
    decision = {"status": release_status, "reason": "release_result", "service_id": 1,
                "scan_assessment": {"status": "noncompliant", "reason": "scan_image_noncompliant", "execution_id": 17}}
    monkeypatch.setattr(runtime_policy, "evaluate_observation", lambda *args, **kwargs: decision)

    for filters in [{}] + [{"issue_code": code} for code in codes]:
        page = client.get("/api/runtime", params={**filters, "issue_namespace": "default", "issue_limit": 1}).json()
        assert page["total_issues"] == page["unfiltered_total_issues"] == page["clusters"][0]["issue_count"] == 1
        assert page["namespaces"][0]["issue_count"] == 1 and page["next_issue_offset"] is None
        issue, = page["issues"]
        assert issue["uid"] == first["uid"] and issue["codes"] == codes and issue["severity"] == "error"
        assert issue["code"] == codes[0] and issue["compliance"] == page["workloads"][0]["compliance"] == decision
        assert issue["reason"] == (decision["reason"] if codes[0] == "noncompliant" else "scan_image_noncompliant")

    assert report(client, linked, snapshot(2, complete=False, errors=["scan_interrupted"], workloads=[])).is_success
    page = client.get("/api/runtime", params={"issue_code": "scan_noncompliant"}).json()
    assert page["issues"] == [] and page["unfiltered_total_issues"] == 1
    assert all("scan_assessment" not in row["compliance"] for row in page["workloads"])


@pytest.mark.parametrize("scan", [None, {"status": "unverified", "reason": "evidence_unavailable"},
                                  {"status": "compliant", "reason": "scan_image_compliant"}])
def test_unknown_or_compliant_scan_does_not_create_scan_violation(context, monkeypatch, scan):
    from app import runtime_policy
    client, _, _ = context
    linked, _ = enroll(client)
    assert report(client, linked, snapshot()).is_success
    decision = {"status": "approved", "reason": "approved"}
    if scan is not None:
        decision["scan_assessment"] = scan
    monkeypatch.setattr(runtime_policy, "evaluate_observation", lambda *args, **kwargs: decision)
    page = client.get("/api/runtime", params={"issue_code": "scan_noncompliant"}).json()
    assert page["issues"] == [] and page["total_issues"] == page["unfiltered_total_issues"] == 0


def test_namespace_refresh_finds_later_pipeline_violation_without_new_report(context, monkeypatch):
    from app.cyber_approvals import CyberApproval, digest as snapshot_digest
    from app.models import Execution, Group, PortalSetting
    from app.oci_models import OCIRepository, OCIUpstream
    from app.release_validity import new_validity, utc

    client, db, _ = context
    client.app.include_router(portal_app.pipeline_router)
    pipeline_token = secrets.token_urlsafe(32)
    monkeypatch.setenv("PIPELINE_API_TOKEN", pipeline_token)
    monkeypatch.setenv("CATS_DEPENDENCY_PROJECTION_ON_INGEST", "false")
    service = db.get(Service, 1)
    service.groups.append(Group(name="Core"))
    db.add(PortalSetting(key="raw_due_rules", value='[{"severity":"High","days":1}]'))
    upstream = OCIUpstream(name="upstream", endpoint="https://registry.example")
    db.add(upstream)
    db.flush()
    db.add(OCIRepository(public_repository="approved/api", upstream_id=upstream.id,
                         upstream_repository="project/api", service_id=1))
    db.commit()
    observation = {**snapshot()["workloads"][0], "namespace": "payments", "pod": "api-7"}
    image_id = observation["image_id"]
    digest = image_id.split("@")[1]
    approved_at = now() - timedelta(days=5)

    def ingest(key, stamp, findings):
        data = dict(execution_id=key, scanned_at=stamp.isoformat(), complete=True, fixable_only=True,
                    service={"id": "application", "name": "Application", "version": "1.2", "groups": ["Core"]},
                    service_overview={"images": [{"image": image_id, "digest": digest}]}, findings=findings)
        receipt = client.post("/api/v1/pipeline-results", json=data, headers={"Authorization": "Bearer " + pipeline_token})
        assert receipt.status_code == 201, receipt.text
        return db.get(Execution, receipt.json()["execution_id"])

    scan = ingest("initial", approved_at, [])
    evidence = dict(service_id=1, source_execution_id=scan.id, source_version_id=scan.service_version_id,
                    source_payload_digest=scan.payload_digest, approval_validity=new_validity(approved_at),
                    artifacts=[dict(kind="image", reference=image_id, digest=digest)])
    approval = CyberApproval(service_id=1, source_execution_id=scan.id, variant="current", status="approved",
                             snapshot=evidence, snapshot_digest=snapshot_digest(evidence), decided_at=approved_at)
    db.add(approval)
    db.commit()
    linked, _ = enroll(client)
    assert report(client, linked, snapshot(workloads=[observation])).is_success
    filters = {"environment_id": linked["environment_id"], "issue_namespace": "payments", "issue_code": "scan_noncompliant"}
    initial = client.get("/api/runtime", params=filters).json()
    original = initial["workloads"][0]["compliance"]
    assert original["status"] == "approved", original
    assert initial["total_issues"] == 0

    later = ingest("repeat", approved_at + timedelta(days=1), [{
        "cve": "CVE-2026-1234", "severity": "High", "image": image_id, "image_digest": digest,
        "package": "test-package", "fixed_version": "2.0"}])
    refreshed = client.get("/api/runtime", params=filters).json()
    assert refreshed["unfiltered_total_issues"] == refreshed["total_issues"] == refreshed["namespaces"][0]["issue_count"] == 1
    issue, = refreshed["issues"]
    assert (issue["namespace"], issue["pod"], issue["codes"]) == ("payments", "api-7", ["scan_noncompliant"])
    decision = issue["compliance"]
    assert decision == refreshed["workloads"][0]["compliance"]
    assert decision["status"] == "approved" and decision["approval_id"] == approval.id
    assert decision["scan_assessment"] == {"status": "noncompliant", "reason": "scan_image_noncompliant",
                                           "execution_id": later.id, "source": "local_scan",
                                           "scanned_at": utc(later.scanned_at).isoformat()}
