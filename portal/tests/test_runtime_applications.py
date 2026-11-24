"""Discovery, human assignment, release preparation and role-specific reporting via HTTP."""
from types import SimpleNamespace

import pytest
from sqlalchemy import event, func, select
from app.auth import SYSTEM_ROLES
from app.models import AuditEvent, Group, Service
from app.runtime_applications import RuntimeApplication
from app.runtime_candidates import RuntimeReleaseCandidate
from app.runtime_application_routes import discovery_notifications, runtime_notifications
from test_runtime_routes import context, enroll, post, report, snapshot


def setup(context, role='validation', mode='all'):
    client, db, auth = context
    service = db.get(Service, 1)
    group = Group(name='Platform')
    service.groups.append(group)
    db.commit()
    manager = SimpleNamespace(role=SimpleNamespace(name='Service Manager', permissions=SYSTEM_ROLES['Service Manager']),
        service_id=None, group_id=group.id, group=group)
    auth.user.role_assignments.append(manager)
    agent, _ = enroll(client)
    response = client.put('/api/runtime/environments/' + str(agent['environment_id']),
        headers={'X-CSRF-Token': 'csrf'}, json={'cluster_role': role, 'discovery_group_id': group.id,
            'service_scope': mode, 'service_ids': [] if mode == 'all' else [1]})
    assert response.is_success, response.text
    return client, db, auth, agent


def component(name='api', **values):
    return {**snapshot()['workloads'][0], 'workload_kind': 'Deployment', 'workload_uid': name + '-uid',
            'namespace_uid': 'ns-uid', 'uid': name + '-pod:api', 'workload': name, 'container_kind': 'regular',
            'app_part_of': 'shop', 'service_hint': 'application', **values}


def publish(client, agent, sequence, rows, **kwargs):
    response = report(client, agent, snapshot(sequence, discovery_version=1, workloads=rows, **kwargs))
    assert response.is_success, response.text


def inventory(client):
    result = client.get('/api/runtime/applications')
    assert result.is_success, result.text
    return result.json()


def assign(client, app, **choice):
    return post(client, 'applications/' + str(app['id']) + '/assignment', {
        'expected_fingerprint': app['fingerprint'], 'expected_service_id': app['service_id'], **choice})


@pytest.mark.parametrize(('role', 'queries'), [
    ('Assessor', 0), ('Administrator', 0), ('Cybersecurity', 1), ('Service Manager', 1),
])
def test_empty_runtime_notifications_skip_unnecessary_queries(context, role, queries):
    _, db, auth = context
    auth.user.role_assignments[0].role = SimpleNamespace(name=role, permissions=SYSTEM_ROLES[role])
    statements = []
    def record(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.get_bind(), 'before_cursor_execute', record)
    try:
        assert runtime_notifications(db, auth) == []
    finally:
        event.remove(db.get_bind(), 'before_cursor_execute', record)
    assert len(statements) == queries
    if role == 'Cybersecurity':
        assert 'runtime_release_candidates' in statements[0] and 'runtime_applications' not in statements[0]


def test_group_without_services_receives_unassigned_application_notifications(context):
    client, db, auth, agent = setup(context)
    service = db.get(Service, 1)
    service.groups.clear()
    db.commit()
    publish(client, agent, 1, [component()])
    assert auth.accessible_service_ids('runtime.prepare_release') == set()
    notifications = runtime_notifications(db, auth)
    assert [(item['label'], item['count']) for item in notifications] == [('Unassigned applications', 1)]


def test_assignment_is_scoped_idempotent_and_changed_bytes_make_a_revision(context):
    client, db, auth, agent = setup(context)
    api, worker = component(), component('worker')
    publish(client, agent, 1, [api, worker])
    app, = inventory(client)['applications']
    assert app['name'] == 'shop' and len(app['components']) == 2 and app['service_id'] is None
    assert app['suggestions'][0]['evidence'] == ['CATS service annotation']
    assert not inventory(client)['candidates']
    assert discovery_notifications(db, auth)[0]['label'] == 'Unassigned applications'
    assert assign(client, app, service_id=1).is_success
    first, = inventory(client)['candidates']
    assert first['status'] == 'draft' and not first['approval_id']
    assert 'runtime_candidate_id=' in first['href']
    assert assign(client, app, service_id=1).status_code == 409
    publish(client, agent, 2, [{**api, 'uid': 'replacement:api'}, worker])
    assert inventory(client)['candidates'] == [first]
    changed = {**api, 'image_id': 'registry.example/project/api@sha256:' + 'b' * 64}
    publish(client, agent, 3, [changed, worker])
    new, old = inventory(client)['candidates']
    assert new['version'] == 2 and new['current'] and not old['current']
    assert 'runtime_candidate_id=' in old['href']
    publish(client, agent, 4, [changed, worker, component('forged')])
    records = inventory(client)['applications']
    assert {a['service_id'] for a in records} == {None, 1}
    assert len(inventory(client)['candidates']) == 2
    assert sum(a['action'] == 'runtime.application.assigned' for a in
               db.execute(select(AuditEvent.action)).mappings()) == 1
    auth.user.role_assignments[-1].role = SimpleNamespace(name='Reader', permissions=['service.view'])
    assert all(c['href'] is None for c in inventory(client)['candidates'])


def test_stale_and_incomplete_inventory_and_multicluster_isolation(context):
    client, db, _, agent = setup(context)
    second, _ = enroll(client, 'Other cluster')
    publish(client, agent, 1, [component()])
    publish(client, second, 1, [component()])
    assert db.scalar(select(func.count()).select_from(RuntimeApplication)) == 2
    app = next(a for a in inventory(client)['applications'] if a['environment_id'] == agent['environment_id'])
    publish(client, agent, 2, [], complete=False, errors=['list_failed'])
    assert db.get(RuntimeApplication, app['id']).present
    publish(client, agent, 3, [])
    assert not db.get(RuntimeApplication, app['id']).present
    assert assign(client, app, service_id=1).status_code == 409
    publish(client, agent, 4, [component()])
    assert db.get(RuntimeApplication, app['id']).present
    assert db.scalar(select(func.count()).select_from(RuntimeApplication)) == 2


def test_reappearing_controller_outside_reviewed_inventory_requires_assignment(context):
    client, _, _, agent = setup(context)
    api, worker = component(), component('worker')
    publish(client, agent, 1, [api])
    publish(client, agent, 2, [api, worker])
    publish(client, agent, 3, [worker])
    app, = inventory(client)['applications']
    assert assign(client, app, service_id=1).is_success
    publish(client, agent, 4, [api, worker])
    assert {(a['components'][0]['workload'], a['service_id']) for a in inventory(client)['applications']} == {
        ('api', None), ('worker', 1)}


def test_matching_label_drift_preserves_assigned_release_and_event_history(context):
    client, db, _, agent = setup(context)
    api = component()
    publish(client, agent, 1, [api])
    app, = inventory(client)['applications']
    assert assign(client, app, service_id=1).is_success
    original = inventory(client)['candidates']
    publish(client, agent, 2, [api, {**api, 'uid': 'another-pod:api', 'service_hint': 'other-service'}])
    assert inventory(client)['candidates'] == original
    assert not db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'runtime.application.changed'))


def test_cyber_and_administrator_grants_do_not_confer_assignment(context):
    client, db, auth, agent = setup(context)
    publish(client, agent, 1, [component()])
    app, = inventory(client)['applications']
    assignment = auth.user.role_assignments[-1]
    for role in ('Cybersecurity', 'Administrator'):
        assignment.role = SimpleNamespace(name=role, permissions=SYSTEM_ROLES[role])
        assert not inventory(client)['applications']
        assert assign(client, app, service_id=1).status_code == 403
        assert not discovery_notifications(db, auth)


def test_two_managers_assigning_the_same_observation_create_one_candidate(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from fastapi import HTTPException
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.database import Base
    from app.runtime_application_routes import Assignment, assign as assign_observation
    from app.runtime_applications import reconcile_inventory
    from app.runtime_models import RuntimeEnvironment, now
    from test_cyber_approvals import auth, request

    engine = create_engine('sqlite:///' + str(tmp_path / 'competing-assignments.db'))
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            group = Group(name='Owners')
            service = Service(service_key='api', name='API', groups=[group])
            env = RuntimeEnvironment(name='Test', kind='kubernetes', cluster_role='validation', service_scope='all')
            db.add_all([service, env])
            db.flush()
            reconcile_inventory(db, env, now(), [component()])
            app = db.scalars(select(RuntimeApplication)).one()
            app_id = app.id
            choice = Assignment(expected_fingerprint=app.fingerprint, expected_service_id=None, service_id=service.id)
            db.commit()
        ready = Barrier(2)

        def attempt():
            with Session(engine) as db:
                actor = auth(None, SYSTEM_ROLES['Service Manager'])
                ready.wait(timeout=5)
                try:
                    assign_observation(app_id, choice, request(), db, actor)
                    return 200
                except HTTPException as error:
                    return error.status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = [pool.submit(attempt) for _ in range(2)]
            assert sorted(result.result() for result in attempts) == [200, 409]
        with Session(engine) as db:
            assert db.scalar(select(func.count()).select_from(RuntimeReleaseCandidate)) == 1
    finally:
        engine.dispose()


def test_group_creation_permissions_and_forged_service_hint(context):
    client, db, auth, agent = setup(context, 'production')
    other = Service(service_key='private', name='Restricted', groups=[Group(name='Other')])
    db.add(other)
    db.commit()
    publish(client, agent, 1, [component(service_hint='private')])
    app, = inventory(client)['applications']
    assert not app['suggestions'] and 'Restricted' not in str(inventory(client))
    assert assign(client, app, service_id=other.id).status_code == 403
    assert assign(client, app, new_service_key='Application').status_code == 409
    removed = auth.user.role_assignments.pop()
    assert not inventory(client)['applications']
    assert assign(client, app, new_service_key='shop').status_code == 403
    auth.user.role_assignments.append(removed)
    created = assign(client, app, new_service_key='shop')
    assert created.is_success, created.text
    service = db.get(Service, created.json()['service_id'])
    assert service.groups == [removed.group] and service.service_key == 'shop'
    assert db.scalar(select(func.count()).select_from(RuntimeReleaseCandidate)) == 0
    assert discovery_notifications(db, auth)[0]['label'] == 'Application assigned'


def test_production_requires_authorized_mapping_and_dev_permits_unapproved(context):
    client, _, _, agent = setup(context, 'production')
    publish(client, agent, 1, [component()])
    overview = client.get('/api/runtime').json()
    assert overview['issues'][0]['reason'] == 'unassigned_application'
    assert overview['issues'][0]['observed_at'] and overview['issues'][0]['image_id']
    app, = inventory(client)['applications']
    assert assign(client, app, service_id=1).is_success
    assert client.get('/api/runtime').json()['workloads'][0]['compliance']['service_id'] == 1
    changed = client.put('/api/runtime/environments/' + str(agent['environment_id']), json={'cluster_role': 'development'},
                         headers={'X-CSRF-Token': 'csrf'})
    assert changed.is_success
    overview = client.get('/api/runtime').json()
    assert overview['workloads'][0]['compliance']['status'] == 'observed' and not overview['issues']
    assert len(inventory(client)['candidates']) == 1


def test_replica_manager_maps_existing_import_for_reporting_only(context, monkeypatch):
    from app.replica_models import ReplicaRecordMap

    client, db, auth, agent = setup(context, 'production')
    manager = auth.user.role_assignments[-1]
    other = Service(service_key='local', name='Local', groups=[manager.group])
    db.add_all([other, ReplicaRecordMap(service_id=1, table_name='services', source_id=177, local_id=1)])
    db.commit()
    monkeypatch.setenv('CATS_MODE', 'replica')
    publish(client, agent, 1, [component()])
    app, = inventory(client)['applications']
    assert {s['id'] for s in app['services']} == {1} and not app['can_create']
    assert assign(client, app, new_service_key='duplicate').status_code == 403
    assert assign(client, app, service_id=other.id).status_code == 403
    manager.role = SimpleNamespace(name='Administrator', permissions=SYSTEM_ROLES['Administrator'])
    assert not inventory(client)['applications']
    assert assign(client, app, service_id=1).status_code == 403
    manager.role = SimpleNamespace(name='Service Manager', permissions=SYSTEM_ROLES['Service Manager'])
    assert assign(client, app, service_id=1).is_success
    assert runtime_notifications(db, auth)[0]['label'] == 'Application assigned'
    assert not db.scalars(select(RuntimeReleaseCandidate)).first()


def test_template_and_replica_metadata_disagreement_can_never_split_one_controller(context):
    client, _, _, agent = setup(context, 'unspecified')
    pod = component(app_part_of='pod-label')
    template = {**pod, 'state': 'desired', 'uid': 'template:api', 'image_id': '', 'app_part_of': 'shop'}
    publish(client, agent, 1, [template, pod])
    app, = inventory(client)['applications']
    assert app['name'] == 'shop' and len(app['components']) == 1
    assert client.get('/api/runtime').json()['total_workloads'] == 1
    assert assign(client, app, service_id=1).is_success
    assert not inventory(client)['candidates']
