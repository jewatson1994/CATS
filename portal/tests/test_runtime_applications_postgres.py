"""Opt-in runtime migration and two-connection checks. Set CATS_TEST_POSTGRES_URL."""
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from time import monotonic, sleep

from fastapi import HTTPException
import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from app.auth import SYSTEM_ROLES
from app.database import Base, portal_tables
from app.models import Group, Service
from app.runtime_application_routes import Assignment, assign
from app.runtime_applications import RuntimeApplication
from app.runtime_candidates import RuntimeReleaseCandidate, checksum
from app.runtime_models import RuntimeAgent, RuntimeEnvironment, now, upgrade_connection
from app.runtime_routes import accept_report, hashed
from test_cyber_approvals import auth, request
from test_runtime_applications import component
from test_runtime_routes import snapshot
from test_startup_support_postgres import postgres_engine


def test_runtime_upgrade_preserves_legacy_scope_and_discovery_configuration(postgres_engine):
    with postgres_engine.begin() as connection:
        connection.execute(text("""CREATE TABLE runtime_environments (
            id SERIAL PRIMARY KEY, name VARCHAR(160) NOT NULL UNIQUE, kind VARCHAR(24) NOT NULL,
            service_ids JSON NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)"""))
        connection.execute(text("""INSERT INTO runtime_environments (name, kind, service_ids)
            VALUES ('isolated', 'kubernetes', '[]'), ('limited', 'kubernetes', '[42]')"""))
        Base.metadata.create_all(connection, tables=portal_tables())
        upgrade_connection(connection)
        assert {'runtime_applications', 'runtime_release_candidates'} <= set(inspect(connection).get_table_names())

    with Session(postgres_engine) as db:
        isolated, limited = db.scalars(select(RuntimeEnvironment).order_by(RuntimeEnvironment.id)).all()
        assert [isolated.service_ids, limited.service_ids] == [[], [42]]
        assert all(env.service_scope == 'selected' and env.cluster_role == 'unspecified'
                   and env.discovery_group_id is None and env.discovery_observed_at is None for env in (isolated, limited))
        group = Group(name='Owners')
        db.add(group)
        db.flush()
        observed = now()
        limited.cluster_role, limited.discovery_group_id, limited.discovery_observed_at = 'validation', group.id, observed
        env_id, group_id = limited.id, group.id
        db.commit()

    with postgres_engine.begin() as connection:
        Base.metadata.create_all(connection, tables=portal_tables())
        upgrade_connection(connection)
    with Session(postgres_engine) as db:
        env = db.get(RuntimeEnvironment, env_id)
        assert (env.cluster_role, env.discovery_group_id, env.discovery_observed_at) == ('validation', group_id, observed)
        db.delete(db.get(Group, group_id))
        db.commit()
        assert env.discovery_group_id is None and env.service_ids == [42] and env.service_scope == 'selected'


def test_diagnostics_upgrade_preserves_submitted_inventory(postgres_engine):
    Base.metadata.create_all(postgres_engine, tables=portal_tables())
    inventory = {'images': [{'reference': 'registry.example/api@sha256:' + 'a' * 64}]}
    fingerprint = checksum(inventory)
    with Session(postgres_engine) as db:
        env = RuntimeEnvironment(name='Legacy validation', kind='kubernetes')
        service = Service(service_key='legacy-api', name='Legacy API')
        db.add_all([env, service])
        db.flush()
        candidate = RuntimeReleaseCandidate(environment_id=env.id, service_id=service.id, namespace='test',
            version=1, proposed_version='1.0', status='submitted', inventory=inventory, fingerprint=fingerprint)
        db.add(candidate)
        db.flush()
        candidate_id = candidate.id
        db.commit()

    with postgres_engine.begin() as connection:
        # Recreate the preceding schema in this test's private PostgreSQL schema.
        connection.execute(text('ALTER TABLE runtime_release_candidates DROP COLUMN resolution_diagnostics'))
        upgrade_connection(connection)
        upgrade_connection(connection)
        column = next(c for c in inspect(connection).get_columns('runtime_release_candidates')
                      if c['name'] == 'resolution_diagnostics')
        assert column['nullable']

    with Session(postgres_engine) as db:
        retained = db.get(RuntimeReleaseCandidate, candidate_id)
        assert retained.status == 'submitted' and retained.resolution_diagnostics is None
        assert retained.inventory == inventory and retained.fingerprint == fingerprint


def test_refresh_fences_a_waiting_assignment_with_a_stale_fingerprint(postgres_engine, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    Base.metadata.create_all(postgres_engine, tables=portal_tables())
    token = hashed('runtime-test-token')
    original = 'registry.example/project/api@sha256:' + 'a' * 64
    replacement = 'registry.example/project/api@sha256:' + 'b' * 64

    def refresh(db, agent_id, sequence, image):
        data = snapshot(sequence, discovery_version=1, workloads=[component(image_ref=image, image_id=image)])
        assert accept_report(db, db.get(RuntimeAgent, agent_id), token, data, now()).status_code == 200

    with Session(postgres_engine) as db:
        env = RuntimeEnvironment(name='Validation', kind='kubernetes', cluster_role='validation', service_scope='all')
        service = Service(service_key='api', name='API', groups=[Group(name='Owners')])
        db.add_all([env, service])
        db.flush()
        agent = RuntimeAgent(environment_id=env.id, name='Collector', source_id='cluster', version='test', token_hash=token)
        db.add(agent)
        db.flush()
        agent_id, service_id = agent.id, service.id
        refresh(db, agent_id, 1, original)
        app = db.scalars(select(RuntimeApplication)).one()
        app_id = app.id
        stale = Assignment(expected_fingerprint=app.fingerprint, expected_service_id=None, service_id=service_id)

    def assign_stale(connection_pids):
        with Session(postgres_engine) as db:
            db.execute(text("SET LOCAL statement_timeout = '15s'"))
            connection_pids.put(db.scalar(text('SELECT pg_backend_pid()')))
            with pytest.raises(HTTPException) as rejected:
                assign(app_id, stale, request(), db, auth(None, SYSTEM_ROLES['Service Manager']))
            assert rejected.value.status_code == 409 and 'Inventory or assignment changed' in rejected.value.detail

    with ThreadPoolExecutor(max_workers=1) as pool, postgres_engine.connect() as writer:
        with writer.begin():
            writer_pid = writer.scalar(text('SELECT pg_backend_pid()'))
            # Hold the report transaction open after accept_report has committed its savepoint.
            with Session(writer, join_transaction_mode='create_savepoint') as db:
                refresh(db, agent_id, 2, replacement)
            connection_pids = Queue()
            waiting = pool.submit(assign_stale, connection_pids)
            waiter_pid = connection_pids.get(timeout=5)
            with postgres_engine.connect() as observer:
                deadline = monotonic() + 5
                while writer_pid not in observer.scalar(text('SELECT pg_blocking_pids(:pid)'), {'pid': waiter_pid}):
                    assert monotonic() < deadline, 'Assignment did not wait for the report transaction'
                    sleep(0.02)
        waiting.result(timeout=10)

    with Session(postgres_engine) as db:
        app = db.get(RuntimeApplication, app_id)
        assert app.service_id is None and app.fingerprint != stale.expected_fingerprint
        assert db.scalars(select(RuntimeReleaseCandidate)).first() is None
        current = Assignment(expected_fingerprint=app.fingerprint, expected_service_id=None, service_id=service_id)
        assign(app_id, current, request(), db, auth(None, SYSTEM_ROLES['Service Manager']))
        candidate = db.scalars(select(RuntimeReleaseCandidate)).one()
        assert candidate.version == 1 and candidate.service_id == service_id
        assert [image['reference'] for image in candidate.inventory['images']] == [replacement]
