"""Opt-in real PostgreSQL checks; each test uses disposable UUID schemas only.

Set CATS_TEST_REPLICA_POSTGRES_URL to a dedicated test database. Existing schemas
are never changed. The same transaction scenarios also run on SQLite by default.
"""
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Service
from app.replica_models import upgrade_connection
import test_replica_import as imports
import test_replica_sync as sync


@pytest.fixture
def postgres_engines():
    url = os.environ.get('CATS_TEST_REPLICA_POSTGRES_URL')
    if not url:
        pytest.skip('Set CATS_TEST_REPLICA_POSTGRES_URL for real PostgreSQL checks')
    admin = create_engine(url)
    created = []

    def factory(*, initialize=True):
        schema = 'replica_test_' + uuid4().hex
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(url, connect_args={'options': f'-csearch_path={schema}'})
        created.append((schema, engine))
        if initialize:
            Base.metadata.create_all(engine)
        return engine

    try:
        yield factory
    finally:
        for schema, engine in created:
            engine.dispose()
            assert schema.startswith('replica_test_') and len(schema) == 45
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def postgres_replica(postgres_engines, monkeypatch, tmp_path):
    monkeypatch.setattr(imports, 'engine', postgres_engines)
    fixture = imports.replica_import.__wrapped__(monkeypatch, tmp_path)
    try:
        state = next(fixture)
        # Explicit seed IDs advance SQLite's allocator but not PostgreSQL's.
        # Move these sequences to preserve the intentional source/local clash.
        for table in ('users', 'services', 'service_artifacts'):
            state.db.execute(text(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), (SELECT max(id) FROM {table}))"))
        state.db.commit()
        yield state
    finally:
        fixture.close()


@pytest.mark.parametrize('scenario', [
    imports.test_all_evidence_domains_remap_foreign_keys_and_preserve_assessments,
    imports.test_complete_snapshot_replaces_23_of_100_images_and_keeps_history,
    imports.test_replay_collision_rollback_and_incomplete_import_do_not_move_active_release,
    imports.test_signed_revocation_is_durable_and_tampered_revocation_cannot_restore_trust,
    sync.test_delayed_revocation_applies_without_rolling_back_newer_release,
], ids=lambda scenario: scenario.__name__.removeprefix('test_'))
def test_postgres_reconciliation(postgres_replica, scenario):
    scenario(postgres_replica)


def test_postgres_projection_failure_is_atomic(postgres_replica, monkeypatch):
    imports.test_failure_after_projection_rolls_back_activation_and_changed_evidence(postgres_replica, monkeypatch)


def test_postgres_preserves_frozen_finding_decisions(postgres_replica, monkeypatch):
    sync.test_frozen_finding_views_never_consult_local_policy_or_intelligence(postgres_replica, monkeypatch)


def test_postgres_additive_upgrade_preserves_existing_full_deployment(postgres_engines):
    engine = postgres_engines(initialize=False)
    added = {name for name in Base.metadata.tables if name.startswith(('replica_', 'local_cyber_'))}
    added.add('release_publication_sequences')
    Base.metadata.create_all(engine, tables=[table for name, table in Base.metadata.tables.items() if name not in added])
    with Session(engine) as db:
        db.add(Service(service_key='existing-full-service', name='Existing full deployment'))
        db.commit()
    assert not added.intersection(inspect(engine).get_table_names())
    for _ in range(2):
        with engine.begin() as connection:
            upgrade_connection(connection)
            # Application startup also creates additive local override tables.
            Base.metadata.create_all(connection)
    assert added.issubset(inspect(engine).get_table_names())
    with Session(engine) as db:
        assert db.scalar(select(Service.name).where(Service.service_key == 'existing-full-service')) == 'Existing full deployment'
