"""Source status counts stay bounded without conflating retained history and snapshots."""
import os
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session

from app import risk_routes as routes
from app.auth import AuthContext
from app.database import Base
from app.intelligence_models import IntelligencePackageInstall, IntelligencePackageState
from app.vex_models import VexSource, VexDocument, VexStatement

DATE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def admin_auth():
    assignment = SimpleNamespace(role=SimpleNamespace(name='Admin', permissions=['config.manage']),
        service_id=None, group_id=None, group=None)
    return AuthContext(user=SimpleNamespace(id=None, username='admin', role_assignments=[assignment]),
        session=SimpleNamespace(csrf_token='csrf'))


@pytest.fixture(params=['sqlite', 'postgresql'])
def source_db(request):
    url = os.environ.get('CATS_TEST_POSTGRES_URL') if request.param == 'postgresql' else 'sqlite://'
    if not url:
        pytest.skip('Set CATS_TEST_POSTGRES_URL for isolated PostgreSQL source checks')
    admin = create_engine(url)
    schema = 'source_status_' + uuid.uuid4().hex
    options = {}
    if request.param == 'postgresql':
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA {schema}'))
        options['connect_args'] = {'options': f'-c search_path={schema}'}
    engine = create_engine(url, **options)
    try:
        Base.metadata.create_all(engine, tables=[VexSource.__table__, VexDocument.__table__,
            VexStatement.__table__, IntelligencePackageInstall.__table__, IntelligencePackageState.__table__])
        with Session(engine) as db:
            yield db
    finally:
        engine.dispose()
        if request.param == 'postgresql':
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA {schema} CASCADE'))
        admin.dispose()


def add_document(db, source_id, count, *, revision='1', withdrawn=False):
    item = VexDocument(source_id=source_id, sha256=revision.zfill(64), raw_text='{}',
        format='openvex', document_key='same-document', version=revision,
        issued_at=DATE, verification='unverified', withdrawn=withdrawn)
    db.add(item)
    db.flush()
    if count:
        db.execute(VexStatement.__table__.insert(), [dict(document_id=item.id, cve='CVE-2026-12345',
            product_id=f'pkg:generic/package-{index}@1', identity={}, status='affected')
            for index in range(count)])
    db.flush()


def test_retained_history_is_exact_through_bound_and_separate_from_snapshot(source_db, monkeypatch):
    db = source_db
    monkeypatch.setattr(routes, 'SOURCE_STATEMENT_COUNT_LIMIT', 3)
    source = VexSource(name='Vendor', enabled=True, trusted=True)
    empty = VexSource(name='Empty source')
    db.add_all([source, empty])
    db.flush()
    add_document(db, source.id, 1)
    # A withdrawn revision and an unverified manual document still count as retained history.
    add_document(db, source.id, 2, revision='2', withdrawn=True)
    db.add(IntelligencePackageInstall(version='latest', sequence=1, counts={'vex_statements': 99},
        manifest={'built_at': DATE.isoformat(), 'sources': [{'id': 'vendor', 'name': 'Vendor',
        'acquired_at': DATE.isoformat(), 'max_age_days': 30, 'counts': {'vex_statements': 99}}]}))
    db.commit()

    result = routes.sources(admin_auth(), db)
    items = {item['name']: item for item in result['items']}
    assert items['Vendor']['documents'] == 2
    assert items['Vendor']['statements'] == 3
    assert items['Vendor']['statement_count_state'] == 'exact'
    assert items['Vendor']['statement_count_scope'] == 'retained_history'
    assert items['Empty source']['statements'] == 0
    assert result['embedded_package']['sources'][0]['counts']['vex_statements'] == 99

    add_document(db, source.id, 2, revision='3')
    source.enabled = False
    db.commit()
    result = routes.sources(admin_auth(), db)
    item = next(item for item in result['items'] if item['name'] == 'Vendor')
    assert item['documents'] == 3
    assert item['statements'] is None
    assert item['statement_count_state'] == 'lower_bound'
    assert item['statement_count_lower_bound'] == 4
    assert item['health'] == 'disabled'


def test_source_probe_is_limited_and_uses_document_first_access(source_db, monkeypatch):
    db = source_db
    monkeypatch.setattr(routes, 'SOURCE_STATEMENT_COUNT_LIMIT', 3)
    db.add_all([VexSource(id=1, name='Earlier source'), VexSource(id=2, name='Later source')])
    db.flush()
    add_document(db, 1, 12)
    add_document(db, 2, 5)
    db.commit()
    captured = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        captured.append((statement, parameters))
    event.listen(db.get_bind(), 'before_cursor_execute', capture)
    try:
        result = routes._source_statement_count(db, 2)
    finally:
        event.remove(db.get_bind(), 'before_cursor_execute', capture)
    assert result['statements'] is None
    assert result['statement_count_lower_bound'] == 4
    assert len(captured) == 1
    query, params = captured[0]
    assert 'LIMIT' in query and 'GROUP BY' not in query
    if db.get_bind().dialect.name == 'postgresql':
        assert 'CROSS JOIN LATERAL' in query and query.count('LIMIT') == 2
        # Tiny fixtures can favor scans; disable seq scans only for this EXPLAIN
        # to verify both existing indexes are usable, without touching corpus tables.
        db.execute(text('SET LOCAL enable_seqscan = off'))
        plan = db.connection().exec_driver_sql('EXPLAIN ' + query, params).all()
        rendered = '\n'.join(row[0] for row in plan)
        assert 'ix_vex_documents_source_id' in rendered
        assert 'ix_vex_statements_document_id' in rendered
    else:
        assert 'CROSS JOIN' in query
        plan = db.connection().exec_driver_sql('EXPLAIN QUERY PLAN ' + query, params).all()
        rendered = str(plan)
        assert 'ix_vex_documents_source_id' in rendered
        assert 'ix_vex_statements_document_id' in rendered


def test_sources_still_require_configuration_permission(source_db):
    from fastapi import HTTPException
    denied = SimpleNamespace(has=lambda *args: False)
    with pytest.raises(HTTPException) as error:
        routes.sources(denied, source_db)
    assert error.value.status_code == 403
