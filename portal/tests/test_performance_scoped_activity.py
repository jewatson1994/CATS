from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import main
from app.database import Base
from app.models import AuditEvent, Service, utcnow


@pytest.fixture
def scoped_db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "get_configuration", lambda db: {})
    monkeypatch.setattr(main, "configuration_for_service", lambda db, service: {})
    monkeypatch.setattr(main, "service_view", lambda *args: {"warning_items": [], "evidence_noncompliant": False})
    monkeypatch.setattr(main, "page_context", lambda auth, **context: context)
    monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
    with Session(engine) as db:
        yield db


def audit(db, detail, when, target_type="other", target_id=None):
    row = AuditEvent(action="test", target_type=target_type, target_id=target_id,
                     detail=detail, created_at=when)
    db.add(row)
    db.flush()
    return row.id


def test_service_activity_scopes_before_limit_and_excludes_json_boolean(scoped_db):
    db = scoped_db
    service = Service(service_key="first", name="First")
    db.add(service)
    db.flush()
    now = utcnow()
    expected = audit(db, {"service_id": service.id}, now - timedelta(days=1))
    text_id = audit(db, {"service_id": str(service.id)}, now - timedelta(hours=1))
    for index in range(510):
        audit(db, {"service_id": True}, now + timedelta(seconds=index))
        audit(db, {"service_id": 999}, now + timedelta(seconds=index))
    db.commit()
    request = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": []})
    context = main.service_detail(service.service_key, request, activity=True, db=db, auth=SimpleNamespace())
    assert [row.id for row in context["events"]] == [text_id, expected]
    assert len([row for row in db.identity_map.values() if isinstance(row, AuditEvent)]) == 2


def test_export_audit_scope_preserves_truthy_id_fallback(scoped_db, monkeypatch):
    db = scoped_db
    service = Service(service_key="first", name="First")
    db.add(service)
    db.flush()
    now = utcnow()
    expected = [
        audit(db, {}, now, "service", str(service.id)),
        audit(db, {"service_id": service.id}, now),
        audit(db, {"service_key": service.service_key}, now),
        audit(db, {"service_id": 0, "service_key": service.service_key}, now),
    ]
    audit(db, {"service_id": 999, "service_key": service.service_key}, now)
    for index in range(100):
        audit(db, {"service_id": 999}, now)
    db.commit()
    captured = {}
    monkeypatch.setattr(main, "build_service_workbook", lambda *args, **kwargs: captured.update(kwargs))
    monkeypatch.setattr(main, "workbook_response", lambda *args: None)
    main.export_service(service.service_key, db=db, auth=SimpleNamespace())
    assert [row.id for row in captured["activity_events"]] == expected
    # One candidate with conflicting detail is residual-filtered; unrelated rows
    # never hydrate despite the export retaining its full historical scope.
    assert len([row for row in db.identity_map.values() if isinstance(row, AuditEvent)]) <= 5


def test_snapshot_export_permission_is_in_sql_before_loading(scoped_db, monkeypatch):
    db = scoped_db
    db.add_all([Service(service_key="one", name="One"), Service(service_key="two", name="Two")])
    db.commit()
    db.expunge_all()
    statements = []
    event.listen(db.bind, "before_cursor_execute", lambda conn, cursor, statement, parameters, context, many: statements.append(statement))
    seen = []
    hydrated = []
    def capture(service, *args):
        seen.append(service.service_key)
        hydrated.append(service)
        raise RuntimeError("stop after scoped hydration")
    monkeypatch.setattr(main, "service_view", capture)
    with pytest.raises(RuntimeError, match="scoped hydration"):
        main.export_services(db=db, auth=SimpleNamespace(accessible_service_ids=lambda permission: {1}))
    assert seen == ["one"]
    # Snapshot export hydrates authorized graphs in disposable batch sessions.
    assert [row.service_key for row in db.identity_map.values() if isinstance(row, Service)] == []
    service_query = next(statement for statement in statements if "FROM services" in statement)
    assert "WHERE services.id IN" in service_query
    statements.clear()
    with pytest.raises(HTTPException) as denied:
        main.export_services(db=db, auth=SimpleNamespace(accessible_service_ids=lambda permission: set()))
    assert denied.value.status_code == 403
    assert not any("FROM services" in statement for statement in statements)


@pytest.mark.parametrize("detail_value", [True, ["legacy"], {"legacy": 1}])
def test_export_retains_legacy_python_string_matching(scoped_db, monkeypatch, detail_value):
    db = scoped_db
    service = Service(service_key=str(detail_value), name="Legacy key")
    db.add(service)
    db.flush()
    expected = audit(db, {"service_key": detail_value}, utcnow())
    db.commit()
    captured = {}
    monkeypatch.setattr(main, "build_service_workbook", lambda *args, **kwargs: captured.update(kwargs))
    monkeypatch.setattr(main, "workbook_response", lambda *args: None)
    main.export_service(service.service_key, db=db, auth=SimpleNamespace())
    assert [row.id for row in captured["activity_events"]] == [expected]
