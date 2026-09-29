"""Real route transactions on distinct file-backed SQLite connections.

Authentication is a small scoped stub; CSRF, claim, locking, writes and audits
run through the actual confirmation handlers. This does not test login middleware.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import exchange_routes as routes
from app.exchange import context_and_rows, record_key
from app.models import AuditEvent, BundlePreview, ExchangePreview, InventoryRecord, Service, ServiceMetadata, User


def auth(user_id=1, scope=1, permissions=None):
    allowed = {"ppsm.import", "bundle.import", "metadata.edit"} if permissions is None else permissions
    return SimpleNamespace(user=SimpleNamespace(id=user_id, username="tester", display_name="Tester"), csrf_token="csrf-good", has=lambda permission, service_id=None: permission in allowed and service_id == scope)


@pytest.fixture
def sessions(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'confirm.db').as_posix()}", connect_args={"check_same_thread": False, "timeout": 15})
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add_all([User(id=1, username="tester", display_name="Tester"), User(id=2, username="other", display_name="Other"), Service(id=1, service_key="target", name="Target", manual_version="1"), Service(id=2, service_key="other", name="Other", manual_version="1")])
        db.commit()
    yield factory
    engine.dispose()


def preview(sessions, kind, token="one", expired=False):
    with sessions() as db:
        expiry = datetime.now(timezone.utc) + timedelta(minutes=-1 if expired else 30)
        if kind == "workbook":
            service = db.get(Service, 1)
            context, rows = context_and_rows(db, service, "1", "ppsm", "tester")
            values = {"network.port": 443, "network.protocol": "TCP"}
            db.add(ExchangePreview(token=token, service_id=1, user_id=1, version="1", dataset="ppsm", expires_at=expiry, payload={"errors": [], "conflicts": [], "baseline": routes.state_hash(context, rows), "rows": [{"key": record_key("ppsm", values), "values": values}]}))
        else:
            db.add(BundlePreview(token=token, user_id=1, target_key="target", expires_at=expiry, payload={"mode": "replace_metadata", "target_id": 1, "baseline": routes.metadata_digest(db, 1), "manifest": {"service_key": "source", "schema_version": "service-state-v2"}, "state": {"records": {"service_metadata": [{"values": {"system.owner": "Imported team"}}]}}}))
        db.commit()


def confirm(sessions, kind, token="one", actor=None, csrf="csrf-good", service="target"):
    with sessions() as db:
        try:
            if kind == "workbook":
                response = routes.confirm_import(service, token, csrf, "update", db, actor or auth())
            else:
                response = routes.bundle_confirm(token, csrf, True, db, actor or auth())
            return response.status_code, ""
        except HTTPException as error:
            db.rollback()
            return error.status_code, str(error.detail)


@pytest.mark.parametrize("kind", ["workbook", "bundle"])
def test_simultaneous_same_preview_applies_once(sessions, monkeypatch, kind):
    preview(sessions, kind)
    barrier = Barrier(2)
    original = routes.lock_service
    connections = []
    def rendezvous(db, service_id):
        connections.append(id(db.connection().connection.driver_connection))
        barrier.wait(timeout=10)
        original(db, service_id)
    monkeypatch.setattr(routes, "lock_service", rendezvous)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(confirm, sessions, kind) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert len(set(connections)) == 2
    assert sorted(code for code, _ in results) == [303, 409]
    monkeypatch.setattr(routes, "lock_service", original)
    assert confirm(sessions, kind)[0] == 409
    with sessions() as db:
        action = "exchange.import" if kind == "workbook" else "bundle.import"
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == action)) == 1
        model = ExchangePreview if kind == "workbook" else BundlePreview
        assert db.get(model, "one").consumed is True
        if kind == "workbook":
            assert db.scalar(select(func.count()).select_from(InventoryRecord)) == 1
        else:
            assert db.get(ServiceMetadata, 1).values == {"system.owner": "Imported team"}


def test_separate_workbook_previews_same_baseline_reject_stale(sessions, monkeypatch):
    preview(sessions, "workbook", "one")
    preview(sessions, "workbook", "two")
    barrier = Barrier(2)
    original = routes.lock_service
    def rendezvous(db, service_id):
        barrier.wait(timeout=10)
        original(db, service_id)
    monkeypatch.setattr(routes, "lock_service", rendezvous)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(confirm, sessions, "workbook", token) for token in ("one", "two")]
        results = [future.result(timeout=20) for future in futures]
    assert sorted(code for code, _ in results) == [303, 409]
    assert any("Service data changed" in detail for _, detail in results)
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(InventoryRecord)) == 1
        assert sum(db.get(ExchangePreview, token).consumed for token in ("one", "two")) == 1


@pytest.mark.parametrize("kind", ["workbook", "bundle"])
@pytest.mark.parametrize("case,expected", [("wrong_user", 404), ("wrong_scope", 403), ("bad_csrf", 403), ("expired", 409), ("permission_revoked", 403)])
def test_confirmation_guards_leave_preview_and_data_untouched(sessions, kind, case, expected):
    preview(sessions, kind, expired=case == "expired")
    actor = auth(user_id=2) if case == "wrong_user" else auth(scope=2) if case == "wrong_scope" else auth(permissions=set()) if case == "permission_revoked" else auth()
    assert confirm(sessions, kind, actor=actor, csrf="wrong" if case == "bad_csrf" else "csrf-good")[0] == expected
    with sessions() as db:
        assert not db.get(ExchangePreview if kind == "workbook" else BundlePreview, "one").consumed
        assert db.scalar(select(func.count()).select_from(InventoryRecord)) == 0
        assert db.get(ServiceMetadata, 1) is None


def test_workbook_preview_cannot_be_retargeted(sessions):
    preview(sessions, "workbook")
    assert confirm(sessions, "workbook", actor=auth(scope=2), service="other")[0] == 409


def test_bundle_metadata_replacement_requires_metadata_permission(sessions):
    preview(sessions, "bundle")
    assert confirm(sessions, "bundle", actor=auth(permissions={"bundle.import"}))[0] == 403
