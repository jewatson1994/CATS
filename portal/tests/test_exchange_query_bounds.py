from sqlalchemy import create_engine, event, insert, select
from sqlalchemy.orm import Session

from app.database import Base
from app.exchange import selected_evidence
from app.models import Execution, Service, utcnow


def test_version_selection_hydrates_only_selected_evidence():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="versions", name="Versions")
        db.add(service)
        db.flush()
        db.execute(insert(Execution), [{"execution_key": f"scan-{index}", "service_id": service.id,
            "scanned_at": utcnow(), "complete": True, "raw_payload": {
                "service": {"version": "selected" if index in (3, 80) else "other"},
                "evidence": "x" * 10000,
            }} for index in range(100)])
        db.commit()
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda session, item: loaded.append(type(item)))
        version, rows = selected_evidence(db, service, "selected")
        assert version == "selected"
        assert [row.execution_key for row in rows] == ["scan-80", "scan-3"]
        assert loaded.count(Execution) == 2


def test_history_pages_native_and_imported_payloads_before_hydration():
    from app.history_queries import history_page_evidence
    from app.models import ServiceTransferProvenance

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="paged-history", name="History")
        db.add(service)
        db.flush()
        native = {"service": {"version": "selected"}, "evidence": "x" * 10000}
        db.execute(insert(Execution), [{"execution_key": f"native-{index}", "service_id": service.id,
            "scanned_at": utcnow(), "complete": True, "raw_payload": native} for index in range(100)])
        db.add(ServiceTransferProvenance(service_id=service.id, detail={"historical_executions": [
            {"execution_key": f"imported-{index}", "raw_payload": native} if index % 2 else
            {**native, "execution_id": f"imported-{index}"} for index in range(100)]}))
        db.commit()
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda session, item: loaded.append(type(item)))
        result = history_page_evidence(db, service, "selected", page=2, imported_page=3)
        assert result["total_items"] == result["imported_total_items"] == 100
        assert result["total_pages"] == result["imported_total_pages"] == 10
        assert [row.execution_key for row in result["executions"]] == [f"native-{index}" for index in range(89, 79, -1)]
        assert len(result["imported"]) == 10
        assert result["imported_indices"] == list(range(20, 30))
        assert result["imported"][0]["execution_id"] == "imported-20"
        assert loaded.count(Execution) == 10
        assert ServiceTransferProvenance not in loaded


def test_imported_history_query_compiles_for_postgres():
    from sqlalchemy.dialects import postgresql
    from sqlalchemy import select, true
    from types import SimpleNamespace
    from app.history_queries import imported_source

    source, elements, position, item, version = imported_source(SimpleNamespace(
        get_bind=lambda: SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))))
    statement = select(item, version).select_from(source).join(elements, true()).order_by(position).limit(10)
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "WITH ORDINALITY" in sql and "LIMIT" in sql
    assert "json_each" not in sql

def test_history_workspace_pins_one_scan_across_pages_and_versions():
    import pytest
    from app.history_queries import history_page_evidence
    from app.models import ServiceTransferProvenance

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="records", name="Records")
        db.add(service)
        db.flush()
        db.execute(insert(Execution), [dict(execution_key=f"native-{i}", service_id=service.id, scanned_at=utcnow(),
            complete=True, raw_payload={"service": {"version": "other" if i == 0 else "v1", "name": "Old name"}})
            for i in range(16)])
        db.add(ServiceTransferProvenance(service_id=service.id, detail={"historical_executions": [
            {"execution_id": f"remote-{i}", "service": {"version": "v1", "name": "Publisher service"}}
            for i in range(13)]}))
        db.commit()
        pinned_id = db.scalar(select(Execution.id).where(Execution.execution_key == "native-1"))
        other_id = db.scalar(select(Execution.id).where(Execution.execution_key == "native-0"))
        source = db.scalar(select(ServiceTransferProvenance.id))
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda _, item: loaded.append(type(item)))
        native = history_page_evidence(db, service, "v1", scan=f"scan-{pinned_id}", tab="dependencies")
        assert native["page"] == 2 and len(native["executions"]) == 1 and not native["imported"]
        assert native["executions"][0].execution_key == "native-1"
        assert len(native["scan_options"]) == 15 and loaded.count(Execution) == 1
        captured = history_page_evidence(db, service, "v1", scan=f"import-{source}-12", tab="findings")
        assert captured["imported_page"] == 2 and not captured["executions"]
        assert [row["execution_id"] for row in captured["imported"]] == ["remote-12"]
        assert any(row["key"] == "remote-12" and row["name"] == "Publisher service" for row in captured["scan_options"])
        releases = history_page_evidence(db, service, "v1", tab="releases")
        assert not releases["executions"] and not releases["imported"]
        assert loaded.count(Execution) == 1
        with pytest.raises(ValueError, match="Scan not found"):
            history_page_evidence(db, service, "v1", scan=f"scan-{other_id}", tab="findings")


def test_history_releases_require_bound_service_version_and_approved_evidence(monkeypatch):
    from cryptography.fernet import Fernet
    from fastapi import HTTPException
    import pytest
    from app.cyber_approvals import CyberApproval
    from app.history_queries import historical_releases
    from app.replica_integrity import digest, seal_record
    from app.replica_models import ReplicaRelease

    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        local = Service(service_key="app", name="App")
        other = Service(service_key="elsewhere", name="Other")
        db.add_all([local, other])
        db.flush()
        for key, service, version, frozen, status in [
                ("approved-old", local, "1", "1", "approved"), ("pending", local, "1", "1", "pending"),
                ("other-version", local, "2", "2", "approved"), ("elsewhere", other, "1", "1", "approved"),
                ("different-frozen-version", local, "1", "2", "approved")]:
            execution = Execution(execution_key=key, service_id=service.id, scanned_at=utcnow(), complete=True,
                raw_payload={"service": {"version": version}})
            db.add(execution)
            db.flush()
            db.add(CyberApproval(service_id=service.id, release_key=key, source_execution_id=execution.id,
                status=status, snapshot={"version": frozen}, snapshot_digest="sha256:test", variant="current_service"))
        for version in ("1", "2"):
            state = {"extension": {"approval_context": {"version": version, "source_execution_id": 42}}}
            retained = ReplicaRelease(service_id=local.id, publisher="HQ", source_release_id=f"publisher-{version}",
                sequence=int(version), manifest={}, manifest_digest=digest({}), artifacts=[], evidence_state=state,
                evidence_state_digest=digest(state), approved_at=utcnow(), key_fingerprint="test", source_reference="registry",
                verified=True, complete=True)
            seal_record(retained)
            db.add(retained)
        db.commit()
        rows = historical_releases(db, local.id, "1")
        assert [(row["release_key"], row["source"]) for row in rows] == [("approved-old", "Local"), ("publisher-1", "Publisher")]
        damaged = db.scalar(select(ReplicaRelease).where(ReplicaRelease.source_release_id == "publisher-1"))
        damaged.integrity_seal = "invalid"
        db.flush()
        with pytest.raises(HTTPException) as exc:
            historical_releases(db, local.id, "1")
        assert exc.value.status_code == 409
