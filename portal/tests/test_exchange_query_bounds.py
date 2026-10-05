from sqlalchemy import create_engine, event, insert
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
