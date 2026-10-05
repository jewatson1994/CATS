from datetime import timedelta

from sqlalchemy import create_engine, event, insert
from sqlalchemy.orm import Session

from app import main
from app.database import Base
from app.models import Execution, Finding, FindingObservation, Service, ServiceImage, utcnow


def test_watchlist_refresh_batches_evidence_and_retains_transaction(monkeypatch):
    from sqlalchemy import select, func
    from app.models import DependencyWatchlistEntry, DependencyWatchlistMatch

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="watchlist-batches", name="Watchlist")
        db.add(service)
        db.flush()
        db.add(DependencyWatchlistEntry(name="library", enabled=True))
        db.execute(insert(Execution), [{"execution_key": f"scan-{index}", "service_id": service.id,
            "scanned_at": utcnow(), "complete": True, "raw_payload": {
                "sbom_components": [{"name": "library", "version": "1.0"}],
                "retained_evidence": "x" * 10000,
            }} for index in range(100)])
        db.commit()
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, parameters, context, many: statements.append(sql))
        original = main.reconcile_watchlist_matches
        resident = []

        def observe(db, execution, **kwargs):
            resident.append(sum(isinstance(item, Execution) for item in db.identity_map.values()))
            return original(db, execution, **kwargs)

        monkeypatch.setattr(main, "reconcile_watchlist_matches", observe)
        main._refresh_watchlist_matches(db)
        assert max(resident) <= 33
        assert len(resident) == 100
        assert sum("FROM dependency_watchlist_entries" in sql for sql in statements) == 1
        assert all("LIMIT" in sql for sql in statements if "FROM executions" in sql)
        assert db.scalar(select(func.count()).select_from(DependencyWatchlistMatch)) == 100
        db.rollback()
        assert db.scalar(select(func.count()).select_from(DependencyWatchlistMatch)) == 0


def test_image_reconciliation_uses_exists_without_loading_observation_history():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key="images", name="Images")
        db.add(service)
        db.flush()
        db.execute(insert(Execution), [{"id": 1, "execution_key": "scan", "service_id": service.id,
            "scanned_at": now, "complete": True, "raw_payload": {}}])
        db.execute(insert(ServiceImage), [{"service_id": service.id, "image_reference": image,
            "lifecycle_status": status} for image, status in [("target", "active"), ("other", "active"), ("old", "archived")]])
        for index in range(1, 5):
            db.add(Finding(id=index, service_id=service.id, cve=f"CVE-{index}", severity="high",
                first_seen=now-timedelta(days=1), episode_started=now-timedelta(days=1), last_seen=now, active=True))
        db.flush()
        db.execute(insert(FindingObservation), [{"finding_id": finding, "execution_id": 1,
            "image": image, "evidence": {"large": "x" * 1000}} for finding, image in
            [(1, "target"), (2, "other"), (3, "old"), (4, "target")] * 100])
        db.commit()
        loaded = []
        event.listen(db, "loaded_as_persistent", lambda session, item: loaded.append(type(item)))
        main._reconcile_image_scope(db, service, "target", {"CVE-4"}, now)
        db.flush()
        assert FindingObservation not in loaded
        assert ServiceImage not in loaded
        assert {row.cve for row in db.query(Finding).filter_by(active=True)} == {"CVE-2", "CVE-4"}
