from datetime import timedelta

from sqlalchemy import create_engine, event, insert
from sqlalchemy.orm import Session

from app import main
from app.database import Base
from app.models import Execution, Finding, FindingObservation, Service, ServiceImage, utcnow


def test_watchlist_worker_projects_one_inventory_and_commits_checkpoints(monkeypatch):
    from sqlalchemy import func, select
    from sqlalchemy.orm import sessionmaker
    from app import settings_worker as worker
    from app.durable_jobs import DurableJob, JobContext, claim
    from app.models import DependencyWatchlistEntry, DependencyWatchlistMatch

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine)
    with sessions.begin() as db:
        service = Service(service_key="watchlist-batches", name="Watchlist")
        db.add(service)
        db.flush()
        db.add(DependencyWatchlistEntry(name="library", enabled=True))
        db.execute(insert(Execution), [{"execution_key": f"scan-{index}", "service_id": service.id,
            "scanned_at": utcnow(), "complete": True, "raw_payload": {
                "sbom_components": [{"name": "library", "version": "1.0"}],
                "retained_evidence": "x" * 10000,
            }} for index in range(35)])
        worker.queue_watchlist_refresh(db, None)
    claimed = claim((worker.KIND,), "settings-test", sessions)
    snapshots = []
    original = worker.match_rows

    def observe(components, *args):
        # Calculation happens outside the publishing transaction. Previous
        # evidence and its resume cursor have become visible together.
        with sessions() as db:
            snapshots.append((db.get(DurableJob, claimed.id).result.get("execution_cursor", 0),
                              db.scalar(select(func.count()).select_from(DependencyWatchlistMatch))))
        return original(components, *args)

    monkeypatch.setattr(worker, "match_rows", observe)
    statements = []
    event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, parameters, context, many: statements.append(sql))
    worker.handler(JobContext(claimed, sessions), {})
    assert snapshots == [(i, i) for i in range(35)]
    assert sum("FROM dependency_watchlist_entries" in sql for sql in statements) == 1
    assert sum("JSON_EXTRACT(executions.raw_payload" in sql for sql in statements) == 35
    assert not any("executions.raw_payload AS executions_raw_payload" in sql for sql in statements)
    # A restarted handler uses its checkpoint instead of rereading every SBOM.
    worker.handler(JobContext(claimed, sessions), {})
    assert len(snapshots) == 35


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
