from concurrent.futures import ThreadPoolExecutor
from threading import Event

from sqlalchemy import func, select

from test_portal import Base, SessionLocal, csrf, new_client, setup_function
from test_startup_support_postgres import postgres_engine
from app import settings_worker as worker
from app.durable_jobs import DurableJob, claim, execute
from app.models import DependencyWatchlistEntry as Entry, DependencyWatchlistMatch as Match
from app.models import Execution, PendingWatchlistDeletion, Service, utcnow
from app.replica_models import ReplicaRecordMap


def seed_scan(db, key, component="library"):
    service = Service(service_key=key, name=key)
    db.add(service)
    db.flush()
    execution = Execution(execution_key=key, service_id=service.id, complete=True, scanned_at=utcnow(),
                          raw_payload={"sbom_components": [{"name": component, "version": "2", "image": key}]})
    db.add(execution)
    db.flush()
    return execution


def save(client, **kwargs):
    return client.post("/admin/dependency-watchlist", data={"csrf_token": csrf(client), "action": "save",
        "enabled": "true", **kwargs}, follow_redirects=False)


def test_navigation_during_watchlist_refresh_and_concurrent_edit(monkeypatch):
    client = new_client()
    with SessionLocal.begin() as db:
        seed_scan(db, "demo")
    assert save(client, name="library").status_code == 303
    imported = client.post("/admin/dependency-watchlist/import", data={"csrf_token": csrf(client)},
        files={"file": ("entries.txt", b"other\n", "text/plain")}, follow_redirects=False)
    assert imported.status_code == 303
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(DurableJob).where(DurableJob.kind == worker.KIND)) == 1
        assert db.scalar(select(Match.id)) is None
        entry_id = db.scalar(select(Entry.id).where(Entry.name == "library"))

    started, resume = Event(), Event()
    original = worker.match_rows

    def match_while_editing(*args):
        started.set()
        assert resume.wait(15)
        return original(*args)

    monkeypatch.setattr(worker, "match_rows", match_while_editing)
    job = claim((worker.KIND,), "settings-test", SessionLocal)
    with ThreadPoolExecutor(max_workers=1) as executor:
        task = executor.submit(execute, job, worker.handler, SessionLocal)
        try:
            assert started.wait(10)
            # These requests must finish while the worker is deliberately stalled.
            assert client.get("/").status_code == 200
            assert client.get("/admin/dependency-watchlist").status_code == 200
            assert save(client, entry_id=entry_id, name="other").status_code == 303
        finally:
            resume.set()
        task.result(timeout=10)
    with SessionLocal() as db:
        assert db.get(DurableJob, job.id).result["superseded"] is True
        assert db.scalar(select(Match.id)) is None
        assert worker.latest_watchlist_refresh(db)["status"] == "queued"
    replacement = claim((worker.KIND,), "settings-test", SessionLocal)
    execute(replacement, worker.handler, SessionLocal)
    with SessionLocal() as db:
        assert worker.latest_watchlist_refresh(db)["status"] == "completed"
        assert db.scalar(select(Match.id)) is None


def test_deletion_cleans_only_local_evidence_and_imported_rules_are_read_only():
    client = new_client()
    with SessionLocal.begin() as db:
        local = seed_scan(db, "local")
        upstream = seed_scan(db, "upstream")
        rule = Entry(name="library", enabled=True)
        upstream_rule = Entry(name="reported upstream", enabled=False)
        db.add_all([rule, upstream_rule])
        db.flush()
        rule_id, upstream_id = rule.id, upstream_rule.id
        db.add(ReplicaRecordMap(service_id=upstream.service_id, table_name=Entry.__tablename__,
                                source_id=123, local_id=upstream_id))
        for entry, scan in ((rule, local), (upstream_rule, upstream)):
            db.add(Match(entry_id=entry.id, execution_id=scan.id, service_id=scan.service_id,
                         component_name="library", image=scan.execution_key))
    assert save(client, action="delete", entry_id=upstream_id).status_code == 404
    assert save(client, action="delete", entry_id=rule_id).status_code == 303
    assert save(client, name="changed", entry_id=rule_id).status_code == 404
    with SessionLocal() as db:
        assert db.get(PendingWatchlistDeletion, rule_id)
        assert db.scalar(select(func.count()).select_from(Match)) == 2
        assert list(db.scalars(select(Entry.id).where(worker.editable_watchlist_entry()))) == []
    job = claim((worker.KIND,), "settings-test", SessionLocal)
    execute(job, worker.handler, SessionLocal)
    with SessionLocal() as db:
        assert worker.latest_watchlist_refresh(db)["status"] == "completed"
        assert db.get(Entry, rule_id) is None
        assert db.get(PendingWatchlistDeletion, rule_id) is None
        assert list(db.scalars(select(Match.entry_id))) == [upstream_id]


def test_queue_admission_failure_rolls_back_rule(monkeypatch):
    client = new_client()
    with SessionLocal.begin() as db:
        from app.durable_jobs import submit
        submit(db, kind="export_build", payload={}, commit=False)
    monkeypatch.setenv("CATS_JOB_QUEUE_CAPACITY", "1")
    assert save(client, name="blocked").status_code == 429
    with SessionLocal() as db:
        assert db.scalar(select(Entry.id)) is None
        assert worker.latest_watchlist_refresh(db) is None


def test_refresh_retry_does_not_require_another_edit():
    client = new_client()
    assert save(client, name="library").status_code == 303
    with SessionLocal.begin() as db:
        old = db.scalar(select(DurableJob).where(DurableJob.kind == worker.KIND))
        old.status = "failed"
        old_id = old.id
    for _ in range(2):
        response = client.post("/admin/dependency-watchlist/refresh",
                               data={"csrf_token": csrf(client)}, follow_redirects=False)
        assert response.status_code == 303
    with SessionLocal() as db:
        latest = worker.latest_watchlist_refresh(db)
        assert latest["status"] == "queued" and latest["id"] != old_id
        assert db.scalar(select(func.count()).select_from(DurableJob)) == 2


def test_concurrent_sqlite_refresh_admission_coalesces(tmp_path):
    from threading import Barrier
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path / 'settings.db'}")
    sessions = sessionmaker(engine)
    Base.metadata.create_all(engine)
    start = Barrier(4)

    def retry(_):
        with sessions.begin() as db:
            start.wait(timeout=5)
            return worker.queue_watchlist_refresh(db, None, rules_changed=False).id

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(retry, range(4)))
        assert len(set(ids)) == 1
        with sessions() as db:
            assert db.scalar(select(func.count()).select_from(DurableJob)) == 1
    finally:
        engine.dispose()


def test_postgres_refresh_includes_uncommitted_scan_with_older_rules(postgres_engine):
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
    from app.watchlist import reconcile_matches
    from app.durable_jobs import JobContext

    Base.metadata.create_all(postgres_engine)
    sessions = sessionmaker(postgres_engine, expire_on_commit=False)
    waiting = Event()

    @event.listens_for(postgres_engine, "before_cursor_execute")
    def capture_gate(conn, cursor, statement, parameters, context, executemany):
        if statement == "SELECT pg_advisory_xact_lock(73488342)":
            waiting.set()

    with sessions() as ingestion, ThreadPoolExecutor(max_workers=1) as executor:
        scan = seed_scan(ingestion, "in-flight")
        worker.fence_ingestion(ingestion)
        assert reconcile_matches(ingestion, scan) == 0
        with sessions.begin() as settings:
            settings.add(Entry(name="library", enabled=True))
            worker.queue_watchlist_refresh(settings, None)
        job = claim((worker.KIND,), "settings-test", sessions)
        run = executor.submit(worker.handler, JobContext(job, sessions), {})
        try:
            assert waiting.wait(5)
            assert not run.done()
        finally:
            ingestion.commit()
        assert run.result(timeout=10)["last_execution_id"] == scan.id
    with sessions() as db:
        assert db.scalar(select(Match.execution_id)) == scan.id
