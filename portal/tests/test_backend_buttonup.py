"""Regression coverage for the backend performance and correctness button-up."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, event, inspect, select, text

from app.database import SessionLocal, engine
from app.models import (DeploymentValidationRun, Execution, ExecutionSummary, Finding, PolicyFinding, Service)
from app.sql_sets import INLINE_LIMIT, catalog_subset, member_of
from test_portal import helm_payload, new_client, page_data, payload, pipeline_headers, setup_function  # noqa: F401


def _statements(target=engine):
    captured = []
    def listener(conn, cursor, statement, parameters, context, executemany):
        captured.append((statement, parameters))
    event.listen(target, "before_cursor_execute", listener)
    return captured, lambda: event.remove(target, "before_cursor_execute", listener)


def _param_count(parameters):
    if isinstance(parameters, dict):
        return len(parameters)
    return len(parameters or ())


@pytest.mark.parametrize("numeric", [False, True])
def test_member_of_matches_python_membership_with_constant_binds(numeric):
    local = create_engine("sqlite://")
    metadata = MetaData()
    table = Table("t", metadata, Column("id", Integer, primary_key=True), Column("value", String))
    metadata.create_all(local)
    values = list(range(0, 5000)) if numeric else [f"CVE-2026-{index:05d}" for index in range(5000)]
    with local.begin() as connection:
        connection.execute(table.insert(), [{"id": index, "value": f"CVE-2026-{index:05d}"} for index in range(0, 10000, 3)])
    column = table.c.id if numeric else table.c.value
    wanted = set(values[::7])
    captured, stop = _statements(local)
    with local.connect() as connection:
        selected = set(connection.execute(select(column).where(member_of(column, wanted, numeric=numeric))).scalars())
        assert set(connection.execute(select(column).where(member_of(column, set(), numeric=numeric))).scalars()) == set()
        small = set(list(wanted)[:INLINE_LIMIT])
        assert set(connection.execute(select(column).where(member_of(column, small, numeric=numeric))).scalars()) == {
            value for value in (connection.execute(select(column)).scalars()) if value in small}
    stop()
    everything = set(local.connect().execute(select(column)).scalars())
    assert selected == everything & wanted
    assert max(_param_count(parameters) for _, parameters in captured) <= INLINE_LIMIT


def test_member_of_postgresql_binds_one_json_value():
    from sqlalchemy.dialects import postgresql
    table = Table("t", MetaData(), Column("id", Integer), Column("value", String))
    for numeric, column in ((True, table.c.id), (False, table.c.value)):
        compiled = select(column).where(member_of(column, set(range(100)) if numeric else {f"v{i}" for i in range(100)},
                                                  numeric=numeric)).compile(dialect=postgresql.dialect())
        sql = str(compiled)
        assert "json_array_elements_text" in sql and len(compiled.params) == 1
        assert ("AS BIGINT" in sql) is numeric


def test_catalog_subset_is_memoized_per_catalog_snapshot():
    catalog = {"a": 0.1, "b": 0.9}
    calls = []
    first = catalog_subset(catalog, ("test>=", 0.5), lambda score: calls.append(score) or score >= 0.5)
    again = catalog_subset(catalog, ("test>=", 0.5), lambda score: calls.append(score) or score >= 0.5)
    assert first == again == frozenset({"b"}) and len(calls) == 2
    assert catalog_subset(dict(catalog), ("test>=", 0.5), lambda score: score >= 0.5) == frozenset({"b"})


@pytest.mark.parametrize("risk", [False, True])
def test_services_dashboard_scales_to_1000_services_with_large_catalogs(monkeypatch, risk):
    from app import main
    from app.models import PortalSetting
    client = new_client()
    with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        db.execute(Service.__table__.insert(), [{"service_key": f"scale-{index}", "name": f"Scale {index}",
                                                 "created_at": now} for index in range(1000)])
        if risk:
            db.add(PortalSetting(key="compliance_mode", value="risk_based"))
            db.add(PortalSetting(key="kev_enabled", value="true"))
            db.add(PortalSetting(key="epss_enabled", value="true"))
        db.commit()
    kev = frozenset(f"CVE-2020-{index:06d}" for index in range(20000))
    epss = {f"CVE-2021-{index:06d}": index / 50000 for index in range(50000)}
    monkeypatch.setattr(main, "kev_cves", lambda: kev)
    monkeypatch.setattr(main, "epss_scores", lambda: epss)
    captured, stop = _statements()
    try:
        response = client.get("/api/dashboard/services")
    finally:
        stop()
    assert response.status_code == 200
    assert response.json()["total_count"] >= 1000
    assert max(_param_count(parameters) for _, parameters in captured) <= 200


def test_execution_summary_v4_architecture_metadata_and_background_backfill():
    from app.execution_summaries import SUMMARY_VERSION, backfill_stale_summaries, load_execution_summaries
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=helm_payload("summary-v4"), headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        summary = load_execution_summaries(db, [execution.id])[execution.id]
        assert summary["architecture"]["has_architecture"] and summary["architecture"]["helm_original"]
        assert summary["architecture"]["applicable"] and summary["architecture"]["declared_resources"] >= 1
        db.execute(ExecutionSummary.__table__.update().values(summary_version=SUMMARY_VERSION - 1))
        db.commit()
    assert backfill_stale_summaries(SessionLocal) == 1
    assert backfill_stale_summaries(SessionLocal) == 0
    with SessionLocal() as db:
        assert db.scalar(select(ExecutionSummary.summary_version)) == SUMMARY_VERSION


def test_startup_indexes_drop_duplicate_observation_index():
    import ast
    from pathlib import Path
    tree = ast.parse((Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8-sig"))
    loop = next(node for node in ast.walk(tree) if isinstance(node, ast.For)
                and "CREATE INDEX IF NOT EXISTS ix_findings_service_active" in ast.unparse(node.iter))
    STARTUP_INDEX_STATEMENTS = [node.value for node in loop.iter.elts]
    local = create_engine("sqlite://")
    from app.database import Base
    Base.metadata.create_all(local)
    with local.begin() as connection:
        connection.execute(text("CREATE INDEX ix_finding_observations_finding_execution_id "
                                "ON finding_observations (finding_id, execution_id, id)"))
        for statement in STARTUP_INDEX_STATEMENTS:
            connection.execute(text(statement))
        for statement in STARTUP_INDEX_STATEMENTS:  # idempotent on restart
            connection.execute(text(statement))
    names = {index["name"] for index in inspect(local).get_indexes("finding_observations")}
    assert "ix_obs_finding_execution_id" in names
    assert "ix_finding_observations_finding_execution_id" not in names


def test_remediation_preview_counts_active_configuration_findings():
    from app.main import build_plan
    client = new_client()
    body = helm_payload("preview")
    body["policy_findings"] = [{"type": "Configuration", "finding": "KSV-0014", "severity": "High", "scanner": "Trivy",
                                "target": "Deployment/payments-api", "title": "Root file system is not read-only"},
                               {"type": "Configuration", "finding": "KSV999", "severity": "Low", "scanner": "Trivy",
                                "target": "Deployment/payments-api", "title": "Unregistered check"}]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        plan = build_plan(execution.raw_payload, db.scalars(select(PolicyFinding).where(PolicyFinding.active.is_(True))).all(), "PREVIEW")
    expected = (sum(item.get("classification") == "AUTO-REMEDIABLE" for item in plan["configuration_changes"]),
                sum(item.get("classification") == "REVIEW REQUIRED" for item in plan["configuration_changes"]))
    assert sum(expected) >= 1
    for _ in range(2):  # second request is served from the content-keyed preview cache
        preview = page_data(client.get("/services/payments-service?remediations=true&tab=pipeline"))["remediation_preview"]
        assert (preview["configuration_changes"], preview["manual_review"]) == expected


def test_service_tabs_read_evidence_without_writes_and_with_bounded_payload_reads():
    client = new_client()
    for index in range(4):
        body = helm_payload(f"bounded-{index}")
        body["scanned_at"] = (datetime.now(timezone.utc) + timedelta(minutes=index)).isoformat()
        assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    for path in ("?overview=true", "?architecture=true", "?validation=true", "?remediations=true&tab=pipeline",
                 "?findings=true&findings_view=raw&finding_state=noncompliant",
                 "?findings=true&findings_view=raw&finding_state=warnings"):
        captured, stop = _statements()
        try:
            assert client.get("/services/payments-service" + path).status_code == 200
        finally:
            stop()
        statements = [statement for statement, _ in captured]
        assert not [s for s in statements if s.lstrip().split(None, 1)[0].upper() in {"INSERT", "UPDATE", "DELETE"}], path
        payload_reads = [s for s in statements if "executions.raw_payload" in s and "json_extract" not in s
                         and "SELECT executions.raw_payload" in s.replace("\n", " ")]
        assert len(payload_reads) <= 2, path


def test_architecture_polling_returns_summary_and_reuses_cached_graph():
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=helm_payload("poll"), headers=pipeline_headers).status_code == 201
    url = "/api/v1/services/payments-service/architecture-evidence"
    full = client.get(url).json()
    assert full["graph"]["nodes"] and full["active_validation"] is None
    captured, stop = _statements()
    try:
        summary = client.get(url + "?summary=true").json()
    finally:
        stop()
    assert summary["graph"] == {"summary": full["graph"]["summary"]}
    assert not any("raw_payload" in statement and "SELECT executions.raw_payload" in statement.replace("\n", " ")
                   for statement, _ in captured)
    overview = page_data(client.get("/services/payments-service?overview=true"))
    assert overview["architecture_polling"] is False
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        db.add(DeploymentValidationRun(service_id=service.id, run_key="active-run", status="RUNNING", phase="DEPLOYING"))
        db.commit()
    assert page_data(client.get("/services/payments-service?overview=true"))["architecture_polling"] is True
    assert client.get(url + "?summary=true").json()["active_validation"]["run_key"] == "active-run"


def test_ingest_queues_dependency_projection(monkeypatch):
    from app import dependency_queries, main
    scheduled = []
    monkeypatch.setenv("CATS_DEPENDENCY_PROJECTION_ON_INGEST", "true")
    monkeypatch.setattr(dependency_queries, "schedule_projection",
                        lambda binding, execution_id, token, metadata: scheduled.append((execution_id, token)))
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=payload("projection", datetime.now(timezone.utc), ["CVE-2026-0001"]),
                       headers=pipeline_headers).status_code == 201
    from app.models import DependencyProjection
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        row = db.get(DependencyProjection, execution.id)
        assert row is not None and row.status == "pending"
        assert scheduled == [(execution.id, row.build_token)]
    monkeypatch.setenv("CATS_DEPENDENCY_PROJECTION_ON_INGEST", "false")
    assert main._ingest_projection_enabled() is False


@pytest.mark.parametrize("findings", [
    [{"image": "a:1", "image_digest": "sha256:1", "cve": "CVE-1"}, {"image": "", "cve": "x"},
     {"image": "b:2", "discovered_from": "Helm", "cve": "CVE-2"}, {"cve": "no image"},
     {"image": "a:1", "image_digest": "sha256:1", "cve": "CVE-3"}, {"image": None, "cve": "CVE-4"}],
    [],
])
@pytest.mark.parametrize("policy", [None, [], [{"finding": "KSV"}], {}])
def test_overview_payload_subset_matches_full_payload(findings, policy):
    from app.evidence_reads import overview_payload
    from app.models import Execution
    client = new_client()
    body = helm_payload("subset")
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        full = dict(execution.raw_payload)
        full["findings"] = findings
        full["skipped_images"] = ["registry/skipped:1"]
        if policy is None:
            full.pop("policy_findings", None)
        else:
            full["policy_findings"] = policy
        execution.raw_payload = full
        db.commit()
        subset, images = overview_payload(db, execution.id)
    legacy = [{"image": item.get("image"), "digest": item.get("image_digest"), "discovered_from": item.get("discovered_from") or "Submitted"}
              for item in (full.get("findings", []) or []) if isinstance(item, dict) and item.get("image")] if isinstance(full.get("findings"), list) else []
    assert images == legacy
    assert bool(subset.get("policy_findings")) == bool(full.get("policy_findings"))
    for key in ("service_overview", "skipped_images", "skipped_charts"):
        assert subset.get(key) == full.get(key)


def test_lifespan_starts_read_model_maintenance(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import main
    from app.database import Base
    from app.execution_summaries import SUMMARY_VERSION, install_execution_summary_hooks
    assert main._start_read_model_maintenance() is None  # in-memory test database
    started = []
    monkeypatch.setattr(main, "_start_read_model_maintenance", lambda: started.append(True))
    with TestClient(main.app):
        pass
    assert started == [True]
    monkeypatch.undo()
    file_engine = create_engine(f"sqlite:///{tmp_path / 'maintenance.sqlite'}")
    Base.metadata.create_all(file_engine)
    factory = sessionmaker(bind=file_engine, expire_on_commit=False)
    install_execution_summary_hooks(factory.class_)
    with factory() as db:
        service = Service(service_key="m", name="M")
        db.add(service); db.flush()
        db.add(Execution(service_id=service.id, execution_key="m-1", scanned_at=datetime.now(timezone.utc),
                         complete=True, raw_payload={"service": {"version": "1"}}))
        db.commit()
        db.execute(ExecutionSummary.__table__.update().values(summary_version=SUMMARY_VERSION - 1)); db.commit()
    monkeypatch.setattr(main, "engine", file_engine)
    monkeypatch.setattr(main, "SessionLocal", factory)
    thread = main._start_read_model_maintenance()
    thread.join(30)
    with factory() as db:
        assert db.scalar(select(ExecutionSummary.summary_version)) == SUMMARY_VERSION
    file_engine.dispose()
