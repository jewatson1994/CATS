"""Static cross-database checks for the performance read paths.

Every statement emitted while exercising the optimized pages on SQLite is
recompiled for PostgreSQL (psycopg 3 dialect, as deployed) and parsed with the
PostgreSQL grammar (pglast, when installed).  This does not prove PostgreSQL
runtime behavior; it catches dialect compile errors, SQLite-only functions in
PostgreSQL output, and syntax PostgreSQL would reject.
"""
import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, event, select
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
from sqlalchemy.sql.elements import TextClause

from app.database import SessionLocal, engine
from app.models import DeploymentValidationRun, Execution, ExecutionSummary, PortalSetting, Service
from test_overview_counts import _seed
from test_portal import helm_payload, new_client, pipeline_headers, setup_function  # noqa: F401

SQLITE_ONLY = re.compile(r"\b(json_each|json_extract|json_type|json_quote|json_group_array|json_array_length)\s*\(", re.I)
POSTGRES_ONLY = re.compile(r"(json_array_elements|jsonb_typeof|json_typeof|#>|::)", re.I)
PG = PGDialect_psycopg()


def postgres_sql(element):
    compiled = element.compile(dialect=PG, compile_kwargs={"render_postcompile": True})
    counter = iter(range(1, 100000))
    return re.sub(r"%\(([^)]+)\)s", lambda _: f"${next(counter)}", str(compiled))


def parse_postgres(sql):
    pglast = pytest.importorskip("pglast")
    pglast.parse_sql(sql)


# Pre-existing builders that already choose SQLite or PostgreSQL SQL from the
# connection's dialect; recompiling their SQLite form says nothing about their
# PostgreSQL branch, which is compiled directly in the tests below.
DIALECT_BUILT = ("dashboard_ids", "history_elements", "helm_source_files", "audit_events.detail")


def _capture():
    captured = []
    def listener(conn, clauseelement, multiparams, params, execution_options):
        values = dict(params or {})
        if isinstance(multiparams, (list, tuple)) and len(multiparams) == 1 and isinstance(multiparams[0], dict):
            values.update(multiparams[0])
        elif isinstance(multiparams, dict):
            values.update(multiparams)
        captured.append((clauseelement, values))
    event.listen(engine, "before_execute", listener)
    return captured, lambda: event.remove(engine, "before_execute", listener)


def _exercise(client, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "kev_cves", lambda: frozenset(f"CVE-2020-{index:05d}" for index in range(5000)))
    monkeypatch.setattr(main, "epss_scores", lambda: {f"CVE-2021-{index:05d}": index / 10000 for index in range(10000)})
    base = "/services/payments-service"
    paths = [
        "/api/dashboard/services", f"{base}?overview=true", f"{base}?architecture=true",
        f"{base}?architecture=true&layout_width=800", f"{base}?validation=true", f"{base}?validation=true&validation_page=2",
        f"{base}?activity=true", f"{base}?poam=true", f"{base}?artifacts=true", f"{base}?dependencies=true",
        f"{base}?findings=true", f"{base}?findings=true&findings_view=raw&finding_state=active",
        f"{base}?findings=true&findings_view=raw&finding_state=noncompliant&q=cve-2026_0%25&resource=x",
        f"{base}?findings=true&findings_view=raw&finding_state=noncompliant&severity=High",
        f"{base}?findings=true&findings_view=raw&finding_state=noncompliant&page=2",
        f"{base}?findings=true&findings_view=raw&finding_state=warnings",
        f"{base}?findings=true&findings_view=raw&finding_state=warnings&finding_type=vulnerability",
        "/api/v1/services/payments-service/architecture-evidence",
        "/api/v1/services/payments-service/architecture-evidence?summary=true",
        "/api/v1/services/payments-service/architecture-evidence?view_version=2.4.1",
    ] + [f"{base}?remediations=true&tab={tab}&page_size=25" for tab in ("pipeline", "poams", "exceptions", "mitigations")]
    for path in paths:
        response = client.get(path, headers={"Accept": "application/vnd.cats.page+json"})
        assert response.status_code == 200, (path, response.text[:300])


@pytest.mark.parametrize("mode", ["raw", "risk_based"])
def test_optimized_read_paths_compile_and_parse_for_postgresql(monkeypatch, mode):
    from app.execution_summaries import SUMMARY_VERSION
    client = new_client()
    _seed(client, complete=False)
    assert client.post("/api/v1/pipeline-results", json=helm_payload("cross-db"), headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        for key, value in {"compliance_mode": mode, "kev_enabled": "true", "epss_enabled": "true",
                           "incomplete_noncompliant": "true", "minimum_severity": "Low",
                           "epss_rules": '[{"severity":"High","threshold":0.5},{"severity":"Any","threshold":0}]'}.items():
            db.add(PortalSetting(key=key, value=value))
        service = db.scalar(select(Service))
        db.add(DeploymentValidationRun(service_id=service.id, run_key="cross-db-run", status="RUNNING", phase="DEPLOYING"))
        # Outdated summaries exercise the SQL classification of stale scans.
        db.execute(ExecutionSummary.__table__.update().values(summary_version=SUMMARY_VERSION - 1))
        db.commit()
    captured, stop = _capture()
    try:
        _exercise(client, monkeypatch)
    finally:
        stop()
    checked = 0
    failures = []
    for element, values in captured:
        if isinstance(element, TextClause) or not hasattr(element, "compile"):
            continue
        try:
            if values and getattr(element, "is_select", False):
                element = element.params(**values)
            sql = postgres_sql(element)
        except Exception as exc:  # compile failure is a finding
            failures.append(f"compile: {type(exc).__name__}: {exc}"[:300])
            continue
        if SQLITE_ONLY.search(sql) and not any(marker in sql for marker in DIALECT_BUILT):
            failures.append(f"sqlite-only function in PostgreSQL SQL: {sql[:300]}")
        try:
            parse_postgres(sql)
        except pytest.skip.Exception:
            raise
        except Exception as exc:
            failures.append(f"parse: {exc}: {sql[:400]}")
        checked += 1
    assert checked > 100
    assert not failures, "\n".join(failures[:10])


def test_finding_image_statements_are_explicit_per_dialect_and_fall_back_elsewhere(monkeypatch):
    from app import evidence_reads
    sqlite_sql = evidence_reads.finding_images_statement("sqlite")
    postgres = evidence_reads.finding_images_statement("postgresql")
    assert "json_each" in sqlite_sql and not POSTGRES_ONLY.search(sqlite_sql.replace("::", ""))
    assert "WITH ORDINALITY" in postgres and "ORDER BY f.position" in postgres and not SQLITE_ONLY.search(postgres)
    parse_postgres(postgres.replace(":id", "$1"))
    assert evidence_reads.finding_images_statement("mysql") is None
    client = new_client()
    body = helm_payload("images")
    body["findings"] = [{"cve": "CVE-1", "image": "a:1", "image_digest": "sha256:1"}, {"cve": "CVE-2", "image": "b:2"},
                        {"cve": "CVE-3", "image": "a:1", "image_digest": "sha256:1"}]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        execution_id = db.scalar(select(Execution.id))
        native = evidence_reads.overview_payload(db, execution_id)
        monkeypatch.setattr(evidence_reads, "finding_images_statement", lambda name: None)
        assert evidence_reads.overview_payload(db, execution_id) == native
    assert [item["image"] for item in native[1]] == ["a:1", "b:2", "a:1"]


def test_json_set_membership_compiles_for_both_dialects():
    from app.sql_sets import INLINE_LIMIT, member_of
    table = Table("t", MetaData(), Column("id", Integer), Column("value", String))
    for numeric, column, values in ((True, table.c.id, set(range(100))), (False, table.c.value, {f"CVE-{i}" for i in range(100)})):
        statement = select(column).where(member_of(column, values, numeric=numeric), ~member_of(column, values, numeric=numeric))
        sqlite_sql = str(statement.compile(dialect=sqlite_dialect.dialect()))
        assert sqlite_sql.count("json_each(") == 2 and not POSTGRES_ONLY.search(sqlite_sql)
        postgres = postgres_sql(statement)
        assert postgres.count("json_array_elements_text(CAST(") == 2 and not SQLITE_ONLY.search(postgres)
        assert ("AS BIGINT" in postgres) is numeric
        parse_postgres(postgres)
    inline = select(table.c.id).where(member_of(table.c.id, set(range(INLINE_LIMIT)), numeric=True))
    assert "json" not in postgres_sql(inline).lower()
    assert "false" in postgres_sql(select(table.c.id).where(member_of(table.c.id, set()))).lower()


def test_dialect_specific_json_predicates_compile_for_postgresql():
    from app.artifact_tab_queries import helm_original_expression
    from app.models import Execution as Scan
    from app.overview_queries import ArchitectureValueTruth
    for path in ("service_overview.rendered_resources", "rendered_resources", "helm_source_files", "policy_findings"):
        postgres = postgres_sql(select(ArchitectureValueTruth(Scan.raw_payload, path)))
        assert "jsonb_typeof" in postgres and not SQLITE_ONLY.search(postgres)
        parse_postgres(postgres)
        sqlite_sql = str(select(ArchitectureValueTruth(Scan.raw_payload, path)).compile(dialect=sqlite_dialect.dialect()))
        assert "json_type(" in sqlite_sql
    postgres = postgres_sql(select(Scan.id, helm_original_expression("postgresql")))
    assert "json_typeof" in postgres and not SQLITE_ONLY.search(postgres)
    parse_postgres(postgres)


def test_raw_state_ordering_uses_code_point_collation_on_postgresql():
    from types import SimpleNamespace
    from app.raw_states import _codepoint_order
    column = Column("sort_item", String)
    fake = lambda name: SimpleNamespace(get_bind=lambda: SimpleNamespace(dialect=SimpleNamespace(name=name)))
    table = Table("rows", MetaData(), column)
    postgres = postgres_sql(select(table.c.sort_item).order_by(*_codepoint_order(fake("postgresql"), table.c.sort_item)))
    assert 'COLLATE "C"' in postgres
    parse_postgres(postgres)
    sqlite_sql = str(select(table.c.sort_item).order_by(*_codepoint_order(fake("sqlite"), table.c.sort_item))
                     .compile(dialect=sqlite_dialect.dialect()))
    assert "COLLATE" not in sqlite_sql


def test_like_needles_escape_wildcards_on_both_dialects():
    from app.raw_states import LIKE_ESCAPE, _like
    assert _like("a%b_c!\\") == "%a!%b!_c!!\\%"
    table = Table("rows", MetaData(), Column("text", String))
    statement = select(table.c.text).where(table.c.text.like(_like("50%_x"), escape=LIKE_ESCAPE))
    assert "ESCAPE '!'" in postgres_sql(statement)
    parse_postgres(postgres_sql(statement))
    assert "ESCAPE '!'" in str(statement.compile(dialect=sqlite_dialect.dialect()))
