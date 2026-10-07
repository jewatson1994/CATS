from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.dialects import postgresql
import pytest

from portal.app.database import Base
from portal.app.findings_sql import get_raw_finding_page
from portal.app.models import Finding, FindingObservation, ExceptionRecord, PolicyFinding, Service


NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def test_actual_raw_page_statements_compile_for_sqlite_and_postgresql():
    from sqlalchemy.dialects import sqlite
    with database() as db:
        finding(db, 1, active=True)
        db.commit()
        statements = []
        def capture(_connection, _cursor, _sql, _parameters, context, _many):
            if context.compiled is not None:
                statements.append(context.compiled.statement)
        event.listen(db.get_bind(), "before_cursor_execute", capture)
        get_raw_finding_page(db, 1, {}, NOW, page=1)
        event.remove(db.get_bind(), "before_cursor_execute", capture)
        assert len(statements) >= 3
        for dialect in (sqlite.dialect(), postgresql.dialect()):
            sql = [str(statement.compile(dialect=dialect)) for statement in statements]
            # One statement pages the candidates and counts them (window total).
            assert "UNION ALL" in sql[0]
            assert "EXISTS" in sql[0]
            assert "revoked_at IS NULL" in sql[0]
            assert "service_id" in sql[0]
            assert "ORDER BY" in sql[0] and "LIMIT" in sql[0] and "OFFSET" in sql[0] and "OVER ()" in sql[0]
            assert "finding_observations" not in " ".join(sql)


def database():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = Session(engine)
    db.add(Service(id=1, service_key="a", name="A"))
    db.add(Service(id=2, service_key="b", name="B"))
    db.flush()
    return db


def finding(db, number, **kwargs):
    item = Finding(service_id=kwargs.pop("service_id", 1), cve=f"CVE-{number:05}",
                   severity="High", first_seen=NOW, last_seen=NOW, episode_started=NOW, **kwargs)
    db.add(item)
    db.flush()
    return item


def test_count_pagination_and_hydration_are_bounded():
    with database() as db:
        for i in range(115):
            finding(db, i, active=True)
        finding(db, 999, service_id=2, active=True)
        db.add(PolicyFinding(service_id=1, identity_key="p", finding="POLICY", severity="Low",
                             first_seen=NOW, last_seen=NOW, episode_started=NOW, active=True))
        db.commit()
        db.expunge_all()
        statements = []
        event.listen(db.get_bind(), "before_cursor_execute", lambda *args: statements.append(args[2]))
        result = get_raw_finding_page(db, 1, {}, NOW, page=999)
        assert (result["total_items"], result["total_pages"], result["page"]) == (116, 3, 3)
        assert len(result["findings"]) == 15
        assert len(result["policy_findings"]) == 1
        # Past the end: empty page, count, clamped page, then hydration.
        assert len(statements) == 7
        assert sum(isinstance(item, Finding) for item in db.identity_map.values()) == 15
        statements.clear()
        db.expunge_all()
        in_range = get_raw_finding_page(db, 1, {}, NOW, page=2)
        assert (in_range["total_items"], in_range["total_pages"], in_range["page"]) == (116, 3, 2)
        assert len(in_range["findings"]) == 50 and not in_range["policy_findings"]
        assert len(statements) == 3  # page with window total, findings, their current exceptions
        assert not any("FROM finding_observations" in sql for sql in statements)


def test_filters_lifecycle_and_literal_search():
    with database() as db:
        item = finding(db, 1, active=True)
        hidden = finding(db, 2, active=True)
        resolved = finding(db, 3, active=False)
        db.add(ExceptionRecord(finding_id=hidden.id, justification="j", approved_by="a",
                               starts_at=NOW-timedelta(days=1), expires_at=NOW+timedelta(days=1)))
        for i in range(21):
            db.add(FindingObservation(finding_id=item.id, execution_id=1,
                image="historic%image" if i == 0 else "recent", package="test-package", evidence={}))
        db.commit()
        view = {"active": [], "excepted": [SimpleNamespace(id=hidden.id)],
                "resolved": [SimpleNamespace(id=resolved.id)]}
        assert get_raw_finding_page(db, 1, view, NOW)["total_items"] == 1
        assert get_raw_finding_page(db, 1, view, NOW, raw_selector=False)["total_items"] == 0
        assert get_raw_finding_page(db, 1, view, NOW, state="exceptions")["total_items"] == 1
        assert get_raw_finding_page(db, 1, view, NOW, state="resolved")["total_items"] == 1
        assert get_raw_finding_page(db, 1, view, NOW, query="test-package", severities=["HIGH"])["total_items"] == 1
        assert get_raw_finding_page(db, 1, view, NOW, query="historic%image")["total_items"] == 0
        assert get_raw_finding_page(db, 1, view, NOW, resource="historic%image")["total_items"] == 0
        assert get_raw_finding_page(db, 1, view, NOW, resource="test-package")["total_items"] == 1
        assert get_raw_finding_page(db, 1, view, NOW, resource="missing%image")["total_items"] == 0
        assert get_raw_finding_page(db, 1, view, NOW, finding_type="evidence")["total_items"] == 0


def test_postgresql_search_statements_compile():
    statements = []

    class CompileSession:
        def get_bind(self):
            return SimpleNamespace(dialect=postgresql.dialect())

        def scalar(self, statement):
            statements.append(str(statement.compile(dialect=postgresql.dialect())))
            return 0

        def execute(self, statement):
            statements.append(str(statement.compile(dialect=postgresql.dialect())))
            class EmptyRows:
                def __iter__(self):
                    return iter(())

                def all(self):
                    return []
            return EmptyRows()

    assert get_raw_finding_page(CompileSession(), 1, {}, NOW, query="package")["total_items"] == 0
    assert len(statements) == 2
    assert "string_agg" in statements[0] and "ORDER BY finding_observations.id DESC" in statements[0]
    assert "finding_observations.finding_id = findings.id" in statements[0]


@pytest.mark.parametrize("size", [50, 100, 250])
def test_all_page_sizes_empty_and_clamp(size):
    with database() as db:
        empty = get_raw_finding_page(db, 1, {}, NOW, page=999, page_size=size)
        assert (empty["total_items"], empty["total_pages"], empty["page"]) == (0, 1, 1)
        for number in range(251):
            finding(db, number, active=True)
        db.commit()
        first = get_raw_finding_page(db, 1, {}, NOW, page=-10, page_size=size)
        assert first["page"] == 1 and len(first["findings"]) == size
        last = get_raw_finding_page(db, 1, {}, NOW, page=999, page_size=size)
        assert last["page"] == (251 + size - 1) // size
        assert len(last["findings"]) == 251 - (last["page"] - 1) * size


def test_configuration_stable_ties_multiple_severities_and_lifecycle():
    with database() as db:
        finding(db, 1, active=True)
        policies = []
        for number in range(55):
            item = PolicyFinding(service_id=1, identity_key=str(number), finding="SAME", severity="Low" if number % 2 else "HIGH",
                                 first_seen=NOW, last_seen=NOW, episode_started=NOW, active=number < 53)
            db.add(item)
            policies.append(item)
        db.commit()
        result = get_raw_finding_page(db, 1, {}, NOW, finding_type="configuration", severities=["high", "LOW"])
        assert result["total_items"] == 53 and not result["findings"]
        assert [item.id for item in result["policy_findings"]] == [item.id for item in policies[:50]]
        second = get_raw_finding_page(db, 1, {}, NOW, finding_type="configuration", page=2)
        assert [item.id for item in second["policy_findings"]] == [item.id for item in policies[50:53]]
        view = {"policy_excepted": [SimpleNamespace(id=policies[0].id)],
                "policy_resolved": [SimpleNamespace(id=item.id) for item in policies[53:]]}
        assert get_raw_finding_page(db, 1, view, NOW, state="exceptions", finding_type="configuration")["total_items"] == 1
        assert get_raw_finding_page(db, 1, view, NOW, state="resolved", finding_type="configuration")["total_items"] == 2


def test_unicode_casefold_and_field_boundaries():
    with database() as db:
        item = finding(db, 1, active=True)
        db.add(FindingObservation(finding_id=item.id, execution_id=1, image="Straße", package="ΜΆΙΟΣ", evidence={}))
        db.commit()
        assert get_raw_finding_page(db, 1, {}, NOW, query="STRASSE")["total_items"] == 1
        assert get_raw_finding_page(db, 1, {}, NOW, query="Straße ΜΆΙΟΣ")["total_items"] == 1
        assert get_raw_finding_page(db, 1, {}, NOW, resource="μάιοσ")["total_items"] == 1


def test_service_and_observation_lookup_use_indexes():
    with database() as db:
        finding(db, 1, active=True)
        db.commit()
        captured = []
        event.listen(db.get_bind(), "before_cursor_execute", lambda conn, cursor, sql, params, *rest: captured.append((sql, params)))
        get_raw_finding_page(db, 1, {}, NOW, query="image")
        sql, params = next((sql, params) for sql, params in captured if "count(*)" in sql)
        plan = db.connection().exec_driver_sql("EXPLAIN QUERY PLAN " + sql, params).all()
        details = " ".join(row[3] for row in plan)
        assert "USING INDEX" in details or "USING COVERING INDEX" in details
        assert "finding_observations" in details and "finding_id" in details
