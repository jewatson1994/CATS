from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service
from app.dashboard_paging import dashboard_page
from app.execution_summaries import CountOnly


@pytest.mark.parametrize("sort", ["name", "owner", "version", "findings", "overdue", "oldest", "invalid"])
@pytest.mark.parametrize("descending", [False, True])
def test_page_matches_complete_filtered_metrics_and_loads_only_page(sort, descending):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(Service(service_key=f"key-{index:03}", name=f"Straße {index % 7}",
            owner="100%_Owner" if index % 2 else "other", poc="contact",
            lifecycle_status="staged" if index % 11 == 0 else "active") for index in range(113))
        db.commit()
        projected = [SimpleNamespace(**row._mapping) for row in db.execute(
            __import__("sqlalchemy").select(Service.id, Service.name, Service.service_key,
                Service.owner, Service.poc, Service.lifecycle_status).order_by(Service.name, Service.service_key))]
        views = [{"service": service, "archive": service.id % 13 == 0,
            "version": str(service.id % 4), "active": CountOnly(service.id % 8), "policy_findings": [],
            "noncompliant": CountOnly(service.id % 3), "policy_noncompliant": [],
            "oldest_age": service.id % 10, "compliant": service.id % 3 == 0} for service in projected]
        loads = []
        statements = []
        event.listen(db, "loaded_as_persistent", lambda session, obj: loads.append(obj))
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, params, context, many: statements.append(statement))
        rows, filtered, counts, resolved, page, size, pages = dashboard_page(db, views,
            lifecycle="active", query="STRASSE", sort=sort, descending=descending, page=2, page_size=10)
        expected = [view for view in views if not view["archive"] and view["service"].lifecycle_status == "active"]
        keys = {"name": lambda view: (view["service"].name.casefold(), view["service"].service_key.casefold()),
            "owner": lambda view: view["service"].owner.casefold(), "version": lambda view: view["version"],
            "findings": lambda view: len(view["active"]), "overdue": lambda view: len(view["noncompliant"]),
            "oldest": lambda view: view["oldest_age"]}
        expected.sort(key=keys[resolved], reverse=descending)
        assert [view["service"].id for view in filtered] == [view["service"].id for view in expected]
        assert [view["service"].id for view in rows] == [view["service"].id for view in expected[10:20]]
        assert sum(view["compliant"] for view in filtered) == sum(view["compliant"] for view in expected)
        assert len(loads) == 10 and all(isinstance(obj, Service) for obj in loads)
        assert any("LIMIT" in sql and "OFFSET" in sql for sql in statements)
        assert sum(counts.values()) == 113 and page == 2 and size == 10
        literal = dashboard_page(db, views, lifecycle="active", query="100%_Owner", sort="name", descending=False, page=999, page_size=10)
        assert all(view["service"].owner == "100%_Owner" for view in literal[1])
        assert literal[4] == literal[6]
    engine.dispose()


def test_postgresql_search_preserves_casefold_without_sqlite_udf():
    from sqlalchemy.dialects import postgresql
    from app.dashboard_paging import _ordered_id_query
    services = [SimpleNamespace(id=1, name="Straße", service_key="one", owner="", poc="", lifecycle_status="active"),
                SimpleNamespace(id=2, name="other", service_key="two", owner="", poc="", lifecycle_status="active")]
    views = [{"service": service} for service in services]
    class FakeSession:
        statements = []
        def get_bind(self):
            return SimpleNamespace(dialect=postgresql.dialect())
        def connection(self):
            raise AssertionError("PostgreSQL must not register a SQLite UDF")
        def scalars(self, statement):
            self.statements.append(statement)
            return [services[0]] if statement.column_descriptions[0].get("expr") is Service else [1]
    db = FakeSession()
    result = dashboard_page(db, views, lifecycle="active", query="STRASSE", sort="name",
                            descending=False, page=1, page_size=10)
    assert [view["service"].id for view in result[1]] == [1]
    for statement in db.statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        assert "cats_casefold" not in str(compiled) and "lower(" not in str(compiled)
    base, position = _ordered_id_query([1], False)
    compiled = base.order_by(position).offset(0).limit(10).compile(dialect=postgresql.dialect())
    assert "WITH ORDINALITY" in str(compiled) and "LIMIT" in str(compiled) and "OFFSET" in str(compiled)
    assert "JOIN json_array_elements_text(CAST(" in str(compiled)
    assert [1] in compiled.params.values()


def test_summary_startup_upgrade_and_indexes_are_idempotent_for_existing_sqlite():
    import ast
    from pathlib import Path
    from sqlalchemy import inspect, text
    tree = ast.parse((Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8-sig"))
    migration = next(node for node in tree.body if isinstance(node, ast.With)
                     and isinstance(node.items[0].context_expr, ast.Call)
                     and getattr(node.items[0].context_expr.func, "id", None) == "migration_transaction")
    payload_upgrade = next(node for node in migration.body if isinstance(node, ast.If)
                           and "payload_digest" in ast.unparse(node.test))
    indexes = next(node for node in migration.body if isinstance(node, ast.For)
                   and "CREATE INDEX IF NOT EXISTS ix_findings_service_active" in ast.unparse(node))
    module = ast.Module(body=[migration.body[0], payload_upgrade, indexes], type_ignores=[])
    code = compile(ast.fix_missing_locations(module), "startup_summary_upgrade", "exec")
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE executions (id INTEGER PRIMARY KEY, service_id INTEGER, scanned_at TIMESTAMP, raw_payload JSON)"))
        connection.execute(text("INSERT INTO executions (id, raw_payload) VALUES (7, :payload)"), {"payload": '{"evidence":42}'})
        for _ in range(2):
            exec(code, {"Base": Base, "connection": connection, "inspect": inspect, "text": text})
        columns = {column["name"]: column for column in inspect(connection).get_columns("executions")}
        assert columns["payload_digest"]["nullable"]
        assert "execution_summaries" in inspect(connection).get_table_names()
        assert connection.execute(text("SELECT id, raw_payload, payload_digest FROM executions")).one() == (7, '{"evidence":42}', None)
        expected_indexes = [node.value for node in ast.walk(indexes) if isinstance(node, ast.Constant)
                            and isinstance(node.value, str) and node.value.startswith("CREATE INDEX")]
        actual = {row[0] for row in connection.execute(text("SELECT name FROM sqlite_master WHERE type='index'"))}
        assert all(statement.split()[5] in actual for statement in expected_indexes)
    engine.dispose()


def test_postgresql_id_bind_serializes_as_array_not_json_string():
    import json
    from sqlalchemy.dialects import postgresql
    from app.dashboard_paging import _ordered_id_query
    for ids in ([1, 2, 3], []):
        query, _ = _ordered_id_query(ids, False)
        dialect = postgresql.dialect()
        compiled = query.compile(dialect=dialect)
        bind = compiled.binds['param_1']
        encoded = bind.type.bind_processor(dialect)(bind.value)
        assert json.loads(encoded) == ids
        assert isinstance(json.loads(encoded), list)
