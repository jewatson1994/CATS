from datetime import datetime, timezone

from sqlalchemy import create_engine, event, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.attributes import flag_modified

from app.database import Base
from app.models import Execution, ExecutionSummary, Service
from app.execution_summaries import (
    CountOnly, build_summary, install_execution_summary_hooks, load_execution_summaries,
    payload_digest, rebuild_execution_summaries, snapshot_from_summary,
)
from app.security_dashboard import bounded_service_history, scan_snapshot, service_history


def setup_database(hooks=True):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine)
    if hooks:
        install_execution_summary_hooks(sessions.class_)
    db = sessions()
    service = Service(service_key="summary", name="Summary")
    db.add(service)
    db.flush()
    scan = Execution(execution_key="summary-scan", service_id=service.id,
        scanned_at=datetime(2026, 10, 1, tzinfo=timezone.utc), complete=False,
        scan_scope="service", raw_payload={"service": {"version": " 1.0 "},
        "findings": [{"cve": "CVE-1", "severity": "Low"},
                     {"cve": "CVE-1", "severity": "Critical"},
                     {"cve": "CVE-2", "severity": "Other"}],
        "skipped_images": ["repo/private :: access denied"]})
    db.add(scan)
    db.commit()
    return engine, db, scan


def test_summary_matches_snapshot_and_retains_only_required_state():
    engine, db, scan = setup_database()
    data = load_execution_summaries(db, [scan.id])[scan.id]
    assert snapshot_from_summary(data) == scan_snapshot(scan)
    assert data["skipped_image_count"] == 1
    assert data["missing_evidence_count"] >= 1
    assert "repo/private" not in str(data)
    assert db.get(ExecutionSummary, scan.id).payload_digest == payload_digest(scan.raw_payload)
    db.close()
    engine.dispose()


def test_valid_summary_does_not_select_payload_and_results_are_isolated():
    engine, db, scan = setup_database()
    identifier = scan.id
    statements = []
    event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, params, context, many:
                 statements.append(statement))
    db.expire_all()
    data = load_execution_summaries(db, [identifier])[identifier]
    assert not any("raw_payload" in statement for statement in statements)
    data["counts"]["Critical"] = 999
    assert load_execution_summaries(db, [identifier])[identifier]["counts"]["Critical"] == 1
    db.close()
    engine.dispose()


def test_payload_and_complete_changes_refresh_and_rollback_preserves_summary():
    engine, db, scan = setup_database()
    identifier = scan.id
    scan.raw_payload = {"service": {"version": "2.0"}, "findings": []}
    scan.complete = True
    db.commit()
    data = load_execution_summaries(db, [identifier])[identifier]
    assert data["version"] == "2.0" and data["total"] == 0
    assert data["missing_evidence_count"] == 0
    scan.raw_payload = {"service": {"version": "bad"}}
    db.flush()
    db.rollback()
    assert load_execution_summaries(db, [identifier])[identifier]["version"] == "2.0"
    scan.complete = False
    db.commit()
    assert db.get(ExecutionSummary, identifier).source_complete is False
    db.close()
    engine.dispose()


def test_legacy_fallback_and_version_invalidation_and_bounded_rebuild():
    engine, db, scan = setup_database(hooks=False)
    identifier = scan.id
    assert load_execution_summaries(db, [identifier])[identifier]["total"] == 2
    assert db.get(ExecutionSummary, identifier) is None
    assert rebuild_execution_summaries(db, limit=1) == (identifier, 1)
    db.commit()
    summary = db.get(ExecutionSummary, identifier)
    summary.summary_version = -1
    summary.data = {"wrong": True}
    db.commit()
    assert load_execution_summaries(db, [identifier])[identifier]["total"] == 2
    db.close()
    engine.dispose()


def test_digest_canonical_and_summary_version_normalization():
    assert payload_digest({"a": 1, "b": 2}) == payload_digest({"b": 2, "a": 1})
    assert payload_digest({"a": 1}) != payload_digest({"a": 2})
    assert build_summary({"service": {"version": "unknown"}}, True)["version"] == "Unversioned"


def test_flagged_in_place_mutation_and_bulk_invalidation():
    engine, db, scan = setup_database()
    identifier = scan.id
    scan.raw_payload["service"]["version"] = "changed"
    flag_modified(scan, "raw_payload")
    db.commit()
    assert load_execution_summaries(db, [identifier])[identifier]["version"] == "changed"
    db.execute(update(Execution).where(Execution.id == identifier).values(
        raw_payload={"service": {"version": "bulk"}}, payload_digest=None))
    db.commit()
    assert load_execution_summaries(db, [identifier])[identifier]["version"] == "bulk"
    db.close()
    engine.dispose()


def test_retained_history_exact_equivalence_without_execution_materialization():
    import re
    engine, db, scan = setup_database()
    service = db.get(Service, scan.service_id)
    for number, version in enumerate(("2", "unknown", "2", "3"), 1):
        db.add(Execution(execution_key=f"summary-{number}", service_id=service.id,
            scanned_at=datetime(2026, 10, number + 1, tzinfo=timezone.utc),
            complete=True, scan_scope="image" if version == "3" else "service",
            raw_payload={"service": {"version": version}, "findings": []}))
    db.commit()
    expected = service_history(service)
    db.expire_all()
    statements = []
    event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, params, context, many:
                 statements.append(statement))
    actual = bounded_service_history(db, service)
    assert {key: actual[key] for key in expected} == expected
    # Only a scalar legacy version fallback expression may mention raw_payload.
    assert not any(re.search(r"(?<!\()executions\.raw_payload(?:,| \n| AS raw_payload)", statement)
                   for statement in statements)
    db.close()
    engine.dispose()


def test_constant_memory_counts_match_list_consumers():
    import sys
    assert CountOnly(3) == [None] * 3
    assert list(CountOnly(3)) == [None] * 3
    assert CountOnly(3)[-1] is None
    assert CountOnly(10)[1:8:2] == [None] * 4
    assert not CountOnly(0)
    assert sys.getsizeof(CountOnly(10**8)) == sys.getsizeof(CountOnly(1))


def test_overview_retained_summary_matches_legacy_evidence_and_frontend_counts():
    # Execute the isolated function without main's import-time production DB migrations.
    import ast
    from pathlib import Path
    from types import SimpleNamespace
    import sqlalchemy as sa
    from app import models
    from app.frontend import page_data
    from app.overview import normalize_overview
    source = ast.parse((Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8"))
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "service_overview_rows_aggregated")
    namespace = {"__package__": "app", **vars(models),
                 **{key: getattr(sa, key) for key in ("select", "and_", "func", "case")},
                 "_risk_finding_expressions": lambda *args: (sa.true(), sa.false(), False),
                 "_hardening_overdue_expression": lambda *args: sa.false()}
    isolated = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
                                function], type_ignores=[])
    exec(compile(ast.fix_missing_locations(isolated), "isolated_overview", "exec"), namespace)
    engine, db, scan = setup_database()
    service = db.get(Service, scan.service_id)
    raw = scan.raw_payload
    skipped = raw.get("skipped_images", []) or []
    charts = raw.get("skipped_charts", []) or []
    missing = normalize_overview(raw.get("service_overview") or {}, skipped_images=skipped,
                                 skipped_charts=charts, incomplete=not scan.complete)["missing_evidence"]
    expected_evidence = "Incomplete" if not scan.complete or missing else "Complete"
    if skipped and expected_evidence == "Incomplete":
        expected_evidence = f"Incomplete · {len(skipped)} skipped"
    rows, _ = namespace["service_overview_rows_aggregated"](db, None,
        datetime.now(timezone.utc), {}, services=[service],
        configurations={service.id: {"incomplete_noncompliant": "true"}})
    assert rows[0]["evidence_state"] == expected_evidence
    assert rows[0]["version"] == raw["service"]["version"]
    assert rows[0]["compliant"] is False
    request = SimpleNamespace(query_params={}, url=SimpleNamespace(path="/", query=""))
    context = {"views": rows}
    projected = page_data(request, "dashboard.html", context)
    legacy_rows = [{**rows[0], **{key: list(rows[0][key]) for key in
        ("active", "noncompliant", "policy_noncompliant", "excepted", "policy_excepted", "overdue")}}]
    assert projected == page_data(request, "dashboard.html", {"views": legacy_rows})
    db.close()
    engine.dispose()



def test_unflagged_nested_payload_mutations_refresh_summary_transactionally():
    engine, db, scan = setup_database()
    identifier = scan.id
    scan.raw_payload["service"]["version"] = "nested"
    scan.raw_payload["findings"][0]["severity"] = "High"
    scan.raw_payload["findings"].append({"cve": "CVE-3", "severity": "Low"})
    db.commit()
    data = load_execution_summaries(db, [identifier])[identifier]
    assert data["version"] == "nested" and data["total"] == 3
    scan.raw_payload["findings"][:] = [{"cve": "CVE-4", "severity": "Critical"}]
    scan.raw_payload["findings"][0].update(severity="Medium")
    db.flush()
    assert load_execution_summaries(db, [identifier])[identifier]["counts"]["Medium"] == 1
    db.rollback()
    assert load_execution_summaries(db, [identifier])[identifier]["total"] == 3
    db.close()
    engine.dispose()


def test_recursive_json_supported_mutators_and_detached_copies():
    from copy import deepcopy
    import pickle
    from app.recursive_json import JSONDict
    payload = JSONDict({"items": [{"name": "a"}]})
    payload["items"].insert(0, {"name": "b"})
    payload["items"].extend([{"name": "c"}])
    payload["items"] += [{"name": "d"}]
    payload["items"] *= 2
    payload["items"].reverse()
    payload["items"].sort(key=lambda item: item["name"])
    payload["items"].remove({"name": "a"})
    payload["items"].pop()
    payload.setdefault("other", {})["nested"] = []
    payload["other"]["nested"].append({"x": 1})
    copied = deepcopy(payload)
    copied["other"]["nested"][0]["x"] = 2
    assert payload["other"]["nested"][0]["x"] == 1
    assert pickle.loads(pickle.dumps(payload)) == payload
    detached = payload.pop("other")
    detached["nested"][0]["x"] = 3
    payload["items"].clear()
    assert payload == {"items": []}


def test_bulk_payload_assignment_invalidates_digest_without_manual_writer_flag():
    engine, db, scan = setup_database()
    identifier = scan.id
    db.execute(update(Execution).where(Execution.id == identifier).values(
        raw_payload={"service": {"version": "automatic-bulk"}, "findings": []}))
    db.commit()
    assert load_execution_summaries(db, [identifier])[identifier]["version"] == "automatic-bulk"
    db.close()
    engine.dispose()


def test_bulk_parameter_payload_assignment_invalidates_digest():
    engine, db, scan = setup_database()
    identifier = scan.id
    db.execute(update(Execution), [{"id": identifier,
        "raw_payload": {"service": {"version": "bulk-parameters"}},
        "payload_digest": "wrong-supplied-digest"}])
    db.commit()
    assert db.get(Execution, identifier).payload_digest is None
    assert load_execution_summaries(db, [identifier])[identifier]["version"] == "bulk-parameters"
    db.close()
    engine.dispose()


def test_bulk_complete_invalidates_summary_and_rollback_restores_metadata():
    engine, db, scan = setup_database()
    identifier = scan.id
    original_digest = scan.payload_digest
    db.execute(update(Execution).where(Execution.id == identifier).values(complete=True))
    db.flush()
    assert db.get(Execution, identifier).payload_digest is None
    assert load_execution_summaries(db, [identifier])[identifier]["complete"] is True
    db.rollback()
    assert db.get(Execution, identifier).payload_digest == original_digest
    assert load_execution_summaries(db, [identifier])[identifier]["complete"] is False
    db.close()
    engine.dispose()
