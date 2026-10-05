"""Dependencies route cold/warm measurement on the shared 100k fixture."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import tracemalloc
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("backend_benchmark", ROOT / "scripts/benchmark-backend.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def run():
    from sqlalchemy import create_engine, event, select
    from sqlalchemy.orm import Session, defer, sessionmaker
    from sqlalchemy.pool import QueuePool
    from starlette.requests import Request
    with tempfile.TemporaryDirectory(prefix="cats-dependencies-bench-") as directory:
        os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(directory) / "unused.db")
        from app import main
        from app.database import Base, engine as default_engine
        from app.models import Execution, DependencyProjection
        from app.dependency_queries import build_projection
        from app.execution_summaries import refresh_execution_summary
        database = Path(directory) / "fixture.sqlite"
        engine = create_engine("sqlite://", creator=lambda: sqlite3.connect(database, factory=benchmark.Connection), poolclass=QueuePool)
        benchmark.fixture(engine, 100000)
        main.SessionLocal = sessionmaker(engine)
        main.utcnow = lambda: benchmark.NOW
        with Session(engine) as db:
            execution = db.get(Execution, 3)
            execution.raw_payload = {"service": {"version": "1.3"}, "findings": [],
                "sbom_components": [{"name": f"package-{index}", "version": "1.0", "ecosystem": "npm",
                    "image": f"images/bench-{index % 20}:1.0"} for index in range(100000)]}
            refresh_execution_summary(db, execution)
            db.commit()
        auth = SimpleNamespace(user=SimpleNamespace(id=1, username="benchmark", display_name="Benchmark", role_assignments=[]),
            csrf_token="benchmark", has=lambda *args, **kwargs: True, accessible_service_ids=lambda permission: None)
        results = []
        for phase in ("cold", "background-build", "warm", "warm-second-page"):
            metrics = {"phase": phase, "fixture_findings": 100000, "fixture_components": 100000,
                "query_count": 0, "dbapi_rows_fetched": 0, "orm_objects_loaded": 0, "evidence_queries": 0, "evidence_sql": []}
            def before(conn, cursor, statement, parameters, context, many):
                metrics["query_count"] += 1
                if "finding_observations.evidence" in statement or "executions.raw_payload" in statement:
                    metrics["evidence_queries"] += 1
                    metrics["evidence_sql"].append(statement)
            def loaded(item, context):
                metrics["orm_objects_loaded"] += 1
            event.listen(engine, "before_cursor_execute", before)
            event.listen(Base, "load", loaded, propagate=True)
            benchmark.ACTIVE = metrics
            request = Request({"type": "http", "method": "GET", "path": "/services/bench-1", "query_string": b"dependencies=true",
                "headers": [(b"accept", b"application/vnd.cats.page+json")], "scheme": "http", "server": ("benchmark", 80)})
            tracemalloc.start()
            started = time.perf_counter()
            with Session(engine) as db:
                if phase == "background-build":
                    projection = db.get(DependencyProjection, 3)
                    token = projection.build_token
                    db.rollback()
                    metrics["build_succeeded"] = build_projection(engine, 3, token, main.risk_metadata)
                    response = SimpleNamespace(body=b"{}", status_code=200)
                else:
                    response = main.service_detail("bench-1", request, dependencies=True, severity=[],
                        page=2 if phase == "warm-second-page" else 1, page_size=50, db=db, auth=auth)
                metrics["duration_ms"] = (time.perf_counter() - started) * 1000
                metrics["response_bytes"] = len(response.body)
                metrics["status_code"] = response.status_code
                data = json.loads(response.body).get("data", {})
                metrics["dependency_page_rows"] = len(data.get("dependency_rows", []))
                metrics["dependency_total"] = data.get("dependency_total")
                metrics["projection_status"] = data.get("dependency_projection_status")
            _, metrics["python_peak_traced_bytes"] = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            benchmark.ACTIVE = None
            event.remove(engine, "before_cursor_execute", before)
            event.remove(Base, "load", loaded)
            results.append(metrics)
            print(json.dumps(metrics), flush=True)
        output = ROOT / "docs/backend-dependencies-second-pass.json"
        output.write_text(json.dumps({"method": "Actual dependencies route body including DTO/JSON serialization, SQLite, 100k shared fixture findings and 100k components; tracemalloc enabled; no middleware/network/authentication. Cold request and background rebuild measured separately from fresh-session warm requests.", "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [ROOT / "portal/app/main.py", ROOT / "portal/app/service_tab_queries.py", ROOT / "portal/app/dependency_queries.py", ROOT / "portal/app/execution_summaries.py", ROOT / "portal/app/recursive_json.py", ROOT / "portal/app/policy_data.py"]}, "results": results}, indent=2) + "\n")
        engine.dispose()
        default_engine.dispose()


if __name__ == "__main__":
    run()
