"""Fresh history route and focused export extraction measurements at 100k."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bench", ROOT / "scripts/benchmark-backend.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

def run():
    from sqlalchemy import create_engine, insert
    from sqlalchemy.orm import sessionmaker
    from starlette.responses import JSONResponse
    with tempfile.TemporaryDirectory(prefix="cats-history-export-") as directory:
        os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(directory) / "unused.db")
        from app import main
        from app.models import Execution
        from app.database import engine as default_engine
        database = Path(directory) / "fixture.sqlite"
        engine = create_engine("sqlite://", creator=lambda: sqlite3.connect(database, factory=bench.Connection))
        bench.fixture(engine, 100000)
        main.SessionLocal = sessionmaker(engine)
        main.utcnow = lambda: bench.NOW
        # Extraction consumes each projected row; XLSX cells/ZIP serialization excluded.
        main._focused_export_book = lambda headers, rows: sum(1 for _ in rows)
        main.workbook_response = lambda count, filename: JSONResponse({"extracted_rows": count})
        export = bench.measure(engine, main, "/services/bench-1/exports/findings.xlsx", 100000)
        # One selected version with 1000 lightweight retained scan records.
        with engine.begin() as connection:
            for start in range(0, 1000, 1000):
                connection.execute(insert(Execution), [dict(id=1000+i, execution_key=f"history-{i}",
                    service_id=1, scanned_at=bench.NOW, complete=True, scan_scope="service",
                    raw_payload={"service": {"version": "history"}, "findings": []})
                    for i in range(start, start+1000)])
        history = bench.measure(engine, main, "/services/bench-1/history", 100000)
        results = [history, export]
        for result in results:
            print(json.dumps(result), flush=True)
        (ROOT / "docs/backend-history-export-final.json").write_text(json.dumps({
            "method": "SQLite shared 100k findings fixture, history additionally 1000 retained scans. Actual history route plus DTO serialization; focused export database extraction with row consumption, workbook generation excluded. cProfile/tracemalloc instrumentation enabled.",
            "results": results}, indent=2) + "\n")
        engine.dispose()
        default_engine.dispose()

if __name__ == "__main__":
    run()
