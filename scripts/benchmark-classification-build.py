"""Measure classification processing: full and targeted rebuild time, the
whole-portfolio preparation, storage growth and process memory.

    python scripts/benchmark-classification-build.py URL --service perf-9999 --service perf-0001 \\
        [--targeted 1 --targeted 100] [--all] --output build.json

* Full rebuild: ``refresh(full=True)`` of each named service, three times
  (median reported), in one transaction each, exactly as the background
  worker runs it.
* Targeted: a change-log entry for N of the service's findings, then one
  refresh (the work an exception or finding edit triggers).
* ``--all``: drops every service's state and runs the startup preparation
  (``warm``) over the whole database, reporting total time.
* Storage: PostgreSQL table + index sizes of the classification tables, and
  of ``findings``/``finding_observations`` for reference.
* Memory: this process's peak resident set size (``ru_maxrss``).

Only for disposable benchmark databases.
"""
import argparse
import json
import os
import resource
import statistics
import sys
import time
from pathlib import Path


def sizes(connection):
    from sqlalchemy import text
    tables = ("finding_classifications", "finding_classification_state", "finding_classification_changes",
              "findings", "finding_observations")
    result = {}
    for table in tables:
        row = connection.execute(text("select pg_relation_size(:t), pg_indexes_size(:t), pg_total_relation_size(:t), "
                                      "(select count(*) from " + table + ")"), {"t": table}).one()
        result[table] = {"table_bytes": row[0], "index_bytes": row[1], "total_bytes": row[2], "rows": row[3]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("database_url")
    parser.add_argument("--service", action="append", default=[])
    parser.add_argument("--targeted", type=int, action="append", default=[])
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.environ.update(DATABASE_URL=args.database_url, PIPELINE_API_TOKEN="bench-token",
                      CATS_BOOTSTRAP_USERNAME="admin", CATS_BOOTSTRAP_PASSWORD="bench-password-long")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
    from sqlalchemy import delete, func, insert, select
    from app import finding_classification as fc
    from app.database import background_engine, SessionLocal
    from app.models import Finding, FindingClassificationChange, FindingClassificationState, Service
    report = {"services": {}, "rss_before_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    for key in args.service:
        with SessionLocal() as db:
            service_id = db.scalar(select(Service.id).where(Service.service_key == key))
            findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.service_id == service_id))
        runs = []
        for _ in range(args.repeat):
            started = time.perf_counter()
            fc.refresh(background_engine, service_id, full=True)
            runs.append(round((time.perf_counter() - started) * 1000, 1))
        entry = {"findings": findings, "full_ms": runs, "full_median_ms": statistics.median(runs), "targeted": {}}
        for count in args.targeted:
            with SessionLocal() as db:
                ids = db.scalars(select(Finding.id).where(Finding.service_id == service_id).order_by(Finding.id).limit(count)).all()
                db.execute(insert(FindingClassificationChange.__table__), [{"service_id": service_id, "finding_id": i} for i in ids])
                db.commit()
            started = time.perf_counter()
            summary = fc.refresh(background_engine, service_id)
            entry["targeted"][str(count)] = {"ms": round((time.perf_counter() - started) * 1000, 1), "mode": summary["mode"]}
        report["services"][key] = entry
        print(key, json.dumps(entry), flush=True)
    if args.all:
        with SessionLocal() as db:
            db.execute(delete(FindingClassificationState))
            db.commit()
        started = time.perf_counter()
        prepared = fc.warm(background_engine)
        report["warm_all"] = {"services": prepared, "ms": round((time.perf_counter() - started) * 1000, 1)}
        print("warm_all", json.dumps(report["warm_all"]), flush=True)
    with background_engine.connect() as connection:
        report["storage"] = sizes(connection)
    report["rss_peak_kb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps(report["storage"], indent=1))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
