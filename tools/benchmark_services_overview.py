"""Benchmark the Services overview with production-shaped evidence volumes.

Examples:
    python tools/benchmark_services_overview.py --dataset 20x1000
    python tools/benchmark_services_overview.py --all

The benchmark uses the configured DATABASE_URL when supplied; otherwise it
creates a temporary SQLite database. Set DATABASE_URL to PostgreSQL for a
production-like run. The report distinguishes the previous detailed loader
from the aggregate loader now used by the dashboard.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_dataset(value: str) -> tuple[int, int]:
    try:
        services, findings = value.lower().split("x", 1)
        return int(services), int(findings)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("dataset must look like 20x1000") from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=parse_dataset, action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--db-url", default=os.getenv("DATABASE_URL"))
    args = parser.parse_args()
    datasets = args.dataset or []
    if args.all or not datasets:
        datasets = [(20, 1000), (20, 5000), (100, 1000)]

    if args.db_url:
        db_url = args.db_url
    else:
        db_url = f"sqlite:///{Path(tempfile.gettempdir()) / 'cats-services-overview-benchmark.db'}"
    os.environ.update({
        "DATABASE_URL": db_url,
        "CATS_BOOTSTRAP_USERNAME": "admin",
        "CATS_BOOTSTRAP_PASSWORD": "benchmark-password-long",
        "SESSION_COOKIE_SECURE": "false",
        "PIPELINE_API_TOKEN": "benchmark-token",
    })
    repository_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repository_root / "portal"))

    from fastapi.testclient import TestClient
    from sqlalchemy import event, func, insert, select, text
    from starlette.templating import _TemplateResponse

    import app.main as main_module
    from app.auth import seed_auth
    from app.database import Base, SessionLocal, engine
    from app.main import app
    from app.models import (
        ExceptionRecord,
        Execution,
        Finding,
        FindingObservation,
        Group,
        PoamEntry,
        PolicyExceptionRecord,
        PolicyFinding,
        Service,
        ServiceArchiveEvent,
        ServiceGroup,
        ServiceImage,
    )

    timing_records: list[dict] = []
    class _TimingHandler(logging.Handler):
        def emit(self, record):
            timing_records.append(getattr(record, "timings_ms", {}))
    timing_handler = _TimingHandler()
    main_module.snapshot_logger.setLevel(logging.DEBUG)
    main_module.snapshot_logger.addHandler(timing_handler)

    def ensure_benchmark_indexes() -> None:
        statements = (
            "CREATE INDEX IF NOT EXISTS ix_findings_service_active ON findings (service_id, active)",
            "CREATE INDEX IF NOT EXISTS ix_policy_findings_service_active ON policy_findings (service_id, active)",
            "CREATE INDEX IF NOT EXISTS ix_executions_service_scanned ON executions (service_id, scanned_at)",
            "CREATE INDEX IF NOT EXISTS ix_poam_service_status_due ON poam_entries (service_id, status, due_date)",
            "CREATE INDEX IF NOT EXISTS ix_finding_observations_finding_id_id ON finding_observations (finding_id, id)",
            "CREATE INDEX IF NOT EXISTS ix_exceptions_finding_active ON exceptions (finding_id, revoked_at, starts_at, expires_at)",
            "CREATE INDEX IF NOT EXISTS ix_policy_exceptions_finding_active ON policy_exceptions (policy_finding_id, revoked_at, starts_at, expires_at)",
        )
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

    def populate(service_count: int, findings_per_service: int) -> dict[str, int]:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        seed_auth()
        ensure_benchmark_indexes()
        now = datetime.now(timezone.utc)
        vuln_per_service = int(findings_per_service * 0.8)
        policy_per_service = findings_per_service - vuln_per_service
        services = []
        groups = [{"id": 1, "name": "Benchmark Operations", "description": "Synthetic production-shaped group"}]
        service_rows = []
        group_rows = []
        image_rows = []
        execution_rows = []
        finding_rows = []
        observation_rows = []
        exception_rows = []
        policy_rows = []
        policy_exception_rows = []
        poam_rows = []
        archive_rows = []
        finding_id = observation_id = policy_id = exception_id = policy_exception_id = poam_id = image_id = execution_id = 1
        for service_number in range(1, service_count + 1):
            service_id = service_number
            service_rows.append({
                "id": service_id, "service_key": f"benchmark-service-{service_number:03d}",
                "name": f"Benchmark Service {service_number:03d}", "owner": f"owner-{service_number:03d}",
                "poc": f"poc-{service_number:03d}@example.invalid", "manual_version": None,
            })
            group_rows.append({"service_id": service_id, "group_id": 1})
            for image_number in range(1, 13):
                image_rows.append({
                    "id": image_id, "service_id": service_id,
                    "image_reference": f"registry.example.invalid/team-{service_number}/app-{image_number}:2.4",
                    "image_digest": f"sha256:{service_number:04d}{image_number:02d}".ljust(71, "0"),
                    "lifecycle_status": "active", "replacement_of_id": None,
                })
                image_id += 1
            for history in range(6):
                execution_rows.append({
                    "id": execution_id, "execution_key": f"benchmark-{service_id}-{history}",
                    "service_id": service_id, "scanned_at": now - timedelta(days=(5 - history) * 14),
                    "complete": True, "scan_scope": "service", "scope_image": None,
                    "raw_payload": {
                        "service": {"version": f"2.{history}"}, "skipped_images": [], "skipped_charts": [],
                        "service_overview": {"missing_evidence": [
                            {"type": "Image", "item": f"registry.example.invalid/team-{service_number}/unreachable-{item}",
                             "reason": "Repository unavailable", "source_file": "charts/app/values.yaml"}
                            for item in range(3)
                        ] if history == 5 else []},
                    },
                })
                execution_id += 1
            latest_execution_id = execution_id - 1
            for local in range(vuln_per_service):
                active = local % 5 != 0
                severity = ("Critical", "High", "Medium", "Low")[local % 4]
                episode = now - timedelta(days=(local % 180) + (90 if local % 7 == 0 else 0))
                finding_rows.append({
                    "id": finding_id, "service_id": service_id, "cve": f"CVE-2026-{service_id:03d}-{local:05d}",
                    "severity": severity, "first_seen": episode, "episode_started": episode,
                    "last_seen": now - timedelta(days=local % 14), "active": active,
                    "resolved_at": None if active else now - timedelta(days=local % 30), "recurrence_count": local % 3,
                })
                observation_rows.append({
                    "id": observation_id, "finding_id": finding_id, "execution_id": latest_execution_id,
                    "image": f"registry.example.invalid/team-{service_number}/app-{(local % 12) + 1}:2.4",
                    "image_digest": None, "package": ("openssl", "curl", "libxml2")[local % 3],
                    "installed_version": f"{local % 4 + 1}.0", "fixed_version": f"{local % 4 + 2}.0",
                    "evidence": {"kev": local % 17 == 0, "epss": round((local % 100) / 100, 2)},
                })
                if active and local % 19 == 0:
                    exception_rows.append({
                        "id": exception_id, "finding_id": finding_id, "justification": "Benchmark exception",
                        "approved_by": "benchmark", "starts_at": now - timedelta(days=2),
                        "expires_at": now + timedelta(days=30), "revoked_at": None,
                    })
                    exception_id += 1
                finding_id += 1
                observation_id += 1
            for local in range(policy_per_service):
                active = local % 4 != 0
                episode = now - timedelta(days=(local % 160) + (80 if local % 9 == 0 else 0))
                policy_rows.append({
                    "id": policy_id, "service_id": service_id, "identity_key": f"benchmark-policy-{service_id}-{local}",
                    "finding": f"KSV{100 + (local % 30):03d}", "severity": ("Critical", "High", "Medium")[local % 3],
                    "scanner": "BenchmarkScanner", "framework": "CIS", "target": f"Deployment/app-{local % 12}",
                    "title": "Configuration finding", "description": "Synthetic configuration evidence",
                    "remediation": "Apply the approved baseline", "fingerprint": f"fp-{service_id}-{local}",
                    "first_seen": episode, "episode_started": episode, "last_seen": now,
                    "active": active, "resolved_at": None if active else now - timedelta(days=10), "recurrence_count": 0,
                })
                if active and local % 23 == 0:
                    policy_exception_rows.append({
                        "id": policy_exception_id, "policy_finding_id": policy_id,
                        "justification": "Benchmark policy exception", "approved_by": "benchmark",
                        "starts_at": now - timedelta(days=2), "expires_at": now + timedelta(days=30), "revoked_at": None,
                    })
                    policy_exception_id += 1
                policy_id += 1
            for local in range(25):
                status = "active" if local % 3 == 0 else ("pending_approval" if local % 3 == 1 else "completed")
                poam_rows.append({
                    "id": poam_id, "service_id": service_id, "finding_id": None,
                    "policy_finding_id": None, "item_type": "vulnerability", "title": "Benchmark POA&M",
                    "description": "Synthetic remediation item", "remediation": "Apply remediation",
                    "due_date": now - timedelta(days=5) if status == "active" and local % 2 == 0 else now + timedelta(days=30),
                    "ticket": f"BENCH-{service_id}-{local}", "status": status,
                    "created_by_id": 1, "approved_by_id": 1 if status != "pending_approval" else None,
                    "approved_at": now if status != "pending_approval" else None,
                })
                poam_id += 1
            if service_number % 10 == 0:
                archive_rows.append({
                    "id": service_number, "service_id": service_id, "action": "restore",
                    "reason": "Benchmark active service", "performed_by": "benchmark",
                    "created_at": now - timedelta(days=1), "ticket": None,
                })
        with engine.begin() as connection:
            connection.execute(insert(Group), groups)
            connection.execute(insert(Service), service_rows)
            connection.execute(insert(ServiceGroup), group_rows)
            connection.execute(insert(ServiceImage), image_rows)
            connection.execute(insert(Execution), execution_rows)
            connection.execute(insert(Finding), finding_rows)
            connection.execute(insert(FindingObservation), observation_rows)
            if exception_rows:
                connection.execute(insert(ExceptionRecord), exception_rows)
            connection.execute(insert(PolicyFinding), policy_rows)
            if policy_exception_rows:
                connection.execute(insert(PolicyExceptionRecord), policy_exception_rows)
            connection.execute(insert(PoamEntry), poam_rows)
            if archive_rows:
                connection.execute(insert(ServiceArchiveEvent), archive_rows)
        counts = {}
        with SessionLocal() as db:
            for model in (Service, Group, ServiceGroup, ServiceImage, Execution, Finding, FindingObservation, ExceptionRecord, PolicyFinding, PolicyExceptionRecord, PoamEntry, ServiceArchiveEvent):
                counts[model.__tablename__] = db.scalar(select(func.count()).select_from(model)) or 0
        counts["missing_evidence_items"] = service_count * 3
        counts["total_database_rows"] = sum(value for key, value in counts.items() if key != "missing_evidence_items")
        return counts

    original_render = _TemplateResponse.render
    render_timings: list[float] = []

    def timed_render(response, content):
        started = time.perf_counter()
        result = original_render(response, content)
        render_timings.append((time.perf_counter() - started) * 1000)
        return result

    _TemplateResponse.render = timed_render
    try:
        optimized_loader = main_module.service_overview_rows
        for service_count, findings_per_service in datasets:
            counts = populate(service_count, findings_per_service)
            client = TestClient(app)
            login = client.post("/login", data={"username": "admin", "password": "benchmark-password-long"}, follow_redirects=False)
            if login.status_code != 303:
                raise RuntimeError(f"benchmark login failed: {login.status_code}")

            def measure(loader):
                main_module.service_overview_rows = loader
                calls: list[dict] = []
                durations: list[float] = []
                starts: list[float] = []
                before_listener = lambda *args: (starts.append(time.perf_counter()), calls.append({"sql": args[2], "parameters": args[3]}))
                after_listener = lambda *args: durations.append((time.perf_counter() - starts.pop(0)) * 1000)
                event.listen(engine, "before_cursor_execute", before_listener)
                event.listen(engine, "after_cursor_execute", after_listener)
                render_timings.clear()
                timing_records.clear()
                try:
                    started = time.perf_counter()
                    response = client.get("/")
                    request_ms = (time.perf_counter() - started) * 1000
                finally:
                    event.remove(engine, "before_cursor_execute", before_listener)
                    event.remove(engine, "after_cursor_execute", after_listener)
                slowest_duration, slowest_query = max(zip(durations, calls), default=(0.0, {"sql": "", "parameters": ()}), key=lambda item: item[0])
                explain = []
                if engine.dialect.name == "sqlite" and slowest_query["sql"].lstrip().upper().startswith("SELECT"):
                    try:
                        with engine.connect() as connection:
                            explain = [list(row) for row in connection.exec_driver_sql(
                                "EXPLAIN QUERY PLAN " + slowest_query["sql"], slowest_query["parameters"]
                            )]
                    except Exception as exc:
                        explain = [f"EXPLAIN QUERY PLAN unavailable: {exc}"]
                elif engine.dialect.name == "postgresql" and slowest_query["sql"].lstrip().upper().startswith("SELECT"):
                    try:
                        with engine.connect() as connection:
                            explain = [list(row) for row in connection.exec_driver_sql(
                                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + slowest_query["sql"],
                                slowest_query["parameters"],
                            )]
                    except Exception as exc:
                        explain = [f"EXPLAIN ANALYZE unavailable: {exc}"]
                return {
                    "status": response.status_code,
                    "sql_queries": len(calls), "sql_ms": round(sum(durations), 2),
                    "slowest_query_ms": round(slowest_duration, 2),
                    "slowest_query": slowest_query["sql"].splitlines()[0][:240],
                    "explain_query_plan": explain,
                    "server_processing_ms": round(request_ms, 2),
                    "serialization_ms": round(sum(render_timings), 2),
                    "api_response_ms": round(request_ms, 2),
                    "response_bytes": len(response.content), "frontend_requests": 1,
                    "stage_timings_ms": timing_records[-1] if timing_records else {},
                }

            before = measure(main_module.service_overview_rows_detailed)
            # Exercise the real HTTP lifecycle multiple times. The first
            # optimized request includes application/SQLite page-cache warmup;
            # the second and repeated samples show steady-state behavior.
            first = measure(optimized_loader)
            second = measure(optimized_loader)
            repeated = [measure(optimized_loader) for _ in range(3)]
            after = {
                **first,
                "first_request": first,
                "second_request": second,
                "repeated_requests": repeated,
                "repeated_server_processing_ms": [item["server_processing_ms"] for item in repeated],
            }
            print(json.dumps({
                "dataset": f"{service_count}x{findings_per_service}",
                "rows": counts,
                "before_current_detailed_loader": before,
                "after_database_aggregate_loader": after,
                "notes": "React render is not applicable; Services is server-rendered Jinja. TTFB is represented by in-process request time.",
            }, indent=2, default=str))
    finally:
        _TemplateResponse.render = original_render
        main_module.snapshot_logger.removeHandler(timing_handler)


if __name__ == "__main__":
    main()
