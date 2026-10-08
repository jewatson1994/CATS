"""End-to-end navigation benchmark against a disposable PostgreSQL database.

Seeds a synthetic portfolio through the real pipeline ingest route, then
measures the requests the frontend makes for ordinary navigation, through the
full ASGI stack (authentication, middleware, serialization). Each record comes
from CATS' own PerformanceMiddleware: wall time, SQL time, query count and
uncompressed response bytes. Nothing leaves the machine.

What the numbers mean:

* ``first_in_process_ms``: the first request to that scenario in this
  process. Earlier scenarios (and the login) have already run in the same
  process, so process-local caches for other pages may be warm. It is NOT a
  cold start.
* ``isolated_first``: with ``--isolated-first``, each scenario's first
  request runs in its own fresh process (only the login before it), and
  ``process_ready_ms`` records interpreter start to application imported.
* ``warm_*``: computed over the repeats after the first request only
  (``--repeat`` minus one samples), never including the first.
* Background maintenance (application lifespan) does not run under the
  test client; measure preparation on a real server separately.

    python scripts/benchmark-navigation.py \
        --database-url postgresql+psycopg://cats@/cats_perf?host=/tmp&port=55432 \
        --services 10 --findings 1000 --reset --output perf.json

Never point --database-url at a real CATS database: --reset drops its schema.
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import random
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROCESS_STARTED = time.perf_counter()
ROOT = Path(__file__).resolve().parents[1]
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--services", type=int, default=10)
    parser.add_argument("--findings", type=int, default=1000, help="findings per service")
    parser.add_argument("--images", type=int, default=8, help="images per service")
    parser.add_argument("--history", type=int, default=2, help="scans per service (history depth)")
    parser.add_argument("--template", type=Path, help="real portal-result.json supplying service_overview/policy findings")
    parser.add_argument("--reset", action="store_true", help="drop and recreate the database schema, then seed")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--remediation-row", type=Path, help="JSON of a real remediation_executions row to replay")
    parser.add_argument("--profile", help="cProfile the cold request of scenarios containing this text")
    parser.add_argument("--only", help="run only scenarios containing this text")
    parser.add_argument("--explain", help="print the slowest SQL statements (EXPLAIN ANALYZE of the slowest) of the last request of scenarios containing this text")
    parser.add_argument("--dense-findings", type=int, default=0, help="with --reset: also seed service perf-9999 with this many findings per scan")
    parser.add_argument("--resume-seed", action="store_true", help="skip the portfolio services (already seeded); seed the dense service and fixtures")
    parser.add_argument("--service", default="perf-0001", help="service the service-tab scenarios use")
    parser.add_argument("--isolated-first", action="store_true", help="also measure each scenario's first request in a fresh process")
    parser.add_argument("--single", help=argparse.SUPPRESS)  # internal: one scenario name, one request, JSON to stdout
    parser.add_argument("--single-user", default="admin", help=argparse.SUPPRESS)
    return parser.parse_args()


ARGS = parse_args()
os.environ.update({
    "DATABASE_URL": ARGS.database_url, "PIPELINE_API_TOKEN": "bench-token",
    "CATS_BOOTSTRAP_USERNAME": "admin", "CATS_BOOTSTRAP_PASSWORD": "bench-password-long",
    "SESSION_COOKIE_SECURE": "false", "CATS_DEPLOYMENT_VALIDATION_ENABLED": "false",
    "CATS_PERFORMANCE_DIAGNOSTICS": "true",
})
# A dense service's scan exceeds the default 16 MB pipeline limit; a deployment
# with services that dense raises CATS_PIPELINE_MAX_REQUEST_BYTES the same way.
os.environ.setdefault("CATS_PIPELINE_MAX_REQUEST_BYTES", str(256 * 1024 * 1024))
for name in ("CATS_PUBLIC_JOB_ROOT", "CATS_PATCH_JOB_ROOT", "CATS_REMEDIATION_JOB_ROOT"):
    os.environ.setdefault(name, f"/tmp/cats-bench/{name.lower()}")
sys.path.insert(0, str(ROOT / "portal"))

if ARGS.reset:
    from sqlalchemy import create_engine, text
    with create_engine(ARGS.database_url).begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))

RECORDS: list[dict] = []


class Capture(logging.Handler):
    def emit(self, record):
        message = record.getMessage()
        if message.startswith("request_performance "):
            RECORDS.append(json.loads(message.split(" ", 1)[1]))


logging.getLogger("cats.performance").addHandler(Capture())
logging.getLogger("cats.performance").setLevel(logging.INFO)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app import main  # noqa: E402
from app.auth import hash_password, token_hash  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.models import (Group, RemediationExecution, Role, Service, User, UserRoleAssignment,  # noqa: E402
                        UserSession, DeploymentValidationRun, Execution)

PAGE = {"Accept": "application/vnd.cats.page+json"}
PIPELINE = {"Authorization": "Bearer bench-token"}


def template():
    if ARGS.template and ARGS.template.is_file():
        return json.loads(ARGS.template.read_text(encoding="utf-8"))
    return {"service_overview": {"images": []}, "policy_findings": []}


def payload(base, service_number, scan_number, now, finding_count=None):
    finding_count = ARGS.findings if finding_count is None else finding_count
    rng = random.Random(service_number * 1000 + scan_number)
    body = copy.deepcopy(base)
    key = f"perf-{service_number:04d}"
    images = [f"registry.example.invalid/perf/{key}/image-{i}:1.{scan_number}" for i in range(ARGS.images)]
    findings = []
    for number in range(finding_count):
        # Later scans resolve ~5% and introduce ~5% so history has churn.
        offset = number + (scan_number - 1) * finding_count // 20
        findings.append({
            "cve": f"CVE-{2020 + offset % 6}-{service_number:04d}{offset:07d}",
            "severity": SEVERITIES[offset % len(SEVERITIES)],
            "image": images[offset % len(images)],
            "image_digest": None,
            "package": f"package-{offset % 400:04d}",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1" if offset % 3 else None,
            "kev": offset % 97 == 0,
            "epss": round(rng.random(), 4),
            "evidence": {"description": "Synthetic benchmark finding; not production evidence.", "synthetic": True},
        })
    components = [{"name": f"package-{n:04d}", "version": "1.0.0", "ecosystem": "generic", "purl": f"pkg:generic/package-{n:04d}@1.0.0",
                   "image": images[n % len(images)], "license_declared": "MIT" if n % 4 else ""} for n in range(400)]
    body.update({
        "schema_version": "1.0", "execution_id": f"bench:{key}:{scan_number}",
        "scanned_at": (now - timedelta(days=ARGS.history - scan_number)).isoformat(), "complete": True,
        "skipped_images": [], "skipped_charts": [], "fixable_only": True,
        "service": {"id": key, "name": f"Performance {service_number}", "version": f"1.{scan_number}.0",
                    "poc": "bench@example.invalid", "groups": [f"bench-group-{service_number % 10}"]},
        "findings": findings, "sbom_components": components, "sbom_images": images,
    })
    overview = body.setdefault("service_overview", {})
    overview["images"] = [{"image": image} for image in images]
    return body


def seed():
    base = template()
    client = TestClient(main.app)
    now = datetime.now(timezone.utc)
    started = time.perf_counter()
    for service_number in range(1, 0 if ARGS.resume_seed else ARGS.services + 1):
        for scan_number in range(1, ARGS.history + 1):
            response = client.post("/api/v1/pipeline-results", json=payload(base, service_number, scan_number, now), headers=PIPELINE)
            assert response.status_code == 201, response.text[:400]
        if service_number % 10 == 0:
            print(f"  seeded {service_number}/{ARGS.services} services ({time.perf_counter() - started:.0f}s)", flush=True)
    if ARGS.dense_findings:
        for scan_number in range(1, ARGS.history + 1):
            response = client.post("/api/v1/pipeline-results", json=payload(base, 9999, scan_number, now, ARGS.dense_findings), headers=PIPELINE)
            assert response.status_code == 201, response.text[:400]
        print(f"  seeded dense service perf-9999 with {ARGS.dense_findings} findings per scan ({time.perf_counter() - started:.0f}s)", flush=True)
    with SessionLocal() as db:
        first = db.scalar(select(Service).where(Service.service_key == "perf-0001"))
        execution = db.scalar(select(Execution).where(Execution.service_id == first.id).order_by(Execution.id.desc()))
        if ARGS.remediation_row and ARGS.remediation_row.is_file():
            row = json.loads(ARGS.remediation_row.read_text(encoding="utf-8"))
            row = {k: v for k, v in row.items() if k in RemediationExecution.__table__.columns.keys() and k != "id"}
            for column in ("created_at", "started_at", "completed_at", "updated_at"):
                if row.get(column):
                    row[column] = datetime.fromisoformat(row[column]).replace(tzinfo=timezone.utc)
            row.update(service_id=first.id, source_execution_id=execution.id, source_version_id=execution.service_version_id,
                       requested_by_id=db.scalar(select(User.id).where(User.username == "admin")), retry_of_id=None, job_key="R-BENCH-ACTIVE", status="running", phase="final_rescan",
                       completed_at=None, artifact_path=None)
            db.add(RemediationExecution(**row))
        events = [{"type": "Normal", "reason": "Started", "object": f"Pod/worker-{n}", "message": "Started container " * 4,
                   "at": now.isoformat()} for n in range(200)]
        db.add(DeploymentValidationRun(
            run_key="DV-BENCH-RUNNING", service_id=first.id, execution_id=execution.id, artifact_type="ORIGINAL",
            artifact_reference="bench", engine="kind", status="RUNNING", phase="WAITING_FOR_READY",
            reason="Synthetic benchmark run", events=events,
            observed_topology={"resources": [{"kind": "Deployment", "name": f"svc-{n}", "status": {"ready": 1}} for n in range(150)]},
            comparison={"matched": [f"Deployment/svc-{n}" for n in range(150)], "missing": [], "unexpected": []},
            diagnostics={"logs": ["line " * 30 for _ in range(300)]}, cleanup_status="PENDING", started_at=now))
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        group = db.scalar(select(Group).where(Group.name == "bench-group-1"))
        user = User(username="restricted", display_name="Restricted", password_hash=hash_password("bench-password-long"),
                    must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, group_id=group.id if group else None))
        db.commit()
    print(f"seeded {ARGS.services} services x {ARGS.history} scans x {ARGS.findings} findings in {time.perf_counter() - started:.0f}s")


def login(username):
    client = TestClient(main.app)
    response = client.post("/login", data={"username": username, "password": "bench-password-long"}, follow_redirects=False)
    assert response.status_code == 303, response.text[:200]
    return client


def latest_execution_id(service_key):
    from sqlalchemy import select
    from app.models import Execution, Service
    with SessionLocal() as db:
        return db.scalar(select(Execution.id).join(Service).where(Service.service_key == service_key)
                         .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))


def scenarios(service_key):
    root = f"/services/{service_key}"
    return [
        ("services: page", "/", PAGE),
        ("services: rows", "/api/dashboard/services?lifecycle=active", {}),
        ("cybersecurity: page", "/cybersecurity", PAGE),
        ("cybersecurity: data", "/api/dashboard/cybersecurity", {}),
        ("service: overview", f"{root}?overview=true", PAGE),
        ("service: findings simplified", f"{root}?findings=true&findings_view=simplified", PAGE),
        ("service: findings raw", f"{root}?findings_view=raw", PAGE),
        ("service: findings search", f"{root}?findings_view=raw&q=package-01", PAGE),
        ("service: architecture", f"{root}?architecture=true", PAGE),
        ("service: dependencies", f"{root}?dependencies=true", PAGE),
        ("service: validation", f"{root}?validation=true", PAGE),
        ("service: remediations", f"{root}?remediations=true&tab=pipeline", PAGE),
        ("service: activity", f"{root}?activity=true", PAGE),
        ("service: artifacts", f"{root}?artifacts=true", PAGE),
        ("poll: remediation report", f"{root}/remediations/R-BENCH-ACTIVE", PAGE),
        ("poll: deployment validation", f"/api/v1/services/{service_key}/deployment-validations/DV-BENCH-RUNNING", {}),
        # Lightweight status contracts (404 on releases that predate them).
        ("poll: remediation status", f"/api/v1/services/{service_key}/remediations/R-BENCH-ACTIVE/status", {}),
        ("poll: validation status", f"/api/v1/services/{service_key}/deployment-validations/DV-BENCH-RUNNING/status", {}),
        ("poll: dependencies status", f"/api/v1/services/{service_key}/dependencies/status?execution_id={latest_execution_id(service_key)}", {}),
    ]


STATEMENTS: list = []


def capture_statements():
    from sqlalchemy import event
    from app.database import engine

    @event.listens_for(engine, "before_cursor_execute")
    def _before(conn, cursor, statement, params, context, executemany):
        conn.info["bench_started"] = time.perf_counter()

    @event.listens_for(engine, "after_cursor_execute")
    def _after(conn, cursor, statement, params, context, executemany):
        STATEMENTS.append((time.perf_counter() - conn.info.pop("bench_started", time.perf_counter()), statement, params))


def explain(label, name):
    from app.database import engine
    ranked = sorted(STATEMENTS, key=lambda item: -item[0])
    print(f"--- slowest statements {label} {name}")
    for elapsed, statement, _ in ranked[:5]:
        print(f"{elapsed * 1000:9.1f}ms  {' '.join(statement.split())[:400]}")
    if ranked:
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            cursor.execute("EXPLAIN (ANALYZE, BUFFERS) " + ranked[0][1], ranked[0][2])
            for row in cursor.fetchall():
                print("   ", row[0])
        finally:
            raw.close()


def request_sample(client, name, url, headers, label, attempt):
    before = len(RECORDS)
    profiler = None
    if ARGS.profile and ARGS.profile in name and attempt == 0:
        import cProfile
        profiler = cProfile.Profile()
        profiler.enable()
    STATEMENTS.clear()
    started = time.perf_counter()
    response = client.get(url, headers=headers)
    elapsed = (time.perf_counter() - started) * 1000  # before any EXPLAIN/profile output
    if profiler:
        profiler.disable()
        import pstats
        print(f"--- profile {label} {name}")
        pstats.Stats(profiler).sort_stats("cumulative").print_stats(os.getenv("BENCH_PROFILE_FILTER", ""), 30)
    if ARGS.explain and ARGS.explain in name and attempt == ARGS.repeat - 1:
        explain(label, name)
    record = RECORDS[before] if len(RECORDS) > before else {}
    return {"status": response.status_code, "client_ms": round(elapsed, 1),
            "duration_ms": record.get("duration_ms"), "query_ms": record.get("query_ms"),
            "query_count": record.get("query_count"), "response_bytes": record.get("response_bytes"),
            "orm": record.get("orm_instances_loaded")}


def quantile(values, q):
    values = sorted(value for value in values if value is not None)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))] if values else None


def summarize(user, name, samples):
    first, warm = samples[0], [sample for sample in samples[1:] if sample["status"] == 200]
    return {"user": user, "scenario": name, "status": first["status"],
            "first_in_process_ms": first["duration_ms"], "first_query_ms": first["query_ms"],
            "first_queries": first["query_count"],
            "warm_samples": len(warm),
            "warm_median_ms": statistics.median([s["duration_ms"] for s in warm]) if warm else None,
            "warm_p95_ms": quantile([s["duration_ms"] for s in warm], 0.95),
            "warm_query_ms_median": quantile([s["query_ms"] for s in warm], 0.5),
            "queries": samples[-1]["query_count"], "bytes": samples[-1]["response_bytes"], "orm": samples[-1]["orm"],
            "samples": samples}


def measure(client, label, user):
    results = []
    for name, url, headers in scenarios(ARGS.service):
        if ARGS.only and ARGS.only not in name:
            continue
        samples = [request_sample(client, name, url, headers, label, attempt) for attempt in range(ARGS.repeat)]
        results.append(summarize(user, name, samples))
        row = results[-1]
        print(f"{label:<10} {name:<32} {row['status']} first={row['first_in_process_ms']}ms "
              f"warm={row['warm_median_ms']}ms p95={row['warm_p95_ms']}ms (n={row['warm_samples']}) q={row['queries']} "
              f"sql={row['warm_query_ms_median']}ms bytes={row['bytes']} orm={row['orm']}", flush=True)
    return results


def isolated_first(users):
    """Each scenario's first request in its own fresh process."""
    import subprocess
    results = []
    for user in users:
        for name, _url, _headers in scenarios(ARGS.service):
            if ARGS.only and ARGS.only not in name:
                continue
            command = [sys.executable, str(Path(__file__).resolve()), "--database-url", ARGS.database_url,
                       "--service", ARGS.service, "--single", name, "--single-user", user]
            if ARGS.template:
                command += ["--template", str(ARGS.template)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            line = [entry for entry in completed.stdout.splitlines() if entry.startswith("SINGLE ")]
            record = json.loads(line[-1][7:]) if line else {"error": completed.stderr[-400:]}
            record.update(user=user, scenario=name)
            results.append(record)
            print(f"isolated   {user:<10} {name:<32} {record.get('status')} first={record.get('duration_ms')}ms "
                  f"process_ready={record.get('process_ready_ms')}ms q={record.get('query_count')} sql={record.get('query_ms')}ms", flush=True)
    return results


def metadata():
    """Revision, environment and the database's preparation state for the run."""
    import platform
    import subprocess
    from sqlalchemy import func, inspect, text
    from app.database import engine
    from app.models import Execution, Finding
    info = {"started_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
            "args": {key: str(value) for key, value in vars(ARGS).items() if key not in {"database_url"}}}
    try:
        info["git_revision"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        info["git_dirty"] = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                                                capture_output=True, text=True).stdout.strip())
    except Exception:
        info["git_revision"] = None
    with engine.connect() as connection:
        if engine.dialect.name == "postgresql":
            info["database"] = connection.execute(text("select version()")).scalar()
            info["jit"] = connection.execute(text("show jit")).scalar()
        tables = set(inspect(connection).get_table_names())
        info["dataset"] = {
            "services": connection.execute(text("select count(*) from services")).scalar(),
            "executions": connection.execute(text("select count(*) from executions")).scalar(),
            "findings": connection.execute(text("select count(*) from findings")).scalar(),
            "active_findings": connection.execute(text("select count(*) from findings where active")).scalar(),
        }
        prepared = {}
        if "service_posture" in tables:
            prepared["posture_rows"] = connection.execute(text("select count(*) from service_posture")).scalar()
            prepared["posture_services_built"] = connection.execute(text(
                "select count(*) from service_posture where services_built_generation = data_generation")).scalar()
            prepared["posture_cyber_built"] = connection.execute(text(
                "select count(*) from service_posture where cyber_built_generation = data_generation")).scalar()
        if "execution_overviews" in tables:
            prepared["stored_overviews"] = connection.execute(text("select count(*) from execution_overviews")).scalar()
        if "execution_summaries" in tables:
            prepared["execution_summaries"] = connection.execute(text("select count(*) from execution_summaries")).scalar()
        info["preparation"] = prepared
    return info


def single():
    """--single: one scenario, one request, in this fresh process."""
    ready_ms = round((time.perf_counter() - PROCESS_STARTED) * 1000, 1)
    client = login(ARGS.single_user)
    for name, url, headers in scenarios(ARGS.service):
        if name == ARGS.single:
            sample = request_sample(client, name, url, headers, ARGS.single_user, 0)
            sample["process_ready_ms"] = ready_ms
            print("SINGLE " + json.dumps(sample), flush=True)
            return
    raise SystemExit(f"unknown scenario {ARGS.single}")


def main_run():
    if ARGS.single:
        single()
        return
    if ARGS.explain:
        capture_statements()
    if ARGS.reset or ARGS.resume_seed:
        seed()
    info = metadata()
    print("metadata", json.dumps({key: info[key] for key in ("git_revision", "git_dirty", "dataset", "preparation")}), flush=True)
    results = measure(login("admin"), "admin", "admin") + measure(login("restricted"), "restricted", "restricted")
    isolated = isolated_first(["admin", "restricted"]) if ARGS.isolated_first else []
    if ARGS.output:
        ARGS.output.write_text(json.dumps({"services": ARGS.services, "findings_per_service": ARGS.findings,
                                           "history": ARGS.history, "repeat": ARGS.repeat, "metadata": info,
                                           "results": results, "isolated_first": isolated}, indent=2, default=str))


if __name__ == "__main__":
    main_run()
