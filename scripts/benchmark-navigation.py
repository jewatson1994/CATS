"""End-to-end navigation benchmark against a disposable PostgreSQL database.

Seeds a synthetic portfolio through the real pipeline ingest route, then
measures the requests the frontend makes for ordinary navigation, through the
full ASGI stack (authentication, middleware, serialization). Each record comes
from CATS' own PerformanceMiddleware: wall time, SQL time, query count and
uncompressed response bytes. Nothing leaves the machine.

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
    return parser.parse_args()


ARGS = parse_args()
os.environ.update({
    "DATABASE_URL": ARGS.database_url, "PIPELINE_API_TOKEN": "bench-token",
    "CATS_BOOTSTRAP_USERNAME": "admin", "CATS_BOOTSTRAP_PASSWORD": "bench-password-long",
    "SESSION_COOKIE_SECURE": "false", "CATS_DEPLOYMENT_VALIDATION_ENABLED": "false",
    "CATS_PERFORMANCE_DIAGNOSTICS": "true",
})
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


def payload(base, service_number, scan_number, now):
    rng = random.Random(service_number * 1000 + scan_number)
    body = copy.deepcopy(base)
    key = f"perf-{service_number:04d}"
    images = [f"registry.example.invalid/perf/{key}/image-{i}:1.{scan_number}" for i in range(ARGS.images)]
    findings = []
    for number in range(ARGS.findings):
        # Later scans resolve ~5% and introduce ~5% so history has churn.
        offset = number + (scan_number - 1) * ARGS.findings // 20
        findings.append({
            "cve": f"CVE-{2020 + offset % 6}-{service_number:04d}{offset:06d}",
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
    for service_number in range(1, ARGS.services + 1):
        for scan_number in range(1, ARGS.history + 1):
            response = client.post("/api/v1/pipeline-results", json=payload(base, service_number, scan_number, now), headers=PIPELINE)
            assert response.status_code == 201, response.text[:400]
        if service_number % 10 == 0:
            print(f"  seeded {service_number}/{ARGS.services} services ({time.perf_counter() - started:.0f}s)", flush=True)
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
    ]


def measure(client, label, user):
    results = []
    for name, url, headers in scenarios("perf-0001"):
        samples = []
        for attempt in range(ARGS.repeat):
            before = len(RECORDS)
            started = time.perf_counter()
            response = client.get(url, headers=headers)
            elapsed = (time.perf_counter() - started) * 1000
            record = RECORDS[before] if len(RECORDS) > before else {}
            samples.append({"status": response.status_code, "client_ms": round(elapsed, 1),
                            "duration_ms": record.get("duration_ms"), "query_ms": record.get("query_ms"),
                            "query_count": record.get("query_count"), "response_bytes": record.get("response_bytes")})
        ok = [sample for sample in samples if sample["status"] == 200]
        def p(key, quantile):
            values = sorted(sample[key] for sample in ok if sample[key] is not None)
            return values[min(len(values) - 1, int(round(quantile * (len(values) - 1))))] if values else None
        results.append({"user": user, "scenario": name, "status": samples[0]["status"], "cold_ms": samples[0]["duration_ms"],
                        "warm_median_ms": statistics.median([s["duration_ms"] for s in ok[1:]]) if len(ok) > 1 else None,
                        "warm_p95_ms": p("duration_ms", 0.95), "query_ms_median": p("query_ms", 0.5),
                        "queries": samples[-1]["query_count"], "bytes": samples[-1]["response_bytes"]})
        print(f"{label:<10} {name:<32} {samples[0]['status']} cold={samples[0]['duration_ms']}ms "
              f"warm={results[-1]['warm_median_ms']}ms q={samples[-1]['query_count']} "
              f"sql={results[-1]['query_ms_median']}ms bytes={samples[-1]['response_bytes']}", flush=True)
    return results


def main_run():
    if ARGS.reset:
        seed()
    results = measure(login("admin"), "admin", "admin") + measure(login("restricted"), "restricted", "restricted")
    if ARGS.output:
        ARGS.output.write_text(json.dumps({"services": ARGS.services, "findings_per_service": ARGS.findings,
                                           "history": ARGS.history, "repeat": ARGS.repeat, "results": results}, indent=2))


if __name__ == "__main__":
    main_run()
