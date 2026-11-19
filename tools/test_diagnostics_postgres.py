"""Run live PostgreSQL acceptance in a new localhost-only disposable container.

From the repository root: .venv/Scripts/python.exe tools/test_diagnostics_postgres.py
Requires Docker and the portal test dependencies. No existing database is used.
"""
import os
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    "tests/test_diagnostics_postgres.py",
    "tests/test_diagnostics_integration.py",
    "tests/test_durable_jobs_postgres.py",
    "tests/test_durable_worker_concurrency.py",
    "tests/test_scan_coordination_hardening.py",
    "tests/test_scan_worker_coordination.py",
]


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True, timeout=90)


def main():
    identity = uuid.uuid4().hex[:12]
    name = "cats-diagnostics-test-" + identity
    password = secrets.token_hex(20)
    started = False
    started_at = time.monotonic()
    evidence = ROOT / ".test-temp" / ("diagnostics-postgres-" + identity)
    evidence.mkdir(parents=True)
    result_data = {"container": name, "image": "postgres:16-alpine", "tests": TESTS,
                   "status": "starting", "removed": False}
    try:
        docker("run", "--detach", "--rm", "--pull", "never", "--name", name,
               "--label", "cats.test=diagnostics-acceptance", "--publish", "127.0.0.1::5432",
               "--env", "POSTGRES_USER=cats_acceptance", "--env", "POSTGRES_PASSWORD=" + password,
               "--env", "POSTGRES_DB=cats_diagnostics", "postgres:16-alpine")
        started = True
        deadline = time.monotonic() + 60
        while docker("exec", name, "pg_isready", "-U", "cats_acceptance", "-d", "cats_diagnostics", check=False).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError("Disposable PostgreSQL did not become ready within 60 seconds")
            time.sleep(0.5)
        port = docker("port", name, "5432/tcp").stdout.strip().rsplit(":", 1)[1]
        url = f"postgresql+psycopg://cats_acceptance:{password}@127.0.0.1:{port}/cats_diagnostics"
        env = os.environ.copy()
        for key in ("CATS_TEST_DATABASE_URL", "CATS_TEST_POSTGRES_URL", "TEST_DATABASE_URL"):
            env[key] = url
        # Keep application/intelligence storage in the same disposable instance.
        env.pop("INTELLIGENCE_DATABASE_URL", None)
        print(f"Live PostgreSQL16 acceptance: {name} on 127.0.0.1:{port}", flush=True)
        result_data["host"] = "127.0.0.1"
        result_data["port"] = int(port)
        command = [sys.executable, "-m", "pytest", *TESTS, "-q", "-p", "no:cacheprovider",
                   "--basetemp", str(evidence / "tmp"), "--junitxml", str(evidence / "pytest.xml")]
        code = subprocess.run(command, cwd=ROOT / "portal", env=env, timeout=1200).returncode
        result_data.update(status="passed" if code == 0 else "failed", exit_code=code)
        return code
    finally:
        if started:
            result = docker("stop", "--time", "5", name, check=False)
            if result.returncode:
                print(f"Could not remove disposable container {name}: {result.stderr}", file=sys.stderr)
            else:
                result_data["removed"] = True
                print(f"Removed disposable PostgreSQL container {name}", flush=True)
        result_data["elapsed_seconds"] = round(time.monotonic() - started_at, 2)
        (evidence / "result.json").write_text(json.dumps(result_data, indent=2) + "\n", encoding="utf-8")
        print(f"Acceptance evidence: {evidence}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
