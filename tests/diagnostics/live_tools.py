"""Offline acceptance against real tools, through the durable worker boundary.

Run inside the existing tools image with current source mounted read-only:
  python /workspace/tests/diagnostics/live_tools.py --output /evidence
Mount a docker-save archive of the local alpine:3.20.0 at /evidence/alpine.tar.
No daemon socket, network, mocks, or external database is used by this harness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cats-live-tools-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{work / 'jobs.db'}"
    os.environ["CATS_JOB_MAX_RUNTIME_SECONDS"] = "0"
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "portal"))

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models  # Register referenced tables; no production DB.
    from app.diagnostic_store import DiagnosticEvent
    from app.diagnostics import correlation, public_diagnostic, sanitize
    from app.durable_jobs import DurableJob, claim, execute, submit
    from app.patching import run_command

    engine = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    DurableJob.__table__.create(engine)
    DiagnosticEvent.__table__.create(engine)
    env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false",
           "GRYPE_CHECK_FOR_APP_UPDATE": "false", "GRYPE_DB_REQUIRE_UPDATE_CHECK": "false",
           "SYFT_CHECK_FOR_APP_UPDATE": "false", "TRIVY_SKIP_CHECK_UPDATE": "true"}
    report = {
        "schema_version": 1, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "boundary": "current patching.run_command -> durable_jobs.execute -> committed job JSON + diagnostic history",
        "isolation": "network none, no Docker socket, temporary SQLite, existing local image archive",
        "limitations": ["No successful Copa patch: this isolated harness has no BuildKit service.",
                        "Trivy vulnerability database is absent in the local image; normal Trivy acceptance uses its secret scanner.",
                        "This checks the command adapter and durable worker boundary; it does not run the entire scan or patch pipeline."],
        "versions": {}, "cases": [],
    }

    def save():
        (args.output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    for tool in ("trivy", "grype", "syft", "dockle", "copa"):
        option = "version" if tool in {"syft", "grype"} else "--version"
        version = subprocess.run([tool, option], env=env, text=True, capture_output=True, timeout=15)
        assert version.returncode == 0, (tool, version.stderr)
        report["versions"][tool] = (version.stdout + version.stderr).strip()
    save()

    def run_case(name, command, *, expect_failure=False, timeout=90, json_output=False, expected_code=None):
        entry = {"name": name, "command": sanitize(command), "expected_failure": expect_failure,
                 "timeout_seconds": timeout}
        report["cases"].append(entry)
        started = time.monotonic()
        logs = []
        try:
            with factory() as db:
                row = submit(db, kind="external_tool_acceptance", payload={}, max_attempts=1)
                job_id = row.id
            job = claim(["external_tool_acceptance"], "live-tools-acceptance", factory)
            assert job is not None and job.id == job_id

            def handler(ctx, payload):
                assert correlation.get() == job.correlation_id
                ctx.stage("Fixture prepared", 10)
                ctx.stage(f"Running {command[0]}", 20)
                completed = run_command(command, env=env, log=logs.append, timeout=timeout)
                output = completed.stdout or ""
                if json_output:
                    parsed = json.loads(output)
                    assert isinstance(parsed, (dict, list)), "Tool did not return structured JSON"
                return {"tool": command[0], "exit_code": completed.returncode,
                        "stdout_bytes": len(output.encode()),
                        "stdout_sha256": hashlib.sha256(output.encode()).hexdigest()}

            execute(job, handler, factory)
            with factory() as db:
                row = db.get(DurableJob, job_id)
                entry.update(job_id=row.id, status=row.status, attempts=row.attempts,
                             worker_id=row.worker_id, correlation_id=row.correlation_id,
                             lease_cleared=row.lease_token is None and row.lease_until is None,
                             result=row.result)
                assert row.completed_at is not None and entry["lease_cleared"]
                assert row.attempts == 1 and row.worker_id == "live-tools-acceptance"
                if expect_failure:
                    assert row.status == "failed", f"Expected failure, got {row.status}"
                    diagnostic = row.result["diagnostic"]
                    entry["diagnostic"] = diagnostic
                    entry["public_diagnostic"] = public_diagnostic(diagnostic)
                    assert diagnostic["correlation_id"] == row.correlation_id
                    assert diagnostic["resource"]["jobs_view_id"] == row.id
                    assert diagnostic["context"]["stage"] == f"Running {command[0]}"
                    assert diagnostic["context"]["last_successful_stage"] == "Fixture prepared"
                    assert diagnostic["context"]["tool"] == command[0]
                    assert diagnostic["context"]["timeout_seconds"] == timeout
                    assert diagnostic["retryable"] is False
                    if expected_code:
                        assert diagnostic["code"] == expected_code, diagnostic["code"]
                    if timeout < 1:
                        assert diagnostic["category"] == "timeout"
                    else:
                        assert diagnostic["context"]["exit_code"] != 0
                        assert isinstance(diagnostic["context"]["exit_code"], int)
                    assert "technical" not in entry["public_diagnostic"]
                    stored = db.get(DiagnosticEvent, diagnostic["error_id"])
                    assert stored and stored.diagnostic["error_id"] == diagnostic["error_id"]
                    entry["history_persisted"] = True
                else:
                    assert row.status == "completed", row.result
                    assert "diagnostic" not in row.result
            entry["passed"] = True
        except Exception as exc:
            entry["passed"] = False
            entry["assertion_error"] = sanitize(str(exc))
            entry["assertion_traceback"] = sanitize(traceback.format_exc())
        finally:
            entry["elapsed_seconds"] = round(time.monotonic() - started, 3)
            entry["tool_log_tail"] = sanitize("\n".join(logs)[-5000:])
            save()
            print(json.dumps({key: entry.get(key) for key in ("name", "passed", "status", "elapsed_seconds", "assertion_error")}), flush=True)

    archive = args.output / "alpine.tar"
    assert archive.is_file(), f"Missing local image archive: {archive}"
    missing = str(work / "missing.tar")
    trivy_flags = ["--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json"]
    run_case("syft_local_archive_success", ["syft", f"docker-archive:{archive}", "--output", "json"], json_output=True)
    run_case("trivy_local_archive_secret_scan_success", ["trivy", "image", "--input", str(archive),
             "--scanners", "secret", "--offline-scan", "--format", "json"], json_output=True)
    run_case("grype_local_archive_success", ["grype", f"docker-archive:{archive}", "--output", "json"], json_output=True)
    run_case("dockle_local_archive_success", ["dockle", "--input", str(archive), "--format", "json", "alpine:3.20.0"], json_output=True)
    run_case("syft_missing_archive", ["syft", f"docker-archive:{missing}", "--output", "json"], expect_failure=True, expected_code="CAT-UNKNOWN-001")
    run_case("trivy_missing_archive", ["trivy", "image", "--input", missing,
             "--scanners", "secret", "--offline-scan", "--format", "json"], expect_failure=True, expected_code="CAT-TOOL-INPUT-001")
    run_case("trivy_missing_offline_vulnerability_database", ["trivy", "image", "--input", str(archive), *trivy_flags], expect_failure=True, expected_code="CAT-SCANNER-DB-001")
    run_case("grype_missing_sbom", ["grype", f"sbom:{work / 'missing.json'}", "--output", "json"], expect_failure=True, expected_code="CAT-TOOL-INPUT-001")
    run_case("dockle_missing_archive", ["dockle", "--input", missing, "--format", "json", "alpine:3.20.0"], expect_failure=True, expected_code="CAT-TOOL-INPUT-001")
    run_case("copa_missing_report", ["copa", "patch", "--image", "alpine:3.20.0", "--report", str(work / "missing.json"),
                                        "--addr", f"unix://{work / 'missing-buildkit.sock'}"], expect_failure=True, expected_code="CAT-TOOL-INPUT-001")
    run_case("copa_offline_patch_timeout", ["copa", "patch", "--image", "alpine:3.20.0",
                                        "--addr", f"unix://{work / 'missing-buildkit.sock'}", "--timeout", "5s"], expect_failure=True, expected_code="CAT-TIMEOUT-001")
    run_case("syft_real_process_timeout", ["syft", f"docker-archive:{archive}", "--output", "json"], expect_failure=True, timeout=0.001, expected_code="CAT-TIMEOUT-001")
    report["passed"] = sum(case.get("passed", False) for case in report["cases"])
    report["failed"] = len(report["cases"]) - report["passed"]
    save()
    print(json.dumps({"report": str(args.output / "report.json"), "passed": report["passed"], "failed": report["failed"]}), flush=True)
    return int(report["failed"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
