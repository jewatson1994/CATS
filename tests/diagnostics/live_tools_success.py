"""Successful Trivy/Copa acceptance through the current durable worker boundary.

Requires real Docker and BuildKit services, a pre-downloaded Trivy database, and
an already-pulled vulnerable image. Run in the tools image with current source:
  python /workspace/tests/diagnostics/live_tools_success.py \
    --image docker.io/library/alpine@sha256:DIGEST --patched-tag acceptance-patched \
    --docker-host unix:///var/run/docker.sock \
    --buildkit-addr unix:///run/acceptance-buildkit/buildkitd.sock \
    --cache-dir /trivy-cache --output /evidence/success

The report documents the command-adapter/worker boundary, not the complete
application patch pipeline. Original scanner JSON stays in temporary storage;
published JSON copies are sanitized. Image archives contain the requested image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import traceback


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def os_results(document):
    return [result for result in document.get("Results", []) if result.get("Class") == "os-pkgs"]


def findings(document, *, fixable=False):
    """Compare CVE/package identities without treating changed versions as fixes."""
    return {
        (item["PkgName"], item["VulnerabilityID"]): item
        for result in os_results(document)
        for item in result.get("Vulnerabilities") or []
        if not fixable or str(item.get("FixedVersion") or "").strip()
    }


def package_versions(document):
    versions = {}
    for result in os_results(document):
        for item in result.get("Packages") or []:
            versions.setdefault(item["Name"], set()).add(item["Version"])
    return versions


def compare(before, after):
    original = findings(before, fixable=True)
    remaining = findings(after)
    before_versions, after_versions = package_versions(before), package_versions(after)
    assert original, "Source image has no fixable OS vulnerabilities; acceptance cannot prove remediation"
    assert before_versions and after_versions, "Trivy did not return package inventories"
    removed = sorted(set(original) - set(remaining))
    assert removed, "None of the original fixable package/CVE findings were removed"
    affected = sorted({package for package, _ in original})
    changes = []
    for package in affected:
        assert package in before_versions, f"Source inventory omitted vulnerable package {package}"
        assert package in after_versions, f"Patched inventory lost vulnerable package {package}"
        if before_versions[package] != after_versions[package]:
            changes.append({"package": package, "before": sorted(before_versions[package]),
                            "after": sorted(after_versions[package])})
    assert changes, "No affected installed package version changed"
    changed_packages = {item["package"] for item in changes}
    assert all(package in changed_packages for package, _ in removed), "A removed finding lacks a package-version change"
    return {
        "before_os_findings": len(findings(before)), "after_os_findings": len(remaining),
        "before_fixable_findings": len(original),
        "original_fixable_findings_remaining": len(set(original) & set(remaining)),
        "removed_fixable_findings": [
            {"package": package, "vulnerability_id": vulnerability,
             "installed_version": original[(package, vulnerability)]["InstalledVersion"],
             "fixed_version": original[(package, vulnerability)]["FixedVersion"]}
            for package, vulnerability in removed
        ],
        "package_version_changes": changes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", required=True)
    parser.add_argument("--patched-tag", required=True, help="New tag in the source repository")
    parser.add_argument("--docker-host", default=os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock"))
    parser.add_argument("--buildkit-addr", required=True)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=900, help="Maximum seconds per command")
    args = parser.parse_args()
    if not re.search(r"@sha256:[0-9a-f]{64}$", args.image):
        parser.error("--image must use an immutable sha256 digest to bind Docker and BuildKit to the same source")
    if not re.fullmatch(r"[\w][\w.-]{0,127}", args.patched_tag, flags=re.ASCII):
        parser.error("--patched-tag must be a Docker tag, not an image reference")
    if args.timeout < 30:
        parser.error("--timeout must be at least 30 seconds")
    repository = args.image.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    patched_image = f"{repository}:{args.patched_tag}"
    if patched_image == args.image:
        parser.error("--patched-tag must differ from the source image tag")
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cats-live-success-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{work / 'jobs.db'}"
    os.environ["CATS_JOB_MAX_RUNTIME_SECONDS"] = "0"
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "portal"))

    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import sessionmaker
    from app import models  # Register foreign-key targets; no production DB.
    from app.diagnostic_store import DiagnosticEvent
    from app.diagnostics import correlation, sanitize
    from app.durable_jobs import DurableJob, claim, execute, submit
    from app.patching import run_command

    engine = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    DurableJob.__table__.create(engine)
    DiagnosticEvent.__table__.create(engine)
    env = {**os.environ, "DOCKER_HOST": args.docker_host, "TRIVY_CACHE_DIR": str(args.cache_dir),
           "TRIVY_SKIP_CHECK_UPDATE": "true"}
    report = {
        "schema_version": 1, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "boundary": "current patching.run_command -> durable_jobs.execute -> committed jobs and diagnostic history",
        "scope": "Real Trivy OS vulnerability scan, Copa patch, exported patched image and same-DB rescan; not the complete application patch pipeline",
        "image": args.image, "patched_image": patched_image,
        "docker_host": args.docker_host, "buildkit_addr": args.buildkit_addr,
        "versions": {}, "database": {}, "images": {}, "artifacts": {}, "cases": [],
    }

    def scrub(value):
        # Apply production redaction to every scalar/key without its diagnostic
        # node-count limit silently truncating complete vulnerability evidence.
        if isinstance(value, dict):
            return {str(key): ("[REDACTED]" if sanitize({str(key): "value"}).get(str(key)) == "[REDACTED]"
                               else scrub(item)) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return sanitize(value)

    def save():
        (args.output / "report.json").write_text(json.dumps(scrub(report), indent=2), encoding="utf-8")

    def artifact(name, path):
        value = {"path": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)}
        report["artifacts"][name] = value
        return value

    def run_case(name, operation):
        entry = {"name": name, "commands": []}
        report["cases"].append(entry)
        logs, started = [], time.monotonic()
        try:
            with factory() as db:
                job_id = submit(db, kind="external_tool_acceptance", payload={}, max_attempts=1).id
            job = claim(["external_tool_acceptance"], "live-tools-success", factory)
            assert job is not None and job.id == job_id

            def handler(ctx, payload):
                assert correlation.get() == job.correlation_id
                ctx.stage("Acceptance input prepared", 10)

                def command(argv, *, stdout_path=None):
                    entry["commands"].append(scrub(argv))
                    ctx.stage(f"Running {argv[0]}", 20)
                    result = run_command(argv, env=env, log=logs.append, timeout=args.timeout,
                                         stdout_path=stdout_path, checkpoint=ctx.check)
                    assert result.returncode == 0
                    return result

                return operation(command)

            execute(job, handler, factory)
            with factory() as db:
                row = db.get(DurableJob, job_id)
                count = db.scalar(select(func.count()).select_from(DiagnosticEvent).where(
                    DiagnosticEvent.correlation_id == row.correlation_id))
                entry.update(job_id=row.id, status=row.status, attempts=row.attempts,
                             worker_id=row.worker_id, correlation_id=row.correlation_id,
                             lease_cleared=row.lease_token is None and row.lease_until is None,
                             progress=row.progress, result=row.result, error=row.error,
                             diagnostic_history_count=count)
                assert row.status == "completed", row.result
                assert row.completed_at is not None and entry["lease_cleared"]
                assert row.attempts == 1 and row.worker_id == "live-tools-success"
                assert row.progress == 100 and row.error is None
                assert "diagnostic" not in row.result and count == 0
            entry["passed"] = True
        except Exception as exc:
            entry.update(passed=False, assertion_error=sanitize(str(exc)),
                         assertion_traceback=sanitize(traceback.format_exc()))
            raise
        finally:
            entry["elapsed_seconds"] = round(time.monotonic() - started, 3)
            entry["tool_log_tail"] = sanitize("\n".join(logs)[-10000:])
            save()
            print(json.dumps({key: entry.get(key) for key in (
                "name", "passed", "status", "elapsed_seconds", "assertion_error")}), flush=True)

    documents = {}

    def preflight(command):
        for tool, argv in (("trivy", ["trivy", "--version"]), ("copa", ["copa", "--version"]),
                           ("docker", ["docker", "version", "--format", "{{json .}}"]),
                           ("installed_buildkit_binary", ["buildkitd", "--version"])):
            result = command(argv)
            report["versions"][tool] = sanitize((result.stdout or "") + (result.stderr or ""))
        # A stale tag must never pass the post-patch assertions if Copa does not
        # produce a new output. Normalize Docker Hub's equivalent short names.
        def canonical(reference):
            for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
                if reference.startswith(prefix):
                    reference = reference[len(prefix):]
                    break
            return reference if "/" in reference else f"library/{reference}"

        existing = command(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
        assert canonical(patched_image) not in {canonical(line.strip()) for line in existing.stdout.splitlines()}, "Patched tag already exists; choose a fresh --patched-tag"
        metadata = args.cache_dir / "db" / "metadata.json"
        database = args.cache_dir / "db" / "trivy.db"
        assert metadata.is_file() and database.is_file(), "Download the genuine Trivy vulnerability DB before running"
        report["database"] = {"metadata": json.loads(metadata.read_text(encoding="utf-8")),
                              "bytes": database.stat().st_size, "sha256": sha256(database)}
        assert report["database"]["bytes"] > 0
        assert report["database"]["metadata"].get("Version") == 2, "Expected the Trivy schema-2 vulnerability DB"
        return {"tools_verified": list(report["versions"]), "database_sha256": report["database"]["sha256"]}

    def export_image(command, label, reference):
        inspected = json.loads(command(["docker", "image", "inspect", reference]).stdout)[0]
        identity = {key: inspected.get(key) for key in ("Id", "RepoTags", "RepoDigests", "Os", "Architecture")}
        report["images"][label] = identity
        archive = args.output / f"{label}.tar"
        command(["docker", "image", "save", "--output", str(archive), reference])
        assert archive.is_file() and archive.stat().st_size > 0
        if label == "after":
            assert identity["Id"] != report["images"]["before"]["Id"], "Patch produced the original image ID"
        return {"image": identity, "archive": artifact(f"{label}_archive", archive)}

    def scan(command, label):
        raw = work / f"{label}.trivy.json"
        command(["trivy", "image", "--input", str(args.output / f"{label}.tar"),
                 "--cache-dir", str(args.cache_dir), "--skip-db-update", "--skip-java-db-update",
                 "--offline-scan", "--scanners", "vuln", "--pkg-types", "os", "--list-all-pkgs",
                 "--format", "json"], stdout_path=raw)
        document = json.loads(raw.read_text(encoding="utf-8"))
        documents[label] = document
        assert document.get("SchemaVersion") == 2, "Unexpected Trivy report schema"
        assert document.get("Metadata", {}).get("OS", {}).get("Family"), "Trivy did not identify the operating system"
        assert os_results(document), "Trivy returned no operating-system results"
        assert document.get("Metadata", {}).get("ImageID") == report["images"][label]["Id"], "Trivy scanned an unexpected image"
        published = args.output / f"{label}.trivy.json"
        published.write_text(json.dumps(scrub(document), indent=2), encoding="utf-8")
        result = {"report": artifact(f"{label}_trivy", published), "copa_input_sha256": sha256(raw),
                  "os_findings": len(findings(document)), "fixable_os_findings": len(findings(document, fixable=True)),
                  "os_packages": len(package_versions(document))}
        if label == "before":
            assert result["fixable_os_findings"] > 0, "Choose an image with real fixable vulnerabilities"
        else:
            report["comparison"] = compare(documents["before"], document)
            unchanged = sha256(args.cache_dir / "db" / "trivy.db") == report["database"]["sha256"]
            report["database"]["unchanged_during_acceptance"] = unchanged
            assert unchanged, "Trivy database changed between before and after scans"
            result["removed_fixable_findings"] = len(report["comparison"]["removed_fixable_findings"])
            result["changed_packages"] = len(report["comparison"]["package_version_changes"])
        return result

    def patch(command):
        command(["copa", "patch", "--image", args.image, "--report", str(work / "before.trivy.json"),
                 "--scanner", "trivy", "--tag", args.patched_tag, "--loader", "docker",
                 "--addr", args.buildkit_addr, "--timeout", f"{args.timeout - 15}s"])
        return {"patched_image": patched_image, "source_report_sha256": sha256(work / "before.trivy.json")}

    try:
        run_case("real_tool_and_database_preflight", preflight)
        run_case("source_image_export", lambda command: export_image(command, "before", args.image))
        run_case("trivy_vulnerability_scan_success", lambda command: scan(command, "before"))
        run_case("copa_patch_success", patch)
        run_case("patched_image_export", lambda command: export_image(command, "after", patched_image))
        run_case("trivy_patched_image_rescan_success", lambda command: scan(command, "after"))
    except Exception as exc:
        report["failure"] = sanitize(str(exc))
    finally:
        report["passed"] = sum(case.get("passed", False) for case in report["cases"])
        report["failed"] = sum(not case.get("passed", False) for case in report["cases"])
        report["completed_all_cases"] = len(report["cases"]) == 6 and report["failed"] == 0
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save()
        engine.dispose()
    print(json.dumps({"report": str(args.output / "report.json"), "passed": report["passed"],
                      "failed": report["failed"], "completed_all_cases": report["completed_all_cases"]}), flush=True)
    return int(not report["completed_all_cases"])


if __name__ == "__main__":
    raise SystemExit(main())
