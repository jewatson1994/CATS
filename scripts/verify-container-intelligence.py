#!/usr/bin/env python3
"""Read-only coverage and benchmark of retained real scanner evidence.

Run in the application Python environment, with DATABASE_URL selecting an
isolated, already imported PostgreSQL database. This never imports a package,
creates schema, mutates findings, or draws product identity from image labels.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import sys
import threading
import time
from types import SimpleNamespace

PRIMARY = ["ubuntu", "debian-12-9", "alpine-3-20-0", "redhat-ubi", "suse",
           "python", "node-image-catalogers"]
BATCH_SIZE = 250


def write(path, data):
    path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rss_bytes():
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return 0


def memory_sample(stop, samples):
    while not stop.wait(0.01):
        samples.append(rss_bytes())


def logical_id(row):
    # The portal enforces unique(service_id, cve); this audit is one service.
    return hashlib.sha256(row["cve"].encode()).hexdigest()


def package_identity_id(row):
    return hashlib.sha256(json.dumps([row.get(k) for k in
        ("cve", "package", "installed_version", "purl")]).encode()).hexdigest()


def ecosystem(purl):
    # Reporting grouping only, never an input to identity matching.
    return purl[4:].split("/", 1)[0] if isinstance(purl, str) and purl.startswith("pkg:") else "unknown"


def compact_report(report, details, options):
    """Keep measured results and bounded examples; hash the complete raw evidence."""
    result = {key: value for key, value in report.items() if key != "query_plans"}
    result["retained_raw_files"] = {
        path.name: {"sha256": sha(path), "bytes": path.stat().st_size}
        for path in (options.report, options.details)
    }
    result["query_plan_summaries"] = {}
    for label, evidence in report["query_plans"].items():
        plan = evidence["plan"][0]
        nodes, scans = Counter(), {}
        def walk(node):
            nodes[node["Node Type"]] += 1
            if node.get("Relation Name") or node.get("Index Name"):
                key = (node["Node Type"], node.get("Relation Name"), node.get("Index Name"))
                entry = scans.setdefault(key, {"node_type": key[0], "relation": key[1],
                    "index": key[2], "nodes": 0, "maximum_actual_rows": 0, "maximum_actual_loops": 0})
                entry["nodes"] += 1
                entry["maximum_actual_rows"] = max(entry["maximum_actual_rows"], node.get("Actual Rows", 0))
                entry["maximum_actual_loops"] = max(entry["maximum_actual_loops"], node.get("Actual Loops", 0))
            for child in node.get("Plans", []):
                walk(child)
        walk(plan["Plan"])
        result["query_plan_summaries"][label] = {
            "sql_sha256": hashlib.sha256(evidence["sql"].encode()).hexdigest(),
            "planning_time_ms": plan.get("Planning Time"),
            "execution_time_ms": plan.get("Execution Time"),
            "root_shared_hit_blocks": plan["Plan"].get("Shared Hit Blocks"),
            "root_shared_read_blocks": plan["Plan"].get("Shared Read Blocks"),
            "node_types": dict(nodes), "relation_index_scans": list(scans.values()),
            "full_plan_location": options.report.name + "#query_plans." + label}
    # One example per image/ecosystem and additional distinct normalization/absence
    # cases. These are scanner results, not synthetic successful applicability cases.
    selected, categories = [], set()
    for row in details:
        if row["image_key"] not in PRIMARY:
            continue
        keys = {(row["image_key"], ecosystem(row["purl"]))}
        if row["identity"].get("version_normalization"):
            keys.add(("normalization", row["identity"]["version_normalization"]["kind"]))
        if row["vex"].get("cve_present") is False:
            keys.add(("cve_absent", row["image_key"]))
        if row["advisory"].get("has_current"):
            keys.add(("current_advisory", row["image_key"], ecosystem(row["purl"])))
        if keys <= categories:
            continue
        categories.update(keys)
        selected.append({key: row[key] for key in ("image_key", "cve", "package", "installed_version", "purl")} |
            {"identity": {key: row["identity"].get(key) for key in
                ("raw_installed_version", "version_normalization", "context", "reasons")},
             "vex": {key: row["vex"].get(key) for key in
                ("status", "applicability_state", "exact_candidate_count", "cve_present", "reasons", "rejected_candidates")},
             "advisory": row["advisory"], "kev": row["kev"], "epss": row["epss"]})
        if len(selected) == 40:
            break
    result["representative_actual_observations"] = selected
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--details", type=Path, required=True)
    parser.add_argument("--summary", type=Path, help="Optional bounded evidence projection")
    parser.add_argument("--app-path", type=Path, default=Path("/workspace/portal"))
    parser.add_argument("--as-of", help="Explicit diagnostic time, recorded in report; default current UTC")
    parser.add_argument("--coverage-only", action="store_true")
    options = parser.parse_args()
    sys.path.insert(0, str(options.app_path))
    from sqlalchemy import create_engine, event, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker
    url = make_url(os.environ["DATABASE_URL"])
    if url.get_backend_name() != "postgresql" or url.host not in ("localhost", "127.0.0.1", "::1"):
        parser.error("DATABASE_URL must select the isolated loopback PostgreSQL database")
    original_connect = socket.socket.connect
    def guarded_connect(sock, address):
        if isinstance(address, tuple) and address[0] in ("localhost", "127.0.0.1", "::1") and address[1] == (url.port or 5432):
            return original_connect(sock, address)
        raise RuntimeError("External network access is prohibited during offline verification")
    socket.socket.connect = guarded_connect
    engine = create_engine(url, pool_size=5, max_overflow=0,
        connect_args={"options": "-c default_transaction_read_only=on -c statement_timeout=60000"})
    factory = sessionmaker(bind=engine)
    from app.container_intelligence import (observation_identity, evaluate_container_batch,
        advisory_batch, coverage_report, ECOSYSTEMS)
    from app.packaged_risk_intelligence import overlay_packaged_kev, overlay_packaged_epss
    from app.vex_intelligence import _item_cves
    code_hashes = {name: sha(options.app_path / "app" / name) for name in
        ("container_intelligence.py", "vex_intelligence.py", "packaged_risk_intelligence.py")}
    now = datetime.fromisoformat(options.as_of.replace("Z", "+00:00")) if options.as_of else datetime.now(timezone.utc)
    if now.tzinfo is None:
        parser.error("--as-of must contain a timezone")
    local = threading.local()
    query_examples, query_shapes = {}, Counter()
    lock = threading.Lock()

    @event.listens_for(engine, "before_cursor_execute")
    def observe(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("EXPLAIN"):
            return
        if hasattr(local, "queries"):
            local.queries += 1
        normalized = " ".join(statement.split())
        if "vex_documents.raw_text" in normalized:
            raise AssertionError("Assessment must not retrieve raw VEX documents")
        label = None
        if "wanted_cves" in statement:
            label = "vex_cve_presence"
        elif "vex_statements" in statement and "product_id" in statement:
            label = "vex_exact_pairs"
        elif "FROM intelligence_records" in statement and "affected" in statement:
            label = "advisory_membership"
        elif "FROM intelligence_records" in statement and "intelligence_package_members" in statement:
            label = ("epss_membership" if normalized.startswith(
                "SELECT intelligence_records.cve, intelligence_records.data ") else "kev_membership")
        if label:
            with lock:
                query_examples.setdefault(label, (statement, parameters))
                query_shapes[label] += 1

    captures = {}
    records = []
    for entry in json.loads((options.evidence / "manifest.json").read_text())["images"]:
        path = options.evidence / (entry["image_key"] + ".json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["capture_kind"] == "live_scan"
        assert data["capture"]["scanner_exit_code"] == 0
        captures[data["image_key"]] = data
        for row in data["findings"]:
            evidence = {**row.get("evidence", {}), "purl": row["purl"],
                "aliases": row.get("aliases", []), "scanner_distro": data["distro"],
                "scanner_source": data["sbom_source"],
                "scanner_artifact": {"id": row["artifact_id"], "name": row["package"],
                    "version": row["installed_version"], "type": row["ecosystem"],
                    "metadata": row.get("evidence", {}).get("artifact_metadata", {})}}
            identity = observation_identity(SimpleNamespace(evidence=evidence,
                installed_version=row["installed_version"], image_digest=data["image_digest"]))
            records.append({"image_key": data["image_key"], "image": data["image"],
                "image_digest": data["image_digest"], "finding_id": logical_id(row),
                "package_identity_id": package_identity_id(row),
                "row": row, "item": {"cve": row["cve"], "aliases": row.get("aliases", []),
                    "context": identity["context"], "identity": identity}})
    primary = [record for record in records if record["image_key"] in PRIMARY]
    assert len({record["image_key"] for record in primary}) == 7

    def evaluate(workload, *, keep=False):
        local.queries = 0
        started, cpu_started = time.perf_counter(), time.process_time()
        stop, samples = threading.Event(), [rss_bytes()]
        sampler = threading.Thread(target=memory_sample, args=(stop, samples), daemon=True)
        sampler.start()
        details, status_counts = [], Counter()
        try:
            with factory() as db:
                for start in range(0, len(workload), BATCH_SIZE):
                    part = workload[start:start + BATCH_SIZE]
                    items = [record["item"] for record in part]
                    vex = evaluate_container_batch(db, items, now)
                    advisory = advisory_batch(db, items, now)
                    cves = sorted({cve for item in items for cve in _item_cves(item)})
                    snapshot = {"kev": {"state": "MISSING"}, "epss": {"state": "MISSING"},
                        "findings": {cve: {"kev": None, "epss": None} for cve in cves}}
                    snapshot = overlay_packaged_kev(db, snapshot, now)
                    snapshot = overlay_packaged_epss(db, snapshot, now)
                    for record, result, enrichment in zip(part, vex, advisory):
                        status_counts[result.get("applicability_state", result["status"])] += 1
                        if keep:
                            signals = [snapshot["findings"].get(cve, {}) for cve in _item_cves(record["item"])]
                            scores = [signal["epss"] for signal in signals
                                if isinstance(signal.get("epss"), (int, float)) and not isinstance(signal["epss"], bool)]
                            details.append({k: record[k] for k in ("image_key", "image", "image_digest", "finding_id")} |
                                {"cve": record["row"]["cve"], "package": record["row"]["package"],
                                 "installed_version": record["row"]["installed_version"], "purl": record["row"]["purl"],
                                 "identity": record["item"]["identity"], "vex": result, "advisory": enrichment,
                                 "kev": True if any(signal.get("kev") is True for signal in signals) else None,
                                 "epss": max(scores) if scores else None})
        finally:
            stop.set()
            sampler.join()
            samples.append(rss_bytes())
        return {"observations": len(workload), "distinct_findings": len({record["finding_id"] for record in workload}),
            "distinct_package_identities": len({record["package_identity_id"] for record in workload}),
            "batches": (len(workload) + BATCH_SIZE - 1) // BATCH_SIZE,
            "queries": local.queries, "seconds": round(time.perf_counter() - started, 6),
            "process_cpu_seconds": round(time.process_time() - cpu_started, 6),
            "sampled_process_peak_rss_bytes": max(samples),
            "process_lifetime_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            "status_counts": dict(status_counts)}, details

    def coverage(details):
        grouped = {}
        for index, row in enumerate(details):
            grouped.setdefault(row["finding_id"], {"finding_id": row["finding_id"],
                "cve": row["cve"], "observations": []})["observations"].append({
                    "observation_id": index + 1, "image": row["image"],
                    "image_digest": row["image_digest"], "vex": row["vex"],
                    "advisory": row["advisory"], "kev": row["kev"], "epss": row["epss"]})
        result = coverage_report(list(grouped.values()), now)
        result["scanner_observations"] = len(details)
        result["distinct_package_identities"] = len({package_identity_id(row) for row in details})
        result["percentages"] = {key: round(100 * value / result["total_findings"], 4)
            if result["total_findings"] else None for key, value in result["counts"].items()}
        result["statuses"] = dict(Counter(row["vex"].get("applicability_state", row["vex"]["status"]) for row in details))
        result["reasons"] = dict(Counter(reason for row in details for reason in row["vex"].get("reasons", [])))
        result["exact_candidate_rows"] = sum(row["vex"].get("exact_candidate_count", 0) for row in details)
        result["advisory_references"] = sum(len(row["advisory"].get("records", [])) for row in details)
        result["advisory_current_references"] = sum(bool(ref.get("current")) for row in details for ref in row["advisory"].get("records", []))
        return result

    with factory() as db:
        database = db.execute(text("SELECT current_setting('transaction_read_only') AS read_only, version() AS version")).mappings().one()
        assert database["read_only"] == "on"
        installed = db.execute(text("SELECT version, sequence, counts, installed_at FROM intelligence_package_installs ORDER BY sequence DESC LIMIT 1")).mappings().one()
        catalogs = list(db.execute(text("SELECT source_key, kind, record_count, metadata_json FROM intelligence_package_catalogs WHERE install_id = (SELECT id FROM intelligence_package_installs ORDER BY sequence DESC LIMIT 1) ORDER BY source_key")).mappings())
        indexes = list(db.execute(text("SELECT tablename, indexname, indexdef FROM pg_indexes WHERE tablename IN ('vex_statements','vex_documents','intelligence_records','intelligence_package_members') ORDER BY tablename,indexname")).mappings())
    print("Evaluating all real capture findings", flush=True)
    coverage_measurement, details = evaluate(records, keep=True)
    write(options.details, {"as_of": now.isoformat(), "source": "actual scanner observations; original exact PURLs", "findings": details})
    primary_details = [row for row in details if row["image_key"] in PRIMARY]
    per_image = []
    for key, captured in captures.items():
        per_image.append({"image_key": key, "primary_family_sample": key in PRIMARY,
            "image_digest": captured["image_digest"], "scanner_counts": captured["counts"],
            "coverage": coverage([row for row in details if row["image_key"] == key])})
    ecosystems = []
    for kind in sorted(set(ECOSYSTEMS) | {ecosystem(row["row"].get("purl")) for row in primary}):
        selected_details = [row for row in primary_details if ecosystem(row.get("purl")) == kind]
        ecosystems.append({"ecosystem": kind, "live_scanner_observations": len(selected_details),
            "live_validation": bool(selected_details), "advisory_supported": kind in ECOSYSTEMS or kind == "apk",
            "coverage": coverage(selected_details)})
    report = {"schema_version": 1, "as_of": now.isoformat(),
        "mode": "historical_diagnostic" if options.as_of else "current_time",
        "database": dict(database), "installed_package": dict(installed),
        "catalogs": [dict(row) for row in catalogs], "indexes": [dict(row) for row in indexes],
        "code_sha256": code_hashes,
        "verifier_sha256": sha(Path(__file__)),
        "input_sha256": {key + ".json": sha(options.evidence / (key + ".json")) for key in captures},
        "primary_image_keys": PRIMARY, "per_image": per_image, "per_ecosystem": ecosystems,
        "primary_service": coverage(primary_details), "all_captures": coverage(details),
        "coverage_measurement": coverage_measurement,
        "measurement_notes": [
            "No database mutations or schema/import operations. PostgreSQL enforces read-only transactions.",
            "No vendor context inferred from distribution names, SBOM CPEs or OCI labels.",
            "The Grype --only-fixed filter defines the scanner denominator; zero findings are preserved.",
            "One audit service: finding IDs deduplicate scanner CVE IDs, matching unique(service_id,cve). Package and image observations remain separate; coverage flags are unioned per finding.",
            "Scanner observation counts, distinct package identities, statuses, reasons and advisory reference counts are occurrence-level metrics; coverage counts and percentages use unique finding IDs.",
            "1,000 and 10,000 workloads repeat actual primary capture observations; they are scaling tests, not additional scanned findings.",
            "Each query workload uses batches of 250 and includes VEX diagnostics, advisory references, KEV and EPSS.",
            "Process RSS includes loaded input evidence and Python runtime; lifetime peak is cumulative across sequential scenarios.",
            "Concurrent jobs have separate SQLAlchemy sessions; their sampled process RSS overlaps and must not be added.",
            "The /proc RSS samples and getrusage lifetime maximum are separate Linux accounting observations; both are retained without treating their difference as extra memory.",
            "Concurrent job CPU durations cover the shared Python process, so they overlap and must not be summed. Database server memory and CPU are not measured.",
            "No cold-cache claim: PostgreSQL and operating-system caches remain populated.",
            "These real inputs have zero exact VEX candidates: timings exercise the unmatched-identity path plus actual advisory, KEV and EPSS lookups. High-fanout positive VEX candidates are not performance-validated by this sample.",
            "Supplemental advisory version ranges are retained references, not a second vulnerability scanner.",
            "The presence lookup retains one indexed different-product example; it does not enumerate all mismatching products.",
        ]}
    write(options.report, report)
    if not options.coverage_only:
        scenarios = [("single_finding", primary[:1]), ("batch_250", (primary * (250 // len(primary) + 1))[:250]),
            ("1000_observations", (primary * (1000 // len(primary) + 1))[:1000]),
            ("10000_observations", (primary * (10000 // len(primary) + 1))[:10000]),
            ("multiple_images_one_service", primary)]
        report["benchmarks"] = []
        for name, workload in scenarios:
            print(f"Benchmark {name}: {len(workload)} observations", flush=True)
            metric, _ = evaluate(workload)
            report["benchmarks"].append({"name": name, **metric})
            write(options.report, report)
        print("Benchmark four concurrent jobs, 1,000 observations each", flush=True)
        workload = (primary * (1000 // len(primary) + 1))[:1000]
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            jobs = list(executor.map(lambda _: evaluate(workload)[0], range(4)))
        report["concurrent"] = {"jobs": 4, "observations_per_job": 1000,
            "seconds_wall": round(time.perf_counter() - started, 6), "queries": sum(job["queries"] for job in jobs),
            "process_lifetime_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            "job_metrics": jobs}
    report["query_shapes_observed"] = dict(query_shapes)
    report["query_plans"] = {}
    with engine.connect() as connection:
        for label, (statement, parameters) in query_examples.items():
            plan = connection.exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + statement, parameters).scalar()
            report["query_plans"][label] = {"sql": statement, "parameters": parameters, "plan": plan}
    report["details_sha256"] = sha(options.details)
    report["code_unchanged_during_run"] = all(
        sha(options.app_path / "app" / name) == value for name, value in code_hashes.items())
    write(options.report, report)
    if options.summary:
        write(options.summary, compact_report(report, details, options))
    print(json.dumps({"report": str(options.report), "observations": len(records),
        "primary_service": report["primary_service"]["counts"],
        "benchmarks": report.get("benchmarks", []), "concurrent": report.get("concurrent")}, default=str), flush=True)
    engine.dispose()


if __name__ == "__main__":
    main()
