#!/usr/bin/env python3
"""Offline retained-scan identity audit; never imports or manufactures VEX statements.

Verify the pinned capture manifest, replay unchanged scanner identity through the
current resolver before/after SBOM lookup, and separately exercise an explicit
lost-PURL perturbation against a disposable in-memory SQLite component index.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import sqlite3
import statistics
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "22f35d50f4de6d834e3a0c9892dce6359343d461"
PRIMARY = ("ubuntu", "debian-12-9", "alpine-3-20-0", "redhat-ubi", "suse", "python", "node-image-catalogers")
EVIDENCE = "docs/evidence/container-vex-scans"
SOURCE_FILES = ("scripts/audit-sbom-correlation.py", "portal/app/sbom_components.py",
                "portal/app/container_intelligence.py", "portal/app/package_identity_resolution.py",
                "scanning-main/scripts/sbom_identity.py", "scanning-main/scripts/extract-sbom-components.py")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def baseline_file(name):
    return subprocess.run(["git", "show", f"{BASELINE}:{EVIDENCE}/{name}"],
                          cwd=ROOT, check=True, stdout=subprocess.PIPE).stdout


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_summary(identities, resolutions):
    eligible = [candidate for result in resolutions for candidate in result["candidates"]
                if candidate.get("eligible") is True]
    return {"observations": len(identities),
            "sufficient_identity": sum(bool(item["context"]) for item in identities),
            "unresolved_identity": sum(not item["context"] for item in identities),
            "eligible_identity_candidates": len(eligible),
            "eligible_exact_identity_candidates": sum(c["kind"] == "exact_observed" for c in eligible),
            "eligible_derived_identity_candidates": sum(c["kind"] == "authoritative_resolved" for c in eligible),
            "resolver_outcomes": dict(sorted(Counter(r["outcome"] for r in resolutions).items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 10:
        parser.error("--repeats must be between 1 and 10")
    source_hashes = {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}

    # No configured live database, network requests, or external corpus is used.
    os.environ["DATABASE_URL"] = "sqlite://"
    def no_network(*_args, **_kwargs):
        raise RuntimeError("This audit prohibits network access")
    socket.socket.connect = no_network
    sys.path[:0] = [str(ROOT / "portal"), str(ROOT / "scanning-main/scripts")]
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import Session
    from app.database import Base
    from app.models import Service, Execution, Finding
    from app.container_intelligence import observation_identity, observation_identities
    from app.package_identity_resolution import resolve_package_identity, RESOLVER_VERSION
    from app.sbom_components import retain_components, LOOKUP_BATCH, MAX_MATCHES
    from sbom_identity import (artifact_projection, document_binding, document_identity,
                               source_projection)
    extractor = load_module(ROOT / "scanning-main/scripts/extract-sbom-components.py", "audit_extractor")

    manifest_bytes = baseline_file("manifest.json")
    manifest = json.loads(manifest_bytes)
    raw_root = args.raw_evidence or Path(manifest["raw_evidence_directory"])
    now = datetime.now(timezone.utc)
    engine = create_engine("sqlite://")
    # Session hooks maintain ordinary service metadata on commit; keep their
    # tables present too. All setup and writes precede the measured read path.
    Base.metadata.create_all(engine)
    observations, perturbed, provenance, image_counts = [], [], [], {}
    inventories, synthetic = {}, []
    components_total = 0
    with Session(engine) as db:
        db.execute(Service.__table__.insert(), {"id": 1, "name": "Offline retained scan audit", "service_key": "offline-audit"})
        finding_ids = {}
        for execution_id, image_key in enumerate(PRIMARY, 1):
            capture_bytes = baseline_file(image_key + ".json")
            capture = json.loads(capture_bytes)
            entry = next(item for item in manifest["images"] if item["image_key"] == image_key)
            raw_files = []
            for expected in entry["raw_evidence"]:
                raw = (raw_root / expected["name"]).read_bytes()
                actual = {"name": expected["name"], "bytes": len(raw), "sha256": digest(raw)}
                if actual != expected:
                    raise ValueError(f"Raw evidence differs from pinned manifest: {expected['name']}")
                raw_files.append(actual)
            provenance.append({"image_key": image_key, "capture_sha256": digest(capture_bytes),
                               "raw_files": raw_files})
            syft_bytes = (raw_root / (image_key + ".syft.json")).read_bytes()
            syft = json.loads(syft_bytes)
            grype = json.loads((raw_root / (image_key + ".grype.json")).read_bytes())
            inspect = json.loads((raw_root / (image_key + ".image-inspect.json")).read_bytes())
            image_provenance = {"imageID": inspect.get("Id"), "repoDigests": inspect.get("RepoDigests"),
                                "descriptor": inspect.get("Descriptor"), "os": inspect.get("Os"),
                                "architecture": inspect.get("Architecture")}
            if inspect.get("Variant"):
                image_provenance["variant"] = inspect["Variant"]
            binding = document_binding(syft_bytes, syft, capture["image"], image_provenance)
            image_identity = document_identity(syft)
            image_identity.update(binding)
            components = [extractor.normalize(artifact, capture["image"], binding.get("image_digest", ""),
                          image_key + ".syft.json", "Syft", image_identity=image_identity)
                          for artifact in syft["artifacts"]]
            components = [component for component in components if component]
            inventories[execution_id] = components
            components_total += len(components)
            db.execute(Execution.__table__.insert(), {"id": execution_id, "execution_key": image_key,
                "service_id": 1, "scanned_at": now, "complete": True, "raw_payload": {}})
            retain_components(db, execution_id, components)
            artifacts = defaultdict(list)
            for artifact in syft["artifacts"]:
                artifacts[artifact.get("id")].append(artifact)
            def exact_tuple(artifact):
                return tuple(artifact.get(key) for key in ("id", "name", "version", "type", "purl"))
            matches = defaultdict(list)
            for match in grype["matches"]:
                matches[(match["vulnerability"]["id"], exact_tuple(match["artifact"]))].append(match)
            for row in capture["findings"]:
                expected = tuple(row[key] for key in ("artifact_id", "package", "installed_version", "ecosystem", "purl"))
                joined = artifacts[row["artifact_id"]]
                raw_matches = matches[(row["cve"], expected)]
                if len(joined) != 1 or exact_tuple(joined[0]) != expected or len(raw_matches) != 1:
                    raise ValueError(f"Nonunique or changed raw artifact/finding join: {image_key} {expected!r}")
                if row["cve"] not in finding_ids:
                    finding_ids[row["cve"]] = len(finding_ids) + 1
                    db.execute(Finding.__table__.insert(), {"id": finding_ids[row["cve"]], "service_id": 1,
                        "cve": row["cve"], "severity": row.get("severity", "unknown"), "first_seen": now,
                        "episode_started": now, "last_seen": now, "active": True})
                # Both paths receive exactly the same unmodified package tuple and
                # bounded projection of its hash-verified original raw records.
                evidence = deepcopy(row.get("evidence", {}))
                evidence.update(purl=row["purl"], aliases=row.get("aliases", []),
                    scanner_artifact=json.loads(artifact_projection(raw_matches[0]["artifact"])),
                    scanner_distro=grype.get("distro"), scanner_source=source_projection(grype.get("source")),
                    scanner_descriptor={k: v for k, v in grype.get("descriptor", {}).items() if k in ("name", "version", "timestamp")},
                    sbom_artifact=json.loads(artifact_projection(joined[0])), sbom_distro=syft.get("distro"),
                    sbom_source=source_projection(syft.get("source")),
                    sbom_descriptor={k: v for k, v in syft.get("descriptor", {}).items() if k in ("name", "version", "timestamp")})
                observation = SimpleNamespace(evidence=evidence, package=row["package"],
                    installed_version=row["installed_version"], image=capture["image"],
                    image_digest=capture["image_digest"], execution_id=execution_id,
                    finding_id=finding_ids[row["cve"]])
                observations.append(observation)
                changed = deepcopy(observation)
                changed.evidence.pop("purl", None)
                changed.evidence.pop("package_url", None)
                changed.evidence["scanner_artifact"].pop("purl", None)
                for key in ("sbom_artifact", "sbom_distro", "sbom_source", "sbom_descriptor"):
                    changed.evidence.pop(key, None)
                changed.evidence["scanner_component_id"] = row["artifact_id"]
                # This controlled assertion is NOT a scan-time sidecar recovered
                # from the historical run. Its actual digest comes from the
                # hash-verified file, whose exact Grype/Syft tuples joined above.
                changed.evidence["sbom_digest"] = binding["sbom_digest"]
                changed.image_digest = binding.get("image_digest")
                for key in ("image_manifest_digest", "image_platform"):
                    if key in binding:
                        changed.evidence[key] = binding[key]
                perturbed.append(changed)
            image_counts[image_key] = {"components": len(components), "observations": len(capture["findings"]),
                "verified_image_binding_available": bool(binding.get("image_manifest_digest")),
                "verified_manifest_digest": binding.get("image_manifest_digest"),
                "platform": binding.get("image_platform"), "sbom_digest": binding["sbom_digest"]}
        # An explicitly synthetic image scope is useful only for measuring the
        # SQL lookup mechanism with real package record sizes/key distribution.
        # None of these scope digests purports to describe a captured image.
        for execution_id, components in inventories.items():
            synthetic_execution = 100 + execution_id
            synthetic_image = "audit-synthetic-scope/" + PRIMARY[execution_id - 1]
            synthetic_digest = "sha256:" + digest(synthetic_image.encode())
            db.execute(Execution.__table__.insert(), {"id": synthetic_execution,
                "execution_key": synthetic_image, "service_id": 1, "scanned_at": now,
                "complete": True, "raw_payload": {"audit_synthetic_scope": True}})
            retain_components(db, synthetic_execution, [{**component, "image": synthetic_image,
                "image_digest": synthetic_digest, "image_manifest_digest": synthetic_digest,
                "image_platform": "linux/amd64"} for component in components])
            for original in perturbed:
                if original.execution_id != execution_id:
                    continue
                item = deepcopy(original)
                item.execution_id = synthetic_execution
                item.image = synthetic_image
                item.image_digest = synthetic_digest
                item.evidence.update(image_manifest_digest=synthetic_digest, image_platform="linux/amd64")
                synthetic.append(item)
        db.commit()
        original_records = deepcopy([vars(item) for item in observations])
        query_stats, examples = Counter(), []
        def count_query(_conn, _cursor, statement, parameters, _context, _many):
            query_stats["sql_statements"] += 1
            if "sbom_components" in statement.lower():
                query_stats["sbom_lookup_statements"] += 1
                if not examples:
                    examples.append((statement, parameters))
        event.listen(engine, "before_cursor_execute", count_query)
        baseline_identities = [observation_identity(item) for item in observations]
        baseline_resolutions = [resolve_package_identity(item, now=now) for item in baseline_identities]
        new_identities = observation_identities(db, observations)
        complete_queries = dict(query_stats)
        new_resolutions = [resolve_package_identity(item, now=now) for item in new_identities]
        if new_identities != baseline_identities or new_resolutions != baseline_resolutions:
            raise AssertionError("Complete scanner identities changed")
        if query_stats["sbom_lookup_statements"] or query_stats["sql_statements"]:
            raise AssertionError("Complete scanner identities unexpectedly queried the database")
        perturbed_before = [observation_identity(item) for item in perturbed]
        recovered = observation_identities(db, perturbed)
        recovered_resolutions = [resolve_package_identity(item, now=now) for item in recovered]
        statuses = Counter(item.get("sbom_binding", {}).get("status", "no_lookup") for item in recovered)
        reasons = Counter(reason for item in recovered for reason in item.get("sbom_binding", {}).get("reasons", []))
        matched = [i for i, item in enumerate(recovered) if item.get("sbom_binding", {}).get("status") == "matched"]
        for index in matched:
            if recovered[index]["context"] != baseline_identities[index]["context"]:
                raise AssertionError("Recovered identity differs from real original tuple")
        synthetic_recovered = observation_identities(db, synthetic)
        synthetic_statuses = Counter(item.get("sbom_binding", {}).get("status", "no_lookup") for item in synthetic_recovered)
        synthetic_reasons = Counter(reason for item in synthetic_recovered
                                    for reason in item.get("sbom_binding", {}).get("reasons", []))
        synthetic_matches = [i for i, item in enumerate(synthetic_recovered)
                             if item.get("sbom_binding", {}).get("status") == "matched"]
        for index in synthetic_matches:
            if synthetic_recovered[index]["context"] != baseline_identities[index]["context"]:
                raise AssertionError("Synthetic-scope lookup returned a different package tuple")
        performance = []
        for label, workload in (("complete_original_1118", observations),
                ("controlled_lost_purl_1118", perturbed),
                ("synthetic_scope_real_components_1118", synthetic),
                ("synthetic_scope_real_components_repeated_10000", (synthetic * (10000 // len(synthetic) + 1))[:10000])):
            samples = []
            for _ in range(args.repeats):
                query_stats.clear()
                start = time.perf_counter()
                values = observation_identities(db, workload)
                samples.append({"seconds": round(time.perf_counter() - start, 6),
                    "sql_statements": query_stats["sql_statements"],
                    "sbom_lookup_statements": query_stats["sbom_lookup_statements"],
                    "resolved_identities": sum(bool(item["context"]) for item in values)})
            performance.append({"workload": label, "observations": len(workload),
                "distinct_scoped_component_references": len({(item.execution_id, item.image, item.evidence.get("scanner_component_id"))
                    for item in workload if item.image_digest and item.evidence.get("image_platform")
                    and not observation_identity(item)["context"]}), "runs": samples,
                                "median_seconds": statistics.median(item["seconds"] for item in samples)})
        event.remove(engine, "before_cursor_execute", count_query)
        plan_details = []
        if examples:
            statement, parameters = examples[0]
            plan_details = sorted(set(row[3] for row in db.connection().exec_driver_sql(
                "EXPLAIN QUERY PLAN " + statement, parameters) if "sbom_components" in row[3]))
        original_records_preserved = [vars(item) for item in observations] == original_records
        if not original_records_preserved:
            raise AssertionError("Original observation records changed")
        if source_hashes != {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}:
            raise AssertionError("Audit source changed during measurement; rerun after edits finish")
        report = {"schema_version": 1, "audit_kind": "offline_identity_only", "measured_at": now.isoformat(),
            "baseline_ref": BASELINE, "manifest_sha256": digest(manifest_bytes),
            "raw_evidence_directory": str(raw_root.resolve()),
            "comparison": "Current original observation_identity plus unchanged package resolver versus new observation_identities plus the same resolver, on identical raw-record reconstruction. This is not a historical code checkout or VEX corpus comparison.",
            "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                            "platform": platform.platform(), "database": "disposable in-memory SQLite",
                            "network": "blocked", "resolver_version": RESOLVER_VERSION},
            "source_sha256": source_hashes,
            "inputs": provenance,
            "real_scans": {"raw_files_verified": sum(len(item["raw_files"]) for item in provenance),
                "components_retained": components_total, "unique_cve_roots": len(finding_ids),
                "exact_raw_artifact_and_finding_joins": len(observations), "per_image": image_counts,
                "baseline": candidate_summary(baseline_identities, baseline_resolutions),
                "new": candidate_summary(new_identities, new_resolutions),
                "identities_unchanged": len(observations), "resolver_results_unchanged": len(observations),
                "original_records_preserved": original_records_preserved,
                "complete_identity_sql_statements": complete_queries.get("sql_statements", 0),
                "complete_identity_sbom_lookups": complete_queries.get("sbom_lookup_statements", 0)},
            "controlled_perturbation": {"description": "In-memory removal of top-level/scanner-artifact PURL and attached SBOM projection; exact artifact ID retained. Verified capture hash supplied as a controlled consumed-document assertion, not a recovered scan-time sidecar. Image manifest/platform accepted only by current scanner verifier.",
                "before_sufficient_identity": sum(bool(item["context"]) for item in perturbed_before),
                "after": candidate_summary(recovered, recovered_resolutions),
                "binding_statuses": dict(sorted(statuses.items())), "binding_reasons": dict(sorted(reasons.items())),
                "matched_context_equals_real_original": len(matched),
                "matched_candidate_sets_equal_real_original": sum(recovered_resolutions[i]["candidates"] == baseline_resolutions[i]["candidates"] for i in matched),
                "per_image": {key: dict(sorted(Counter(recovered[i].get("sbom_binding", {}).get("status", "no_lookup")
                    for i, item in enumerate(observations) if item.execution_id == number).items()))
                    for number, key in enumerate(PRIMARY, 1)}},
            "synthetic_scope_microbenchmark": {
                "description": "The same real package rows are assigned an artificial execution/image name, synthetic sha256 image-manifest digest and linux/amd64 scope in disposable SQLite. The actual SBOM byte digest and exact package tuples remain unchanged. This is a lookup-mechanism fixture, not verified real-image identity recovery or VEX coverage.",
                "observations": len(synthetic), "binding_statuses": dict(sorted(synthetic_statuses.items())),
                "binding_reasons": dict(sorted(synthetic_reasons.items())),
                "matched_context_equals_real_original": len(synthetic_matches),
                "trusted_applicability_evaluated": False},
            "performance": {"scope": "identity recovery only; excludes inventory ingest, package resolver, VEX/advisory evaluation and network; warmed same-process repeated runs on a shared host; repeated observations add load, not findings",
                "lookup_batch": LOOKUP_BATCH, "maximum_rows_per_exact_key": MAX_MATCHES + 1,
                "sqlite_lookup_plan": plan_details, "workloads": performance},
            "vex": {"new_corpus_evaluation_performed": False, "new_trusted_applicable_count": None,
                "new_excluded_count": None, "historical_trusted_applicable_count": 0,
                "historical_source": "docs/evidence/authoritative-package-identity/README.md",
                "limitation": "No imported PostgreSQL VEX corpus available. Identity candidates are not VEX statements. No synthetic VEX was inserted. Legacy captures lack the new scan-time consumed-SBOM sidecar; the perturbation is not production backfill evidence."}}
    engine.dispose()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "real_scans": report["real_scans"]["new"],
                      "controlled_binding_statuses": report["controlled_perturbation"]["binding_statuses"]}))


if __name__ == "__main__":
    main()
