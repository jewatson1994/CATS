"""Adapt safe Compose discovery to the existing scan job and evidence formats."""
from __future__ import annotations

import copy
import json
import hashlib
import tarfile
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .compose_ingestion import discover


def prepare_compose(inputs: Path, payload: dict) -> dict | None:
    if not payload.get("compose_enabled"):
        return None
    root = inputs / ".cats-compose"
    try:
        model = discover(root, payload.get("compose_files") or [], payload.get("compose_profiles") or [])
    finally:
        # The scanner copies inputs to its reports. Private source bytes must
        # never cross this boundary, even when discovery fails or is partial.
        if root.exists():
            shutil.rmtree(root)
    references = list(dict.fromkeys([*str(payload.get("image_list") or "").splitlines(), *model["images"]]))
    if len(references) > int(os.getenv("CATS_PUBLIC_MAX_IMAGES", "50")):
        raise ValueError("Compose resolves too many images; split the deployment or increase CATS_PUBLIC_MAX_IMAGES")
    payload["image_list"] = "\n".join(references)
    (inputs / "images.txt").write_text(payload["image_list"] + "\n", encoding="utf-8")
    (inputs / "compose-discovery.json").write_text(json.dumps(model), encoding="utf-8")
    return model


def _load(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def finalize_compose(output: Path, model: dict, preview: bool = False) -> None:
    model = copy.deepcopy(model)
    summary = _load(output / "scan-summary.json", {"status": "incomplete", "images": 0, "findings": 0})
    result = _load(output / "portal-result.json", {
        "schema_version": "1.0", "execution_id": "compose-discovery",
        "scanned_at": datetime.now(timezone.utc).isoformat(), "complete": False,
        "service": {"id": "compose-service", "name": "Compose deployment", "version": "Unversioned"},
        "findings": [], "policy_findings": [], "sbom_images": [], "sbom_components": [],
    })
    skipped = result.get("skipped_images") or summary.get("skipped_images") or []
    skipped_refs = {str(item).split(" :: ", 1)[0] for item in skipped} if isinstance(skipped, list) else set()
    scanned = set(result.get("sbom_images") or []) - skipped_refs
    if summary.get("status") != "complete" or (output / "scan-failure.json").exists():
        scanned = set()
    ports, dependencies, images = [], [], []
    for service in model["services"]:
        name, reference, config = service["name"], service.get("image"), service["configuration"]
        eligible = config.get("scan_eligible", bool(reference))
        status = "not_scanned" if preview else "blocked" if not eligible else "complete" if reference in scanned else "incomplete"
        service["image_scan"] = status
        if reference:
            images.append({"image": reference, "discovered_from": "Compose service " + name,
                           "source_file": "\n".join(service["source_files"]), "compose_service": name})
        if status == "incomplete":
            model["issues"].append({"code": "image_scan_incomplete", "message": "Image scan evidence is unavailable; review scanner diagnostics and retry.",
                                    "service": name, "source": service["source_files"][-1], "blocking": True})
        for port in config.get("ports", []):
            ports.append({"port": str(port.get("target") or "unknown"), "protocol": port.get("protocol") or "tcp",
                          "service": name, "source_file": "\n".join(service["source_files"]),
                          "declared_by": "Compose published host port " + str(port.get("published") or "dynamic"),
                          "boundary": "Host published"})
        for port in config.get("expose", []) or []:
            value, _, protocol = str(port).partition("/")
            ports.append({"port": value, "protocol": protocol or "tcp", "service": name,
                          "source_file": "\n".join(service["source_files"]), "declared_by": "Compose expose", "boundary": "Internal"})
        for dependency in config.get("depends_on", []) or []:
            dependencies.append({"dependency": dependency, "used_by": name, "provides": "Compose service dependency"})
    model["coverage"] = {"services": len(model["services"]), "unique_images": len(model["images"]),
                         "scanned_images": len(set(model["images"]) & scanned) if not preview else 0,
                         "preview": preview}
    model["complete"] = not any(issue["blocking"] for issue in model["issues"])
    overview = result.get("service_overview") or _load(output / "service-overview.json", {})
    overview.update(source="Docker Compose declared configuration", compose=model)
    for key, values in (("ports", ports), ("dependencies", dependencies), ("images", images)):
        overview[key] = [*(overview.get(key) or []), *values]
    overview["missing_evidence"] = [*(overview.get("missing_evidence") or []), *[
        {"type": "Compose", "item": issue["service"] or "Compose deployment", "reason": issue["message"], "source_file": issue["source"] or ""}
        for issue in model["issues"] if issue["blocking"]]]
    result["service_overview"] = overview
    # Mixed uploads retain Helm applicability for the existing validation flow.
    result["artifact_type"] = "helm" if (result.get("helm_source_files") or overview.get("charts")) else "compose"
    result["scan_scope"] = "service"
    result["policy_findings"] = [*(result.get("policy_findings") or []), *model["findings"]]
    result["complete"] = bool(result.get("complete")) and model["complete"] and summary.get("status") == "complete" and not preview
    summary["configuration_findings"] = len(result["policy_findings"])
    summary["compose"] = model
    summary["status"] = "complete" if (model["complete"] if preview else result["complete"]) else "incomplete"
    for filename, value in (("portal-result.json", result), ("service-overview.json", overview), ("scan-summary.json", summary), ("compose-discovery.json", model), ("portal-policy-findings.json", result["policy_findings"])):
        (output / filename).write_text(json.dumps(value), encoding="utf-8")

    # The scanner assembled its manual handoff before Compose findings were
    # attached. Refresh that handoff from the same retained evidence.
    if not preview and not (output / "scan-failure.json").exists():
        reports = output / "results"
        cats = reports / "cats"
        cats.mkdir(parents=True, exist_ok=True)
        report = {"name": "Compose configuration", "type": "CATS Configuration", "findings": [
            {"title": finding["title"], "description": finding["description"],
             "severity": finding["severity"], "mitigation": finding["remediation"],
             "component_name": finding["target"], "unique_id_from_tool": finding["finding"] + ":" + finding["target"],
             "evidence": finding["evidence"]} for finding in model["findings"]]}
        report_path = cats / "compose-findings.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        manifest = _load(reports / "manifest.json", {"schema_version": "cats.results/v1", "manual_import": True, "reports": []})
        manifest.setdefault("metadata", {}).update({"service-overview.json": overview, "scan-summary.json": summary})
        manifest["reports"] = [entry for entry in manifest.get("reports", []) if entry.get("path") != "cats/compose-findings.json"]
        manifest["reports"].append({"path": "cats/compose-findings.json", "tool": "cats", "scan_type": "Generic Findings Import",
                                     "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()})
        (reports / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with tarfile.open(output / "results-export.tar.gz", "w:gz") as archive:
            archive.add(reports, arcname="results")
