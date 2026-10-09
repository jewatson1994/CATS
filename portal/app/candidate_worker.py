from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

import yaml

from .remediation import summarize_configuration_report
from .remediation_delivery import checked_values_files


def request_digest(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_request(payload: dict) -> None:
    files = payload.get("files")
    if not isinstance(files, dict) or len(files) > 10000:
        raise ValueError("Invalid candidate source files")
    if len(json.dumps(payload).encode()) > 32 * 1024 * 1024:
        raise ValueError("Candidate source exceeds verification limit")
    for name, content in files.items():
        path = PurePosixPath(name)
        if not name or "\\" in name or ":" in name or path.is_absolute() or ".." in path.parts or any(part.startswith(".cats-") for part in path.parts) or not isinstance(content, str):
            raise ValueError("Unsafe candidate source path")
    checked_values_files(payload.get("helm_values_files", []), files)


def validate_candidate(candidate_dir: Path, payload: dict, plan: dict, validation: dict) -> dict:
    """Run available Level 1 tools and keep missing tools explicit."""
    checks = validation["checks"]
    values_files = checked_values_files(payload.get("helm_values_files", []),
        {path.relative_to(candidate_dir).as_posix() for path in candidate_dir.rglob("*") if path.is_file()})
    overrides = [argument for value in values_files for argument in ("--values", str(candidate_dir / value))]
    chart_roots = sorted({path.parent for path in candidate_dir.rglob("Chart.yaml")
                          if "charts" not in path.relative_to(candidate_dir).parts[:-1]})
    rendered_parts: list[str] = []
    helm = shutil.which("helm")
    if chart_roots and helm:
        lint_results, template_results = [], []
        for chart_root in chart_roots:
            lint = subprocess.run([helm, "lint", str(chart_root), *overrides], capture_output=True, text=True, timeout=180, check=False)
            lint_results.append(lint)
            rendered = subprocess.run([helm, "template", "cats-remediation", str(chart_root), "--include-crds", *overrides],
                                      capture_output=True, text=True, timeout=180, check=False)
            template_results.append(rendered)
            if rendered.returncode == 0:
                rendered_parts.append(rendered.stdout)
        checks["helm_lint"] = {"status": "PASS" if all(item.returncode == 0 for item in lint_results) else "FAIL",
                               "detail": "Validated every discovered chart."}
        checks["helm_template"] = {"status": "PASS" if all(item.returncode == 0 for item in template_results) else "FAIL",
                                   "detail": "Rendered every discovered chart with CRDs."}
    elif chart_roots:
        checks["helm_lint"] = {"status": "FAIL", "detail": "Helm is unavailable in the remediation worker."}
        checks["helm_template"] = {"status": "FAIL", "detail": "Helm is unavailable in the remediation worker."}
    else:
        for raw in sorted(candidate_dir.rglob("*")):
            if raw.suffix in {".yaml", ".yml"} and not raw.name.startswith(".cats-"):
                rendered_parts.append(raw.read_text(encoding="utf-8"))

    rendered_text = "\n---\n".join(rendered_parts)
    if rendered_text:
        try:
            objects = [item for item in yaml.safe_load_all(rendered_text) if isinstance(item, dict) and item.get("kind")]
            checks["yaml_parsing"] = {"status": "PASS", "detail": f"Parsed {len(objects)} candidate Kubernetes resources."}
            expected_kinds = {str(value).split("/")[-2] for value in plan["before"].get("resource_identities", []) if "/" in str(value)}
            actual_kinds = {str(item.get("kind")) for item in objects}
            from .remediation_sources import verify_rendered_changes
            checks["intended_changes"] = verify_rendered_changes(objects, plan.get("configuration_changes", []))
            if "intended_changes" not in validation["required_checks"]:
                validation["required_checks"].append("intended_changes")
            checks["expected_resources"] = {"status": "PASS" if expected_kinds <= actual_kinds else "FAIL",
                                             "detail": "Expected resource kinds remain present in the candidate render."}
            rendered_path = candidate_dir / ".cats-rendered.yaml"
            rendered_path.write_text(rendered_text, encoding="utf-8")
            from .offline_schema import validate_resources
            checks["kubernetes_schema"] = validate_resources(objects)
        except (OSError, yaml.YAMLError) as exc:
            checks["yaml_parsing"] = {"status": "FAIL", "detail": str(exc)}
    if payload.get("render_only"):
        return validation
    checks["candidate_security_evidence"] = {"status": "FAIL", "detail": "Completed configuration scanner evidence is required."}
    if "candidate_security_evidence" not in validation["required_checks"]:
        validation["required_checks"].append("candidate_security_evidence")
    checks["trivy_config_rescan"] = {"status": "FAIL", "detail": "Trivy is unavailable in the remediation worker."}
    trivy = shutil.which("trivy")
    if trivy:
        # Scan the rendered candidate once, not both chart sources and their render.
        scan_target = candidate_dir / ".cats-rendered.yaml"
        if not scan_target.is_file():
            checks["trivy_config_rescan"] = {"status": "FAIL", "detail": "No rendered candidate is available for configuration scanning."}
            validation["status"] = "FAIL"
            return validation
        result = subprocess.run([trivy, "config", "--skip-check-update", "--format", "json", "--exit-code", "0", str(scan_target)], capture_output=True, text=True,
                                timeout=int(os.getenv("CATS_REMEDIATION_SCAN_TIMEOUT", "600")), check=False)
        checks["trivy_config_rescan"] = {"status": "FAIL", "detail": "Configuration scanner did not produce valid completed JSON evidence."}
        if result.returncode == 0:
            try:
                summary = summarize_configuration_report(json.loads(result.stdout))
                plan.setdefault("after", {}).update(summary)
                checks["candidate_security_evidence"] = {"status": "PASS", "detail": "Completed configuration scanner JSON evidence is valid."}
                checks["trivy_config_rescan"] = {"status": "PASS" if summary["configuration_findings"] == 0 else "FAIL",
                    "detail": f"Completed configuration rescan: {summary['configuration_findings']} unresolved findings."}
                (candidate_dir / ".cats-config-scan.json").write_text(result.stdout, encoding="utf-8")
            except (ValueError, TypeError):
                pass
    if not plan.get("images"):
        checks["vulnerability_rescan"] = {"status": "PASS", "detail": "No image references require vulnerability scanning."}
    elif all(item.get("candidate") and item.get("patch_status") in {"PATCHED", "PARTIALLY_PATCHED", "NO_APPLICABLE_FIXES"}
             for item in plan.get("images", [])):
        checks["vulnerability_rescan"] = {"status": "PASS", "detail": "Every staged image completed the existing patch worker's before/after vulnerability scan."}
    validation["status"] = "PASS" if all(checks[name]["status"] == "PASS" for name in validation["required_checks"]) else "FAIL"
    return validation



def execute(payload: dict, output: Path) -> dict:
    validate_request(payload)
    input_digest = request_digest(payload)
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=output.parent) as directory:
        candidate_dir = Path(directory)
        for name, content in payload["files"].items():
            target = candidate_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        plan = payload["plan"]
        validation = validate_candidate(candidate_dir, payload, plan, payload["validation"])
        return {"status": "complete", "attempt_id": payload["attempt_id"],
                "remediation_job_id": payload["remediation_job_id"], "input_digest": input_digest,
                "validation": validation, "after": plan.get("after", {}),
                "rendered": (candidate_dir / ".cats-rendered.yaml").read_text(encoding="utf-8") if (candidate_dir / ".cats-rendered.yaml").is_file() else "",
                "config_scan": (candidate_dir / ".cats-config-scan.json").read_text(encoding="utf-8") if (candidate_dir / ".cats-config-scan.json").is_file() else ""}


def main() -> int:
    config, output = map(Path, sys.argv[1:])
    payload = json.loads(config.read_text(encoding="utf-8"))
    try:
        result = execute(payload, output)
    except Exception as exc:
        result = {"status": "failed", "attempt_id": payload.get("attempt_id"),
                  "remediation_job_id": payload.get("remediation_job_id"), "input_digest": request_digest(payload),
                  "error": "Candidate verification failed: " + type(exc).__name__}
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(result), encoding="utf-8")
    temporary.replace(output)
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
