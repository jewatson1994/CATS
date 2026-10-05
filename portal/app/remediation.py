"""Deterministic remediation planning and validation.

The planner never mutates its input.  It produces a candidate and an audit
record; callers decide whether that candidate is promoted after validation.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
from hashlib import sha256
from typing import Any
import json
import re

import yaml
from .remediation_sources import structured_mapping, container_entries, container_path

from .remediation_mutations import MISSING, MutationError, apply_mutation, mutate_yaml_source, semantic_identity


AUTO = "AUTO-REMEDIABLE"
REVIEW = "REVIEW REQUIRED"
NOT_REMEDIABLE = "NOT REMEDIABLE"
SAFE_AUTOMATIC = "SAFE_AUTOMATIC"
DECISION_REQUIRED = "DECISION_REQUIRED"
MANUAL_ONLY = "MANUAL_ONLY"


def _positive_resource_quantity(value: Any, field_path: str) -> bool:
    """Validate explicit quantities without guessing or silently rounding them."""
    if not isinstance(value, str) or len(value) > 128:
        return False
    match = re.fullmatch(r"(\+?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))(n|u|m|k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei|[eE][+-]?[0-9]+)?", value)
    if not match:
        return False
    number, suffix = match.groups()
    suffix = suffix or ""
    try:
        if suffix.startswith(("e", "E")) and len(suffix) > 1:
            exponent = int(suffix[1:])
            if abs(exponent) > 30:
                return False
            multiplier = Decimal(10) ** exponent
        elif suffix.endswith("i"):
            multiplier = Decimal(1024) ** ("KMGTPE".index(suffix[0]) + 1)
        else:
            multiplier = Decimal(10) ** {"n": -9, "u": -6, "m": -3, "": 0, "k": 3, "M": 6, "G": 9, "T": 12, "P": 15, "E": 18}[suffix]
        with localcontext() as context:
            context.prec = 160
            quantity = Decimal(number) * multiplier
            if not 0 < quantity <= Decimal(2**63 - 1):
                return False
            return not field_path.endswith(".cpu") or quantity * 1000 == (quantity * 1000).to_integral_value()
    except (InvalidOperation, ValueError, KeyError):
        return False


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def resource_identity(resource: dict[str, Any]) -> str:
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    prefix = f"{metadata['namespace']}/" if metadata.get("namespace") else ""
    return f"{prefix}{resource.get('kind', 'Resource')}/{metadata.get('name', 'unknown')}"


def rendered_resources(payload: dict[str, Any]) -> list[dict[str, Any]]:
    overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    values = overview.get("rendered_resources") or payload.get("rendered_resources") or []
    return [deepcopy(item) for item in _list(values) if isinstance(item, dict) and item.get("kind")]


def source_mapping(resource: dict[str, Any], field_path: str = "", container_name=None, container_type=None) -> dict[str, Any]:
    mappings = resource.get("_cats_source_mappings")
    if isinstance(mappings, list):
        candidates = [item for item in mappings if isinstance(item, dict) and (
            item.get("field_path") == field_path or (field_path == "image" and str(item.get("field_path", "")).endswith(".image"))
        ) and (not container_name or item.get("container_name") == container_name or
               (not item.get("container_name") and len(container_entries(resource)) <= 1))
          and (not container_type or not item.get("container_type") or
               {"container": "containers", "initContainer": "initContainers", "ephemeralContainer": "ephemeralContainers"}
               .get(item.get("container_type"), item.get("container_type")) == container_type)]
        if len(candidates) == 1:
            exact = candidates[0]
            return {**exact, "ambiguous": bool(exact.get("ambiguous", not exact.get("values_key")))}
    template = resource.get("_cats_source_file") or resource.get("source_file") or resource.get("template")
    return {"template": template or None, "field_path": field_path, "values_key": None,
            "values_file": None, "ambiguous": True}


def _finding_text(finding: Any) -> str:
    return " ".join(str(getattr(finding, key, "") or "") for key in ("finding", "title", "description", "remediation")).lower()


def _rule_patch(finding: Any) -> dict[str, Any] | None:
    text = _finding_text(finding)
    # Stable scanner IDs supplement wording, which differs between scanner versions.
    registered = {
        "KSV-0017": ("securityContext.privileged", False),
        "KSV-0001": ("securityContext.allowPrivilegeEscalation", False),
        "KSV-0014": ("securityContext.readOnlyRootFilesystem", True),
        "KSV-0106": ("securityContext.capabilities.drop", ["ALL"]),
    }
    rule = registered.get(str(getattr(finding, "finding", "")))
    if rule:
        return {"field_path": rule[0], "new_value": rule[1], "operation": "SET"}
    for resource in ("cpu", "memory"):
        for setting in ("requests", "limits"):
            singular = setting[:-1]
            if resource in text and (setting in text or singular in text) and any(word in text for word in ("not specified", "not set", "missing", "should be set")):
                return {"field_path": f"resources.{setting}.{resource}", "new_value": None,
                        "operation": "SET", "input_type": "quantity"}
    rules = (
        (("allowprivilegeescalation", "allow privilege escalation"), "securityContext.allowPrivilegeEscalation", False),
        (("privileged container", "privileged is set", "privileged mode"), "securityContext.privileged", False),
        (("read only root", "readonlyrootfilesystem"), "securityContext.readOnlyRootFilesystem", True),
        (("run as non-root", "runasnonroot"), "securityContext.runAsNonRoot", True),
        (("drop all capabilities", "capabilities should be dropped", "capabilities must be dropped"), "securityContext.capabilities.drop", ["ALL"]),
    )
    for phrases, path, value in rules:
        if any(phrase in text for phrase in phrases):
            return {"field_path": path, "new_value": value, "operation": "SET"}
    return None


def _find_target(resources: list[dict[str, Any]], target: str | None) -> dict[str, Any] | None:
    value = str(target or "").strip()
    identities = [item for item in resources if resource_identity(item) == value]
    if len(identities) == 1:
        return identities[0]
    kind_name = value.split(":", 1)[0].strip()
    if "/" in kind_name:
        kind, name = kind_name.rsplit("/", 1)
        matches = [item for item in resources if str(item.get("kind", "")).lower() == kind.lower()
                   and str((item.get("metadata") or {}).get("name", "")) == name]
        if len(matches) == 1:
            return matches[0]
        return None
    # Trivy uses "name (kind-or-name) :: rendered-file.yaml". The trailing
    # file is provenance, not the Kubernetes object's name.
    name = re.split(r"\s+\(|\s*::", value, maxsplit=1)[0].strip() if value else ""
    matches = [item for item in resources if str((item.get("metadata") or {}).get("name", "")) == name]
    return matches[0] if len(matches) == 1 else None


def classify_policy_finding(finding: Any, payload: dict[str, Any]) -> dict[str, Any]:
    if is_image_build_finding(finding):
        return {"classification": NOT_REMEDIABLE, "category": MANUAL_ONLY,
                "reason": "Docker image build checks require manual source-image changes; CATS does not rebuild images."}
    patch = _rule_patch(finding)
    if not patch:
        return {"classification": NOT_REMEDIABLE, "category": MANUAL_ONLY, "reason": "No deterministic CATS remediation rule is registered for this check."}
    resources = rendered_resources(payload)
    namespace = getattr(finding, "namespace", None)
    # Scanner check namespaces (builtin.kubernetes.*) are not object namespaces.
    if namespace and not str(namespace).startswith("builtin."):
        resources = [item for item in resources if (item.get("metadata") or {}).get("namespace", "default") == namespace]
    evidence = _retained_evidence(finding, payload)
    lineage = evidence.get("resource_lineage") or {}
    candidates = evidence.get("candidate_resources") or []
    resource = _find_target(resources, getattr(finding, "target", None)) if not lineage and not candidates else None
    options = []
    for candidate in resources:
        if sum(_normalized_identity(item) == _normalized_identity(candidate) for item in resources) != 1:
            continue
        if resource and candidate != resource:
            continue
        entries = container_entries(candidate) or [(None, {})]
        for group, container in entries:
            identity = _normalized_identity(candidate, group, container.get("name"))
            if group and (not container.get("name") or sum(g == group and c.get("name") == container.get("name") for g, c in entries) != 1):
                continue
            if lineage and not _matches_lineage(candidate, identity, lineage):
                continue
            if candidates and not any(_matches_lineage(candidate, identity, item) for item in candidates if isinstance(item, dict)):
                continue
            option = _classify_resource_patch(candidate, payload, patch, container.get("name"), group)
            mapping = option["source_mapping"]
            value = mapping.get("original_value")
            files = payload.get("helm_source_files") or payload.get("source_files") or {}
            path = mapping.get("values_key") or patch["field_path"]
            if mapping.get("values_file") in files and mapping.get("values_key"):
                try:
                    value = yaml.safe_load(files[mapping["values_file"]])
                    for part in re.sub(r"^\.?(Values\.)?", "", str(path)).split("."):
                        value = value.get(part) if isinstance(value, dict) else None
                except yaml.YAMLError:
                    option["editable"] = False
            elif not mapping.get("mutation_path"):
                value = container
                for part in patch["field_path"].split("."):
                    value = value.get(part) if isinstance(value, dict) else None
            option.update(original_value=value, original_file=mapping.get("values_file") or mapping.get("template"),
                          original_line=mapping.get("line"), original_path=path,
                          resource_identity=identity, container_name=container.get("name"), container_type=group,
                          target_id=sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
                          target_lineage={**_resource_lineage(candidate), **lineage, **identity}, target_resolution="unresolved")
            options.append(option)
    # Unique retained identity or safe legacy reconstruction can resolve automatically.
    if len(options) == 1 and (lineage or resource):
        options[0]["target_resolution"] = "automatically-resolved"
        return options[0]
    editable = [option for option in options if option["editable"]]
    reason = ("Select an exact resource and container target before applying the proposal." if editable else
              "The rendered target is known, but its authoritative source mapping is unavailable." if options else
              "The retained scan lacks sufficient target lineage. Re-scan the service to enable source-aware remediation.")
    return {"classification": REVIEW, "category": DECISION_REQUIRED, "editable": False,
            "proposed_value_source": "Hardening Policy", "target_options": editable,
            "target_resolution": "selection-required" if options else "unresolved",
            "source_resolution": "editable-candidates" if editable else "unavailable",
            "actionability": "target-selection-required" if editable else "source-unavailable" if options else "target-unavailable",
            "target_lineage": lineage, "reason": reason, **patch}


def _normalized_identity(resource, container_type=None, container_name=None):
    metadata = resource.get("metadata") or {}
    return {"api_version": resource.get("apiVersion", ""), "kind": resource.get("kind", ""),
            "namespace": metadata.get("namespace", ""), "name": metadata.get("name", ""),
            "container_type": container_type, "container_name": container_name}


def _resource_lineage(resource):
    return resource.get("_cats_resource_lineage") or resource.get("_cats_lineage") or {}


def _matches_lineage(resource, identity, lineage):
    aliases = {"apiVersion": "api_version", "containerType": "container_type", "containerName": "container_name"}
    lineage = {aliases.get(key, key): value for key, value in lineage.items()}
    if lineage.get("container_type"):
        lineage["container_type"] = {"container": "containers", "initContainer": "initContainers",
                                     "ephemeralContainer": "ephemeralContainers"}.get(lineage["container_type"], lineage["container_type"])
    if not lineage.get("kind") or not lineage.get("name"):
        return False
    if any(key in lineage and lineage[key] is not None and lineage[key] != value for key, value in identity.items()):
        return False
    retained = _resource_lineage(resource)
    same_source_render = (
        bool(lineage.get("chart_instance_id")) and lineage.get("chart_instance_id") == retained.get("chart_instance_id")
        and bool(lineage.get("source_template")) and lineage.get("source_template") == retained.get("source_template")
        and bool(lineage.get("rendered_artifact")) and bool(retained.get("rendered_artifact"))
        and lineage["rendered_artifact"] != retained["rendered_artifact"]
    )
    return not any(key in lineage and key in retained and lineage[key] != retained[key]
                   for key in ("chart_instance_id", "chart_id", "source_template", "rendered_artifact", "document_index")
                   if not (same_source_render and key in {"rendered_artifact", "document_index"}))


def _retained_evidence(finding, payload):
    direct = getattr(finding, "evidence", None)
    if isinstance(direct, dict):
        return direct
    fingerprint = getattr(finding, "fingerprint", None)
    rows = [row for row in payload.get("policy_findings", []) if isinstance(row, dict) and fingerprint
            and row.get("fingerprint") == fingerprint]
    return (rows[0].get("evidence") or {}) if len(rows) == 1 else {}


def has_proposal(row: dict[str, Any]) -> bool:
    """False, zero, empty strings and collections are values; null is not."""
    return "new_value" in row and row["new_value"] is not None


def _classify_resource_patch(resource: dict[str, Any], payload: dict[str, Any], patch: dict[str, Any], container_name=None, container_type=None) -> dict[str, Any]:
    mapping = source_mapping(resource, patch["field_path"], container_name, container_type)
    artifact_type = str(payload.get("artifact_type") or "helm").lower()
    source_files = payload.get("helm_source_files") or payload.get("source_files") or {}
    literal = structured_mapping(resource, source_files, patch["field_path"], container_name, container_type)
    if mapping.get("ambiguous", True) and literal:
        mapping = literal
    exact_source = bool(not mapping.get("ambiguous", True) and mapping.get("values_key") and mapping.get("values_file") and isinstance(source_files, dict)
                        and mapping.get("values_file") in source_files)
    raw_manifest = artifact_type in {"kubernetes", "manifest", "raw"} and not source_files and bool(mapping.get("template")) and bool(container_path(resource, patch["field_path"], container_name, container_type))
    structured = bool(mapping.get("mutation_path") and not mapping.get("ambiguous", True))
    classification = AUTO if exact_source or raw_manifest or structured else REVIEW
    reason = ("The change has an exact source mapping." if exact_source or structured else
              "The uploaded artifact is a raw manifest, so its source object is editable." if raw_manifest else
              "The rendered resource and container are known, but no uniquely editable authoritative values or literal source mapping is available.")
    if patch["field_path"] in {"securityContext.readOnlyRootFilesystem", "securityContext.runAsNonRoot"}:
        classification = REVIEW
        reason = "Manager approval is required: this change may break filesystem writes or the application's runtime user requirements."
    if patch.get("input_type") == "quantity":
        classification = REVIEW
        reason = "Supply an explicit workload-appropriate Kubernetes quantity; CATS does not invent resource sizing."
    return {"classification": classification, "category": SAFE_AUTOMATIC if classification == AUTO else DECISION_REQUIRED,
            "editable": bool(exact_source or raw_manifest or structured),
            "source_resolution": "resolved" if exact_source or raw_manifest or structured else "unavailable",
            "actionability": "custom-input-required" if patch.get("input_type") == "quantity" and (exact_source or raw_manifest or structured) else "actionable" if exact_source or raw_manifest or structured else "source-unavailable",
            "proposed_value_source": "Hardening Policy",
            "reason": reason, "resource": resource_identity(resource),
            "source_mapping": mapping, **patch}


def snapshot(payload: dict[str, Any], findings: list[Any]) -> dict[str, Any]:
    severities = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Unknown")}
    vulnerability_rows = [item for item in _list(payload.get("findings")) if isinstance(item, dict)]
    for finding in vulnerability_rows:
        severity = str(finding.get("severity", "Unknown") or "Unknown").title()
        severities[severity if severity in severities else "Unknown"] += 1
    resources = rendered_resources(payload)
    images = sorted({str(container.get("image")) for item in resources for container in _containers(item) if container.get("image")})
    return {"vulnerabilities": severities, "kev": sum(bool(item.get("kev")) for item in vulnerability_rows),
            "configuration_findings": len(findings), "images": len(images),
            "resources": len(resources), "resource_identities": sorted(resource_identity(item) for item in resources),
            "helm_render": "PASS" if resources else "FAIL", "policy_validation": "FAIL" if findings else "PASS",
            "deployment_validation": "NOT RUN"}


def _containers(resource: dict[str, Any]) -> list[dict[str, Any]]:
    spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
    if resource.get("kind") == "CronJob":
        spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    elif resource.get("kind") != "Pod":
        spec = ((spec.get("template") or {}).get("spec") or {})
    return [item for item in [*_list(spec.get("containers")), *_list(spec.get("initContainers")), *_list(spec.get("ephemeralContainers"))] if isinstance(item, dict)]


def is_image_build_finding(finding: Any) -> bool:
    """Exclude Dockle checks, including legacy normalized CIS-DI records."""
    return (str(getattr(finding, "scanner", "") or "").strip().lower() == "dockle"
            or str(getattr(finding, "framework", "") or "").strip().lower() == "docker image configuration"
            or str(getattr(finding, "finding", "") or "").upper().startswith("CIS-DI-"))


def expand_source_mappings(payload: dict[str, Any]) -> None:
    """Backfill retained charts: only uniquely consumed, direct values bindings.

    Whole securityContext values objects permit adding missing leaves. Helpers,
    conditional/default expressions and multi-container templates remain blocked.
    """
    files = payload.get("helm_source_files") or payload.get("source_files") or {}
    overview = payload.get("service_overview") or {}
    resources = overview.get("rendered_resources") or payload.get("rendered_resources") or []
    for resource in resources:
        if not isinstance(resource, dict) or len(_containers(resource)) != 1:
            continue
        name = str(resource.get("_cats_source_file") or resource.get("source_file") or "").replace("\\", "/").lstrip("/")
        paths = [path for path in files if name and (path == name or path.endswith("/" + name) or name.endswith("/" + path))]
        if len(paths) != 1:
            continue
        path = paths[0]
        if sum(str(item.get("_cats_source_file") or item.get("source_file") or "") == str(resource.get("_cats_source_file") or resource.get("source_file") or "") for item in resources if isinstance(item, dict)) != 1:
            continue
        prefix = path.rsplit("/templates/", 1)[0] if "/templates/" in path else ""
        values_file = f"{prefix}/values.yaml" if prefix else "values.yaml"
        if values_file not in files:
            continue
        try:
            document = yaml.safe_load(files[values_file])
        except yaml.YAMLError:
            continue
        if not isinstance(document, dict):
            continue
        template = files[path]
        blocks = re.findall(r"(?m)^\s*securityContext:\s*\n\s*{{-?\s*toYaml\s+\.Values\.([A-Za-z0-9_.]+)\s*\|\s*nindent\s+\d+\s*-?}}\s*$", template)
        contexts = list(re.finditer(r"(?m)^([ \t]*)securityContext:", template))
        containers = list(re.finditer(r"(?m)^([ \t]*)containers:", template))
        # A pod-level context is not a container context. Do not infer through
        # mixed pod/container or init-container sections.
        if len(contexts) != 1 or len(containers) != 1 or contexts[0].start() < containers[0].start() or len(contexts[0][1]) <= len(containers[0][1]) or re.search(r"(?m)^\s*initContainers:", template):
            continue
        mappings = resource.setdefault("_cats_source_mappings", [])
        for leaf in ("allowPrivilegeEscalation", "privileged", "readOnlyRootFilesystem", "runAsNonRoot", "capabilities.drop"):
            direct = re.findall(rf"(?m)^\s*{re.escape(leaf)}:\s*{{{{-?\s*\.Values\.([A-Za-z0-9_.]+)\s*-?}}}}\s*$", template)
            keys = direct if len(direct) == 1 else ([blocks[0] + "." + leaf] if len(blocks) == 1 else [])
            if len(keys) != 1:
                continue
            key = keys[0]
            cursor = document
            for part in key.split(".")[:-1]:
                cursor = cursor.get(part, {}) if isinstance(cursor, dict) else None
            if not isinstance(cursor, dict):
                continue
            # A key consumed elsewhere would change more than the chosen target.
            base = blocks[0] if not direct and blocks else key
            uses = sum(len(re.findall(r"\.Values\." + re.escape(base) + r"(?![A-Za-z0-9_.])", content)) for content in files.values())
            if uses != 1:
                continue
            field = "securityContext." + leaf
            mappings[:] = [item for item in mappings if item.get("field_path") != field]
            mappings.append({"field_path": field, "template": path, "values_file": values_file,
                             "values_key": ".Values." + key, "ambiguous": False})


def build_plan(payload: dict[str, Any], findings: list[Any], job_key: str) -> dict[str, Any]:
    payload = deepcopy(payload)
    expand_source_mappings(payload)
    before = snapshot(payload, findings)
    changes = []
    for finding in findings:
        if is_image_build_finding(finding):
            continue
        decision = classify_policy_finding(finding, payload)
        mapping = decision.get("source_mapping") or {}
        original_value = mapping.get("original_value")
        source_files = payload.get("helm_source_files") or payload.get("source_files") or {}
        if mapping.get("values_file") in source_files and mapping.get("values_key"):
            original_value = yaml.safe_load(source_files[mapping["values_file"]])
            for part in re.sub(r"^\.?(Values\.)?", "", str(mapping["values_key"])).split("."):
                original_value = original_value.get(part) if isinstance(original_value, dict) else None
        elif decision.get("resource") and decision.get("field_path"):
            target = _find_target(rendered_resources(payload), decision["resource"])
            containers = [container for group, container in container_entries(target) if
                          (not decision.get("container_name") or container.get("name") == decision["container_name"]) and
                          (not decision.get("container_type") or group == decision["container_type"])] if target else []
            values = []
            for container in containers:
                value = container
                for part in decision["field_path"].split("."):
                    value = value.get(part) if isinstance(value, dict) else None
                values.append(value)
            original_value = values[0] if len(values) == 1 else values
        changes.append({"finding_id": getattr(finding, "id", None), "rule_id": getattr(finding, "finding", None),
                        "finding_target": getattr(finding, "target", None),
                        "finding_namespace": getattr(finding, "namespace", None),
                        "finding_title": getattr(finding, "title", None),
                        "finding_description": getattr(finding, "description", None),
                        "scanner": getattr(finding, "scanner", None),
                        "severity": getattr(finding, "severity", "Unknown"), "timestamp": datetime.now(timezone.utc).isoformat(),
                        "job_id": job_key, "original_file": mapping.get("values_file") or mapping.get("template"),
                        "original_line": mapping.get("line"), "original_path": mapping.get("values_key") or decision.get("field_path"),
                        "original_value": original_value, **decision})
    after = deepcopy(before)
    applied = [item for item in changes if item["classification"] == AUTO]
    # Planning cannot prove resolution. Only the candidate's actual rescan can.
    forecast = max(0, before["configuration_findings"] - len(applied))
    after["configuration_findings"] = None
    after["policy_validation"] = "NOT RUN"
    return {"schema_version": "1.0", "job_id": job_key, "before": before, "after": after,
            "forecast_configuration_findings": forecast,
            "configuration_changes": changes, "changed_artifacts": _changed_artifacts(changes),
            "images": image_plan(payload), "rollback_reference": payload.get("execution_id") or payload.get("commit_sha")}


def image_plan(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for resource in rendered_resources(payload):
        for container in _containers(resource):
            image = str(container.get("image") or "").strip()
            if not image:
                continue
            mapping = source_mapping(resource, "image")
            rows.append({"original": image, "candidate": None, "digest": None, "patch_status": "PENDING",
                         "classification": REVIEW,
                         "reason": "The existing patch, scan, publish, and sign worker must complete before this source change can be validated.",
                         "source_mapping": mapping, "resource": resource_identity(resource)})
    unique = {}
    for row in rows:
        unique.setdefault((row["original"], json.dumps(row["source_mapping"], sort_keys=True)), row)
    findings = [item for item in _list(payload.get("findings")) if isinstance(item, dict)]
    for finding in findings:
        image = str(finding.get("image") or "").strip()
        if image and not any(row["original"] == image for row in unique.values()):
            unique[(image, "unmapped")] = {"original": image, "candidate": None, "digest": finding.get("image_digest"),
                "patch_status": "PENDING", "classification": REVIEW, "resource": None,
                "source_mapping": {"ambiguous": True},
                "reason": "Retained vulnerability evidence identifies this image; exact chart image rewriting is not yet mapped."}
    for row in unique.values():
        row["vulnerabilities"] = [deepcopy(item) for item in findings if str(item.get("image") or "").strip() == row["original"]]
    return list(unique.values())


def plan_digest(plan: dict[str, Any]) -> str:
    """Bind decisions to immutable plan content, excluding execution metadata."""
    rows = [{key: value for key, value in row.items() if key not in {"timestamp", "job_id"}}
            for row in plan.get("configuration_changes", [])]
    return sha256(json.dumps({"changes": rows, "images": plan.get("images", []), "before": plan.get("before")},
                             sort_keys=True, default=str).encode()).hexdigest()


def resolve_decisions(plan: dict[str, Any], mode: str, decisions: dict[str, Any] | None, actor: str) -> dict[str, Any]:
    """Resolve only registered fields; manager input cannot supply a path or rule."""
    mode = str(mode).lower()
    if mode not in {"automated", "guided"}:
        raise ValueError("Choose Automated or Guided remediation")
    if decisions is None:
        decisions = {}
    if not isinstance(decisions, dict):
        raise ValueError("Decisions must be an object")
    resolved = deepcopy(plan)
    rows = resolved.get("configuration_changes", [])
    known = {str(row.get("finding_id")) for row in rows}
    if set(decisions) - known:
        raise ValueError("Decision references a finding outside this plan")
    expanded = []
    for row in rows:
        entry = decisions.get(str(row.get("finding_id")))
        if isinstance(entry, dict) and "target_all" in entry:
            options = row.get("target_options") or []
            if (entry["target_all"] is not True or "target_id" in entry or "target_resource" in entry
                    or len(options) < 2 or any(not option.get("editable") or not option.get("target_id") for option in options)):
                raise ValueError("All requires multiple exact editable targets from this plan")
            for option in options:
                expanded.append({**deepcopy(row), "_selected_all_target": option["target_id"]})
        elif mode == "automated" and entry is None and row.get("category") != MANUAL_ONLY and has_proposal(row):
            options = [option for option in row.get("target_options", []) if option.get("editable") and option.get("target_id")]
            if options:
                expanded.extend({**deepcopy(row), "_selected_all_target": option["target_id"]} for option in options)
            else:
                expanded.append(row)
        else:
            expanded.append(row)
    rows = resolved["configuration_changes"] = expanded
    timestamp = datetime.now(timezone.utc).isoformat()
    for row in rows:
        category = row.get("category", MANUAL_ONLY)
        entry = decisions.get(str(row.get("finding_id")))
        user_entry = entry
        if "_selected_all_target" in row:
            entry = {**(entry or {}), "target_id": row.pop("_selected_all_target"), "action": (entry or {}).get("action", "proposed")}
            entry.pop("target_all", None)
        if entry is not None and (not isinstance(entry, dict) or set(entry) - {"action", "value", "target_resource", "target_id"}):
            raise ValueError("Invalid decision fields")
        if entry and ("target_resource" in entry or "target_id" in entry):
            options = [option for option in row.get("target_options", [])
                       if (option.get("target_id") == entry["target_id"] if "target_id" in entry else
                           option.get("resource") == entry["target_resource"]) and option.get("editable")]
            if len(options) != 1:
                raise ValueError("Select an exact editable target from this plan")
            # Only server-built, digest-bound mappings may replace the target.
            for key in ("resource", "resource_identity", "target_id", "target_lineage", "container_name", "container_type", "source_mapping", "source_resolution", "actionability", "editable", "reason", "original_value", "original_file", "original_line", "original_path"):
                row[key] = deepcopy(options[0].get(key))
            row["target_resolution"] = "user-selected"
        automatic = mode == "automated" and category != MANUAL_ONLY and row.get("editable", False) and has_proposal(row) and (user_entry is None or category == SAFE_AUTOMATIC)
        action = "proposed" if automatic else (entry or {}).get("action")
        if category == MANUAL_ONLY:
            if action not in {None, "unresolved"}:
                raise ValueError("Manual-only findings cannot be applied")
            action = "unresolved"
        elif action is None:
            if mode == "automated" and user_entry is None:
                action = "unresolved"
            elif category == SAFE_AUTOMATIC:
                action = "proposed"
            else:
                raise ValueError("Explicit decision required for each review finding")
        if action not in {"proposed", "custom", "unresolved"}:
            raise ValueError("Invalid remediation decision")
        if automatic and entry and entry.get("action") != "proposed":
            raise ValueError("Automated safe actions are automatically accepted; use Guided to review them")
        if action != "unresolved" and not row.get("editable", False):
            raise ValueError("This finding has no exact editable source; leave unresolved")
        if action == "proposed" and not has_proposal(row):
            raise ValueError("This finding has no proposed value")
        if action == "custom":
            value = entry.get("value")
            proposed = row.get("new_value")
            if row.get("input_type") == "quantity":
                if not _positive_resource_quantity(value, str(row.get("field_path") or "")):
                    raise ValueError("Enter a positive Kubernetes resource quantity")
            elif type(proposed) is bool and type(value) is not bool:
                raise ValueError("Custom security setting must be a boolean")
            elif isinstance(proposed, list):
                allowed = {"ALL", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP", "NET_BIND_SERVICE", "NET_RAW", "SYS_CHROOT", "MKNOD", "AUDIT_WRITE", "SETFCAP"}
                if not isinstance(value, list) or not value or any(type(item) is not str or item not in allowed for item in value):
                    raise ValueError("Custom capabilities must be a nonempty list of known capability names")
            elif type(proposed) is not bool:
                raise ValueError("This rule does not support custom values")
            row["new_value"] = deepcopy(value)
            row["proposed_value_source"] = "Explicit Service Manager input"
        row.update(decision=action, approval="automatic" if automatic else "manager-approved" if action != "unresolved" else "unresolved",
                   actor=None if automatic else actor, timestamp=timestamp, post_scan_result="NOT RUN")
        row["classification"] = AUTO if action != "unresolved" else NOT_REMEDIABLE if category == MANUAL_ONLY else REVIEW
    resolved["mode"] = mode
    resolved["changed_artifacts"] = _changed_artifacts([row for row in rows if row["classification"] == AUTO])
    resolved["decisions"] = [{key: row.get(key) for key in ("finding_id", "rule_id", "decision", "approval", "actor", "timestamp", "proposed_value_source", "original_value", "new_value", "field_path", "resource")} for row in rows]
    return resolved


def associate_patch_results(payload: dict[str, Any], plan: dict[str, Any], patch_records: list[Any]) -> None:
    """Attach only published immutable outputs from the existing patch worker."""
    source_files = payload.get("helm_source_files") or payload.get("source_files") or {}
    for row in plan.get("images", []):
        matches = [record for record in patch_records if getattr(record, "status", None) == "complete"
                   and getattr(record, "source_image", None) == row.get("original")]
        matches.sort(key=lambda item: getattr(item, "completed_at", None) or getattr(item, "created_at", None), reverse=True)
        for record in matches:
            summary = getattr(record, "summary", None) or {}
            immutable = summary.get("immutable_destination")
            mapping = row.get("source_mapping") or {}
            editable = (not mapping.get("ambiguous", True) and isinstance(source_files, dict)
                        and (mapping.get("values_file") or "") in source_files)
            if summary.get("delivery_status") == "delivered" and immutable and editable:
                row.update(candidate=immutable, digest=str(immutable).split("@", 1)[-1], patch_status=summary.get("patch_status"),
                           signature_status=summary.get("signature_status", "not_configured"), patch_job_id=record.job_key,
                           vulnerabilities_before=summary.get("vulnerabilities_before"), vulnerabilities_after=summary.get("vulnerabilities_after"),
                           classification=AUTO, reason="A published immutable result from the existing patch worker has an exact Helm source mapping.")
                break


def _changed_artifacts(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    for change in changes:
        mapping = change.get("source_mapping") or {}
        source = mapping.get("values_file") or mapping.get("template") or "Unresolved source"
        grouped.setdefault(source, []).append(f"{change.get('rule_id')}: {change.get('field_path')} → {change.get('new_value')}")
    return [{"path": path, "changes": values} for path, values in sorted(grouped.items())]


def static_validation(payload: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    resources = rendered_resources(payload)
    identities = [resource_identity(item) for item in resources]
    checks = {
        "yaml_parsing": {"status": "PASS", "detail": "All persisted rendered objects are parsed YAML."},
        "expected_resources": {"status": "PASS" if identities == plan["before"]["resource_identities"] else "FAIL",
                               "detail": f"{len(identities)} expected resources retained."},
        "image_references": {"status": "PASS" if all(row["original"] for row in plan["images"]) else "FAIL"},
        "source_mapping": {"status": "PASS" if all(not item.get("source_mapping", {}).get("ambiguous") for item in plan["configuration_changes"] if item["classification"] == AUTO) else "FAIL"},
        "helm_lint": {"status": "NOT RUN", "detail": "Requires a candidate chart directory."},
        "helm_template": {"status": "PASS" if resources else "FAIL", "detail": "Uses the persisted Helm render for planning."},
        "kubernetes_schema": {"status": "NOT RUN", "detail": "No configured schema validator was available."},
        "trivy_config_rescan": {"status": "NOT RUN", "detail": "Runs after a materialized candidate exists."},
        "vulnerability_rescan": {"status": "NOT RUN", "detail": "Runs after patched images exist."},
        "cats_policy": {"status": plan["after"]["policy_validation"]},
    }
    required = ["yaml_parsing", "expected_resources", "image_references", "source_mapping", "kubernetes_schema", "cats_policy", "trivy_config_rescan"]
    if str(payload.get("artifact_type") or "helm").lower() == "helm":
        required.extend(("helm_lint", "helm_template"))
    if plan.get("images"):
        required.append("vulnerability_rescan")
    return {"level": "STATIC", "status": "PASS" if all(checks[key]["status"] == "PASS" for key in required) else "FAIL",
            "required_checks": required, "checks": checks, "deployment": {"status": "NOT RUN", "detail": "No validation cluster was configured."}}


def candidate_files(payload: dict[str, Any], plan: dict[str, Any]) -> dict[str, str]:
    """Materialize changes only when the uploaded source is available and exact."""
    supplied = payload.get("helm_source_files") or payload.get("source_files") or {}
    files = {str(path): str(content) for path, content in supplied.items()} if isinstance(supplied, dict) else {}
    resources = rendered_resources(payload)

    def target_resource(change):
        identity = change.get("resource_identity")
        if isinstance(identity, dict):
            matches = [item for item in resources if all(_normalized_identity(item).get(key) == identity.get(key)
                       for key in ("api_version", "kind", "namespace", "name"))]
            if len(matches) != 1:
                raise MutationError("Resource target must match exactly one resource")
            return matches[0]
        matches = [item for item in resources if (semantic_identity(item) == tuple(identity)
                   if isinstance(identity, (list, tuple)) else resource_identity(item) == change.get("resource"))]
        if len(matches) != 1:
            raise MutationError("Resource target must match exactly one resource")
        return matches[0]

    def target_path(change, resource):
        mapping = change.get("source_mapping") or {}
        explicit = change.get("mutation_path", change.get("path", mapping.get("mutation_path", mapping.get("path"))))
        if isinstance(explicit, list):
            return explicit
        field = str(change.get("field_path") or "")
        if not field.startswith(("securityContext.", "resources.")):
            return field.split(".")
        path = container_path(resource, field, change.get("container_name") or mapping.get("container_name"),
                              change.get("container_type") or mapping.get("container_type"))
        if not path:
            raise MutationError("Container target requires an exact type and name or a single named container")
        return path

    def edit_values(filename, key, operation, value):
        source = files[filename]
        if "{{" in source or "}}" in source:
            raise MutationError("Go template source cannot be edited as plain YAML")
        document = yaml.safe_load(source)
        if document is None:
            document = {}
        parts = key if isinstance(key, list) else re.sub(r"^\.?(Values\.)?", "", str(key)).split(".")
        changed = apply_mutation(document, parts, operation, value)
        files[filename] = yaml.safe_dump(changed, sort_keys=False, allow_unicode=True)

    for change in plan.get("configuration_changes", []):
        if change.get("classification") != AUTO:
            continue
        mapping = change.get("source_mapping") or {}
        values_file, values_key = mapping.get("values_file"), mapping.get("values_key")
        if values_file and values_key and values_file in files:
            edit_values(values_file, values_key, change.get("operation", "SET"), change.get("new_value", MISSING))
        elif files:
            filename = mapping.get("template") or mapping.get("source_file")
            if not filename or filename not in files:
                raise MutationError("Exact retained source file is required")
            resource = target_resource(change)
            source_identity = tuple(mapping.get("source_resource_identity") or semantic_identity(resource))
            files[filename] = mutate_yaml_source(files[filename], source_identity, target_path(change, resource),
                                                 change.get("operation", "SET"), change.get("new_value", MISSING))
    for image in plan.get("images", []):
        if image.get("classification") != AUTO or not image.get("candidate"):
            continue
        mapping = image.get("source_mapping") or {}
        values_file, values_key = mapping.get("values_file"), mapping.get("values_key")
        if values_file and values_key and values_file in files:
            edit_values(values_file, values_key, "SET", image["candidate"])
    if files:
        return files
    if str(payload.get("artifact_type") or "").lower() not in {"kubernetes", "manifest", "raw"}:
        return {}
    for change in plan.get("configuration_changes", []):
        if change.get("classification") != AUTO:
            continue
        resource = target_resource(change)
        index = next(index for index, item in enumerate(resources) if item is resource)
        resources[index] = apply_mutation(resource, target_path(change, resource), change.get("operation", "SET"),
                                          change.get("new_value", MISSING))
    manifests = [{key: value for key, value in item.items() if not key.startswith("_cats_")}
                 for item in resources]
    return {"remediated-manifests.yaml": "---\n" + "\n---\n".join(yaml.safe_dump(item, sort_keys=False).strip() for item in manifests) + "\n"}


def versioned_charts(files: dict[str, str], job_key: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Give retained Helm charts a unique SemVer candidate version."""
    updated = dict(files)
    charts = []
    job_suffix = re.sub(r"[^a-z0-9]", "", job_key.lower())[-12:]
    for path, content in files.items():
        if path.replace("\\", "/").split("/")[-1] != "Chart.yaml":
            continue
        try:
            chart = yaml.safe_load(content)
            if not isinstance(chart, dict):
                raise ValueError("Chart.yaml must contain chart metadata")
            name = str(chart.get("name") or "")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", name):
                raise ValueError("Chart name is not a safe Helm package name")
            original = str(chart.get("version") or "")
            if not re.fullmatch(
                r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", original):
                raise ValueError("Chart version must be SemVer before remediation")
            base = original.split("+", 1)[0]
            suffix = job_suffix + "." + sha256(path.encode("utf-8")).hexdigest()[:6]
            remediated = base + ("." if "-" in base else "-") + "cats." + suffix
            chart["version"] = remediated
            updated[path] = yaml.safe_dump(chart, sort_keys=False, allow_unicode=True)
            charts.append({"path": path, "name": name,
                           "original_version": original, "remediated_version": remediated})
        except (ValueError, yaml.YAMLError) as exc:
            charts.append({"path": path, "name": "", "original_version": "", "remediated_version": "",
                           "package_status": "FAILED", "reason": type(exc).__name__})
    return updated, charts


def summarize_grype_reports(reports: list[dict], risk_lookup) -> dict:
    """Summarize fresh full Grype reports without mutating service findings."""
    severity_order = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    by_cve: dict[str, str] = {}
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
            raise ValueError("Vulnerability scan has no completed matches evidence")
        for match in report["matches"]:
            if not isinstance(match, dict) or not isinstance(match.get("vulnerability"), dict):
                raise ValueError("Invalid vulnerability scan match")
            vulnerability = match["vulnerability"]
            cve = str(vulnerability.get("id") or "").upper()
            if not cve:
                raise ValueError("Vulnerability scan match lacks identity")
            severity = str(vulnerability.get("severity") or "Unknown").title()
            if severity not in severity_order:
                severity = "Unknown"
            if severity_order[severity] > severity_order.get(by_cve.get(cve, "Unknown"), 0):
                by_cve[cve] = severity
            else:
                by_cve.setdefault(cve, severity)
    counts = {name: sum(value == name for value in by_cve.values()) for name in severity_order}
    risks = {cve: risk_lookup(cve) for cve in by_cve}
    return {"vulnerabilities": counts, "kev": sum(bool(kev) for kev, _ in risks.values()),
            "epss_max": max((score for _, score in risks.values() if score is not None), default=None),
            "cve_count": len(by_cve)}


def summarize_configuration_report(report: dict) -> dict:
    """Require completed Trivy JSON evidence; missing evidence is not clean."""
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ValueError("Unsupported or missing configuration scan evidence")
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("Configuration scan has no completed results")
    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Invalid configuration scan result")
        rows = result.get("Misconfigurations", [])
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise ValueError("Invalid configuration findings")
        for row in rows:
            if not isinstance(row, dict) or not row.get("ID"):
                raise ValueError("Configuration finding lacks identity")
            if str(row.get("Status", "FAIL")).upper() != "PASS":
                findings.append({"rule_id": str(row["ID"]), "target": str(result.get("Target", "")),
                                 "severity": str(row.get("Severity", "UNKNOWN")),
                                 "cause_metadata": deepcopy(row.get("CauseMetadata") or {})})
    return {"configuration_findings": len(findings), "configuration_scan_findings": findings,
            "policy_validation": "FAIL" if findings else "PASS"}


def plan_yaml(plan: dict[str, Any]) -> str:
    return yaml.safe_dump(plan, sort_keys=False, allow_unicode=True)
