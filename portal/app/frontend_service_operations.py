"""Explicit, JSON-only projections for service evidence operations."""
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urlunsplit

import yaml


def retained_scan_charts(files, execution):
    """Read-only chart identities from retained evidence, not persisted artifacts."""
    markers = {PurePosixPath(str(path).replace("\\", "/")): content
               for path, content in files.items()
               if PurePosixPath(str(path).replace("\\", "/")).name == "Chart.yaml"}
    roots = sorted(marker for marker in markers if not any(
        parent / "Chart.yaml" in markers for parent in marker.parent.parents))
    rows = []
    for marker in roots:
        if not isinstance(markers[marker], str):
            continue
        try:
            metadata = yaml.safe_load(markers[marker])
        except (yaml.YAMLError, TypeError, ValueError):
            continue
        if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str):
            continue
        name = metadata["name"]
        if not name.strip():
            continue
        version = metadata.get("version")
        root = marker.parent
        count = sum(PurePosixPath(str(path).replace("\\", "/")).is_relative_to(root) for path in files)
        rows.append({
            "semantic_type": "helm_chart", "retained_scan": True,
            "source_label": "Scan source", "file_count": count,
            "artifact": {"id": f"scan:{field(execution, 'execution_key', '')}:{marker}",
                         "artifact_type": "helm_chart", "artifact_name": name,
                         "chart_name": name, "chart_version": str(version) if isinstance(version, (str, int, float)) else None,
                         "source_type": "scan", "source_reference": str(root)},
            "revision": None,
            "validation": {"key": "not-validated", "label": "Not Validated"},
        })
    return rows


def field(value, key, default=None):
    return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)


def json_evidence(value):
    """Only evidence dictionaries may recurse; never serialize model internals."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): json_evidence(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_evidence(item) for item in value]
    return None


def fields(value, names):
    return {name: json_evidence(field(value, name)) for name in names}


# Evidence shapes produced by the validation engine. Raw Kubernetes specs,
# environment dictionaries, Secret data and arbitrary diagnostic extensions are
# deliberately outside this contract, including nested provider evidence.
EVIDENCE_KEYS = set("""id run_id run_key status phase engine artifact_type artifact_reference artifact_revision_id execution_key execution_scanned_at static_scan_complete created_at started_at completed_at checked_at duration_seconds reason_category classification classification_reasons classification_summary capability_assessment reason detail preflight_blocked cluster_name namespace cleanup_status helm_result resource_summary conditions dependencies observed_topology comparison events unhealthy_resources capability_preflight capability_bootstrap security_policy_violations sandbox_sensitive_behaviors resource_isolation warnings diagnostics terminal cleanup_terminal checks
expected_resources observed_expected expected_only runtime_generated observed_only failed code resource kind name expected_state observed_state explanation capability required source source_field strategy provider_specific evidence provider version attempted supported controller_ready ready duration_ms failure_reason reconciliation configmaps secrets tls_secrets missing_configmaps missing_secrets configuration_dependencies references required_keys missing_keys present keys key_count key_names type source_template source_line source_value_path resource_name resource_kind container field_path value rule_id rule_name isolation_control template
cpu memory pids overall configured_limit pods deployments statefulsets daemonsets jobs pvcs bound expected services ingresses cronjobs template_duration_ms install_duration_ms install release_status rendered_resource_count crashloopbackoff imagepullbackoff oomkilled pending_pods unschedulable insufficient_cpu insufficient_memory failed_jobs probe_failures unsupported_load_balancer unsupported_ingress missing_crds missing_storage_classes unavailable_images nodes edges target matched declared_only defaulted changed unresolved state involvedObject message condition count source_reference annotation_keys requested_class ready_replicas aggregate_pvcs_bound observed_resource event_collection endpoint_slices addresses ports port protocol readyEndpoints ready_endpoints service servicePort targetPort endpoint_count installed_resources expected_resources_count
cleanup_failure kind_delete network_delete validation_infrastructure ingress_provider load_balancer_provider workload_evidence sandbox_preflight policy_violations classification_summary provisioned provisioner storage_classes ingress_class ingress_classes load_balancer_class ip addresses hostname controller service_name service_namespace external_ips endpoints ingress runtime generated source_file reference yaml_path parent_chart parent_chart_name chart_name chart_version discovery_source_file discovery_source confidence label classifications provenance api_version generic flow_rank network primary style points label_position label_lines node_ids positions bounds x y width height rank schema_version incomplete summary relationships ports unresolved warnings node_id chart_provenance""".split())
EVIDENCE_KEYS.update("statuses required_count verified_count available_count failed_count unexercised_count rows provisioned_by_cats dependency_rows dependency_total dependency_available dependency_kind dependency_name required_by optional source_resource provider_id bootstrap_status readiness_status reconciliation_result verification_method item chart node declared runtime_verified differences".split())

# Lifecycle digest shared with the lightweight status contract (opaque, no evidence).
EVIDENCE_KEYS.update({"revision", "terminal", "cleanup_terminal"})


def safe_evidence(value):
    """Known evidence fields only, even inside a nominally safe engine DTO."""
    if isinstance(value, Mapping):
        return {str(key): safe_evidence(item) for key, item in value.items() if str(key) in EVIDENCE_KEYS}
    if isinstance(value, (tuple, list)):
        return [safe_evidence(item) for item in value]
    if isinstance(value, str) and "://" in value and not any(character.isspace() for character in value):
        return public_reference(value)
    return json_evidence(value)


def scalar_values(value):
    """Leaf evidence has no arbitrary nested dictionaries."""
    if isinstance(value, Mapping):
        return {str(key): json_evidence(item) for key, item in value.items() if not isinstance(item, (Mapping, list, tuple))}
    if isinstance(value, (list, tuple)):
        return [json_evidence(item) for item in value if not isinstance(item, (Mapping, list, tuple))]
    return json_evidence(value)


def public_reference(value):
    """Source links must not disclose URL userinfo, signed queries or fragments."""
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        try:
            if parsed.port:
                host += f":{parsed.port}"
        except ValueError:
            return None
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    return value


def project_service_operations(template_name, context):
    data = {}
    if template_name == "service_dependencies.html":
        keys = ("dependency_projection_status", "dependency_projection_error", "dependency_rows", "dependency_total", "dependency_all_total", "dependency_page", "dependency_pages", "dependency_page_url", "dependency_types", "dependency_images", "dependency_query", "dependency_artifacts", "vulnerable_components", "critical_components", "kev_components", "fixed_components", "license_unknown_components", "watchlisted_components", "history_versions")
        data.update(fields(context, keys))
        row_names = ("name", "version", "type", "license_expression", "license_declared", "license_detected", "image", "vulnerabilities", "severity", "kev", "epss", "fixed_versions", "watchlisted", "purl", "cpe", "supplier", "author", "architecture", "hashes", "copyright", "license_source", "image_digest", "sbom", "location", "origin", "severity_counts", "risk", "dependency_parents", "dependency_children")
        data["dependency_query"] = fields(context.get("dependency_query", {}), ("q", "type", "image", "license", "filter", "epss"))
        data["dependency_rows"] = []
        for item in context.get("dependency_rows", []):
            row = {name: scalar_values(field(item, name)) for name in row_names}
            row["risk"] = [fields(risk, ("cve", "severity", "scanner", "kev", "epss", "fixed_version")) for risk in field(item, "risk", []) or []]
            row["hashes"] = fields(field(item, "hashes", {}), ("MD5", "SHA1", "SHA256", "SHA512", "SHA-1", "SHA-256", "SHA-512")) if isinstance(field(item, "hashes"), Mapping) else scalar_values(field(item, "hashes"))
            if isinstance(row["hashes"], dict):
                row["hashes"] = {key: value for key, value in row["hashes"].items() if value is not None}
            row["severity_counts"] = {key: json_evidence(field(field(item, "severity_counts", {}), key)) for key in ("Critical", "High", "Medium", "Low", "Unknown", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if field(field(item, "severity_counts", {}), key) is not None}
            data["dependency_rows"].append(row)
        names = ("id", "scanned_at", "execution_key")
        data["dependency_executions"] = [fields(item, names) for item in context.get("dependency_executions", [])]
        selected = context.get("dependency_selected_execution")
        data["dependency_selected_execution"] = fields(selected, names) if selected else None
    elif template_name == "service_artifacts.html":
        data.update(fields(context, ("can_edit", "can_validate", "can_image_workflow", "repository_count", "chart_count", "helm_file_count", "manifest_count")))
        data["original_file_count"] = len(context.get("original_files") or {})
        original = context.get("original_execution")
        data["original_execution"] = fields(original, ("execution_key",)) if original else None
        legacy = context.get("legacy_helm_repository")
        data["legacy_helm_repository"] = fields(legacy, ("chart_count",)) if legacy else None
        data["artifact_rows"] = []
        for row in context.get("artifact_rows", []):
            item = fields(row, ("semantic_type", "source_label", "validation", "chart_count"))
            item["validation"] = fields(field(row, "validation"), ("key", "label", "symbol", "run_key", "checked_at"))
            item["artifact"] = fields(field(row, "artifact"), ("id", "artifact_type", "artifact_name", "chart_name", "chart_version", "source_type", "source_reference", "source_metadata", "created_at", "last_refreshed_at"))
            metadata = field(field(row, "artifact"), "source_metadata", {}) or {}
            item["artifact"]["source_reference"] = public_reference(item["artifact"].get("source_reference"))
            item["artifact"]["source_metadata"] = {"chart_count": json_evidence(field(metadata, "chart_count", 0)), "versions": [fields(version, ("version",)) for version in field(metadata, "versions", [])]}
            revision = field(row, "revision")
            item["revision"] = fields(revision, ("revision_label", "revision_number", "checksum", "created_at")) if revision else None
            item["file_count"] = len(field(row, "files", {}) or {})
            data["artifact_rows"].append(item)
        scanned_charts = retained_scan_charts(context.get("original_files") or {}, original)
        data["artifact_rows"].extend(scanned_charts)
        data["scan_chart_count"] = len(scanned_charts)
        data["chart_count"] = (data.get("chart_count") or 0) + len(scanned_charts)
        data["image_inventory"] = []
        for row in context.get("image_inventory", []):
            item = fields(row, ("count", "references"))
            item["image"] = fields(field(row, "image"), ("id", "image_reference", "image_digest", "scan_status", "last_scanned_at", "scan_error", "lifecycle_status"))
            data["image_inventory"].append(item)
    elif template_name == "service_validation.html":
        data.update(fields(context, ("can_validate", "validation_unavailable_reason")))
        data["validation"] = safe_evidence(context.get("validation"))
        if data["validation"]:
            data["validation"]["artifact_reference"] = public_reference(data["validation"].get("artifact_reference"))
            diagnostics = field(context.get("validation"), "diagnostics", {}) or {}
            diagnostic_names = ("cleanup_failure", "kind_delete", "network_delete", "validation_infrastructure", "ingress_provider", "load_balancer_provider", "workload_evidence", "reconciliation", "resource_isolation", "sandbox_preflight", "security_policy_violations", "classification", "classification_summary")
            data["validation"]["diagnostics"] = {name: safe_evidence(diagnostics[name]) for name in diagnostic_names if name in diagnostics}
        history = context.get("validation_history") or {}
        data["validation_history"] = {key: history.get(key) for key in ("page", "pages", "total", "page_size")} if history else None
        data["validation_runs"] = [fields(run, ("run_key", "artifact_type", "status", "completed_at", "duration_seconds", "cleanup_status")) | {"artifact_reference": public_reference(field(run, "artifact_reference"))} for run in context.get("validation_runs", [])]
    return data
