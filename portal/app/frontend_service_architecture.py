"""Page contract from the normalized architecture graph, never execution payloads."""
from .architecture_evidence import architecture_summary_json
from .frontend_service_operations import fields, json_evidence, safe_evidence, public_reference


def project_graph(graph):
    data = fields(graph, ("schema_version", "incomplete", "source"))
    data["summary"] = safe_evidence(graph.get("summary", {}))
    row_keys = {
        "nodes": ("id", "kind", "type", "name", "namespace", "label", "source", "chart_provenance", "generic", "api_version", "evidence", "ports", "provenance", "flow_rank", "classifications"),
        "relationships": ("id", "source", "target", "classification", "classifications", "style", "label", "confidence", "evidence", "primary", "network", "provenance"),
        "unresolved": ("node_id", "reason"),
        "warnings": ("type", "item", "reason", "message", "source_file"),
        "ports": ("port", "protocol", "name", "source"),
    }
    for collection, keys in row_keys.items():
        data[collection] = [safe_evidence(fields(row, keys)) if isinstance(row, dict) else json_evidence(row) for row in graph.get(collection, [])]
    data["layouts"] = {}
    for name in ("all", "declared", "runtime", "differences", "configuration", "containers", "flow", "network", "storage"):
        layout = (graph.get("layouts") or {}).get(name)
        if not isinstance(layout, dict):
            continue
        projected = {key: safe_evidence(layout.get(key)) for key in ("node_ids", "edges", "bounds")}
        projected["positions"] = {str(node_id): fields(point, ("x", "y", "rank")) for node_id, point in (layout.get("positions") or {}).items()}
        data["layouts"][name] = projected
    return data


def project_service_architecture(context):
    graph = context.get("architecture_graph") or {}
    verification = json_evidence(architecture_summary_json(context.get("architecture_verification") or {}))
    verification["artifact_reference"] = public_reference(verification.get("artifact_reference"))
    return {
        "architecture_state": context.get("architecture_state"),
        "architecture_verification": verification,
        "architecture_graph": project_graph(graph),
    }
