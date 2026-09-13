from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Callable, Iterable


_AUTH = re.compile(r"(unauthorized|authentication required|denied|forbidden|no basic auth)", re.I)
_NOT_FOUND = re.compile(r"(repository.*not found|name unknown|manifest unknown)", re.I)
_TAG_NOT_FOUND = re.compile(r"(tag.*not found|manifest.*not found)", re.I)
_TLS = re.compile(r"(x509|certificate|tls|unknown authority)", re.I)
_NETWORK = re.compile(r"(timeout|timed out|connection refused|no such host|network is unreachable|dns)", re.I)
_IMAGE_PLACEHOLDERS = {"", "---", "—", "-", "null", "none", "nil", "n/a", "na", "not provided", "unknown image"}


def _text(value: Any, fallback: str = "") -> str:
    value = "" if value is None else str(value).strip()
    return value or fallback


def _list(value: Any) -> list:
    return value if isinstance(value, list) else ([] if value is None else [value])


def _valid_image_reference(value: Any) -> bool:
    if isinstance(value, dict):
        value = value.get("image") or value.get("reference") or value.get("name") or value.get("item")
    text = _text(value)
    if " :: " in text:
        text = text.split(" :: ", 1)[0].strip()
    elif "\t" in text:
        text = text.split("\t", 1)[0].strip()
    text = text.lower()
    return bool(text) and text not in _IMAGE_PLACEHOLDERS


def _valid_missing_item(value: Any) -> bool:
    if not isinstance(value, dict):
        return True
    kind = _text(value.get("type"), "Other").lower()
    if kind == "image":
        return _valid_image_reference(value)
    item = _text(value.get("item") or value.get("reference") or value.get("name"))
    return bool(item) and item.lower() not in _IMAGE_PLACEHOLDERS


def normalize_missing_reason(raw: Any, kind: str = "Other") -> str:
    message = _text(raw, "Unknown error").replace("\r", " ").replace("\n", " ")
    message = re.sub(r"\s+", " ", message)
    prefix = (
        "Image could not be pulled" if kind == "Image"
        else "Chart could not be downloaded" if kind == "Chart"
        else "Dependency could not be resolved" if kind == "Dependency"
        else "Evidence could not be processed"
    )
    if _AUTH.search(message):
        return f"{prefix} — authentication required"
    if _TAG_NOT_FOUND.search(message):
        return "Image could not be pulled — tag not found"
    if _NOT_FOUND.search(message) or "404" in message:
        if kind == "Image":
            return f"{prefix} — repository not found"
        if kind == "Chart":
            return f"{prefix} — HTTP 404"
        return "Dependency repository unavailable"
    if _TLS.search(message):
        return "TLS verification failed"
    if _NETWORK.search(message):
        if kind == "Image":
            return "Registry could not be reached"
        if kind == "Dependency":
            return "Dependency repository unavailable"
        return "Chart repository could not be reached"
    if "invalid reference" in message.lower():
        return "Invalid image reference"
    if kind == "Dependency" or "dependenc" in message.lower():
        return "Helm dependencies could not be resolved"
    # Preserve useful render diagnostics.  Older callers supplied only a
    # generic phrase, while recursive Helm discovery now includes the chart,
    # stage, template and sanitized Helm error in the message.
    if "render" in message.lower() or "template" in message.lower():
        return message if len(message) <= 220 else message[:217].rstrip() + "…"
    if len(message) > 220:
        message = message[:217].rstrip() + "…"
    return message or "Unknown error"


def missing_evidence_entry(value: Any, default_type: str, reason_override: Any = None) -> dict[str, str]:
    # Also accept the direct (type, item, reason) form used by API/worker
    # adapters, while retaining the historical (value, default_type) form.
    if reason_override is not None:
        value, default_type = {"type": value, "item": default_type, "reason": reason_override}, _text(value, "Other")
    source_file = "—"
    if isinstance(value, dict):
        kind = _text(value.get("type"), default_type).title()
        item = _text(value.get("item") or value.get("reference") or value.get("name") or value.get("resource"), f"Unknown {kind.lower()}")
        reason = value.get("reason") or value.get("details") or value.get("error")
        source_file = _text(
            value.get("source_file") or value.get("source_path") or value.get("filepath")
            or value.get("file") or value.get("chart_path") or value.get("values_file")
            or value.get("template") or value.get("provenance") or value.get("source") or value.get("resource_path"),
            "—",
        )
    else:
        raw = _text(value)
        item, sep, reason = raw.partition(" :: ")
        if not sep and "\t" in raw:
            item, reason = raw.split("\t", 1)
            sep = "\t"
        kind = default_type
        if not sep:
            reason = "Evidence was not available"
        item = item or f"Unknown {kind.lower()}"
    result = {"type": kind, "item": item, "reason": normalize_missing_reason(reason, kind)}
    if source_file != "—":
        result["source_file"] = source_file
    return result


def parse_image_reference(reference: Any) -> dict[str, str]:
    raw = _text(reference)
    digest = ""
    name = raw
    if "@" in name:
        name, digest = name.rsplit("@", 1)
    last_slash = name.rfind("/")
    last_colon = name.rfind(":")
    tag = ""
    if last_colon > last_slash:
        name, tag = name[:last_colon], name[last_colon + 1 :]
    parts = [part for part in name.split("/") if part]
    if not parts:
        return {"registry": "—", "repository": "—", "artifact": raw or "Unknown image", "version": "—", "digest": digest or "—"}
    first = parts[0]
    explicit_registry = "." in first or ":" in first or first == "localhost"
    if explicit_registry:
        registry, path = first, parts[1:]
    else:
        registry, path = "docker.io", parts
        if len(path) == 1:
            path = ["library", *path]
    artifact = path[-1] if path else first
    repository = "/".join(path[:-1]) or "—"
    return {
        "registry": registry,
        "repository": repository,
        "artifact": artifact,
        "version": tag or ("—" if digest else "latest"),
        "digest": digest or "—",
    }


def _split_port(value: Any) -> tuple[str, str]:
    text = _text(value)
    if "/" in text:
        left, right = text.rsplit("/", 1)
        if right.isdigit():
            return left or "Port", right
    if text.isdigit():
        return "Port", text
    return text or "Port", "Not provided"


def normalize_port(item: Any) -> dict[str, str]:
    if not isinstance(item, dict):
        service, port = _split_port(item)
        return {"port": port, "protocol": "TCP", "service": service, "declared_by": "—", "provenance": "—"}
    service = _text(item.get("service") or item.get("name"), "Port")
    port = item.get("port") or item.get("container_port")
    details = _text(item.get("details"))
    if port is None:
        service_from_details, port_from_details = _split_port(details)
        service = service if service != "Port" else service_from_details
        port = port_from_details
    port_text = _text(port, "Not provided")
    target = item.get("target_port") or item.get("targetPort")
    if target is not None and _text(target) != port_text:
        port_text = f"{port_text} → {_text(target)}"
    declared_by = _text(item.get("declared_by") or item.get("source") or item.get("found_in"), "—")
    result = {
        "port": port_text,
        "protocol": _text(item.get("protocol"), "TCP").upper(),
        "service": service,
        "declared_by": declared_by,
        "provenance": _text(item.get("provenance") or item.get("field_path"), declared_by),
    }
    source_file = _text(item.get("source_file") or item.get("source_path") or item.get("template"))
    if source_file:
        result["source_file"] = source_file
    return result


def _scope(kind: str, namespace: Any) -> str:
    return "Cluster" if kind.startswith("Cluster") else f"Namespace ({_text(namespace, 'default')})"


def normalize_accounts(items: Iterable[Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw in items:
        if not isinstance(raw, dict):
            rows.append({"name": _text(raw, "Unknown account"), "scope": "Namespace (default)", "relationships": "—"})
            continue
        kind = _text(raw.get("kind") or raw.get("type"), "ServiceAccount").replace(" ", "")
        name = _text(raw.get("name"), "unknown")
        if not name.startswith(f"{kind}/"):
            name = f"{kind}/{name}"
        relationships = raw.get("relationships")
        if relationships is None:
            relationships = raw.get("bound_to") or raw.get("bindings") or raw.get("subjects") or raw.get("role_ref")
        if isinstance(relationships, list):
            relationships = "; ".join(_text(v.get("name") if isinstance(v, dict) else v) for v in relationships if _text(v.get("name") if isinstance(v, dict) else v))
        row = {"name": name, "scope": _scope(kind, raw.get("namespace")), "relationships": _text(relationships, "—")}
        source_file = _text(raw.get("source_file") or raw.get("source_path") or raw.get("template"))
        if source_file:
            row["source_file"] = source_file
        rows.append(row)
    return rows


def _chart_fields(item: Any) -> dict[str, str]:
    if isinstance(item, dict):
        name = _text(item.get("name") or item.get("chart"), "Unknown chart")
        repository = _text(item.get("repository") or item.get("repo"), "—")
        version = _text(item.get("version"), "—")
        source = _text(item.get("discovered_from") or item.get("source"), "Submitted")
    else:
        raw = _text(item, "Unknown chart")
        filename = raw.rsplit("/", 1)[-1]
        match = re.match(r"(.+?)-([0-9][A-Za-z0-9.+_-]*)\.(?:tgz|tar\.gz|tar|zip)$", filename)
        name, version = (match.group(1), match.group(2)) if match else (re.sub(r"\.(tgz|tar\.gz|tar|zip)$", "", filename), "—")
        repository, source = "—", "Submitted"
    return {"type": "Chart", "registry": "—", "repository": repository, "artifact": name, "version": version, "discovered_from": source, "digest": "—"}


def _image_artifact(item: Any) -> dict[str, str]:
    raw = item if isinstance(item, dict) else {"image": item}
    reference = raw.get("image") or raw.get("reference") or raw.get("name") or "Unknown image"
    parsed = parse_image_reference(reference)
    supplied_digest = _text(raw.get("digest") or raw.get("image_digest"))
    if supplied_digest.startswith("sha256:"):
        parsed["digest"] = supplied_digest
    result = {"type": "Image", **parsed, "discovered_from": _text(raw.get("discovered_from") or raw.get("found_in") or raw.get("source"), "Submitted")}
    source_file = _text(raw.get("source_file") or raw.get("source_path") or raw.get("template"))
    if source_file:
        result["source_file"] = source_file
    return result


def _merge_image_artifacts(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse image occurrences into canonical service-level images.

    A digest is the strongest identity.  Before it is known, the normalized
    registry/repository/tag identity is used.  An unresolved occurrence is
    folded into the resolved row when the same normalized reference later
    gains a digest, while all source occurrences remain available for
    provenance and remediation.
    """
    grouped: dict[tuple, dict[str, Any]] = {}
    unresolved_by_base: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    resolved_by_base: dict[tuple, list[dict[str, Any]]] = defaultdict(list)

    def base(row: dict[str, Any]) -> tuple[str, ...]:
        return tuple(str(row.get(key) or "—").strip().lower() for key in ("registry", "repository", "artifact", "version"))

    def merge_into(target: dict[str, Any], source: dict[str, Any]) -> None:
        for field in ("discovered_from", "source_file"):
            values = [str(target.get(field) or ""), str(source.get(field) or "")]
            merged = []
            for value in values:
                merged.extend(part.strip() for part in value.splitlines() if part.strip())
            if merged:
                target[field] = "\n".join(dict.fromkeys(merged))
        occurrences = list(target.get("occurrences") or [])
        occurrence = {key: source.get(key) for key in ("registry", "repository", "artifact", "version", "digest", "discovered_from", "source_file") if source.get(key)}
        if occurrence and occurrence not in occurrences:
            occurrences.append(occurrence)
        target["occurrences"] = occurrences

    for row in rows:
        item = dict(row)
        digest = str(item.get("digest") or "—")
        identity = base(item)
        if digest != "—":
            matches = resolved_by_base[identity]
            target = matches[0] if matches else None
            if target is None:
                target = dict(item)
                target["occurrences"] = []
                grouped[("digest", identity, digest)] = target
                matches.append(target)
            merge_into(target, item)
            # Reconcile all unresolved rows collected for this reference.
            pending_rows = unresolved_by_base.pop(identity, [])
            # Digest-only references omit the tag.  They still identify the
            # same repository/artifact as an unresolved tagged occurrence.
            if identity[3] == "—":
                for pending_key in list(unresolved_by_base):
                    if pending_key[:3] == identity[:3]:
                        pending_rows.extend(unresolved_by_base.pop(pending_key, []))
                        grouped.pop(("reference", pending_key), None)
            for pending in pending_rows:
                merge_into(target, pending)
            grouped.pop(("reference", identity), None)
        else:
            matches = resolved_by_base.get(identity) or []
            if not matches:
                matches = [row for key, rows_for_key in resolved_by_base.items() if key[:3] == identity[:3] for row in rows_for_key if key[3] == "—"]
            if matches:
                merge_into(matches[0], item)
                continue
            target = grouped.get(("reference", identity))
            if target is None:
                target = dict(item)
                target["occurrences"] = []
                grouped[("reference", identity)] = target
            merge_into(target, item)
            unresolved_by_base[identity].append(item)
    return list(grouped.values())


def _unique(rows: Iterable[dict], keys: tuple[str, ...]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for row in rows:
        key = tuple(row.get(k) for k in keys)
        if key not in merged:
            merged[key] = dict(row)
            continue
        existing = merged[key]
        if row.get("discovered_from") and row["discovered_from"] not in existing.get("discovered_from", ""):
            existing["discovered_from"] = f"{existing.get('discovered_from', '')}, {row['discovered_from']}".lstrip(", ")
        source_files = [value.strip() for value in (existing.get("source_file", ""), row.get("source_file", "")) if value and value.strip()]
        if source_files:
            existing["source_file"] = "\n".join(dict.fromkeys("\n".join(source_files).splitlines()))
    return list(merged.values())


def normalize_dependencies(items: Iterable[Any]) -> list[dict[str, str]]:
    rows = []
    for raw in items:
        item = raw if isinstance(raw, dict) else {"name": raw}
        provides = item.get("provides") or item.get("resource_types") or []
        images = item.get("images") or []
        if isinstance(provides, list):
            provides = ", ".join(sorted({_text(value) for value in provides if _text(value)}))
        if isinstance(images, list):
            images = ", ".join(dict.fromkeys(_text(value) for value in images if _text(value)))
        rows.append({
            "dependency": _text(item.get("dependency") or item.get("name"), "Unknown dependency"),
            "used_by": _text(item.get("used_by") or item.get("parent"), "—"),
            "provides": _text(provides, "—"),
            "images": _text(images, "—"),
        })
    return rows


def normalize_render_warnings(items: Iterable[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        message = re.sub(r"\s+", " ", _text(raw.get("message") or raw.get("warning"))).strip()
        if not message:
            continue
        images = raw.get("unrecognized_images") or raw.get("images") or []
        if not isinstance(images, list):
            images = [images]
        rows.append({
            "type": _text(raw.get("type"), "render-warning"),
            "chart": _text(raw.get("chart"), "Unknown chart"),
            "source": _text(raw.get("source"), "—"),
            "message": message,
            "original_error": re.sub(r"\s+", " ", _text(raw.get("original_error"))).strip(),
            "unrecognized_images": [_text(image) for image in images if _text(image)],
        })
    return _unique(rows, ("type", "chart", "source", "message"))


def normalize_overview(
    raw: dict | None,
    *,
    skipped_images: Iterable[Any] = (),
    skipped_charts: Iterable[Any] = (),
    findings_images: Iterable[Any] = (),
    submitted_charts: Iterable[Any] = (),
    incomplete: bool = False,
    digest_resolver: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    raw_image_rows = [value for value in [*_list(raw.get("images") or raw.get("container_images"))] if isinstance(value, dict)]
    raw_images_by_reference = {}
    for image_row in raw_image_rows:
        reference = _text(image_row.get("image") or image_row.get("reference") or image_row.get("name") or image_row.get("item"))
        if reference:
            existing = raw_images_by_reference.get(reference)
            if not existing:
                raw_images_by_reference[reference] = image_row
            else:
                merged = dict(existing)
                for key in ("source_file", "source_path", "template"):
                    values = [merged.get(key), image_row.get(key)]
                    paths = list(dict.fromkeys(path.strip() for value in values if value for path in str(value).splitlines() if path.strip()))
                    if paths:
                        merged["source_file"] = "\n".join(paths)
                for key in ("discovered_from", "found_in", "source"):
                    if image_row.get(key) and image_row.get(key) not in str(merged.get(key) or ""):
                        merged[key] = f"{merged.get(key, '')}, {image_row[key]}".lstrip(", ")
                raw_images_by_reference[reference] = merged

    def enrich_skipped_image(value: Any) -> Any:
        if isinstance(value, dict):
            return value
        raw_value = _text(value)
        reference, separator, reason = raw_value.partition(" :: ")
        source = raw_images_by_reference.get(reference.strip())
        if not source:
            return value
        enriched = dict(source)
        enriched["item"] = reference.strip()
        if separator:
            enriched["reason"] = reason
        return enriched

    missing = [missing_evidence_entry(enrich_skipped_image(v), "Image") for v in skipped_images if _valid_image_reference(v)]
    missing += [missing_evidence_entry(v, "Chart") for v in skipped_charts]
    missing += [missing_evidence_entry(v, _text(v.get("type"), "Other") if isinstance(v, dict) else "Other") for v in _list(raw.get("missing_evidence") or raw.get("evidence")) if _valid_missing_item(v)]
    if incomplete and not missing:
        missing.append({"type": "Other", "item": "Assessment", "reason": "Latest assessment did not provide complete evidence"})

    image_values = [value for value in [*_list(raw.get("images") or raw.get("container_images")), *list(findings_images)] if _valid_image_reference(value)]
    image_artifacts = _merge_image_artifacts(_image_artifact(value) for value in image_values)
    artifacts = image_artifacts
    artifacts += [_chart_fields(value) for value in [*_list(raw.get("charts") or raw.get("helm_charts")), *list(submitted_charts)]]
    artifacts = _unique(artifacts, ("type", "registry", "repository", "artifact", "version", "digest"))
    if digest_resolver:
        for artifact in artifacts:
            if artifact["type"] != "Image" or artifact["digest"] != "—":
                continue
            repository = "/".join(p for p in (artifact["repository"], artifact["artifact"]) if p != "—")
            ref = f"{artifact['registry']}/{repository}:{artifact['version']}"
            try:
                artifact["digest"] = digest_resolver(ref) or "—"
            except Exception:
                artifact["digest"] = "—"

    raw_dependencies = _list(raw.get("dependencies"))
    resolved_dependencies = []
    for dependency in raw_dependencies:
        if isinstance(dependency, dict) and dependency.get("resolved") is False:
            missing.append(missing_evidence_entry({
                "type": "Dependency",
                "item": dependency.get("dependency") or dependency.get("name"),
                "reason": dependency.get("reason") or dependency.get("error") or "Dependency could not be resolved",
            }, "Dependency"))
        else:
            resolved_dependencies.append(dependency)

    return {
        "source": _text(raw.get("source"), "Submitted scan evidence"),
        "description": _text(raw.get("description")),
        "missing_evidence": _unique(missing, ("type", "item", "reason", "source_file")),
        "ports": _unique((normalize_port(value) for value in _list(raw.get("ports"))), ("port", "protocol", "service", "declared_by")),
        "accounts": _unique(normalize_accounts(_list(raw.get("accounts") or raw.get("rbac"))), ("name", "scope", "relationships")),
        "artifacts": artifacts,
        "dependencies": _unique(normalize_dependencies(resolved_dependencies), ("dependency", "used_by", "provides", "images")),
        "warnings": normalize_render_warnings(_list(raw.get("warnings") or raw.get("render_warnings"))),
    }
