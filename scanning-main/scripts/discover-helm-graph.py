#!/usr/bin/env python3
"""Discover a complete, bounded Helm chart graph from an artifact.

This utility deliberately does not assign meaning to one values-file schema.
It uses actual chart structure, safe local resolution, and combined YAML
signals. Rendering remains in the existing shell workers so dependency and
network policy continue to be enforced there.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.parse
import zipfile

import yaml


SKIP_DIRS = {".git", ".cats-helm-graph", "results", "sboms", "trivy-results", "helm-rendered", "helm-image-rendered"}
PATH_KEYS = {"path", "location", "source", "chart", "helmchart", "chartpath", "chart_path", "localpath", "local_path", "reference", "ref", "artifact"}
CHART_KEYS = {"chart", "helmchart", "chartref", "chart_ref", "chartname", "name", "reference", "ref", "source"}
REPOSITORY_KEYS = {"repository", "repo", "repourl", "repo_url", "helmrepo", "registry", "url", "oci"}
VERSION_KEYS = {"version", "chartversion", "chart_version", "tag"}
MAX_NESTING = int(os.getenv("HELM_DISCOVERY_MAX_DEPTH", "24"))
MAX_CHARTS = int(os.getenv("HELM_DISCOVERY_MAX_CHARTS", "500"))
MAX_REFS = int(os.getenv("HELM_DISCOVERY_MAX_REFERENCES", "2000"))
# Avoid asking the host filesystem to stat paths that are already beyond the
# platform's practical path limit.  The exact limit differs by OS/filesystem;
# this conservative bound keeps malformed recursive references harmless.
MAX_PATH_CHARS = int(os.getenv("HELM_DISCOVERY_MAX_PATH_CHARS", "240"))


def norm_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def safe_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return (bool(normalized) and not normalized.startswith("/") and
            not re.match(r"^[A-Za-z]:/", normalized) and ".." not in normalized.split("/"))


def inside(path: Path, roots: list[Path]) -> bool:
    resolved = path.resolve()
    return any(resolved == root.resolve() or root.resolve() in resolved.parents for root in roots)


def read_yaml_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8-sig")
            documents = list(yaml.safe_load_all(text))
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        for document_index, document in enumerate(documents):
            if document is not None:
                yield path, document_index, document


def chart_meta(chart_path: Path) -> tuple[str, str]:
    try:
        data = yaml.safe_load((chart_path / "Chart.yaml").read_text(encoding="utf-8-sig")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        data = {}
    return str(data.get("name") or chart_path.name), str(data.get("version") or "")


def chart_identity(path: Path, name: str, version: str, context: dict) -> str:
    material = f"{path.resolve()}|{name}|{version}|{json.dumps(context, sort_keys=True, default=str)}"
    return hashlib.sha256(material.encode()).hexdigest()[:24]


def canonical_source(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def path_value(value: str, source: Path, roots: list[Path], extraction_root: Path) -> tuple[Path | None, str]:
    value = value.strip().strip("\"'")
    if not value or len(value) > 1024 or value.startswith(("{{", "$", "#")):
        return None, ""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme in {"http", "https", "oci"}:
        return None, value
    candidates = []
    raw = Path(value)
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend((source.parent / raw, roots[0] / raw))
    for candidate in candidates:
        try:
            if len(str(candidate)) > MAX_PATH_CHARS:
                continue
            resolved = candidate.resolve()
            if len(str(resolved)) > MAX_PATH_CHARS:
                continue
            if not inside(resolved, roots + [extraction_root]):
                continue
            if ((resolved / "Chart.yaml").is_file() or
                    (resolved.is_file() and resolved.name.lower().endswith((".tgz", ".tar.gz", ".zip")))):
                return resolved, value
        except (OSError, RuntimeError):
            # A broken symlink, symlink loop, or overlong candidate is simply
            # an unresolved reference. Discovery must continue for siblings.
            continue
    return None, value


def extract_package(package: Path, extraction_root: Path, roots: list[Path]) -> Path | None:
    digest = hashlib.sha256(package.read_bytes()).hexdigest()[:24]
    destination = extraction_root / digest
    if not destination.exists():
        destination.mkdir(parents=True, exist_ok=True)
        try:
            if package.suffix.lower() == ".zip":
                with zipfile.ZipFile(package) as archive:
                    members = archive.infolist()
                    if any(not safe_member(item.filename) or stat.S_ISLNK((item.external_attr >> 16) & 0o170000)
                           for item in members):
                        raise ValueError("unsafe chart archive path")
                    archive.extractall(destination)
            else:
                with tarfile.open(package, mode="r:*") as archive:
                    members = archive.getmembers()
                    if any(not safe_member(item.name) or item.issym() or item.islnk() for item in members):
                        raise ValueError("unsafe chart archive path")
                    # Members have already passed traversal and link checks.
                    # Use the safer extraction filter where available while
                    # retaining compatibility with older scanner runtimes.
                    try:
                        archive.extractall(destination, filter="data")
                    except TypeError:
                        archive.extractall(destination)
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile):
            shutil.rmtree(destination, ignore_errors=True)
            return None
    charts = sorted(destination.rglob("Chart.yaml"))
    return charts[0].parent if charts else None


def mapping_values(node: object, path: str = "") -> tuple[object | None, str | None, dict]:
    """Return the first useful chart reference and its render context."""
    if not isinstance(node, dict):
        return None, None, {}
    lower = {norm_key(key): (key, value) for key, value in node.items()}
    reference = None
    for key, value in node.items():
        key_norm = norm_key(key)
        if key_norm in PATH_KEYS | CHART_KEYS and isinstance(value, str):
            if value.startswith(("oci://", "http://", "https://", "./", "../", "/")) or "/" in value or value.endswith((".tgz", ".tar.gz", ".zip")):
                reference = value
                break
    chartish = bool(set(lower) & (CHART_KEYS | REPOSITORY_KEYS | VERSION_KEYS))
    repo = next((value for key, value in lower.items() if key in REPOSITORY_KEYS and isinstance(value, str)), None)
    if reference is None and chartish and repo:
        reference = next((value for key, value in lower.items() if key in CHART_KEYS and isinstance(value, str)), None)
    if reference is None:
        return None, None, {}
    context: dict = {}
    for context_key, aliases in (("values", {"valuesfile", "valuesfiles", "values"}), ("release", {"release", "releasename"}),
                                 ("namespace", {"namespace", "ns"}), ("version", VERSION_KEYS), ("repository", REPOSITORY_KEYS), ("set", {"set", "setvalues"})):
        value = next((value for key, value in lower.items() if key in aliases), None)
        if value is not None:
            context[context_key] = value
    for context_key, aliases in (("alias", {"alias"}), ("condition", {"condition"}), ("tags", {"tags"}),
                                 ("include_crds", {"includecrds", "include_crd"}), ("dependency_mode", {"dependencymode"}),
                                 ("framework", {"framework"})):
        value = next((value for key, value in lower.items() if key in aliases), None)
        if value is not None:
            context[context_key] = value
    if "values" not in context:
        for key, value in node.items():
            key_norm = norm_key(key)
            if isinstance(value, dict) and any(token in key_norm for token in ("value", "config", "override", "setting")):
                context["values"] = value
                break
    return reference, repo, context


def walk_references(node: object, source: Path, root: Path, roots: list[Path], extraction_root: Path, yaml_path: str = "", depth: int = 0):
    if depth > MAX_NESTING:
        return
    if isinstance(node, dict):
        reference, repo, context = mapping_values(node, yaml_path)
        if reference:
            resolved, raw = path_value(str(reference), source, roots, extraction_root)
            instance = yaml_path.rsplit(".", 1)[-1] if yaml_path else ""
            yield {"reference": raw, "resolved": resolved, "repository": repo, "context": context, "yaml_path": yaml_path, "instance": instance}
        for key, value in node.items():
            # The mapping itself is the occurrence.  Do not emit a second
            # scalar occurrence for its chart/path field.
            if reference is not None and value == reference:
                continue
            child_path = f"{yaml_path}.{key}" if yaml_path else str(key)
            yield from walk_references(value, source, root, roots, extraction_root, child_path, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_references(value, source, root, roots, extraction_root, f"{yaml_path}[{index}]", depth + 1)
    elif isinstance(node, str):
        resolved, raw = path_value(node, source, roots, extraction_root)
        # A local path that resolves to Chart.yaml is high-confidence even
        # when its YAML key is arbitrary.  Keep scalar references source-level
        # occurrences (no logical instance) so data paths do not create
        # synthetic chart instances during cycle traversal.
        if resolved or raw.startswith(("oci://", "http://", "https://")):
            yield {"reference": raw, "resolved": resolved, "context": {}, "yaml_path": yaml_path, "instance": ""}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--entries", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    entries_path = Path(args.entries).resolve()
    graph_root = output.parent / ".cats-helm-graph"
    extraction_root = graph_root / "packages"
    extraction_root.mkdir(parents=True, exist_ok=True)
    roots = [root]

    charts: dict[tuple[str, str], dict] = {}
    chart_paths = sorted({path.parent.resolve() for path in root.rglob("Chart.yaml") if inside(path, roots) and not any(part in SKIP_DIRS for part in path.relative_to(root).parts)})
    for chart_path in chart_paths:
        name, version = chart_meta(chart_path)
        chart_id = chart_identity(chart_path, name, version, {})
        charts[(str(chart_path), json.dumps({"context": {}, "instance": ""}, sort_keys=True))] = {"chart_id": chart_id, "chart": name, "instance": "", "version": version,
            "path": str(chart_path), "source": canonical_source(chart_path, root), "parent": None,
            "discovery_method": "filesystem", "discovery_source_file": None, "yaml_path": None,
            "discovery_source_path": None,
            "reference": None, "confidence": "HIGH", "resolution": "LOCAL_CHART", "status": "Discovered",
            "embedded_dependency": False, "context": {}}

    # Packaged charts are first-class artifact inputs even when no YAML file
    # happens to point at them. Extraction is content-addressed and guarded by
    # the archive path/symlink checks in ``extract_package``.
    package_paths = sorted({path.resolve() for suffix in ("*.tgz", "*.tar.gz", "*.zip")
                            for path in root.rglob(suffix)
                            if path.is_file() and not any(part in SKIP_DIRS for part in path.relative_to(root).parts)})
    for package_path in package_paths:
        packaged_chart = extract_package(package_path, extraction_root, roots)
        if not packaged_chart or not (packaged_chart / "Chart.yaml").is_file():
            continue
        name, version = chart_meta(packaged_chart)
        key = (str(packaged_chart), json.dumps({"context": {}, "instance": ""}, sort_keys=True))
        if key in charts:
            continue
        charts[key] = {"chart_id": chart_identity(packaged_chart, name, version, {}), "chart": name, "instance": "", "version": version,
            "path": str(packaged_chart), "source": canonical_source(package_path, root), "parent": None,
            "discovery_method": "packaged chart", "discovery_source_file": canonical_source(package_path, root),
            "discovery_source_path": str(package_path), "yaml_path": None, "reference": package_path.name,
            "confidence": "HIGH", "resolution": "LOCAL_CHART", "status": "Discovered",
            "embedded_dependency": False, "context": {}}

    # Establish structural parentage before following references. A standard
    # vendored child is represented in the graph but is not independently
    # rendered because the parent Helm render already contains it.
    for chart in charts.values():
        chart_path = Path(chart["path"])
        ancestors = [candidate for candidate in charts.values()
                     if candidate is not chart and chart_path.parent != chart_path and Path(candidate["path"]) in chart_path.parents]
        if ancestors:
            parent = max(ancestors, key=lambda item: len(Path(item["path"]).parts))
            chart["parent"] = parent["chart_id"]
            chart["parent_chart_name"] = parent["chart"]
            chart["embedded_dependency"] = (Path(parent["path"]) / "charts") in chart_path.parents

    def source_owner(source_file: Path):
        candidates = [item for item in charts.values()
                      if Path(item["path"]).resolve() == source_file.resolve() or
                      Path(item["path"]).resolve() in source_file.resolve().parents]
        # A values file outside a chart is an artifact-level/root occurrence.
        # It must never inherit whichever top-level chart happened to be
        # traversed first.
        return max(candidates, key=lambda item: len(Path(item["path"]).parts)) if candidates else None

    references: list[dict] = []
    unresolved: list[dict] = []
    queue = list(charts.values())
    visited_sources: set[tuple[str, str]] = set()
    processed_documents: set[tuple[str, int]] = set()
    while queue and len(charts) < MAX_CHARTS and len(references) < MAX_REFS:
        chart = queue.pop(0)
        chart_path = Path(chart["path"])
        instance_key = (str(chart_path), json.dumps({"context": chart.get("context") or {}, "instance": chart.get("instance") or ""}, sort_keys=True, default=str))
        if instance_key in visited_sources:
            continue
        visited_sources.add(instance_key)
        chart_yaml = chart_path / "Chart.yaml"
        # Standard dependency declarations are always high confidence.
        try:
            chart_data = yaml.safe_load(chart_yaml.read_text(encoding="utf-8-sig")) or {}
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            chart_data = {}
        for dependency in chart_data.get("dependencies", []) if isinstance(chart_data.get("dependencies"), list) else []:
            if isinstance(dependency, dict) and dependency.get("name"):
                references.append({"parent_chart": chart["chart_id"], "reference": dependency.get("name"), "repository": dependency.get("repository"),
                                   "version": dependency.get("version"), "discovery_method": "Chart.yaml dependency", "source_file": canonical_source(chart_yaml, root),
                                   "source_path": str(chart_yaml.resolve()), "yaml_path": "dependencies", "context": {},
                                   "confidence": "HIGH", "resolution_status": "DECLARED_DEPENDENCY"})
        document_root = chart_path if chart.get("discovery_method") == "packaged chart" else (root if chart.get("parent") is None else chart_path)
        for source_file, document_index, document in read_yaml_files(document_root):
            owner = source_owner(source_file)
            if owner and Path(owner["path"]).resolve() != chart_path.resolve():
                continue
            document_key = (str(source_file.resolve()), document_index)
            if document_key in processed_documents:
                continue
            processed_documents.add(document_key)
            for candidate in walk_references(document, source_file, root, roots, extraction_root):
                raw = str(candidate.get("reference") or "")
                resolved = candidate.get("resolved")
                relationship_parent = chart["chart_id"] if owner else None
                ref_entry = {"parent_chart": relationship_parent, "parent_chart_name": chart.get("chart") if owner else "Root", "instance": candidate.get("instance") or "",
                             "reference": raw, "repository": candidate.get("repository"),
                             "version": (candidate.get("context") or {}).get("version"), "discovery_method": "recursive YAML reference",
                             "source_file": canonical_source(source_file, root), "yaml_path": candidate.get("yaml_path") or "—",
                             "source_path": str(source_file.resolve()), "context": candidate.get("context") or {},
                             "confidence": "MEDIUM", "resolution_status": "UNRESOLVED"}
                if resolved:
                    ref_entry["confidence"] = "HIGH"
                elif raw.startswith("oci://"):
                    ref_entry["confidence"] = "HIGH"
                elif candidate.get("repository") and raw:
                    ref_entry["confidence"] = "MEDIUM"
                elif raw.startswith(("http://", "https://")):
                    # A bare URL is evidence, but is never an automatic
                    # render candidate without an explicitly configured repo.
                    ref_entry["confidence"] = "LOW"
                else:
                    continue
                references.append(ref_entry)
                child_path = resolved
                if child_path and child_path.is_file():
                    child_path = extract_package(child_path, extraction_root, roots)
                if child_path and child_path.is_dir() and (child_path / "Chart.yaml").is_file():
                    child_name, child_version = chart_meta(child_path)
                    context = candidate.get("context") or {}
                    instance = str(candidate.get("instance") or "")
                    key = (str(child_path), json.dumps({"context": context, "instance": instance}, sort_keys=True, default=str))
                    if key not in charts and len(charts) < MAX_CHARTS:
                        child_id = chart_identity(child_path, child_name, child_version, {**context, "__instance": instance})
                        embedded = (chart_path / "charts") in child_path.parents
                        charts[key] = {"chart_id": child_id, "chart": child_name, "instance": instance, "version": child_version, "path": str(child_path),
                        "source": canonical_source(child_path, root), "parent": relationship_parent, "parent_chart_name": chart.get("chart") if relationship_parent else "Root", "discovery_method": ref_entry["discovery_method"],
                            "discovery_source_file": ref_entry["source_file"], "discovery_source_path": str(source_file.resolve()),
                            "yaml_path": ref_entry["yaml_path"], "reference": raw,
                            "confidence": ref_entry["confidence"], "resolution": "LOCAL_CHART", "status": "Discovered",
                            "embedded_dependency": embedded, "context": context}
                        queue.append(charts[key])
                    ref_entry.update(resolution_status="LOCAL_CHART", resolved_path=str(child_path), chart_name=child_name, chart_version=child_version)
                elif raw.startswith(("oci://", "http://", "https://")) or candidate.get("repository"):
                    unresolved.append({"type": "Helm Chart", "item": raw, "reason": "External chart resolution is controlled by configured Helm/OCI access and was not available during discovery.",
                                       "source_file": ref_entry["source_file"], "yaml_path": ref_entry["yaml_path"],
                                       "repository": ref_entry.get("repository"), "version": ref_entry.get("version"),
                                       "parent_chart": relationship_parent, "instance": ref_entry.get("instance") or ""})
                else:
                    unresolved.append({"type": "Helm Chart", "item": raw, "reason": "Referenced path did not resolve to a chart inside the uploaded artifact.",
                                       "source_file": ref_entry["source_file"], "yaml_path": ref_entry["yaml_path"],
                                       "repository": ref_entry.get("repository"), "version": ref_entry.get("version"),
                                       "parent_chart": relationship_parent, "instance": ref_entry.get("instance") or ""})

    # Resolve the local portion of standard dependency declarations after the
    # recursive walk. Vendored directories are already in ``charts``; this
    # also marks an exact packaged dependency when it was discovered above.
    chart_by_id = {item["chart_id"]: item for item in charts.values()}
    # A filesystem chart can be only the source for explicit instances. Keep
    # that source in the graph inventory, but do not emit an uninstantiated
    # render entry alongside the instance entries.
    instantiated_paths = {item.get("path") for item in charts.values() if item.get("instance")}
    for item in charts.values():
        item["source_only"] = bool(
            not item.get("instance")
            and item.get("path") in instantiated_paths
            and item.get("discovery_method") == "filesystem"
        )
    for reference in references:
        if reference.get("discovery_method") != "Chart.yaml dependency":
            continue
        parent = chart_by_id.get(reference.get("parent_chart"))
        if not parent:
            continue
        dependency_name = str(reference.get("reference") or "")
        candidates = [item for item in charts.values()
                      if item.get("chart") == dependency_name and
                      Path(parent["path"]) in Path(item["path"]).parents]
        if not candidates:
            candidates = [item for item in charts.values()
                          if item.get("chart") == dependency_name and
                          item.get("discovery_method") == "packaged chart" and
                          (not reference.get("version") or item.get("version") == reference.get("version"))]
        if candidates:
            child = min(candidates, key=lambda item: len(Path(item["path"]).parts))
            if child.get("parent") is None:
                child["parent"] = parent["chart_id"]
                child["parent_chart_name"] = parent.get("chart")
                package_source = Path(child.get("discovery_source_path") or "")
                child["embedded_dependency"] = (package_source.parent.name == "charts" and
                                                  Path(parent["path"]).resolve() in package_source.resolve().parents)
            reference.update(resolution_status="LOCAL_CHART", resolved_path=child["path"],
                             chart_name=child.get("chart"), chart_version=child.get("version"))
        else:
            unresolved.append({"type": "Helm Chart", "item": dependency_name,
                               "reason": "Chart.yaml dependency was declared but no local chart or permitted configured repository artifact was available.",
                               "source_file": reference.get("source_file", "—"), "yaml_path": reference.get("yaml_path", "dependencies"),
                               "repository": reference.get("repository"), "version": reference.get("version"),
                               "parent_chart": reference.get("parent_chart")})

    # Keep a bounded, stable set of references even when a map and its scalar
    # child both expose the same chart signal.
    reference_keys = set()
    stable_references = []
    for reference in references:
        key = (reference.get("parent_chart"), reference.get("reference"), reference.get("repository"),
               reference.get("version"), reference.get("source_file"), reference.get("yaml_path"))
        if key in reference_keys:
            continue
        reference_keys.add(key)
        stable_references.append(reference)
    references = stable_references

    def apply_context(entry: dict, context: dict, source_path: str | None) -> None:
        context = context if isinstance(context, dict) else {}
        entry["context"] = context
        values = context.get("values")
        if isinstance(values, dict):
            inline_dir = graph_root / "inline-values"
            inline_dir.mkdir(parents=True, exist_ok=True)
            inline_path = inline_dir / f"{entry['chart_id']}.yaml"
            inline_path.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")
            entry["values"] = [str(inline_path)]
        elif isinstance(values, str):
            values_path, _ = path_value(values, Path(source_path or root), roots, extraction_root)
            if values_path and values_path.is_file():
                entry["values"] = [str(values_path)]
        elif isinstance(values, list):
            resolved_values = []
            for value in values:
                if isinstance(value, str):
                    values_path, _ = path_value(value, Path(source_path or root), roots, extraction_root)
                    if values_path and values_path.is_file():
                        resolved_values.append(str(values_path))
            if resolved_values:
                entry["values"] = resolved_values
        if isinstance(context.get("release"), str):
            entry["release"] = context["release"]
        if isinstance(context.get("namespace"), str):
            entry["namespace"] = context["namespace"]
        if context.get("set") is not None:
            entry["set"] = context["set"]
        for key in ("alias", "condition", "tags", "include_crds", "dependency_mode", "framework"):
            if context.get(key) is not None:
                entry[key] = context[key]

    entries = []
    for chart in charts.values():
        if chart.get("embedded_dependency"):
            continue
        if chart.get("source_only"):
            continue
        entry = {"path": chart["path"], "name": chart["chart"], "instance": chart.get("instance") or "", "release": chart["chart"], "version": chart.get("version"),
                 "declared_by": chart.get("discovery_source_file") or "filesystem", "declared_enabled": "unknown",
                 "chart_id": chart["chart_id"], "parent_chart": chart.get("parent"), "parent_chart_name": chart.get("parent_chart_name") or "Root",
                 "discovery_method": chart.get("discovery_method"),
                 "discovery_source_file": chart.get("discovery_source_file"), "yaml_path": chart.get("yaml_path"),
                 "reference": chart.get("reference"), "confidence": chart.get("confidence"), "context": chart.get("context") or {}}
        apply_context(entry, chart.get("context") or {}, chart.get("discovery_source_path"))
        entries.append(entry)

    # External references remain render candidates, but the shell workers
    # enforce HELM_ALLOW_NETWORK and configured repository/OCI access.
    known_remote = {(item.get("reference"), item.get("repository"), item.get("version"), item.get("instance"),
                     json.dumps(item.get("context") or {}, sort_keys=True, default=str))
                    for item in entries if item.get("reference")}
    for reference in references:
        raw = str(reference.get("reference") or "")
        repository = reference.get("repository")
        if reference.get("resolution_status") == "LOCAL_CHART" or not raw:
            continue
        if not (repository or raw.startswith("oci://")):
            continue
        context_key = json.dumps(reference.get("context") or {}, sort_keys=True, default=str)
        key = (raw, repository, reference.get("version"), reference.get("instance"), context_key)
        if key in known_remote:
            continue
        known_remote.add(key)
        entry = {"name": Path(raw.rstrip("/")).name or raw, "instance": reference.get("instance") or "", "reference": raw, "repository": repository,
                        "version": reference.get("version"), "declared_by": reference.get("source_file"),
                        "declared_enabled": "unknown", "chart_id": hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24],
                        "parent_chart": reference.get("parent_chart"), "parent_chart_name": reference.get("parent_chart_name") or "Root", "discovery_method": reference.get("discovery_method"),
                        "discovery_source_file": reference.get("source_file"), "yaml_path": reference.get("yaml_path"),
                        "confidence": reference.get("confidence", "MEDIUM"), "graph_discovery": True}
        apply_context(entry, reference.get("context") or {}, reference.get("source_path"))
        entries.append(entry)

    warnings = []
    if len(charts) >= MAX_CHARTS:
        warnings.append({"type": "Helm Discovery", "item": "chart limit", "reason": f"Discovery limit {MAX_CHARTS} reached"})
    if len(references) >= MAX_REFS:
        warnings.append({"type": "Helm Discovery", "item": "reference limit", "reason": f"Discovery limit {MAX_REFS} references reached"})
    graph = {"schema_version": "1.0", "root": str(root), "charts": list(charts.values()), "references": references,
             "unresolved": unresolved, "warnings": warnings}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(graph, indent=2), encoding="utf-8")
    entries_path.parent.mkdir(parents=True, exist_ok=True)
    entries_path.write_text("\n".join(json.dumps(entry) for entry in entries) + ("\n" if entries else ""), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
