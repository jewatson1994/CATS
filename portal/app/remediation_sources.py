"""Fail-closed mappings from rendered resources to retained structured YAML."""
from __future__ import annotations

import yaml
import json
from copy import deepcopy
from .remediation_mutations import semantic_identity, read_path, MutationError
from .remediation_mutations import apply_mutation
from .remediation_mutations import source_documents, shared_source_documents


def container_entries(resource):
    prefix = ["spec"]
    if resource.get("kind") == "CronJob":
        prefix += ["jobTemplate", "spec", "template", "spec"]
    elif resource.get("kind") != "Pod":
        prefix += ["template", "spec"]
    spec = resource
    for key in prefix:
        spec = spec.get(key, {}) if isinstance(spec, dict) else {}
    return [(group, item) for group in ("containers", "initContainers", "ephemeralContainers")
                  for item in spec.get(group, []) if isinstance(item, dict)]


def container_path(resource, field, container_name=None, container_type=None):
    container_type = {"container": "containers", "initContainer": "initContainers",
                      "ephemeralContainer": "ephemeralContainers"}.get(container_type, container_type)
    prefix = (["spec"] if resource.get("kind") == "Pod" else
              ["spec", "jobTemplate", "spec", "template", "spec"] if resource.get("kind") == "CronJob" else
              ["spec", "template", "spec"])
    candidates = container_entries(resource)
    if container_type:
        candidates = [(group, item) for group, item in candidates if group == container_type]
    if container_name:
        candidates = [(group, item) for group, item in candidates if item.get("name") == container_name]
    if len(candidates) != 1 or not candidates[0][1].get("name"):
        return None
    group, container = candidates[0]
    return prefix + [group, {"name": container["name"]}] + field.split(".")


def _chart_roots(files):
    """Map each retained chart name (from Chart.yaml) to the directories that declare it."""
    roots = {}
    for path, content in files.items():
        normalized = str(path).replace("\\", "/")
        if normalized.split("/")[-1] != "Chart.yaml":
            continue
        try:
            name = (yaml.safe_load(content) or {}).get("name")
        except yaml.YAMLError:
            continue
        if isinstance(name, str) and name:
            roots.setdefault(name, []).append(normalized.rsplit("/", 1)[0] if "/" in normalized else "")
    return roots


def retained_source_paths(name, files):
    """Retained source files for a rendered ``# Source:`` path.

    Helm names rendered templates ``<chart-name>/templates/<file>`` (and
    ``<parent>/charts/<child>/templates/<file>``) using the chart *name*, while the
    retained source keeps the directory it was uploaded in, which can differ
    (``demo/`` for chart ``helm-diagram-demo``, ``harbor-1.15.0/`` for ``harbor``).
    Suffix matches are used first; otherwise the leading chart name is resolved
    through each retained Chart.yaml. An ambiguous result returns every candidate
    so callers keep failing closed.
    """
    name = str(name or "").replace("\\", "/").lstrip("/")
    if not name:
        return []
    paths = [path for path in files if path == name or path.endswith("/" + name) or name.endswith("/" + path)]
    if paths:
        return paths
    head, separator, rest = name.partition("/")
    if not separator:
        return []
    candidates = []
    for root in _chart_roots(files).get(head, []):
        candidate = f"{root}/{rest}" if root else rest
        if candidate in files:
            candidates.append(candidate)
    return candidates


def _identity_or_none(resource):
    """Kubernetes identity, or None for documents that are not addressable objects.

    Chart sources legitimately contain YAML documents with a ``kind`` but no
    ``metadata`` (Kustomization, kind: List, tool configuration). They can never
    be a mutation target, so they are skipped rather than failing the whole plan.
    """
    try:
        return semantic_identity(resource)
    except MutationError:
        return None


def structured_mapping(resource, files, field, container_name=None, container_type=None):
    """Only exact literal YAML resources; never parse/edit Go template expressions."""
    identity = _identity_or_none(resource)
    if identity is None:
        return None
    lineage = resource.get("_cats_resource_lineage") or resource.get("_cats_lineage") or {}
    source = str(resource.get("_cats_source_file") or resource.get("source_file") or resource.get("template") or "").replace("\\", "/")
    matches = []
    source_paths = set(retained_source_paths(source, files)) if source else set()
    for path, content in files.items():
        if not str(path).endswith((".yaml", ".yml")):
            continue
        if source and path not in source_paths:
            continue
        try:
            # Read-only inspection of the memoized parse; matched values are copied.
            docs, _, _, expressions = shared_source_documents(content)
        except MutationError:
            continue
        # A dynamic resource name is addressable only through affirmative render
        # provenance and a unique resource of this kind in this exact template.
        same_kind = [doc for doc in docs if isinstance(doc, dict) and doc.get("kind") == resource.get("kind")
                     and doc.get("apiVersion") == resource.get("apiVersion")]
        for doc in docs:
            doc_identity = _identity_or_none(doc) if isinstance(doc, dict) else None
            if doc_identity is None:
                continue
            dynamic_identity = (bool(source and lineage.get("source_template")) and len(same_kind) == 1
                                and any(token in str(doc.get("metadata", {})) for token in expressions))
            if dynamic_identity:
                source_identity = doc_identity
                dynamic_identity = all(left == right or any(token in left for token in expressions)
                                       or (offset == 1 and not left and lineage.get("namespace_source") == "helm-release")
                                       for offset, (left, right) in enumerate(zip(source_identity, identity)))
            if (doc.get("kind") and
                    (doc_identity == identity or
                     dynamic_identity or
                     (lineage.get("namespace_source") == "helm-release" and not (doc.get("metadata") or {}).get("namespace")
                      and doc_identity[0::2] == identity[0::2]))
                    and doc.get("apiVersion") == resource.get("apiVersion")):
                target = container_path(doc, field, container_name, container_type)
                if target:
                    try:
                        present, value = read_path(doc, target)
                    except MutationError:
                        continue
                    if any(token in str(value) for token in expressions):
                        continue
                    matches.append({"template": path, "source_file": path, "resource_identity": list(identity),
                                    "source_resource_identity": list(doc_identity),
                                    "mutation_path": target, "field_path": field, "ambiguous": False,
                                    "original_present": present, "original_value": deepcopy(value)})
    return matches[0] if len(matches) == 1 else None


def verify_rendered_changes(resources, changes):
    """Writing source is insufficient: require exact typed values in the render."""
    failures, warnings = [], []
    for change in changes:
        if change.get("decision") not in {"proposed", "custom"}:
            continue
        identity = change.get("resource")
        matches = []
        for resource in resources:
            resource_identity = _identity_or_none(resource)
            if resource_identity is None:
                continue
            kind, namespace, name = resource_identity
            normalized = change.get("resource_identity")
            exact = (isinstance(normalized, dict) and
                     (kind, namespace, name) == (normalized.get("kind"), normalized.get("namespace", ""), normalized.get("name")) and
                     resource.get("apiVersion", "") == normalized.get("api_version", ""))
            if exact or (not isinstance(normalized, dict) and identity in {f"{kind}/{name}", f"{namespace}/{kind}/{name}"}):
                matches.append(resource)
        if len(matches) > 1:
            failures.append("Duplicate rendered resource identity is unsafe.")
            continue
        if not matches:
            warnings.append("Accepted change cannot be attributed to one rendered resource.")
            continue
        path = container_path(matches[0], str(change.get("field_path") or ""), change.get("container_name"), change.get("container_type"))
        if not path:
            warnings.append("Accepted change cannot be attributed to one rendered container.")
            continue
        try:
            present, actual = read_path(matches[0], path)
        except MutationError:
            present, actual = False, None
        expected = change.get("new_value")
        removed = change.get("operation") in {"REMOVE", "DELETE"}
        if (present if removed else not present or type(actual) is not type(expected) or actual != expected):
            failures.append("Accepted source mutation is absent or different in the final render.")
    return {"status": "FAIL" if failures else "WARNING_UNVERIFIED" if warnings else "PASS", "detail": " ".join(failures + warnings) or "Every accepted configuration value appears at its exact rendered target."}


def verify_rendered_scope(before, after, changes, images=()):
    """Compare semantic resources after applying only explicitly accepted edits."""
    expected = deepcopy(before)
    try:
        for change in changes:
            if change.get("decision") not in {"proposed", "custom"}:
                continue
            normalized = change.get("resource_identity")
            identities = [(_identity_or_none(resource), resource) for resource in expected]
            matches = [i for i, (resource_identity, resource) in enumerate(identities) if resource_identity is not None and
                       ((resource_identity == (normalized.get("kind"), normalized.get("namespace", ""), normalized.get("name"))
                         and resource.get("apiVersion", "") == normalized.get("api_version", "")) if isinstance(normalized, dict) else
                        change.get("resource") in {
                            f"{resource_identity[1]}/{resource_identity[0]}/{resource_identity[2]}",
                            f"{resource_identity[0]}/{resource_identity[2]}"})]
            if len(matches) != 1:
                raise MutationError("Ambiguous resource")
            index = matches[0]
            path = container_path(expected[index], str(change.get("field_path") or ""), change.get("container_name"), change.get("container_type"))
            if not path:
                raise MutationError("Ambiguous container")
            expected[index] = apply_mutation(expected[index], path, change.get("operation") or "SET", change.get("new_value"))
        replacements = {row["original"]: row["candidate"] for row in images if row.get("candidate")}
        def normalize(value):
            if isinstance(value, dict):
                return {key: ("<chart-version>" if key == "helm.sh/chart" else
                              replacements.get(item, item) if key == "image" and isinstance(item, str) else normalize(item))
                        for key, item in value.items() if not key.startswith("_cats_")}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            return value
        def inventory(resources):
            result, unaddressable = {}, []
            for resource in resources:
                identity = _identity_or_none(resource)
                if identity is None:
                    # Documents without metadata cannot be edited, but must still be unchanged.
                    unaddressable.append(json.dumps(normalize(resource), sort_keys=True, default=str))
                    continue
                if identity in result:
                    raise MutationError("Duplicate resource")
                result[identity] = normalize(resource)
            return result, sorted(unaddressable)
        valid = inventory(expected) == inventory(after)
    except MutationError as exc:
        if str(exc).startswith("Ambiguous"):
            return {"status": "WARNING_UNVERIFIED", "detail": "Static rendered attribution is uncertain; source mutation is retained but runtime verification is required."}
        valid = False
    except (TypeError, KeyError):
        valid = False
    return {"status": "PASS" if valid else "FAIL", "detail":
            "Render differs only by accepted edits, image mappings and chart version labels." if valid else
            "Unexpected or ambiguous rendered changes require review; candidate is not verified."}
