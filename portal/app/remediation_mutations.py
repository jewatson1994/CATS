"""Typed, non-mutating YAML edits with explicit presence and target identity."""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from typing import Any

import yaml
import re

MISSING = object()


class MutationError(ValueError):
    """The requested mutation cannot be applied unambiguously."""


def _validate_path(path):
    if not isinstance(path, list) or not path:
        raise MutationError("Path must be a nonempty list")
    for part in path:
        if isinstance(part, str):
            if not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise MutationError("Unsafe or empty path segment")
        elif not (isinstance(part, dict) and set(part) == {"name"}
                  and isinstance(part["name"], str) and part["name"]):
            raise MutationError("List selectors must specify an exact name")


def _key(parent, part):
    if isinstance(part, str):
        if not isinstance(parent, dict):
            raise MutationError("Dictionary path traverses a scalar or list")
        return part, part in parent
    if not isinstance(parent, list):
        raise MutationError("Name selector requires a list")
    matches = [i for i, item in enumerate(parent)
               if isinstance(item, dict) and item.get("name") == part["name"]]
    if len(matches) != 1:
        raise MutationError("Name selector must match exactly one item")
    return matches[0], True


def read_path(document: Any, path: list) -> tuple[bool, Any]:
    """Return presence separately from the typed value (including null)."""
    _validate_path(path)
    current = document
    for part in path:
        key, present = _key(current, part)
        if not present:
            return False, None
        current = current[key]
    return True, deepcopy(current)


def _merge(target, value):
    for key, item in value.items():
        if key in target and isinstance(target[key], dict) and isinstance(item, dict):
            _merge(target[key], item)
        else:
            target[key] = deepcopy(item)


def apply_mutation(document: Any, path: list, operation: str, value=MISSING) -> Any:
    """Apply SET/upsert, ADD/absent, REMOVE, APPEND/item, MERGE/object or REPLACE/present.

    Missing dictionary parents are created only for SET and ADD. APPEND adds one
    typed item; passing an array appends that array as one item.
    """
    _validate_path(path)
    op = str(operation).upper()
    if op not in {"SET", "ADD", "REMOVE", "APPEND", "MERGE", "REPLACE"}:
        raise MutationError("Unknown mutation operation")
    if op != "REMOVE" and value is MISSING:
        raise MutationError("Mutation requires an explicit typed value")
    result = deepcopy(document)
    parent = result
    for position, part in enumerate(path[:-1]):
        key, present = _key(parent, part)
        if not present:
            if op not in {"SET", "ADD"} or not isinstance(path[position + 1], str):
                raise MutationError("Missing parent")
            parent[key] = {}
        parent = parent[key]
    key, present = _key(parent, path[-1])
    if op == "ADD" and present:
        raise MutationError("ADD requires an absent target")
    if op in {"REMOVE", "REPLACE", "APPEND", "MERGE"} and not present:
        raise MutationError("Operation requires a present target")
    if op == "REMOVE":
        del parent[key]
    elif op == "APPEND":
        if not isinstance(parent[key], list):
            raise MutationError("APPEND requires a list")
        parent[key].append(deepcopy(value))
    elif op == "MERGE":
        if not isinstance(parent[key], dict) or not isinstance(value, dict):
            raise MutationError("MERGE requires objects")
        _merge(parent[key], value)
    else:
        parent[key] = deepcopy(value)
    return result


def semantic_identity(resource: dict) -> tuple[str, str, str]:
    """Return exact kind, namespace (empty when absent), and resource name."""
    metadata = resource.get("metadata")
    if not isinstance(metadata, dict):
        raise MutationError("Resource has no metadata")
    identity = resource.get("kind"), metadata.get("namespace", ""), metadata.get("name")
    if not all(isinstance(item, str) for item in identity) or not identity[0] or not identity[2]:
        raise MutationError("Resource identity requires kind and name")
    return identity


def locate_resource(documents: list, identity: tuple[str, str, str]) -> int:
    matches = []
    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            continue
        try:
            candidate = semantic_identity(document)
        except MutationError:
            continue
        if candidate == tuple(identity):
            matches.append(index)
    if len(matches) != 1:
        raise MutationError("Resource identity must match exactly one document")
    return matches[0]


def source_documents(source: str):
    """Parse literal YAML structure with opaque scalar Helm expressions.

    Control flow, includes producing structure, and dynamic keys remain unsafe.
    Expressions are never evaluated or rewritten.  Parsing is memoized by exact
    source text (a plan classifies every finding against the same files); each
    caller receives an independent deep copy, so no parsed state is shared.
    """
    result = _parsed_source_documents(source)
    if isinstance(result, MutationError):
        raise type(result)(*result.args)
    return deepcopy(result)


def shared_source_documents(source: str):
    """Memoized parse for read-only inspection; callers must not modify the result."""
    result = _parsed_source_documents(source)
    if isinstance(result, MutationError):
        raise type(result)(*result.args)
    return result


@lru_cache(maxsize=256)
def _parsed_source_documents(source: str):
    try:
        return _source_documents(source)
    except MutationError as exc:
        return exc


def _source_documents(source: str):
    expressions = {}
    def mask(match):
        expression = match.group(0)
        before = source[:match.start()].rsplit("\n", 1)[-1]
        if not before.strip() or re.search(r"{{-?\s*(if|else|end|range|with|define|template|block)\b", expression):
            raise MutationError("Structural Helm expressions require explicit source mapping")
        token = f"CATSHELMOPAQUE{len(expressions)}TOKEN"
        if token in source:
            raise MutationError("Reserved source token")
        expressions[token] = expression
        return token
    masked = re.sub(r"{{.*?}}", mask, source, flags=re.DOTALL)
    # Adjacent closing braces can be ordinary nested YAML flow mappings.
    if "{{" in masked:
        raise MutationError("Unbalanced Helm expression")
    try:
        documents = list(yaml.safe_load_all(masked))
        nodes = list(yaml.compose_all(masked))
    except yaml.YAMLError as exc:
        raise MutationError("Invalid YAML source") from exc
    def keys(value):
        if isinstance(value, dict):
            if any(any(token in str(key) for token in expressions) for key in value):
                raise MutationError("Dynamic YAML keys are not editable")
            for item in value.values(): keys(item)
        elif isinstance(value, list):
            for item in value: keys(item)
    for document in documents: keys(document)
    return documents, nodes, masked, expressions


def mutate_yaml_source(source: str, identity: tuple[str, str, str], path: list,
                       operation: str, value=MISSING) -> str:
    """Edit one plain YAML resource, retaining other documents byte for byte.

    Literal target serialization can normalize its formatting and comments.
    Scalar Helm expressions remain opaque; structural expressions are rejected.
    """
    if "{{" in source or "}}" in source:
        documents, nodes, masked, expressions = source_documents(source)
        original_masked = masked
        index = locate_resource(documents, identity)
        changed = apply_mutation(documents[index], path, operation, value)
        current, updated, node = documents[index], changed, nodes[index]
        for part in path:
            key, present = _key(current, part)
            if not present:
                # Insert a new literal branch without serializing templated siblings.
                if not isinstance(node, yaml.MappingNode) or node.flow_style:
                    break
                insertion = yaml.safe_dump({key: updated[key]}, sort_keys=False)
                indent = node.value[0][0].start_mark.column if node.value else node.start_mark.column
                insertion = "".join(" " * indent + line if line.strip() else line
                                    for line in insertion.splitlines(keepends=True))
                offset = sum(len(line) for line in masked.splitlines(keepends=True)[:node.end_mark.line])
                prefix = masked[:offset]
                if prefix and not prefix.endswith("\n"):
                    prefix += "\n"
                masked = prefix + insertion + masked[offset:]
                break
            if isinstance(node, yaml.MappingNode):
                next_node = next(v for k, v in node.value if k.value == key)
            elif isinstance(node, yaml.SequenceNode):
                next_node = node.value[key]
            else:
                raise MutationError("Unsupported source node")
            # Rewrite the smallest literal mapping containing the accepted field.
            if isinstance(current[key], dict) and not any(token in str(current[key]) for token in expressions):
                node, updated = next_node, updated[key]
                break
            current, updated, node = current[key], updated[key], next_node
        else:
            raise MutationError("Templated target requires a values mapping")
        if masked == original_masked:
            if any(token in str(updated) for token in expressions):
                raise MutationError("Templated target requires a values mapping")
            replacement = yaml.safe_dump(updated, sort_keys=False, default_flow_style=bool(node.flow_style)).rstrip("\n")
            indent = node.start_mark.column
            replacement = replacement.replace("\n", "\n" + " " * indent)
            if not node.flow_style:
                replacement += "\n" + " " * node.end_mark.column
            masked = masked[:node.start_mark.index] + replacement + masked[node.end_mark.index:]
        for token, expression in expressions.items():
            masked = masked.replace(token, expression)
        return masked
    try:
        documents = list(yaml.safe_load_all(source))
        nodes = list(yaml.compose_all(source))
    except yaml.YAMLError as exc:
        raise MutationError("Invalid YAML source") from exc
    index = locate_resource(documents, identity)
    changed = apply_mutation(documents[index], path, operation, value)
    node = nodes[index]
    return (source[:node.start_mark.index] + yaml.safe_dump(changed, sort_keys=False)
            + source[node.end_mark.index:])
