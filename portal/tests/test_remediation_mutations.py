from copy import deepcopy

import pytest
import yaml

from app.remediation_mutations import (MutationError, apply_mutation, locate_resource,
                                      mutate_yaml_source, read_path, semantic_identity)


@pytest.mark.parametrize("value", [False, True, 0, "", None, [], {}, [False, 0], {"x": None}])
def test_typed_values_and_presence(value):
    original = {"existing": None}
    changed = apply_mutation(original, ["parent", "value"], "SET", value)
    assert read_path(changed, ["parent", "value"]) == (True, value)
    assert type(changed["parent"]["value"]) is type(value)
    assert read_path(original, ["existing"]) == (True, None)
    assert read_path(original, ["absent"]) == (False, None)
    assert original == {"existing": None}


def test_primitives():
    original = {"list": [1], "object": {"nested": {"a": 1}, "keep": True}, "null": None}
    saved = deepcopy(original)
    assert apply_mutation(original, ["new"], "ADD", False)["new"] is False
    assert "null" not in apply_mutation(original, ["null"], "REMOVE")
    assert apply_mutation(original, ["null"], "REPLACE", 0)["null"] == 0
    assert apply_mutation(original, ["list"], "APPEND", [2])["list"] == [1, [2]]
    merged = apply_mutation(original, ["object"], "MERGE", {"nested": {"b": None}})
    assert merged["object"] == {"nested": {"a": 1, "b": None}, "keep": True}
    assert original == saved


@pytest.mark.parametrize("operation,path,value", [
    ("ADD", ["x"], 1), ("REPLACE", ["absent"], 1),
    ("REMOVE", ["absent"], None), ("APPEND", ["x"], 1),
    ("MERGE", ["x"], {}), ("SET", ["x", "child"], 1),
    ("SET", [".."], 1), ("SET", ["a/b"], 1),
])
def test_invalid_mutations(operation, path, value):
    with pytest.raises(MutationError):
        apply_mutation({"x": None}, path, operation, value)


def test_explicit_value_required():
    with pytest.raises(MutationError):
        apply_mutation({}, ["x"], "SET")


def test_exact_list_selector():
    original = {"containers": [{"name": "api"}, {"name": "sidecar"}]}
    result = apply_mutation(original, ["containers", {"name": "api"}, "enabled"], "SET", False)
    assert result["containers"] == [{"name": "api", "enabled": False}, {"name": "sidecar"}]
    assert original["containers"] == [{"name": "api"}, {"name": "sidecar"}]
    for containers in [[], [{"name": "api"}, {"name": "api"}]]:
        with pytest.raises(MutationError):
            apply_mutation({"containers": containers}, ["containers", {"name": "api"}, "x"], "SET", 1)
    with pytest.raises(MutationError):
        apply_mutation(original, ["containers", "x"], "SET", 1)


def test_source_identity_and_multi_document():
    docs = [{"kind": "ConfigMap", "metadata": {"name": "api", "namespace": ns}, "data": {"x": "a"}}
            for ns in ["one", "two"]]
    identity = semantic_identity(docs[1])
    assert locate_resource(docs, identity) == 1
    result = list(yaml.safe_load_all(mutate_yaml_source(yaml.safe_dump_all(docs), identity,
                                                      ["data", "x"], "SET", False)))
    assert result[0] == docs[0]
    assert result[1]["data"]["x"] is False
    with pytest.raises(MutationError):
        locate_resource([docs[1], docs[1]], identity)
    with pytest.raises(MutationError):
        mutate_yaml_source("kind: {{ .Values.kind }}", identity, ["data"], "SET", {})


def test_unrelated_source_documents_preserved_exactly():
    prefix = "# Keep this comment\nkind: ConfigMap\nmetadata: {name: untouched}\ndata: {quoted: 'yes'}\n---\n"
    target = "kind: ConfigMap\nmetadata: {name: target}\ndata: {x: old}\n"
    suffix = "---\n# Last comment\nkind: Service\nmetadata: {name: last}\n"
    result = mutate_yaml_source(prefix + target + suffix, ("ConfigMap", "", "target"),
                                ["data", "x"], "SET", None)
    assert result.startswith(prefix)
    assert result.endswith(suffix)


def test_candidate_container_selection_fails_closed():
    from app.remediation import AUTO, candidate_files
    resource = {"kind": "Pod", "metadata": {"name": "api"},
                "spec": {"containers": [{"name": "api"}, {"name": "sidecar"}]}}
    payload = {"artifact_type": "raw", "rendered_resources": [resource]}
    change = {"classification": AUTO, "resource": "Pod/api", "field_path": "securityContext.privileged", "new_value": False}
    with pytest.raises(MutationError):
        candidate_files(payload, {"configuration_changes": [change]})
    change["container_name"] = "api"
    result = yaml.safe_load(candidate_files(payload, {"configuration_changes": [change]})["remediated-manifests.yaml"])
    assert result["spec"]["containers"] == [{"name": "api", "securityContext": {"privileged": False}}, {"name": "sidecar"}]
    assert resource["spec"]["containers"] == [{"name": "api"}, {"name": "sidecar"}]


def test_candidate_generic_values_and_retained_source():
    from app.remediation import AUTO, candidate_files
    values_payload = {"source_files": {"values.yaml": "items: [1]\n"}}
    change = {"classification": AUTO, "operation": "APPEND", "new_value": None,
              "source_mapping": {"values_file": "values.yaml", "values_key": ".Values.items"}}
    assert yaml.safe_load(candidate_files(values_payload, {"configuration_changes": [change]})["values.yaml"]) == {"items": [1, None]}
    resource = {"kind": "ConfigMap", "metadata": {"name": "api"}, "data": {"x": "old"}}
    suffix = "---\n# untouched\nkind: Service\nmetadata: {name: other}\n"
    payload = {"artifact_type": "raw", "rendered_resources": [resource],
               "source_files": {"source.yaml": yaml.safe_dump(resource) + suffix}}
    change = {"classification": AUTO, "resource": "ConfigMap/api", "path": ["data", "x"],
              "new_value": False, "source_mapping": {"template": "source.yaml"}}
    result = candidate_files(payload, {"configuration_changes": [change]})["source.yaml"]
    assert result.endswith(suffix)
    assert list(yaml.safe_load_all(result))[0]["data"]["x"] is False
