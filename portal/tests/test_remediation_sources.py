from types import SimpleNamespace
import pytest
import yaml
from app.remediation import build_plan, resolve_decisions, candidate_files, AUTO
from app.remediation_sources import structured_mapping


def fixture(containers=None):
    resource = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api", "namespace": "default"},
                "spec": {"template": {"spec": {"containers": containers or [{"name": "app", "image": "ubuntu:latest"}]}}}}
    resource["_cats_source_file"] = "chart/templates/deployment.yaml"
    source = {key: value for key, value in resource.items() if not key.startswith("_cats")}
    payload = {"rendered_resources": [resource], "helm_source_files": {"chart/templates/deployment.yaml": yaml.safe_dump(source)}, "artifact_type": "helm"}
    return payload, resource


def finding(rule="KSV-0017", text="Privileged"):
    return SimpleNamespace(id=1, finding=rule, title=text, target="api (api) :: api-rendered.yaml", namespace="default")


def test_literal_helm_source_adds_missing_false_only_to_exact_container():
    payload, resource = fixture()
    plan = build_plan(payload, [finding()], "R1")
    assert plan["configuration_changes"][0]["editable"]
    plan = resolve_decisions(plan, "guided", {"1": {"action": "proposed"}}, "manager")
    result = yaml.safe_load(candidate_files(payload, plan)["chart/templates/deployment.yaml"])
    assert result["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False
    assert "securityContext" not in resource["spec"]["template"]["spec"]["containers"][0]


def test_ambiguous_containers_and_go_templates_remain_blocked():
    payload, resource = fixture([{"name": "one"}, {"name": "two"}])
    assert structured_mapping(resource, payload["helm_source_files"], "securityContext.privileged") is None
    assert not build_plan(payload, [finding()], "R1")["configuration_changes"][0]["editable"]
    payload, resource = fixture()
    payload["helm_source_files"]["chart/templates/deployment.yaml"] += "\n{{ include \"unsafe\" . }}"
    assert structured_mapping(resource, payload["helm_source_files"], "securityContext.privileged") is None


def test_guided_resource_quantity_is_not_invented():
    payload, _ = fixture()
    plan = build_plan(payload, [finding("sizing", "CPU requests not specified")], "R1")
    assert plan["configuration_changes"][0]["new_value"] is None
    resolved = resolve_decisions(plan, "guided", {"1": {"action": "custom", "value": "100m"}}, "manager")
    result = yaml.safe_load(candidate_files(payload, resolved)["chart/templates/deployment.yaml"])
    assert result["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["cpu"] == "100m"
    with pytest.raises(ValueError):
        resolve_decisions(plan, "guided", {"1": {"action": "custom", "value": "$(bad)"}}, "manager")


def test_namespace_collision_does_not_guess():
    payload, resource = fixture()
    other = dict(resource, metadata={"name": "api", "namespace": "other"})
    payload["rendered_resources"].append(other)
    plan = build_plan(payload, [finding()], "R1")
    assert plan["configuration_changes"][0]["resource"] == "default/Deployment/api"


def test_render_validation_requires_exact_typed_value():
    from app.remediation_sources import verify_rendered_changes
    payload, resource = fixture()
    change = {"decision": "proposed", "resource": "default/Deployment/api",
              "field_path": "securityContext.privileged", "new_value": False}
    assert verify_rendered_changes([resource], [change])["status"] == "FAIL"
    resource["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {"privileged": False}
    assert verify_rendered_changes([resource], [change])["status"] == "PASS"
    resource["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = 0
    assert verify_rendered_changes([resource], [change])["status"] == "FAIL"
    assert verify_rendered_changes([resource, resource], [change])["status"] == "FAIL"


def test_scope_validation_rejects_unexpected_edits():
    from copy import deepcopy
    from app.remediation_sources import verify_rendered_scope
    _, original = fixture()
    candidate = deepcopy(original)
    candidate["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {"privileged": False}
    changes = [{"decision": "proposed", "resource": "default/Deployment/api",
                "field_path": "securityContext.privileged", "new_value": False}]
    assert verify_rendered_scope([original], [candidate], changes)["status"] == "PASS"
    candidate["spec"]["replicas"] = 9
    assert verify_rendered_scope([original], [candidate], changes)["status"] == "FAIL"
    assert "replicas" not in original["spec"]


@pytest.mark.parametrize("block", ["", "        resources: {}\n", "        securityContext: {}\n"])
@pytest.mark.parametrize("field,value", [("resources.requests.memory", "256Mi"),
                                         ("securityContext.capabilities.drop", ["ALL"]),
                                         ("securityContext.privileged", False)])
def test_scalar_helm_expressions_preserved_while_literal_branch_is_mutated(block, field, value):
    from app.remediation_mutations import mutate_yaml_source
    source = ('apiVersion: apps/v1\nkind: Deployment\nmetadata:\n'
              '  name: {{ include "demo.fullname" . }}\n'
              'spec:\n  template:\n    spec:\n      containers:\n'
              '      - name: app\n        image: "{{ .Values.image }}"\n' + block +
              '      - name: worker\n        image: busybox\n')
    _, resource = fixture([{"name": "app"}, {"name": "worker"}])
    resource["_cats_resource_lineage"] = {"source_template": "chart/templates/deployment.yaml", "namespace_source": "helm-release"}
    mapping = structured_mapping(resource, {"chart/templates/deployment.yaml": source}, field, "app", "containers")
    assert mapping is not None
    changed = mutate_yaml_source(source, tuple(mapping["source_resource_identity"]), mapping["mutation_path"], "SET", value)
    assert 'name: {{ include "demo.fullname" . }}' in changed
    assert 'image: "{{ .Values.image }}"' in changed
    rendered = changed.replace('{{ include "demo.fullname" . }}', 'api').replace('{{ .Values.image }}', 'nginx')
    document = yaml.safe_load(rendered)
    cursor = document["spec"]["template"]["spec"]["containers"][0]
    for key in field.split("."): cursor = cursor[key]
    assert cursor == value
    assert document["spec"]["template"]["spec"]["containers"][1] == {"name": "worker", "image": "busybox"}
    from app.remediation_summary import _actual
    row = {"source_mapping": mapping, "field_path": field, "container_name": "app", "container_type": "containers"}
    assert _actual(row, {"chart/templates/deployment.yaml": changed}, []) == (True, value)


@pytest.mark.parametrize("value,field,valid", [
    ("256Mi", "resources.requests.memory", True),
    ("100m", "resources.requests.cpu", True),
    (".001", "resources.requests.cpu", True),
    ("+1k", "resources.requests.memory", True),
    ("1e3", "resources.requests.memory", True),
    ("0e3", "resources.requests.memory", False),
    ("0Mi", "resources.requests.memory", False),
    ("-1", "resources.requests.memory", False),
    ("1K", "resources.requests.memory", False),
    ("0.1m", "resources.requests.cpu", False),
    ("1e999999", "resources.requests.memory", False),
    ("", "resources.requests.memory", False),
])
def test_explicit_resource_quantity_validation(value, field, valid):
    from app.remediation import _positive_resource_quantity
    assert _positive_resource_quantity(value, field) is valid


def test_dynamic_container_and_control_flow_are_not_literal_targets():
    _, resource = fixture()
    resource["_cats_resource_lineage"] = {"source_template": "chart/templates/deployment.yaml", "namespace_source": "helm-release"}
    source = yaml.safe_dump({key: value for key, value in resource.items() if not key.startswith("_cats")})
    for unsafe in (source.replace('name: app', 'name: {{ .Values.container }}'), '{{ if .Values.enabled }}\n' + source + '{{ end }}\n'):
        assert structured_mapping(resource, {"chart/templates/deployment.yaml": unsafe}, "resources.requests.memory", "app") is None
