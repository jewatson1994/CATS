from types import SimpleNamespace

import yaml

from app.architecture import build_architecture_graph
from app.remediation import AUTO, NOT_REMEDIABLE, REVIEW, associate_patch_results, build_plan, candidate_files, classify_policy_finding, static_validation


def finding(**values):
    defaults = dict(id=7, finding="KSV-allowPrivilegeEscalation", title="Container allows privilege escalation",
                    description="allowPrivilegeEscalation should be false", remediation="Set the field to false",
                    severity="High", target="Deployment/api")
    defaults.update(values)
    return SimpleNamespace(**defaults)


def helm_payload(mapping=None):
    resource = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"},
                "spec": {"template": {"spec": {"containers": [{"name": "api", "image": "registry/api:1"}]}}},
                "_cats_source_file": "templates/deployment.yaml"}
    if mapping:
        resource["_cats_source_mappings"] = [mapping]
    return {"artifact_type": "helm", "service_overview": {"rendered_resources": [resource]}}


def test_ambiguous_template_mapping_requires_review():
    decision = classify_policy_finding(finding(), helm_payload())
    assert decision["classification"] == REVIEW
    assert decision["source_mapping"]["template"] == "templates/deployment.yaml"


def test_exact_values_mapping_materializes_candidate_without_touching_input():
    mapping = {"field_path": "securityContext.allowPrivilegeEscalation", "template": "templates/deployment.yaml",
               "values_file": "values.yaml", "values_key": ".Values.security.allowPrivilegeEscalation", "ambiguous": False}
    payload = helm_payload(mapping)
    payload["helm_source_files"] = {"values.yaml": "security:\n  allowPrivilegeEscalation: true\n", "Chart.yaml": "apiVersion: v2\nname: api\nversion: 1.0.0\n"}
    plan = build_plan(payload, [finding()], "R-TEST")
    assert plan["configuration_changes"][0]["classification"] == AUTO
    files = candidate_files(payload, plan)
    assert yaml.safe_load(files["values.yaml"])["security"]["allowPrivilegeEscalation"] is False
    assert yaml.safe_load(payload["helm_source_files"]["values.yaml"])["security"]["allowPrivilegeEscalation"] is True
    validation = static_validation(payload, plan)
    assert validation["status"] == "FAIL"
    assert validation["checks"]["helm_lint"]["status"] == "NOT RUN"


def test_unknown_rules_are_not_changed():
    assert classify_policy_finding(finding(title="Manual application review", description="Business decision", remediation="Review", finding="CUSTOM"), helm_payload())["classification"] == NOT_REMEDIABLE


def test_gateway_and_unknown_custom_resources_are_kept_and_linked():
    resources = [
        {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway", "metadata": {"name": "edge"}, "spec": {}},
        {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute", "metadata": {"name": "api-route"},
         "spec": {"parentRefs": [{"name": "edge"}], "rules": [{"backendRefs": [{"name": "api", "port": 8080}]}]}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "api"}, "spec": {"ports": [{"port": 8080}]}},
        {"apiVersion": "example.invalid/v1", "kind": "Widget", "metadata": {"name": "custom"}, "spec": {"serviceRef": {"apiVersion": "v1", "kind": "Service", "name": "api"}}},
    ]
    graph = build_architecture_graph({"service_overview": {"rendered_resources": resources}})
    assert {node["kind"] for node in graph["nodes"]} >= {"Gateway", "HTTPRoute", "Service", "Widget"}
    assert any(edge["label"] == "accepts route" for edge in graph["relationships"])
    assert any(edge["source"].startswith("widget:") and edge["target"].startswith("service:") for edge in graph["relationships"])


def test_published_digest_updates_exact_image_values_source():
    mapping = {"field_path": "spec.template.spec.containers[0].image", "template": "templates/deployment.yaml",
               "values_file": "values.yaml", "values_key": ".Values.image", "ambiguous": False}
    payload = helm_payload(mapping)
    payload["helm_source_files"] = {"values.yaml": "image: registry/api:1\n"}
    plan = build_plan(payload, [], "R-IMAGE")
    patch = SimpleNamespace(status="complete", source_image="registry/api:1", completed_at=None, created_at=None,
                            job_key="patch-1", summary={"delivery_status": "delivered", "immutable_destination": "stage/api@sha256:" + "a" * 64,
                                                        "patch_status": "PATCHED", "signature_status": "signed"})
    associate_patch_results(payload, plan, [patch])
    assert plan["images"][0]["classification"] == AUTO
    assert yaml.safe_load(candidate_files(payload, plan)["values.yaml"])["image"].endswith("a" * 64)
