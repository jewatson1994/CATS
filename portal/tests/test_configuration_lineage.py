"""Scanner identity regression coverage independent of scanner executables."""
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parents[2] / "scanning-main" / "scripts"
spec = importlib.util.spec_from_file_location("configuration_lineage", SCRIPTS / "configuration-lineage.py")
lineage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lineage)


def manifest(name="web", field="containers", namespace=""):
    return (f"# Source: demo/templates/deployment.yaml\napiVersion: apps/v1\nkind: Deployment\n"
            f"metadata:\n  name: {name}\n" + (f"  namespace: {namespace}\n" if namespace else "") +
            f"spec:\n  template:\n    spec:\n      {field}:\n      - name: {name}\n        image: nginx\n")


def finding(path, start=0, end=0):
    return {"finding": "KSV-0106", "evidence": {"scanner_target": str(path),
            "cause_metadata": {"Resource": "kubernetes.deployment.web", "StartLine": start, "EndLine": end}}}


@pytest.mark.parametrize("field,expected", [("containers", "container"), ("initContainers", "initContainer"),
                                            ("ephemeralContainers", "ephemeralContainer")])
def test_unique_container_lineage(tmp_path, field, expected):
    path = tmp_path / "graph-1.yaml"
    path.write_text(manifest(field=field))
    path.with_suffix(".chart.json").write_text(json.dumps({"chart_id": "instance-1", "namespace": "release-ns",
        "release": "demo", "path": "source/chart.tgz", "values": ["source/values.yaml"]}))
    result = lineage.enrich([finding(path)])[0]["evidence"]
    assert result["lineage_status"] == "resolved"
    target = result["resource_lineage"]
    assert target["container_type"] == expected
    assert target["container_name"] == "web"
    assert target["namespace"] == "release-ns"
    assert target["namespace_source"] == "helm-release"
    assert target["document_index"] == 0
    assert target["source_template"] == "demo/templates/deployment.yaml"
    assert target["chart_instance_id"] == "instance-1"
    assert target["values_sources"] == ["source/values.yaml"]


def test_multiple_documents_and_containers_resolve_only_line_match(tmp_path):
    path = tmp_path / "graph-1.yaml"
    text = manifest() + "      - name: worker\n        image: nginx\n---\n" + manifest("second")
    path.write_text(text)
    line = text.splitlines().index("      - name: worker") + 1
    row = finding(path, line, line + 1)
    result = lineage.enrich([row])[0]["evidence"]
    assert result["resource_lineage"]["container_name"] == "worker"
    assert result["resource_lineage"]["document_index"] == 0
    line = len(text.splitlines()) - 1
    result = lineage.enrich([finding(path, line, line + 1)])[0]["evidence"]
    assert result["resource_lineage"]["name"] == "second"
    assert result["resource_lineage"]["document_index"] == 1


def test_ambiguous_resource_span_keeps_candidates_without_first_match(tmp_path):
    path = tmp_path / "graph-1.yaml"
    path.write_text(manifest() + "      - name: worker\n        image: nginx\n")
    evidence = lineage.enrich([finding(path, 2, 12)])[0]["evidence"]
    assert evidence["lineage_status"] == "ambiguous"
    assert "resource_lineage" not in evidence
    assert [item["container_name"] for item in evidence["candidate_resources"]] == ["web", "worker"]


@pytest.mark.parametrize("kind,namespace,expected,source", [("Namespace", "", "", "cluster"),
    ("Deployment", "explicit-ns", "explicit-ns", "explicit"), ("CustomWidget", "", "", "unknown")])
def test_namespace_scope_is_not_fabricated(tmp_path, kind, namespace, expected, source):
    path = tmp_path / "resource.yaml"
    path.write_text(manifest(namespace=namespace).replace("kind: Deployment", f"kind: {kind}"))
    row = finding(path)
    row["evidence"]["deployment_namespace"] = "release-ns"
    result = lineage.enrich([row])[0]["evidence"]["resource_lineage"]
    assert result["namespace"] == expected
    assert result["namespace_source"] == source


def test_missing_manifest_preserves_cause_metadata(tmp_path):
    row = finding(tmp_path / "missing.yaml", 11, 12)
    assert lineage.enrich([row])[0]["evidence"]["cause_metadata"]["StartLine"] == 11
    assert row["evidence"]["lineage_status"] == "unavailable"


def test_policy_namespace_does_not_replace_resource_namespace(tmp_path):
    path = tmp_path / "deployment.yaml"
    path.write_text(manifest(namespace="application"))
    row = finding(path)
    row["namespace"] = "builtin.kubernetes.KSV106"
    row["evidence"]["policy_namespace"] = row["namespace"]
    lineage.enrich([row])
    assert row["namespace"] == "application"
    assert row["evidence"]["policy_namespace"] == "builtin.kubernetes.KSV106"


def test_trivy_resource_suffix_and_container_identity(tmp_path):
    path = tmp_path / "graph-1.yaml"
    path.write_text(manifest() + "      - name: worker\n        image: nginx\n---\n" + manifest("second"))
    row = finding(path)
    row["evidence"]["scanner_target"] += ": apps/v1/Deployment/web"
    row["evidence"]["cause_metadata"]["Resource"] = "worker"
    result = lineage.enrich([row])[0]["evidence"]
    assert result["lineage_status"] == "ambiguous"
    assert {target["name"] for target in result["candidate_resources"]} == {"web"}
    assert {target["container_name"] for target in result["candidate_resources"]} == {"web", "worker"}


def test_export_retains_lineage(tmp_path):
    spec = importlib.util.spec_from_file_location("assemble_results", SCRIPTS / "assemble-results.py")
    assembly = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(assembly)
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([{"finding": "KSV-0106", "evidence": {"resource_lineage": {"name": "web"}}}]))
    assert assembly.generic_findings_report(path)["findings"][0]["evidence"]["resource_lineage"]["name"] == "web"


def test_source_headers_are_delimited_by_documents(tmp_path):
    path = tmp_path / "graph-1.yaml"
    path.write_text(manifest() + "---\n# Source: demo/templates/empty.yaml\nnull\n---\n" +
                    manifest("second").replace("deployment.yaml", "second.yaml"))
    documents = lineage.resources(path)
    assert [(item["document_index"], item["source_template"]) for item in documents] == [
        (0, "demo/templates/deployment.yaml"), (2, "demo/templates/second.yaml")]


def test_relative_target_with_scan_directory_prefix(tmp_path, monkeypatch):
    root = tmp_path / "configuration"
    root.mkdir()
    (root / "deployment.yaml").write_text(manifest())
    monkeypatch.chdir(tmp_path.parent)
    row = finding("configuration/deployment.yaml")
    assert lineage.enrich([row], str(root))[0]["evidence"]["lineage_status"] == "resolved"


def test_single_file_input_does_not_substitute_unrelated_target(tmp_path):
    path = tmp_path / "deployment.yaml"
    path.write_text(manifest())
    row = finding("missing.yaml")
    row["evidence"]["resource_lineage"] = {"name": "stale"}
    evidence = lineage.enrich([row], str(path))[0]["evidence"]
    assert evidence["lineage_status"] == "unavailable"
    assert "resource_lineage" not in evidence


@pytest.mark.parametrize("artifact", ["helm-rendered/remediation-gauntlet-hash.yaml",
                                      "helm-image-rendered/graph-1.yaml"])
def test_both_render_paths_retain_same_chart_instance(tmp_path, monkeypatch, artifact):
    path = tmp_path / artifact
    path.parent.mkdir()
    path.write_text(manifest())
    path.with_suffix(".chart.json").write_text(json.dumps({"chart_id": "graph-id",
        "chart_instance_id": "release-instance", "release": "application",
        "namespace": "application-ns", "source_chart": "charts/remediation-gauntlet",
        "values": ["configuration/values.yaml"]}))
    monkeypatch.chdir(tmp_path.parent)
    row = finding(artifact)
    row["evidence"]["scanner_target"] += ": apps/v1/Deployment/application-ns/web"
    target = lineage.enrich([row], str(tmp_path))[0]["evidence"]["resource_lineage"]
    assert target["chart_id"] == "graph-id"
    assert target["chart_instance_id"] == "release-instance"
    assert target["source_chart"] == "charts/remediation-gauntlet"
    assert target["source_template"] == "demo/templates/deployment.yaml"
    assert target["document_index"] == 0
    assert target["container_name"] == "web"
    assert target["namespace"] == "application-ns"
