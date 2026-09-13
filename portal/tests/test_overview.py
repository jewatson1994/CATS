from __future__ import annotations

import json
import subprocess
from pathlib import Path

from app.overview import (
    missing_evidence_entry,
    normalize_accounts,
    normalize_overview,
    normalize_port,
    parse_image_reference,
)
from app.main import _resolve_manifest_digest


def test_port_normalization_preserves_protocol_mapping_and_provenance():
    simple = normalize_port({"details": "http/80", "declared_by": "Service/web"})
    assert simple == {
        "port": "80", "protocol": "TCP", "service": "http",
        "declared_by": "Service/web", "provenance": "Service/web",
    }
    mapped = normalize_port({
        "name": "https", "port": 443, "target_port": 8443,
        "protocol": "UDP", "declared_by": "Service/api",
        "field_path": "spec.ports[].port → spec.ports[].targetPort",
    })
    assert mapped["port"] == "443 → 8443"
    assert mapped["protocol"] == "UDP"
    assert mapped["service"] == "https"
    assert mapped["declared_by"] == "Service/api"
    assert "targetPort" in mapped["provenance"]


def test_accounts_use_security_scope_and_relationships():
    rows = normalize_accounts([
        {"kind": "ServiceAccount", "name": "builder", "namespace": "tools", "relationships": ["Used by Deployment/api"]},
        {"kind": "ClusterRole", "name": "reader"},
        {"kind": "RoleBinding", "name": "bind", "namespace": "default", "relationships": ["Grants Role/view", "Binds ServiceAccount/default"]},
    ])
    assert rows[0] == {"name": "ServiceAccount/builder", "scope": "Namespace (tools)", "relationships": "Used by Deployment/api"}
    assert rows[1]["scope"] == "Cluster"
    assert rows[2]["scope"] == "Namespace (default)"
    assert rows[2]["relationships"] == "Grants Role/view; Binds ServiceAccount/default"


def test_placeholders_are_not_images_or_missing_evidence_and_duplicate_ports_keep_provenance():
    overview = normalize_overview(
        {"images": ["---", " ", None, "docker.io/library/nginx:1.27"]},
        skipped_images=["---", "None", "docker.io/acme/private:1.0 :: repository not found"],
    )
    assert [row["artifact"] for row in overview["artifacts"]] == ["nginx"]
    assert all(row["item"] != "---" for row in overview["missing_evidence"])
    assert any(row["item"] == "docker.io/acme/private:1.0" for row in overview["missing_evidence"])
    duplicate = normalize_overview({"ports": [
        {"port": 80, "protocol": "TCP", "service": "http", "declared_by": "Service/web"},
        {"port": 80, "protocol": "TCP", "service": "http", "declared_by": "Deployment/web"},
    ]})
    assert {row["declared_by"] for row in duplicate["ports"]} == {"Service/web", "Deployment/web"}


def test_image_and_helm_artifact_normalization():
    image = parse_image_reference("registry.example.invalid/platform/security/myapp:2.1")
    assert image == {
        "registry": "registry.example.invalid", "repository": "platform/security",
        "artifact": "myapp", "version": "2.1", "digest": "—",
    }
    docker = parse_image_reference("nginx:1.27-alpine")
    assert docker["registry"] == "docker.io" and docker["repository"] == "library"
    pinned = parse_image_reference("ghcr.io/acme/tool@sha256:" + "a" * 64)
    assert pinned["digest"].startswith("sha256:")
    overview = normalize_overview({"charts": [{"name": "prometheus", "version": "25.0.0", "repository": "https://prometheus-community.github.io/helm-charts"}]})
    chart = overview["artifacts"][0]
    assert chart == {
        "type": "Chart", "registry": "—",
        "repository": "https://prometheus-community.github.io/helm-charts",
        "artifact": "prometheus", "version": "25.0.0",
        "discovered_from": "Submitted", "digest": "—",
    }


def test_helm_image_source_file_and_duplicate_provenance_are_preserved():
    overview = normalize_overview({"images": [
        {"image": "registry.example/team/api:2.0", "source_file": "charts/api/templates/deployment.yaml", "discovered_from": "Deployment/api"},
        {"image": "registry.example/team/api:2.0", "source_file": "charts/api/templates/worker.yaml", "discovered_from": "Deployment/worker"},
    ]}, skipped_images=["registry.example/team/api:2.0 :: registry unavailable"])
    artifact = overview["artifacts"][0]
    assert set(artifact["source_file"].splitlines()) == {
        "charts/api/templates/deployment.yaml", "charts/api/templates/worker.yaml",
    }
    missing = overview["missing_evidence"][0]
    assert set(missing["source_file"].splitlines()) == {
        "charts/api/templates/deployment.yaml", "charts/api/templates/worker.yaml",
    }


def test_resolved_digest_reconciles_unresolved_image_occurrence():
    digest = "sha256:" + "c" * 64
    overview = normalize_overview({"images": [
        {"image": "registry.example/team/api:2.0", "source_file": "customer/deployment.yaml"},
        {"image": "registry.example/team/api:2.0", "digest": digest, "source_file": "scan/manifest.json"},
    ]})
    images = [row for row in overview["artifacts"] if row["type"] == "Image"]
    assert len(images) == 1
    assert images[0]["digest"] == digest
    assert {item["source_file"] for item in images[0]["occurrences"]} == {"customer/deployment.yaml", "scan/manifest.json"}


def test_bitnami_render_warning_is_preserved_with_image_metadata():
    overview = normalize_overview({"warnings": [{
        "type": "bitnami-image-verification-override",
        "chart": "postgresql",
        "source": "charts/postgresql",
        "message": "Bitnami container image verification blocked the initial Helm render.",
        "original_error": "ERROR: Original containers have been substituted for unrecognized ones.",
        "unrecognized_images": ["docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4"],
    }]})
    assert overview["warnings"][0]["chart"] == "postgresql"
    assert overview["warnings"][0]["unrecognized_images"] == ["docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4"]
    assert overview["missing_evidence"] == []


def test_missing_evidence_reason_and_dependency_provenance():
    assert missing_evidence_entry("Image", "busybox", "unauthorized: authentication required") == {
        "type": "Image", "item": "busybox",
        "reason": "Image could not be pulled — authentication required",
    }
    missing_chart = missing_evidence_entry("Chart", "prometheus", "dependency build failed")
    assert missing_chart["reason"] == "Helm dependencies could not be resolved"
    overview = normalize_overview({
        "dependencies": [{
            "dependency": "alertmanager", "used_by": "prometheus → alertmanager",
            "provides": ["Service", "StatefulSet", "Service"],
            "images": ["quay.io/prometheus/alertmanager:v0.34.0"], "resolved": True,
        }, {
            "dependency": "missing", "used_by": "prometheus", "resolved": False,
            "reason": "repository unavailable",
        }]
    })
    assert overview["dependencies"] == [{
        "dependency": "alertmanager", "used_by": "prometheus → alertmanager",
        "provides": "Service, StatefulSet",
        "images": "quay.io/prometheus/alertmanager:v0.34.0",
    }]
    assert any(row["item"] == "missing" for row in overview["missing_evidence"])


def test_digest_resolution_is_best_effort(monkeypatch):
    digest = "sha256:" + "b" * 64
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, json.dumps({"Descriptor": {"digest": digest}}), ""))
    _resolve_manifest_digest.cache_clear()
    assert _resolve_manifest_digest("docker.io/library/nginx:1.27") == digest
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    _resolve_manifest_digest.cache_clear()
    overview = normalize_overview({"images": [{"image": "docker.io/library/nginx:1.27", "discovered_from": "Deployment/nginx"}]}, digest_resolver=_resolve_manifest_digest)
    assert overview["artifacts"][0]["digest"] == "—"


def test_rendered_resource_normalizer_resolves_rbac_and_dependency(tmp_path: Path):
    resources = [{
        "apiVersion": "apps/v1", "kind": "Deployment",
        "_cats_source_file": "root/charts/child-1.0.0.tgz/templates/deployment.yaml",
        "metadata": {"name": "api", "namespace": "app", "labels": {"helm.sh/chart": "child-1.0.0"}},
        "spec": {"template": {"metadata": {"labels": {"app": "api"}}, "spec": {"serviceAccountName": "runner", "containers": [{"name": "api", "image": "registry.example/team/api:2.0", "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}]}], "initContainers": [{"name": "placeholder", "image": "---"}]}}},
    }, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "api", "namespace": "app", "labels": {"helm.sh/chart": "child-1.0.0"}},
        "spec": {"selector": {"app": "api"}, "ports": [{"name": "https", "port": 443, "targetPort": "http", "protocol": "TCP"}]},
    }, {
        "apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "runner", "namespace": "app", "labels": {"helm.sh/chart": "child-1.0.0"}},
    }, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "reader", "namespace": "app"},
    }, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "read", "namespace": "app"},
        "roleRef": {"kind": "Role", "name": "reader"}, "subjects": [{"kind": "ServiceAccount", "name": "runner", "namespace": "app"}],
    }, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "global-reader"},
    }, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "global-read"},
        "roleRef": {"kind": "ClusterRole", "name": "global-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "runner", "namespace": "app"}],
    }]
    input_path = tmp_path / "resources.json"
    output_path = tmp_path / "overview.json"
    input_path.write_text(json.dumps(resources), encoding="utf-8")
    script = Path(__file__).parents[2] / "scanning-main" / "scripts" / "normalize-service-overview.py"
    completed = subprocess.run(["python", str(script), str(input_path), str(output_path)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    normalized = json.loads(output_path.read_text(encoding="utf-8"))
    assert all(row["image"] != "---" for row in normalized["images"])
    image_row = next(row for row in normalized["images"] if row["image"] == "registry.example/team/api:2.0")
    assert image_row["source_file"] == "charts/child-1.0.0.tgz/templates/deployment.yaml"
    assert any(row["declared_by"] == "Deployment/api" and row["port"] == 8080 for row in normalized["ports"])
    service_port = next(row for row in normalized["ports"] if row["declared_by"] == "Service/api")
    assert service_port["port"] == 443
    assert service_port["target_port"] == 8080
    assert service_port["service"] == "https"
    assert "Deployment/api" in service_port["provenance"]
    final = normalize_overview(normalized)
    accounts = {row["name"]: row for row in final["accounts"]}
    assert "Used by Deployment/api" in accounts["ServiceAccount/runner"]["relationships"]
    assert "Bound by RoleBinding/read" in accounts["ServiceAccount/runner"]["relationships"]
    assert "Bound by ClusterRoleBinding/global-read" in accounts["ServiceAccount/runner"]["relationships"]
    assert "Grants Role/reader" in accounts["RoleBinding/read"]["relationships"]
    assert accounts["ClusterRole/global-reader"]["scope"] == "Cluster"
    assert final["dependencies"][0]["used_by"]
    assert "Deployment" in final["dependencies"][0]["provides"]
    assert "registry.example/team/api:2.0" in final["dependencies"][0]["images"]
