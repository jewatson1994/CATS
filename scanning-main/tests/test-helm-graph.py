import importlib.util
import json
from pathlib import Path
import shutil
import tarfile

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "discover-helm-graph.py"
SPEC = importlib.util.spec_from_file_location("discover_helm_graph", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def chart(root: Path, relative: str, name: str, version: str = "1.0.0") -> Path:
    path = root / relative
    (path / "templates").mkdir(parents=True)
    (path / "Chart.yaml").write_text(f"apiVersion: v2\nname: {name}\nversion: {version}\n", encoding="utf-8")
    (path / "values.yml").write_text("image: example.invalid/" + name + ":1\n", encoding="utf-8")
    (path / "templates" / "deployment.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + name + "\n", encoding="utf-8")
    return path


def discover(root: Path):
    output = root / "graph.json"
    entries = root / "entries.jsonl"
    import sys
    old = sys.argv
    try:
        sys.argv = [str(SCRIPT), "--root", str(root), "--output", str(output), "--entries", str(entries)]
        assert MODULE.main() == 0
    finally:
        sys.argv = old
    return json.loads(output.read_text(encoding="utf-8")), [json.loads(line) for line in entries.read_text(encoding="utf-8").splitlines() if line]


def test_unconventional_recursive_yaml_references_and_instances(tmp_path):
    chart(tmp_path, "root", "platform")
    chart(tmp_path, "random/stuff/frontend", "frontend")
    chart(tmp_path, "backend/weird/backend-chart", "backend")
    chart(tmp_path, "components/auth", "auth")
    chart(tmp_path, "deep/one/two/three/worker", "worker")
    (tmp_path / "root" / "values.yml").write_text(
        """platform:\n  fleet:\n    - location: ../random/stuff/frontend\n      overrides: {mode: customer}\n    - location: ../backend/weird/backend-chart\n      overrides: {mode: admin}\n  opaque:\n    nested:\n      target: ../components/auth\n""", encoding="utf-8")
    (tmp_path / "backend" / "weird" / "backend-chart" / "values.yml").write_text(
        """anything:\n  next: ../../../deep/one/two/three/worker\n""", encoding="utf-8")
    graph, entries = discover(tmp_path)
    names = {item["chart"] for item in graph["charts"]}
    assert {"platform", "frontend", "backend", "auth", "worker"} <= names
    backend_instances = [item for item in entries if item.get("name") == "backend"]
    assert backend_instances
    assert all(item.get("chart_id") for item in backend_instances)
    assert any(item.get("context", {}).get("values") for item in backend_instances)


def test_arbitrary_yaml_key_resolving_to_chart_is_high_confidence(tmp_path):
    chart(tmp_path, "components/backend/chart", "backend")
    (tmp_path / "config.yml").write_text(
        "something:\n  completely:\n    arbitrary:\n      banana:\n        location: ./components/backend/chart\n",
        encoding="utf-8",
    )
    graph, entries = discover(tmp_path)
    assert any(item.get("name") == "backend" and item.get("discovery_source_file") == "config.yml" for item in entries)
    assert any(item.get("reference") == "./components/backend/chart" and item.get("confidence") == "HIGH" for item in graph["references"])


def test_unrelated_urls_do_not_become_helm_artifacts(tmp_path):
    chart(tmp_path, "app", "app")
    (tmp_path / "config.yml").write_text(
        "identity:\n  claim: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\n"
        "links:\n  - https://example.invalid/documentation\n"
        "nested:\n  source: https://example.invalid/schema\n",
        encoding="utf-8",
    )
    graph, entries = discover(tmp_path)
    assert not any("schemas.xmlsoap.org" in str(item) or "example.invalid" in str(item)
                   for item in graph["references"] + graph["unresolved"] + entries)


def test_remote_chart_requires_explicit_helm_structure(tmp_path):
    chart(tmp_path, "app", "app")
    (tmp_path / "config.yml").write_text(
        "applications:\n"
        "  remote:\n    chart: worker\n    repository: https://charts.example.invalid/internal\n"
        "  oci:\n    chart: oci://registry.example.invalid/charts/worker\n"
        "  missing:\n    chart: oci://registry.example.invalid/charts/missing\n",
        encoding="utf-8",
    )
    graph, entries = discover(tmp_path)
    assert any(item.get("reference") == "worker" and item.get("repository") == "https://charts.example.invalid/internal" for item in graph["references"])
    assert any(item.get("reference") == "oci://registry.example.invalid/charts/worker" for item in graph["references"])
    assert any(item.get("item") == "oci://registry.example.invalid/charts/missing" for item in graph["unresolved"])
    assert any(item.get("reference") == "worker" for item in entries)


def test_cycles_are_bounded_and_plain_paths_are_not_charts(tmp_path):
    chart(tmp_path, "a", "a")
    chart(tmp_path, "b", "b")
    (tmp_path / "a" / "values.yml").write_text("opaque: ../b\nnormal: /var/lib/data\n", encoding="utf-8")
    (tmp_path / "b" / "values.yml").write_text("another: ../a\n", encoding="utf-8")
    graph, _ = discover(tmp_path)
    assert len(graph["charts"]) == 2
    assert not any(item.get("reference") == "/var/lib/data" for item in graph["references"])


def test_overlong_or_unstatable_reference_does_not_abort_discovery(tmp_path, monkeypatch):
    chart(tmp_path, "root", "root")
    (tmp_path / "values.yml").write_text(
        "bad: ./" + ("nested/" * 35) + "missing-chart\n", encoding="utf-8"
    )
    monkeypatch.setattr(MODULE, "MAX_PATH_CHARS", 4096)
    original_is_file = MODULE.Path.is_file

    def guarded_is_file(path):
        if len(str(path)) > 180:
            raise OSError(36, "Filename too long")
        return original_is_file(path)

    monkeypatch.setattr(MODULE.Path, "is_file", guarded_is_file)
    graph, _ = discover(tmp_path)
    assert any(item["chart"] == "root" for item in graph["charts"])


def test_packaged_chart_is_discovered_and_unsafe_archive_is_ignored(tmp_path):
    package_root = tmp_path / "package" / "redis"
    (package_root / "templates").mkdir(parents=True)
    (package_root / "Chart.yaml").write_text("name: redis\nversion: 1.2.3\n", encoding="utf-8")
    archive = tmp_path / "packaged" / "redis-1.2.3.tgz"
    archive.parent.mkdir()
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(package_root, arcname="redis")

    unsafe = tmp_path / "packaged" / "unsafe.tgz"
    with tarfile.open(unsafe, "w:gz") as handle:
        payload = tarfile.TarInfo("../../outside/Chart.yaml")
        content = b"name: outside\nversion: 1.0.0\n"
        payload.size = len(content)
        import io
        handle.addfile(payload, io.BytesIO(content))

    graph, entries = discover(tmp_path)
    assert any(item["chart"] == "redis" and item["discovery_method"] == "packaged chart" for item in graph["charts"])
    assert not any(item.get("name") == "outside" for item in entries)


def test_oversized_archive_is_isolated_from_healthy_sibling(tmp_path, monkeypatch):
    chart(tmp_path, "healthy", "healthy")
    package_root = tmp_path / "package" / "oversized"
    package_root.mkdir(parents=True)
    (package_root / "Chart.yaml").write_text("name: oversized\nversion: 1.0.0\n", encoding="utf-8")
    (package_root / "payload").write_bytes(b"x" * 256)
    archive = tmp_path / "oversized.tgz"
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(package_root, arcname="oversized")
    shutil.rmtree(tmp_path / "package")
    monkeypatch.setattr(MODULE, "MAX_ARCHIVE_EXPANDED_BYTES", 64)

    graph, entries = discover(tmp_path)

    assert any(item["chart"] == "healthy" for item in graph["charts"])
    assert not any(item.get("name") == "oversized" for item in entries)


def test_cats_helm_torture_graph_preserves_instances_and_independent_charts(tmp_path):
    generic = chart(tmp_path, "charts/generic-api", "generic-api")
    chart(tmp_path, "charts/good", "good")
    chart(tmp_path, "charts/render-failed", "render-failed")
    (tmp_path / "charts/generic-api" / "templates" / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n      containers:\n      - name: api\n        image: registry.example/team/api:2.0\n", encoding="utf-8")
    (tmp_path / "values.yml").write_text(
        "applications:\n"
        "  customerApi:\n    chart: charts/generic-api\n"
        "  adminApi:\n    chart: charts/generic-api\n"
        "  internalApi:\n    chart: charts/generic-api\n"
        "  bogus:\n    chart: oci://registry.invalid/missing\n    repository: oci://registry.invalid\n"
        "  good:\n    chart: charts/good\n"
        "  failed:\n    chart: charts/render-failed\n", encoding="utf-8")
    (tmp_path / "fake-chart").mkdir()
    package_root = tmp_path / "package" / "packaged"
    (package_root / "templates").mkdir(parents=True)
    (package_root / "Chart.yaml").write_text("name: packaged\nversion: 1.0.0\n", encoding="utf-8")
    archive = tmp_path / "packaged.tgz"
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(package_root, arcname="packaged")

    graph, entries = discover(tmp_path)
    instances = [item for item in entries if item.get("name") == "generic-api" and item.get("instance")]
    assert len(instances) == 3
    assert {item["instance"] for item in instances} == {"customerApi", "adminApi", "internalApi"}
    assert all(item.get("parent_chart_name") == "Root" and item.get("declared_by") == "values.yml" for item in instances)
    assert {item.get("yaml_path") for item in instances} == {
        "applications.customerApi", "applications.adminApi", "applications.internalApi"
    }
    assert any(item.get("chart") == "packaged" and item.get("discovery_method") == "packaged chart" for item in graph["charts"])
    assert any(item.get("item") == "oci://registry.invalid/missing" for item in graph["unresolved"])
    assert not any(item.get("name") == "fake-chart" for item in entries)
    assert {item.get("name") for item in entries} >= {"good", "render-failed"}


def dependency(parent: Path, name: str, repository: str, version: str = "2.41.0"):
    (parent / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\n"
        f"dependencies:\n  - name: {name}\n    version: {version}\n    repository: {repository}\n",
        encoding="utf-8",
    )


def test_vendored_library_and_application_are_edges_not_render_targets(tmp_path):
    parent = chart(tmp_path, "parent", "parent")
    library = chart(tmp_path, "parent/charts/helpers", "helpers", "2.0.0")
    (library / "Chart.yaml").write_text(
        "apiVersion: v2\nname: helpers\nversion: 2.0.0\ntype: library\n", encoding="utf-8"
    )
    chart(tmp_path, "parent/charts/worker", "worker", "3.0.0")
    (parent / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 1.0.0\n"
        "dependencies:\n  - name: helpers\n    version: 2.0.0\n"
        "  - name: worker\n    version: 3.0.0\n", encoding="utf-8"
    )
    graph, entries = discover(tmp_path)
    assert [item["name"] for item in entries] == ["parent"]
    children = {item["chart"]: item for item in graph["charts"] if item["chart"] != "parent"}
    assert children["helpers"]["chart_type"] == "library"
    assert children["worker"]["chart_type"] == "application"
    assert all(item["embedded_dependency"] for item in children.values())
    refs = [item for item in graph["references"] if item["discovery_method"] == "Chart.yaml dependency"]
    assert {item["reference"] for item in refs} == {"helpers", "worker"}
    assert all(item["resolution_status"] == "LOCAL_CHART" for item in refs)
    assert not graph["unresolved"]


@pytest.mark.parametrize("allow_network", ["false", "true"])
def test_missing_oci_dependency_is_parent_edge_never_standalone(tmp_path, monkeypatch, allow_network):
    monkeypatch.setenv("HELM_ALLOW_NETWORK", allow_network)
    parent = chart(tmp_path, "parent", "parent")
    dependency(parent, "helpers", "oci://registry.example.invalid/team")
    (parent / "Chart.lock").write_text(
        "dependencies:\n  - name: helpers\n    repository: oci://registry.example.invalid/team\n",
        encoding="utf-8",
    )
    graph, entries = discover(tmp_path)
    assert [item["name"] for item in entries] == ["parent"]
    refs = [item for item in graph["references"] if item["discovery_method"] == "Chart.yaml dependency"]
    assert len(refs) == 1
    assert refs[0]["reference"] == "helpers"
    assert refs[0]["chart_reference"] == "oci://registry.example.invalid/team/helpers"
    assert refs[0]["version"] == "2.41.0"
    assert not graph["unresolved"]
    assert not any(item.get("reference") == "oci://registry.example.invalid/team" for item in entries)


def test_vendored_package_is_dependency_not_independent_chart(tmp_path):
    parent = chart(tmp_path, "parent", "parent")
    dependency(parent, "helpers", "oci://registry.example.invalid/team")
    package_root = tmp_path / "staging" / "helpers"
    package_root.mkdir(parents=True)
    (package_root / "Chart.yaml").write_text(
        "apiVersion: v2\nname: helpers\nversion: 2.41.0\ntype: library\n", encoding="utf-8"
    )
    archive = parent / "charts" / "helpers-2.41.0.tgz"
    archive.parent.mkdir()
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(package_root, arcname="helpers")
    shutil.rmtree(tmp_path / "staging")
    graph, entries = discover(tmp_path)
    assert [item["name"] for item in entries] == ["parent"]
    child = next(item for item in graph["charts"] if item["chart"] == "helpers")
    assert child["embedded_dependency"] and child["chart_type"] == "library"
    assert any(item.get("resolution_status") == "LOCAL_CHART" and item.get("chart_type") == "library"
               for item in graph["references"])


def test_independently_supplied_chart_stays_independent_despite_dependency_name(tmp_path):
    parent = chart(tmp_path, "parent", "parent")
    dependency(parent, "worker", "oci://registry.example.invalid/team")
    chart(tmp_path, "independent/worker", "worker", "2.41.0")
    graph, entries = discover(tmp_path)
    assert {item["name"] for item in entries} == {"parent", "worker"}
    assert any(item["reference"] == "worker" and item["resolution_status"] == "DECLARED_DEPENDENCY"
               for item in graph["references"])
    assert not any(item["chart"] == "worker" and item["embedded_dependency"] for item in graph["charts"])


def test_independent_oci_reference_is_complete_and_sibling_is_retained(tmp_path):
    parent = chart(tmp_path, "parent", "parent")
    dependency(parent, "helpers", "oci://registry.example.invalid/team")
    chart(tmp_path, "healthy", "healthy")
    (tmp_path / "catalog.yml").write_text(
        "charts:\n  dashboard:\n    chart: dashboard\n"
        "    repository: oci://registry.example.invalid/team\n    version: 5.0.0\n",
        encoding="utf-8",
    )
    graph, entries = discover(tmp_path)
    assert {"parent", "healthy", "dashboard"} <= {item["name"] for item in entries}
    dashboard = next(item for item in entries if item["name"] == "dashboard")
    assert dashboard["reference"] == "oci://registry.example.invalid/team/dashboard"
    assert dashboard["repository"] is None
    assert not any(item["name"] == "helpers" for item in entries)


def test_dependency_edge_does_not_duplicate_parent_render_or_missing_evidence(tmp_path):
    parent = chart(tmp_path, "parent", "parent")
    dependency(parent, "helpers", "oci://registry.example.invalid/team")
    chart(tmp_path, "healthy", "healthy")

    graph, entries = discover(tmp_path)

    assert [item["name"] for item in entries].count("parent") == 1
    assert [item["name"] for item in entries].count("healthy") == 1
    assert not any(item["name"] == "helpers" for item in entries)
    assert not any(item.get("item") in {"helpers", "oci://registry.example.invalid/team"}
                   for item in graph["unresolved"])


def test_chart_processing_yq_queries_do_not_use_jq_only_empty():
    scripts = SCRIPT.parent
    for name in ("scan-configurations.sh", "extract-helm-images.sh"):
        source = (scripts / name).read_text(encoding="utf-8")
        yq_lines = [line for line in source.splitlines() if "yq " in line and not line.lstrip().startswith("#")]
        assert yq_lines
        assert all("// empty" not in line for line in yq_lines)
    assert "yq -r '.name // \"\"'" in (scripts / "scan-configurations.sh").read_text(encoding="utf-8")
