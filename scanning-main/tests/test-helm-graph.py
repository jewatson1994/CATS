import importlib.util
import json
from pathlib import Path
import tarfile


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
