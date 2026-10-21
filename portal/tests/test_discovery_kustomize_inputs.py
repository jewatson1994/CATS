from pathlib import Path
import pytest
from app.discovery_kustomize_inputs import collect_inputs


def put(base, name, text="kind: ConfigMap\n"):
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_local_closure(tmp_path):
    put(tmp_path, "overlay/kustomization.yaml", """resources: [../base, extra.yaml]
components: [../component]
patches: [{path: patch.yaml}, {patch: 'inline'}]
patchesStrategicMerge: [strategic.yaml]
patchesJson6902: [{path: json.yaml, target: {kind: Deployment}}]
configMapGenerator:
- name: settings
  files: [key=config.txt]
  envs: [values.env]
secretGenerator:
- name: secret
  env: secret.env
configurations: [config.yaml]
crds: [crd.yaml]
""")
    put(tmp_path, "base/Kustomization", "resources: [object.yaml]\n")
    put(tmp_path, "component/kustomization.yml", "resources: []\n")
    expected = {tmp_path / "overlay/kustomization.yaml", tmp_path / "base/Kustomization", tmp_path / "component/kustomization.yml"}
    for name in ("base/object.yaml", "overlay/extra.yaml", "overlay/patch.yaml", "overlay/strategic.yaml", "overlay/json.yaml", "overlay/config.txt", "overlay/values.env", "overlay/secret.env", "overlay/config.yaml", "overlay/crd.yaml"):
        expected.add(put(tmp_path, name))
    put(tmp_path, "unrelated.txt")
    assert collect_inputs(tmp_path / "overlay", tmp_path) == expected


@pytest.mark.parametrize("text", [
    "resources: [https://example.com/x]", "resources: [../outside.yaml]",
    "resources: [missing.yaml]", "resources: [.]", "resources: invalid",
    "helmCharts: []", "replacements: []", "unknown: true",
    "resources: []\nresources: []", "patches: [{path: x, patch: y}]",
    "configMapGenerator: [{name: x, unknown: []}]", "!!python/object:bad {}",
])
def test_unsupported_falls_back(tmp_path, text):
    put(tmp_path, "kustomization.yaml", text)
    assert collect_inputs(tmp_path, tmp_path) is None


def test_multiple_markers(tmp_path):
    put(tmp_path, "kustomization.yaml", "resources: []")
    put(tmp_path, "Kustomization", "resources: []")
    assert collect_inputs(tmp_path, tmp_path) is None


def test_duplicate_dependency_is_allowed(tmp_path):
    marker = put(tmp_path, "kustomization.yaml", "resources: [child, child]")
    child = put(tmp_path, "child/kustomization.yaml", "resources: []")
    assert collect_inputs(tmp_path, tmp_path) == {marker, child}


def test_cycle_falls_back(tmp_path):
    put(tmp_path, "kustomization.yaml", "resources: [child]")
    put(tmp_path, "child/kustomization.yaml", "resources: [..]")
    assert collect_inputs(tmp_path, tmp_path) is None


def test_symlink_falls_back(tmp_path):
    put(tmp_path, "kustomization.yaml", "resources: [link.yaml]")
    target = put(tmp_path, "target.yaml")
    try:
        (tmp_path / "link.yaml").symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert collect_inputs(tmp_path, tmp_path) is None


def test_document_limit(tmp_path):
    put(tmp_path, "kustomization.yaml", "#" * (1024 * 1024 + 1))
    assert collect_inputs(tmp_path, tmp_path) is None
