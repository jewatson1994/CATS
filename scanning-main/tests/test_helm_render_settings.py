import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("retain_helm", Path(__file__).parents[1] / "scripts" / "retain-helm-render-settings.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_exact_instances_and_value_order_survive_report(tmp_path):
    metadata = tmp_path / "helm-image-rendered"
    metadata.mkdir()
    entry = {"render_chart_root": str(tmp_path / "charts" / "app"), "release": "alpha", "namespace": "prod",
             "values": ["charts/base.yaml", "charts/override.yaml"], "set": {"feature": "false"}, "include_crds": False}
    (metadata / "alpha.chart.json").write_text(json.dumps(entry))
    (metadata / "beta.chart.json").write_text(json.dumps({**entry, "release": "beta"}))
    duplicate = tmp_path / "helm-rendered"
    duplicate.mkdir()
    (duplicate / "alpha.chart.json").write_text(json.dumps(entry))
    overview = tmp_path / "overview.json"
    overview.write_text("{}")
    module.retain(tmp_path, overview)
    settings = json.loads(overview.read_text())["helm_render_settings"]
    assert len(settings) == 2
    assert settings[0] == {"chart_root": "app", "release": "alpha", "namespace": "prod",
        "values": ["base.yaml", "override.yaml"], "set": ["feature=false"], "include_crds": False}
    assert settings[1]["release"] == "beta"
