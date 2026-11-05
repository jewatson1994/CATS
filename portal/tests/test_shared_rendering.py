from pathlib import Path

import pytest

from app import rendering
from app.discovery_engine import run_discovery


def test_helm_stages_only_chart_and_ordered_selected_values(tmp_path, monkeypatch):
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 1.0.0\n")
    (tmp_path / "first.yaml").write_text("replicas: 1\n")
    (tmp_path / "second.yaml").write_text("replicas: 3\n")
    (tmp_path / "worker-secret").write_text("PRIVATE")
    calls = []

    def runner(tool, args, cwd, **kwargs):
        calls.append(args)
        assert {p.name for p in Path(cwd).iterdir()} == {"chart", "values-0.yaml", "values-1.yaml"}
        assert (Path(cwd) / "values-0.yaml").read_text() == "replicas: 1\n"
        assert (Path(cwd) / "values-1.yaml").read_text() == "replicas: 3\n"
        assert args[:2] == ["template", "my-release"]
        assert args[3:6] == ["--namespace", "prod", "--include-crds"]
        assert args[-2:] == ["--set-string", "feature=false"]
        return {"stdout": "manifest"}

    monkeypatch.setattr(rendering, "isolated_runner", runner)
    assert rendering.render_action("helm", ["template", "my-release", str(chart), "-n", "prod",
        "-f", "first.yaml", "-f", "second.yaml", "--set-string", "feature=false"], tmp_path)["stdout"] == "manifest"
    assert len(calls) == 1


def test_chart_values_never_automatically_overridden(tmp_path, monkeypatch):
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 1.0.0\n")
    calls = []

    def reject(tool, args, cwd, **kwargs):
        calls.append(args)
        raise rendering.RendererError("helm failed")

    monkeypatch.setattr(rendering, "isolated_runner", reject)
    with pytest.raises(rendering.RendererError):
        rendering.helm_template(tmp_path)
    assert len(calls) == 1
    assert not any("allowInsecureImages" in value for value in calls[0])


@pytest.mark.parametrize("budget", [0, 1234, 128 * 1024 * 1024])
def test_render_action_preserves_operator_output_budget(tmp_path, monkeypatch, budget):
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 1.0.0\n")
    calls = []
    def runner(tool, args, cwd, **kwargs):
        calls.append(kwargs["max_output"])
        return {"stdout": "manifest"}
    monkeypatch.setattr(rendering, "isolated_runner", runner)
    rendering.render_action("helm", ["template", "probe", str(tmp_path)], tmp_path, max_output=budget)
    rendering.render_action("compose", ["config"], tmp_path, max_output=budget)
    assert calls == [budget, budget]


def test_discovery_reports_host_isolation_failure_without_values_advice(tmp_path):
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 1.0.0\n")

    def fail(*args):
        raise rendering.RendererError("Worker isolation is unavailable", infrastructure=True)

    result = run_discovery(tmp_path, runner=fail)
    diagnostic, = [d for d in result["diagnostics"] if d["code"] == "worker_isolation_unavailable"]
    assert "Changing chart values will not fix" in diagnostic["message"]
    assert result["completeness"] != "complete"


def test_values_outside_discovery_source_rejected(tmp_path):
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: probe\nversion: 1.0.0\n")
    (tmp_path / "private.yaml").write_text("password: secret\n")
    with pytest.raises(rendering.RendererError, match="outside"):
        rendering.helm_template(chart, source_root=chart, values=[tmp_path / "private.yaml"])


@pytest.mark.parametrize("kind", ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"])
def test_builtin_webhooks_are_not_unknown_workload_controllers(tmp_path, kind):
    path = tmp_path / "webhook.yaml"
    path.write_text(f"apiVersion: admissionregistration.k8s.io/v1\nkind: {kind}\nmetadata: {{name: check}}\nwebhooks: []\n")
    result = run_discovery(tmp_path)
    assert not any(d["code"] == "custom_resource_workloads_not_evaluated" for d in result["diagnostics"])
    path.write_text(path.read_text().replace("admissionregistration.k8s.io/v1", "custom.example/v1"))
    result = run_discovery(tmp_path)
    assert any(d["code"] == "custom_resource_workloads_not_evaluated" for d in result["diagnostics"])
