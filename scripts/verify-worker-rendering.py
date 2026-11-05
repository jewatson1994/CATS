#!/usr/bin/env python3
"""Run inside a built worker, with a local cert-manager v1.20.2 archive.

This exercises production archive extraction, Discovery, the scan CLI, and the
shared candidate/delivery rendering action. No network or registry is needed.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from app.discovery_engine import run_discovery
from app.helm_archives import extract_chart
from app.rendering import helm_template, render_action


def verify_other_renderers():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "compose.yaml").write_text("services:\n  web:\n    image: nginx:1.27\n")
        compose = render_action("compose", ["--project-name", "discovery", "-f",
            str(root / "compose.yaml"), "config", "--format", "json"], root)
        assert json.loads(compose["stdout"])["services"]["web"]["image"] == "nginx:1.27"
        (root / "pod.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: web\n    image: nginx:1.27\n")
        (root / "kustomization.yaml").write_text("resources:\n- pod.yaml\n")
        kustomize = render_action("kustomize", ["build", str(root)], root)
        assert "image: nginx:1.27" in kustomize["stdout"]


def verify(archive):
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == "d2a50bd44a09d838c2576a8f3dfca1524597c7393cf8d82ab3ec8a465b9eeb79"
    renders = []

    def discovery_runner(tool, args, cwd):
        result = render_action(tool, args, cwd)
        if tool == "helm":
            renders.append(result["stdout"])
        return result

    inventory = run_discovery(archive, runner=discovery_runner)
    assert inventory["completeness"] == "complete", inventory["diagnostics"]
    expected = {f"quay.io/jetstack/cert-manager-{name}:v1.20.2" for name in
                ("cainjector", "controller", "startupapicheck", "webhook")}
    assert {image["reference"] for image in inventory["images"]} == expected
    assert len(renders) == 1
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        with archive.open("rb") as stream:
            extract_chart(stream, archive.name, root)
        chart, = root.rglob("Chart.yaml")
        scan = subprocess.run([sys.executable, "-m", "app.rendering", "helm", "template",
                               "cert-manager", str(chart.parent), "--namespace", "default", "--include-crds"],
                              check=True, capture_output=True, text=True).stdout
        candidate = helm_template(chart.parent, release="cert-manager")["stdout"]
        assert scan == renders[0] == candidate
        digest = hashlib.sha256(scan.encode()).hexdigest()
    verify_other_renderers()
    print(json.dumps({"chart": archive.name, "images": sorted(expected), "compose_kustomize": "passed",
                      "render_sha256": digest, "discovery_scan_candidate_equal": True}))


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
