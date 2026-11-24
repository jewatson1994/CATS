"""Validate collector/chart versions and package a runtime chart for an exact CATS release."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

RUNTIME = Path("runtime-agent")
CHART = RUNTIME / "helm/cats-runtime"


def verify():
    sys.path.insert(0, str(RUNTIME.resolve()))
    from cats_runtime import __version__

    metadata = yaml.safe_load((CHART / "Chart.yaml").read_text())
    if metadata["appVersion"] != __version__:
        raise ValueError("Chart.appVersion must match the collector version")
    base = os.getenv("BASE_SHA")
    if not base or base == "0" * 40:
        return
    previous = subprocess.run(["git", "show", f"{base}:{CHART.as_posix()}/Chart.yaml"], capture_output=True, text=True)
    if previous.returncode != 0:
        # First release in this history.
        return
    old = yaml.safe_load(previous.stdout)
    changes = subprocess.check_output(["git", "diff", "--name-only", base, "HEAD", "--", str(RUNTIME)], text=True).splitlines()
    collector_changed = any(p.startswith("runtime-agent/cats_runtime/") for p in changes)
    if collector_changed and old["appVersion"] == metadata["appVersion"]:
        raise ValueError("Bump the collector version for a changed runtime collector")
    if collector_changed or any(p.startswith(CHART.as_posix() + "/") for p in changes):
        if old["version"] == metadata["version"]:
            raise ValueError("Bump the chart version for a changed release package")


def package():
    image = os.environ["IMAGE"]
    digest = os.environ["CATS_IMAGE_DIGEST"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Invalid CATS image index digest")
    with tempfile.TemporaryDirectory() as temp:
        chart = Path(temp) / "cats-runtime"
        shutil.copytree(CHART, chart)
        metadata_file = chart / "Chart.yaml"
        metadata = yaml.safe_load(metadata_file.read_text())
        metadata.setdefault("annotations", {})["cats.io/image-digest"] = digest
        metadata_file.write_text(yaml.safe_dump(metadata, sort_keys=False))
        values_file = chart / "values.yaml"
        values = yaml.safe_load(values_file.read_text())
        values["image"]["repository"] = image
        values_file.write_text(yaml.safe_dump(values, sort_keys=False))
        subprocess.run(["helm", "package", str(chart), "--destination", "dist"], check=True)
    archive = f"dist/cats-runtime-{metadata['version']}.tgz"
    rendered = subprocess.check_output(["helm", "template", "cats", archive, "--set", "catsUrl=https://cats.example",
                                        "--set", "linkingKeySecret=existing"], text=True)
    deployment, = [item for item in yaml.safe_load_all(rendered) if item and item["kind"] == "Deployment"]
    if deployment["spec"]["template"]["spec"]["containers"][0]["image"] != f"{image}@{digest}":
        raise ValueError("Packaged Helm chart does not deploy the tested CATS image")
    with open(os.environ["GITHUB_ENV"], "a") as env:
        print("CHART_VERSION=" + metadata["version"], file=env)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("verify", "package"))
    if parser.parse_args().operation == "verify":
        verify()
    else:
        package()
