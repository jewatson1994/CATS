from pathlib import Path
import runpy
from types import SimpleNamespace

import yaml

from app.runtime_version import deployed_version, normalize_version


def test_version_normalization_never_duplicates_v():
    assert normalize_version("1.2.2") == "v1.2.2"
    assert normalize_version("v1.2.2") == "v1.2.2"
    assert normalize_version("V1.2.2") == "v1.2.2"


def test_missing_runtime_version_is_omitted(monkeypatch):
    monkeypatch.delenv("CATS_VERSION", raising=False)
    assert deployed_version() is None


def test_global_header_uses_runtime_value_without_hardcoded_release():
    from app.frontend import page_data
    from starlette.requests import Request
    request = Request({"type": "http", "path": "/", "query_string": b"", "headers": []})
    assert page_data(request, "home.html", {}, deployed_version="v9.8.7", formatters={})["data"]["cats_deployed_version"] == "v9.8.7"
    assert page_data(request, "home.html", {}, formatters={})["data"]["cats_deployed_version"] is None


def test_build_and_compose_propagate_one_requested_image_version():
    root = Path(__file__).parents[2]
    build = runpy.run_path(str(root / "scripts" / "build-cats-release.py"))
    compose = (root / "compose.yaml").read_text(encoding="utf-8")
    dockerfile = (root / "cats-image" / "Dockerfile.all-in-one").read_text(encoding="utf-8")
    version = "9.8.7"
    commands = build["commands"](SimpleNamespace(image="unified", scanner_base=None,
                                                cats_version=version, tag=None))
    final = commands[-1]
    build_args = [final[index + 1] for index, value in enumerate(final) if value == "--build-arg"]
    assert f"CATS_VERSION={version}" in build_args
    assert "CATSCAN_BASE_IMAGE=catscan-base:local" in build_args
    assert final[final.index("-t") + 1] == f"cats:{version}"
    services = yaml.safe_load(compose)["services"]
    for name in ("portal", "portal-control", "scan-worker", "patch-worker"):
        assert services[name]["image"] == "${CATS_IMAGE:-cats:local}", name
    assert "cats:1.2.1" not in compose
    assert 'ENV CATS_VERSION="${CATS_VERSION}"' in dockerfile
