from pathlib import Path

from app.runtime_version import deployed_version, normalize_version


def test_version_normalization_never_duplicates_v():
    assert normalize_version("1.2.2") == "v1.2.2"
    assert normalize_version("v1.2.2") == "v1.2.2"
    assert normalize_version("V1.2.2") == "v1.2.2"


def test_missing_runtime_version_is_omitted(monkeypatch):
    monkeypatch.delenv("CATS_VERSION", raising=False)
    assert deployed_version() is None


def test_global_header_uses_runtime_value_without_hardcoded_release():
    root = Path(__file__).parents[1]
    template = (root / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "cats_deployed_version" in template
    assert "v1.2." not in template


def test_build_and_compose_propagate_one_requested_image_version():
    root = Path(__file__).parents[2]
    build = (root / "build.ps1").read_text(encoding="utf-8")
    compose = (root / "compose.yaml").read_text(encoding="utf-8")
    dockerfile = (root / "cats-image" / "Dockerfile.all-in-one").read_text(encoding="utf-8")
    assert "--build-arg CATS_VERSION=$version" in build
    assert '$env:CATS_IMAGE = $expectedImage' in build
    assert compose.count("${CATS_IMAGE:-cats:local}") == 2
    assert "cats:1.2.1" not in compose
    assert 'ENV CATS_VERSION="${CATS_VERSION}"' in dockerfile
