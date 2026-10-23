import pytest
from app.patch_publication import resolve_destination, publication_error

@pytest.mark.parametrize("image,expected", [
    ("cats:patched", "registry.example/team/cats:patched"),
    ("cats", "registry.example/team/cats"),
    ("nested/cats:patched", "registry.example/team/nested/cats:patched"),
    ("registry.example/team/cats:patched", "registry.example/team/cats:patched"),
])
def test_selected_registry_resolves_tagged_unqualified_names(image, expected):
    assert resolve_destination(image, {"endpoint": "https://registry.example", "namespace": "team"}) == expected


def test_explicit_docker_hub_is_supported():
    assert resolve_destination("cats:patched", {"endpoint": "https://docker.io", "namespace": "myteam"}) == "docker.io/myteam/cats:patched"

@pytest.mark.parametrize("endpoint", ["", "registry", "https://", "https://user:secret@registry.example", "https://registry.example/path"])
def test_invalid_registry_rejected(endpoint):
    with pytest.raises(ValueError):
        resolve_destination("cats:patched", {"endpoint": endpoint})


def test_mismatched_explicit_registry_rejected():
    with pytest.raises(ValueError, match="match"):
        resolve_destination("docker.io/library/cats:patched", {"endpoint": "registry.example"})


def test_read_only_storage_diagnostic_preserves_root_cause():
    error = "mkdir /repostorage/containers_registry/docker/registry/v2/repositories/docker.io/library/cats: read-only file system"
    result = publication_error(error, "registry.example/team/cats:patched")
    assert "registry reported read-only storage" in result
    assert "registry.example/team/cats:patched" in result
    assert error in result
