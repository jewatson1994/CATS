import pytest

from app.patch_worker import runtime_commit_command


def test_maintenance_commit_restores_runtime_without_shell_interpolation():
    command = runtime_commit_command("maintenance", "candidate:r1", {
        "Entrypoint": ["/start", "$(do-not-execute)"], "Cmd": ["serve", "--port=8080"],
    })
    assert command == ["docker", "commit", "--change", 'ENTRYPOINT ["/start", "$(do-not-execute)"]',
                       "--change", 'CMD ["serve", "--port=8080"]', "maintenance", "candidate:r1"]


def test_empty_runtime_configuration_is_restored_explicitly():
    assert runtime_commit_command("maintenance", "candidate:r1", {})[2:6] == [
        "--change", "ENTRYPOINT []", "--change", "CMD []",
    ]


def test_invalid_runtime_configuration_fails_closed():
    with pytest.raises(ValueError):
        runtime_commit_command("maintenance", "candidate:r1", {"Entrypoint": "sh -c unsafe"})
