import importlib.util
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location('cats_release', Path(__file__).resolve().parents[2] / 'scripts/build-cats-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_unified_builds_discovery_from_exact_release_tag():
    args = SimpleNamespace(image='unified', scanner_base='scanner:ready', tag='cats:release', cats_version='2', discovery_tag='discovery:release')
    commands = release.commands(args)
    assert len(commands) == 1
    assert commands[0][-2] == 'cats:release'
    assert release.discovery_tag(args) == 'cats:release'
    args.image = 'portal'
    assert len(release.commands(args)) == 1


def test_offline_companion_includes_exact_policy_and_image(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    (root / 'deploy').mkdir(parents=True)
    policy = b'{"defaultAction":"SCMP_ACT_ERRNO"}\n'
    (root / 'deploy/discovery-seccomp.json').write_bytes(policy)
    policy_files = ('cats-worker-actions.apparmor', 'compose.worker-apparmor.yaml', 'worker-isolation.md')
    for name in policy_files:
        (root / 'deploy' / name).write_bytes(name.encode())
    mirror = b'services: {}\n'
    (root / 'deploy/compose.discovery-mirror.yaml').write_bytes(mirror)
    (root / 'deploy/discovery-mirror').mkdir()
    default_manifest = b'{"version":1,"artifacts":[]}'
    (root / 'deploy/discovery-mirror/manifest.json').write_bytes(default_manifest)
    monkeypatch.setattr(release, 'ROOT', root)
    calls = []
    identity = 'sha256:' + 'a' * 64
    def run(command, **kwargs):
        calls.append(command)
        if command[1:3] == ['image', 'inspect']:
            return SimpleNamespace(stdout=json.dumps([{'Id': identity, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'User': ''}}]))
        if command[1] == 'save':
            Path(command[3]).write_bytes(b'image archive')
        return SimpleNamespace()
    monkeypatch.setattr(release.subprocess, 'run', run)
    output = tmp_path / 'export'
    manifest = release.export_discovery(output, 'discovery:release')
    assert (output / 'deploy/discovery-seccomp.json').read_bytes() == policy
    assert manifest['files']['deploy/discovery-seccomp.json'] == hashlib.sha256(policy).hexdigest()
    assert manifest['files']['discovery-image.tar'] == hashlib.sha256(b'image archive').hexdigest()
    assert manifest['files']['deploy/compose.discovery-mirror.yaml'] == hashlib.sha256(mirror).hexdigest()
    assert (output / 'deploy/compose.discovery-mirror.yaml').read_bytes() == mirror
    assert (output / 'deploy/discovery-mirror/manifest.json').read_bytes() == default_manifest
    for name in policy_files:
        assert (output / 'deploy' / name).read_bytes() == name.encode()
        assert manifest['files']['deploy/' + name] == hashlib.sha256(name.encode()).hexdigest()
    assert 'four isolated-action preflights' in (output / 'IMPORT.txt').read_text()
    assert manifest['image_id'] == identity
    assert calls[-1][-1] == 'cats:' + 'a' * 64
    assert all('pull' not in call for call in calls)
    with pytest.raises(FileExistsError):
        release.export_discovery(output, 'discovery:release')


@pytest.mark.parametrize("filename", ["compose.yaml", "templates/compose.main.yaml"])
def test_discovery_uses_shared_image_with_isolated_worker_entrypoint(filename):
    import yaml
    root = Path(__file__).resolve().parents[2]
    worker = yaml.safe_load((root / filename).read_text())["services"]["discovery-worker"]
    assert worker["image"] == "${CATS_IMAGE:-cats:local}"
    assert worker["entrypoint"] == []
    assert worker["command"] == ["/opt/cats-venv/bin/python", "-m", "app.discovery_worker"]
    assert worker["user"] == "10003:10003"
    assert worker["read_only"] is True
    assert "ALL" in worker["cap_drop"]
    assert any("no-new-privileges" in option for option in worker["security_opt"])
    assert any("discovery-seccomp.json" in option for option in worker["security_opt"])
    assert "docker.sock" not in str(worker.get("volumes", []))


@pytest.mark.parametrize("filename", ["compose.yaml", "templates/compose.main.yaml"])
def test_discovery_large_input_deployment_settings(filename):
    import yaml
    root = Path(__file__).resolve().parents[2]
    deployment = yaml.safe_load((root / filename).read_text())
    for service in ("portal", "discovery-worker"):
        env = deployment["services"][service]["environment"]
        for suffix in ("UPLOAD_BYTES", "FILE_BYTES", "EXTRACTED_BYTES", "FILES", "RENDERED_BYTES"):
            key = "CATS_DISCOVERY_MAX_" + suffix
            assert env[key] == "${" + key + ":-0}"
    worker = deployment["services"]["discovery-worker"]
    assert "discovery_scratch:/tmp" in worker["volumes"]
    assert not worker.get("tmpfs")
    assert "discovery_scratch" in deployment["volumes"]
    example = "templates/main.env.example" if filename.startswith("templates/") else ".env.example"
    settings = (root / example).read_text().splitlines()
    for suffix in ("UPLOAD_BYTES", "FILE_BYTES", "EXTRACTED_BYTES", "FILES", "RENDERED_BYTES"):
        assert "CATS_DISCOVERY_MAX_" + suffix + "=0" in settings


@pytest.mark.parametrize("filename", ["compose.yaml", "templates/compose.main.yaml"])
def test_gitlab_import_settings_apply_only_to_public_portal(filename):
    import yaml
    root = Path(__file__).resolve().parents[2]
    services = yaml.safe_load((root / filename).read_text())["services"]
    for setting in ("CATS_DISCOVERY_GITLAB_SOURCES", "CATS_DISCOVERY_GITLAB_CA_FILE"):
        assert services["portal"]["environment"][setting] == "${" + setting + ":-}"
        assert all(setting not in (service.get("environment") or {})
                   for name, service in services.items() if name != "portal")


def test_optional_gitlab_ca_is_a_read_only_portal_mount():
    import yaml
    root = Path(__file__).resolve().parents[2]
    overlay = yaml.safe_load((root / "deploy/compose.discovery-gitlab-ca.yaml").read_text())["services"]
    assert set(overlay) == {"portal"}
    mount, = overlay["portal"]["volumes"]
    assert mount["type"] == "bind"
    assert mount["source"].startswith("${CATS_DISCOVERY_GITLAB_CA_FILE:?")
    assert mount["target"] == overlay["portal"]["environment"]["CATS_DISCOVERY_GITLAB_CA_FILE"]
    assert mount["read_only"] and not mount["bind"]["create_host_path"]
