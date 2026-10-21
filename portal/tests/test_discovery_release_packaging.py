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
    assert len(commands) == 2
    assert commands[0][-2] == 'cats:release'
    assert 'CATS_TOOL_IMAGE=cats:release' in commands[1]
    assert commands[1][-2] == 'discovery:release'
    args.image = 'portal'
    assert len(release.commands(args)) == 1


def test_offline_companion_includes_exact_policy_and_image(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    (root / 'deploy').mkdir(parents=True)
    policy = b'{"defaultAction":"SCMP_ACT_ERRNO"}\n'
    (root / 'deploy/discovery-seccomp.json').write_bytes(policy)
    mirror = b'services: {}\n'
    (root / 'deploy/compose.discovery-mirror.yaml').write_bytes(mirror)
    monkeypatch.setattr(release, 'ROOT', root)
    calls = []
    identity = 'sha256:' + 'a' * 64
    def run(command, **kwargs):
        calls.append(command)
        if command[1:3] == ['image', 'inspect']:
            return SimpleNamespace(stdout=json.dumps([{'Id': identity, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'User': '10003:10003'}}]))
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
    assert manifest['image_id'] == identity
    assert calls[-1][-1] == 'cats-discovery:' + 'a' * 64
    assert all('pull' not in call for call in calls)
    with pytest.raises(FileExistsError):
        release.export_discovery(output, 'discovery:release')
