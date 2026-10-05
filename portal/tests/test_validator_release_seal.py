"""Image seal creation delegates asset verification and never publishes partial trust."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import types

import pytest

spec = importlib.util.spec_from_file_location('release_sealer', Path(__file__).resolve().parents[2] / 'scripts/seal-managed-validator-release.py')
sealer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sealer)


def fixture_release(tmp_path, monkeypatch, versions=('22.04', '24.04'), fail=False):
    source = tmp_path / 'assets'
    source.mkdir()
    (source / 'release.json').write_text('reviewed input')
    calls = []
    entries = [{'os': 'ubuntu', 'os_version': v, 'architecture': 'amd64'} for v in versions]
    def platform(root, digest, facts):
        calls.append(facts['os_version'])
        if fail:
            raise ValueError('Asset verification failed')
    module = types.ModuleType('app.validator_payload_builds')
    module.validate_release = lambda root, digest: {'cats_version': 'release-1', 'platforms': entries}
    module.load_release_platform = platform
    monkeypatch.setitem(sys.modules, 'app.validator_payload_builds', module)
    return source, calls


def test_seal_verifies_every_platform_before_publication(tmp_path, monkeypatch):
    source, calls = fixture_release(tmp_path, monkeypatch)
    seal = tmp_path / 'trust.sha256'
    digest = sealer.seal_release(source, seal, 'release-1')
    assert calls == ['22.04', '24.04']
    assert digest == hashlib.sha256((source / 'release.json').read_bytes()).hexdigest()
    assert seal.read_text() == digest + '\n'


@pytest.mark.parametrize('version,platforms,fail,error', [
    ('other-release', ('22.04', '24.04'), False, 'CATS_VERSION'),
    ('release-1', ('24.04',), False, '22.04 amd64'),
    ('release-1', ('22.04', '24.04'), True, 'Asset verification'),
])
def test_invalid_release_never_writes_seal(tmp_path, monkeypatch, version, platforms, fail, error):
    source, _ = fixture_release(tmp_path, monkeypatch, platforms, fail)
    seal = tmp_path / 'trust.sha256'
    with pytest.raises(ValueError, match=error):
        sealer.seal_release(source, seal, version)
    assert not seal.exists()


def test_complete_ubuntu_2204_release_does_not_require_2404(tmp_path, monkeypatch):
    source, calls = fixture_release(tmp_path, monkeypatch, ('22.04',))
    seal = tmp_path / 'trust.sha256'
    sealer.seal_release(source, seal, 'release-1')
    assert calls == ['22.04']
    assert seal.is_file()
