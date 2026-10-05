"""Connected preparation helper checks; fixtures never imply native qualification."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p = load('release_preparation', 'prepare-managed-validator-release.py')
b = load('release_build', 'build-cats-release.py')


@pytest.fixture
def pins():
    return json.loads((ROOT/'scripts/managed-validator-release/pins.json').read_text())


def test_real_release_pins_are_exact_and_compatible(pins):
    assert p.validate_pins(pins) == pins
    assert int(pins['docker']['engine_version'].split('.')[0]) >= 28
    for name in ('kind','kubectl','helm'):
        assert 'latest' not in pins[name]['url']
    assert '@sha256:' in pins['node_image']['reference']


@pytest.mark.parametrize('component,field,value',[
    ('kind','version','latest'),('kubectl','sha256','placeholder'),
    ('helm','url','https://example.test/latest/helm'),
    ('node_image','reference','kindest/node:latest'),
    ('ubuntu_image','reference','ubuntu:22.04'),
    ('kubectl','version','v1.20.0'),
])
def test_invalid_production_pins_rejected(pins,component,field,value):
    pins = copy.deepcopy(pins);pins[component][field]=value
    with pytest.raises(ValueError):p.validate_pins(pins)


def test_download_verifies_independent_hash_and_cache(monkeypatch,tmp_path):
    content=b'official artifact fixture';digest=hashlib.sha256(content).hexdigest()
    calls=[]
    def download(*args,**kwargs):calls.append(args[0]);return io.BytesIO(content)
    monkeypatch.setattr(p.urllib.request,'urlopen',download)
    p.verified_download('https://example.test/v1.0.0',digest,tmp_path/'cache',tmp_path/'one')
    p.verified_download('https://example.test/v1.0.0',digest,tmp_path/'cache',tmp_path/'two')
    assert len(calls)==1 and (tmp_path/'two').read_bytes()==content
    (tmp_path/'cache'/digest).write_bytes(b'corrupted cache')
    with pytest.raises(ValueError,match='Corrupted cached'):p.verified_download('https://example.test/v1.0.0',digest,tmp_path/'cache',tmp_path/'three')
    assert not (tmp_path/'three').exists()


def test_corrupted_upstream_never_enters_cache(monkeypatch,tmp_path):
    monkeypatch.setattr(p.urllib.request,'urlopen',lambda *a,**k:io.BytesIO(b'corrupted'))
    digest=hashlib.sha256(b'correct').hexdigest()
    with pytest.raises(ValueError,match='SHA256 mismatch'):p.verified_download('https://example.test/v1',digest,tmp_path/'cache',tmp_path/'artifact')
    assert not (tmp_path/'cache'/digest).exists()
    assert not (tmp_path/'artifact').exists()
    assert list((tmp_path/'cache').iterdir())==[]


@pytest.mark.parametrize('omitted', ['packages/runtime.deb','wheels/native.whl'])
def test_inventory_requires_packages_and_wheels(tmp_path,omitted):
    sources={n:'fixture' for n in ('packages/runtime.deb','wheels/native.whl') if n!=omitted}
    for name in sources:
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
    with pytest.raises(ValueError,match='closure'):p.validate_inventory(tmp_path,p.inventory(tmp_path,sources))


def test_inventory_mutation_rejected(tmp_path):
    sources={n:'fixture' for n in ('packages/runtime.deb','wheels/native.whl')}
    for name in sources:
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
    inventory=p.inventory(tmp_path,sources);p.validate_inventory(tmp_path,inventory)
    (tmp_path/'wheels/native.whl').write_bytes(b'mutation')
    with pytest.raises(ValueError,match='mutated'):p.validate_inventory(tmp_path,inventory)


@pytest.mark.parametrize('content', ['dependencies:\n- name: remote\n', 'description: https://example.test/chart\n', 'description: oci://example.test/chart\n'])
def test_chart_remote_dependencies_rejected(tmp_path,content):
    (tmp_path/'Chart.yaml').write_text('apiVersion: v2\nname: fixture\nversion: 1.0.0\n'+content)
    with pytest.raises(ValueError):p.validate_chart(tmp_path)


@pytest.mark.parametrize('image',['unified','portal'])
@pytest.mark.parametrize('profile',['release','development','runtime'])
def test_supported_image_build_passes_assets_and_explicit_profile(tmp_path,image,profile):
    args=SimpleNamespace(image=image,profile=profile,scanner_base='fixture-base',cats_version='fixture',tag=None)
    command=b.commands(args,tmp_path)[-1]
    assert 'validator_assets='+str(tmp_path) in command
    assert 'CATS_DEVELOPMENT_WITHOUT_VALIDATOR_ASSETS='+('true' if profile in ('development','runtime') else 'false') in command
    assert 'CATS_VERSION=fixture' in command
    assert 'linux/amd64' in command


def test_failed_native_qualification_never_generates_release_manifest(tmp_path,pins):
    base=tmp_path/p.PLATFORM;base.mkdir()
    sources={n:'fixture' for n in ('packages/runtime.deb','wheels/native.whl')}
    for name in sources:
        path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
    p.json_write(base/'inventory.json',p.inventory(base,sources))
    with pytest.raises(ValueError,match='qualification'):p.write_manifest(tmp_path,'fixture',pins,{})
    assert not (tmp_path/'release.json').exists()
    assert not (base/'validator-assets.json').exists()


@pytest.mark.parametrize('dockerfile',['portal/Dockerfile','cats-image/Dockerfile.all-in-one'])
def test_image_build_requires_seal_unless_explicit_development_omission(dockerfile):
    text=(ROOT/dockerfile).read_text()
    assert 'ARG CATS_DEVELOPMENT_WITHOUT_VALIDATOR_ASSETS=false' in text
    assert '"managed_validator_assets":"omitted"' in text
    assert 'test ! -e /opt/cats/validator-assets/release.json' in text
    assert 'seal-managed-validator-release.py' in text
    assert '--cats-version "$CATS_VERSION"' in text


def test_production_wrapper_stops_before_image_build_when_preparation_fails(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(sys,'argv',['build-cats-release.py','--cache-dir',str(tmp_path),'--image','portal'])
    monkeypatch.setattr(b.shutil,'which',lambda tool:'fixture-docker')
    def execute(command,**kwargs):
        calls.append(command)
        if any('prepare-managed-validator-release.py' in str(arg) for arg in command):
            raise subprocess.CalledProcessError(1,command)
    monkeypatch.setattr(b.subprocess,'run',execute)
    with pytest.raises(subprocess.CalledProcessError):b.main()
    assert not any('buildx' in command for command in calls)


def test_explicit_development_wrapper_creates_omission_without_preparation(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(sys,'argv',['build-cats-release.py','--cache-dir',str(tmp_path),'--image','portal','--profile','development'])
    monkeypatch.setattr(b.shutil,'which',lambda tool:'fixture-docker')
    monkeypatch.setattr(b.subprocess,'run',lambda command,**kwargs:calls.append(command))
    b.main()
    assert json.loads((tmp_path/'omitted/omitted.json').read_text())=={'format':1,'managed_validator_assets':'omitted'}
    assert not any(any('prepare-managed-validator-release.py' in str(arg) for arg in command) for command in calls)


def test_copy_pinned_image_requires_exact_archive_manifest(tmp_path, monkeypatch):
    import io
    import tarfile
    manifest = b'{"schemaVersion":2}'
    digest = hashlib.sha256(manifest).hexdigest()
    archive_path = tmp_path / 'image.tar'
    with tarfile.open(archive_path, 'w') as archive:
        for name, data in [('index.json', json.dumps({'manifests': [{'digest': 'sha256:' + digest}]}).encode()),
                           ('blobs/sha256/' + digest, manifest)]:
            info = tarfile.TarInfo(name); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    calls = []
    monkeypatch.setattr(p, 'run', lambda *args: calls.append(args))
    destination = 'oci-archive:' + str(archive_path) + ':test@sha256:' + digest
    p.copy_pinned_image('docker://test', destination, 'test@sha256:' + digest)
    assert '--preserve-digests' not in calls[0]
    p.copy_pinned_image('docker://registry.test:5000/kindest/node:v1.35.0@sha256:' + digest,
                        destination, 'test@sha256:' + digest)
    assert calls[-1][-2] == 'docker://registry.test:5000/kindest/node@sha256:' + digest
    assert '--all' in calls[-1]
    p.copy_pinned_image('docker://node:v1.35.0@sha256:' + digest,
                        destination, 'test@sha256:' + digest)
    assert calls[-1][-2] == 'docker://node@sha256:' + digest
    with pytest.raises(ValueError, match='digest mismatch'):
        p.copy_pinned_image('docker://test', 'oci-archive:' + str(archive_path) + ':test@sha256:' + '0' * 64, 'test@sha256:' + '0' * 64)


def test_runtime_build_does_not_prepare_ubuntu_installer(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(sys, 'argv', ['build-cats-release.py', '--cache-dir', str(tmp_path),
                                   '--scanner-base', 'catscan-base:local', '--profile', 'runtime'])
    monkeypatch.setattr(b.shutil, 'which', lambda tool: 'docker')
    monkeypatch.setattr(b.subprocess, 'run', lambda command, **kwargs: calls.append(command))
    b.main()
    assert not any('prepare-managed-validator-release.py' in str(command) for command in calls)
    command = next(command for command in calls if command[:3] == ['docker', 'buildx', 'build'])
    assert 'validator_assets=' + str(tmp_path / 'omitted') in command
    assert 'CATS_DEVELOPMENT_WITHOUT_VALIDATOR_ASSETS=true' in command
