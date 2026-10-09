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


@pytest.mark.parametrize('image', ['unified', 'portal'])
@pytest.mark.parametrize('profile', ['release', 'development', 'runtime'])
@pytest.mark.parametrize('tag', [None, 'registry.test/cats:custom'])
def test_image_build_selects_context_version_and_tag(image, profile, tag):
    args = SimpleNamespace(image=image, profile=profile, scanner_base='fixture-base',
                           cats_version='fixture', tag=tag)
    commands = b.commands(args)
    assert len(commands) == 1
    command = commands[0]
    assert command[:6] == ['docker', 'buildx', 'build', '--load', '--platform', 'linux/amd64']
    dockerfile = 'cats-image/Dockerfile.all-in-one' if image == 'unified' else 'portal/Dockerfile'
    assert command[command.index('-f') + 1] == str(ROOT / dockerfile)
    assert command[-1] == str(ROOT if image == 'unified' else ROOT / 'portal')
    assert command[command.index('-t') + 1] == (tag or 'cats:fixture')
    build_args = [command[index + 1] for index, value in enumerate(command) if value == '--build-arg']
    expected_args = ['CATS_VERSION=fixture']
    if image == 'unified':
        expected_args.insert(0, 'CATSCAN_BASE_IMAGE=fixture-base')
    assert build_args == expected_args


@pytest.mark.parametrize('image', ['unified', 'portal'])
def test_scanner_base_is_built_only_for_unified_image_without_override(image):
    args = SimpleNamespace(image=image, profile='runtime', scanner_base=None,
                           cats_version='fixture', tag=None)
    commands = b.commands(args)
    if image == 'unified':
        assert len(commands) == 2
        assert commands[0] == [
            'docker', 'buildx', 'build', '--load', '--platform', 'linux/amd64', '--pull',
            '-f', str(ROOT / 'cats-scanner/Dockerfile'), '-t', 'catscan-base:local',
            str(ROOT / 'cats-scanner'),
        ]
        assert 'CATSCAN_BASE_IMAGE=catscan-base:local' in commands[1]
    else:
        assert len(commands) == 1


def test_failed_native_qualification_never_generates_release_manifest(tmp_path,pins):
    base=tmp_path/p.PLATFORM;base.mkdir()
    sources={n:'fixture' for n in ('packages/runtime.deb','wheels/native.whl')}
    for name in sources:
        path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
    p.json_write(base/'inventory.json',p.inventory(base,sources))
    with pytest.raises(ValueError,match='qualification'):p.write_manifest(tmp_path,'fixture',pins,{})
    assert not (tmp_path/'release.json').exists()
    assert not (base/'validator-assets.json').exists()


@pytest.fixture
def wrapper(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(b.shutil, 'which', lambda tool: 'fixture-docker')
    monkeypatch.setattr(b.uuid, 'uuid4', lambda: SimpleNamespace(hex='fixture-release'))

    def invoke(*options, node_cached=True, fail_stage=None):
        monkeypatch.setattr(sys, 'argv', [
            'build-cats-release.py', '--cache-dir', str(tmp_path),
            '--cats-version', 'fixture', *options,
        ])

        def execute(command, **kwargs):
            if command == ['docker', 'info']:
                stage = 'engine'
            elif 'buildx' in command:
                stage = 'scanner-build' if str(ROOT / 'cats-scanner/Dockerfile') in command else 'runtime-build'
            elif command[:2] == ['docker', 'pull']:
                stage = 'node-pull'
            elif command[0] == sys.executable:
                stage = 'package'
            elif '--format' in command:
                stage = 'final-inspect'
            else:
                stage = 'node-inspect'
            calls.append((stage, command, kwargs))
            if stage == fail_stage:
                assert kwargs.get('check') is True
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, int(stage == 'node-inspect' and not node_cached))

        monkeypatch.setattr(b.subprocess, 'run', execute)
        b.main()
        return calls

    return invoke, calls


@pytest.mark.parametrize('node_cached', [True, False])
@pytest.mark.parametrize('tag', [None, 'registry.test/cats:custom'])
def test_release_builds_runtime_then_packages_and_activates_docker_release(wrapper, tmp_path, capsys, node_cached, tag):
    from app.deployment_validation import ValidationConfig

    invoke, _ = wrapper
    calls = invoke(*(['--tag', tag] if tag else []), node_cached=node_cached)
    stages = ['engine', 'scanner-build', 'runtime-build', 'node-inspect']
    if not node_cached:
        stages.append('node-pull')
    assert [stage for stage, _, _ in calls] == stages + ['package', 'final-inspect']
    by_stage = {stage: (command, kwargs) for stage, command, kwargs in calls}
    for stage in ('scanner-build', 'runtime-build'):
        assert by_stage[stage][1] == {'check': True, 'cwd': ROOT}
    assert by_stage['node-inspect'][0] == ['docker', 'image', 'inspect', ValidationConfig.kind_node_image]
    if not node_cached:
        assert by_stage['node-pull'] == (['docker', 'pull', ValidationConfig.kind_node_image], {'check': True})
    output = tmp_path.resolve() / 'fixture-release'
    image = tag or 'cats:fixture'
    assert by_stage['package'] == ([
        sys.executable, str(ROOT / 'scripts/prepare-docker-validator-release.py'),
        '--output', str(output), '--cats-image', image, '--activate-env', str(ROOT / '.env'),
    ], {'check': True})
    assert by_stage['final-inspect'] == ([
        'docker', 'image', 'inspect', image, '--format', '{{.Id}} {{.Size}}',
    ], {'check': True})
    assert capsys.readouterr().out.strip() == 'Set CATS_MANAGED_VALIDATOR_RELEASE_SOURCE=' + str(output)


@pytest.mark.parametrize('fail_stage', ['engine', 'scanner-build', 'runtime-build', 'node-pull', 'package'])
def test_release_failure_stops_subsequent_build_and_packaging_steps(wrapper, capsys, fail_stage):
    invoke, calls = wrapper
    with pytest.raises(subprocess.CalledProcessError) as failure:
        invoke(node_cached=False, fail_stage=fail_stage)
    stages = ['engine', 'scanner-build', 'runtime-build', 'node-inspect', 'node-pull', 'package']
    assert [stage for stage, _, _ in calls] == stages[:stages.index(fail_stage) + 1]
    assert failure.value.cmd == calls[-1][1]
    assert 'CATS_MANAGED_VALIDATOR_RELEASE_SOURCE=' not in capsys.readouterr().out


def test_release_rejects_portal_image_before_building(wrapper, capsys):
    invoke, calls = wrapper
    with pytest.raises(SystemExit) as failure:
        invoke('--image', 'portal')
    assert failure.value.code == 2
    assert [stage for stage, _, _ in calls] == ['engine']
    assert 'Docker-host releases require the unified CATS runtime image' in capsys.readouterr().err


@pytest.mark.parametrize('image', ['unified', 'portal'])
@pytest.mark.parametrize('profile', ['development', 'runtime'])
def test_nonrelease_profiles_build_without_packaging_or_activation(wrapper, tmp_path, image, profile):
    invoke, _ = wrapper
    calls = invoke('--image', image, '--profile', profile, '--scanner-base', 'catscan-base:local')
    assert [stage for stage, _, _ in calls] == ['engine', 'runtime-build', 'final-inspect']
    assert calls[-1][1] == ['docker', 'image', 'inspect', 'cats:fixture', '--format', '{{.Id}} {{.Size}}']
    assert list(tmp_path.iterdir()) == []


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
