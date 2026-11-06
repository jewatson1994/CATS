"""Bounded local regressions; real Harbor/runtime acceptance is opt-in."""
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

import harbor_inventory_qualification as qualification
from app import portable_release


def base_config():
    return {'architecture': 'amd64', 'os': 'linux',
        'config': {'Entrypoint': ['/docker-entrypoint.sh'], 'Cmd': ['nginx'], 'Labels': {'base': 'preserved'}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]},
        'history': [{'created_by': 'real base'}]}


def test_real_variant_layers_are_distinct_and_preserve_base_filesystem():
    original = base_config()
    untouched = deepcopy(original)
    layers, configurations = set(), set()
    for index in range(123):
        config, layer = qualification.variant(original, index)
        with tarfile.open(fileobj=io.BytesIO(layer)) as archive:
            assert archive.getnames() == ['qualification-id']
            assert archive.extractfile('qualification-id').read() == qualification.marker(index)
        assert config['rootfs']['diff_ids'] == original['rootfs']['diff_ids'] + [qualification.digest(layer)]
        assert config['config']['Entrypoint'] == ['/bin/sh', '-c', 'cat /qualification-id']
        assert config['config']['Labels']['base'] == 'preserved'
        assert qualification.LABEL in config['history'][-1]['comment']
        assert qualification.variant(original, index) == (config, layer)
        layers.add(qualification.digest(layer))
        configurations.add(qualification.digest(portable_release.canonical(config)))
    assert len(layers) == len(configurations) == 123
    assert original == untouched
    assert len(set(qualification.FIRST) & set(qualification.SUCCESSOR)) == 77
    assert len(set(qualification.FIRST) - set(qualification.SUCCESSOR)) == 23
    assert len(set(qualification.SUCCESSOR) - set(qualification.FIRST)) == 23


@pytest.mark.parametrize('change', [{'architecture': 'arm64'}, {'os': 'windows'},
    {'rootfs': {'type': 'layers', 'diff_ids': []}}, {'rootfs': {'type': 'not-layers', 'diff_ids': ['a']}}])
def test_invalid_runtime_base_is_rejected_before_publication(change):
    with pytest.raises(AssertionError):
        qualification.variant({**base_config(), **change}, 0)


def test_docker_archive_reconstructs_real_shared_layers_and_all_configurations(tmp_path):
    layer = qualification.tar_bytes({'bin/fixture-shell': b'bounded archive test, not runtime evidence'})
    compressed = gzip.compress(layer, mtime=0)
    descriptor = {'digest': qualification.digest(compressed), 'size': len(compressed),
        'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}
    config = base_config()
    config['rootfs']['diff_ids'] = [qualification.digest(layer)]
    layout = tmp_path / 'corpus-oci'
    qualification.retain(layout, descriptor, compressed)
    qualification.write_json(tmp_path / 'base.json', {'config': config, 'document': {'layers': [descriptor]}})
    images = []
    for index in range(123):
        configured, marker = qualification.variant(config, index)
        cfg_bytes = portable_release.canonical(configured)
        cfg = {'digest': qualification.digest(cfg_bytes), 'size': len(cfg_bytes),
            'mediaType': qualification.CONFIG_TYPE}
        added = {'digest': qualification.digest(marker), 'size': len(marker),
            'mediaType': qualification.LAYER_TYPE}
        qualification.retain(layout, cfg, cfg_bytes)
        qualification.retain(layout, added, marker)
        manifest = portable_release.canonical({'schemaVersion': 2, 'mediaType': qualification.IMAGE_TYPE,
            'config': cfg, 'layers': [descriptor, added]})
        root = {'digest': qualification.digest(manifest), 'size': len(manifest)}
        qualification.retain(layout, root, manifest)
        images.append({'index': index, 'name': f'image-{index:03d}', 'config': cfg,
            'marker_layer': added, 'digest': root['digest'],
            'expected_stdout': qualification.marker(index).decode()})
    ctx = SimpleNamespace(root=tmp_path, portable=portable_release,
        publication=SimpleNamespace(file_digest=lambda path: qualification.digest(path.read_bytes())))
    qualification.runtime_archive(ctx, images)
    with tarfile.open(tmp_path / 'runtime-images.tar') as archive:
        manifests = json.load(archive.extractfile('manifest.json'))
        native = json.load(archive.extractfile('index.json'))['manifests']
        assert len(native) == 123
        for index, descriptor in enumerate(native):
            assert descriptor['digest'] == images[index]['digest']
            assert descriptor['annotations']['io.containerd.image.name'] == (
                f'docker.io/library/cats-inventory-qualification:image-{index:03d}')
            contents = archive.extractfile('blobs/sha256/' + descriptor['digest'][7:]).read()
            assert qualification.digest(contents) == descriptor['digest']
            root = json.loads(contents)
            assert root['config']['digest'] == images[index]['config']['digest']
            for blob in [root['config'], *root['layers']]:
                contents = archive.extractfile('blobs/sha256/' + blob['digest'][7:]).read()
                assert qualification.digest(contents) == blob['digest']
                assert len(contents) == blob['size']
        assert len(manifests) == 123
        assert len({entry['Layers'][0] for entry in manifests}) == 1
        for index, entry in enumerate(manifests):
            cfg = json.load(archive.extractfile(entry['Config']))
            assert entry['RepoTags'] == [f'cats-inventory-qualification:image-{index:03d}']
            actual = [qualification.digest(archive.extractfile(name).read()) for name in entry['Layers']]
            assert cfg['rootfs']['diff_ids'] == actual
    report = json.loads((tmp_path / 'runtime-images.json').read_text())
    assert report['archive_digest'] == qualification.digest((tmp_path / 'runtime-images.tar').read_bytes())


def test_runtime_identity_requires_exact_published_config_or_manifest():
    image = {'oci_digest': 'sha256:' + 'a' * 64, 'config_digest': 'sha256:' + 'b' * 64}
    assert qualification.runtime_identity(image['oci_digest'], image) == 'oci-manifest'
    assert qualification.runtime_identity(image['config_digest'], image) == 'image-config'
    with pytest.raises(AssertionError, match='Loaded Docker identity sha256:c'):
        qualification.runtime_identity('sha256:' + 'c' * 64, image)


@pytest.mark.parametrize('identity_field', ['oci_digest', 'config_digest'])
def test_runtime_executes_verified_identity_when_tag_is_reassigned(monkeypatch, identity_field):
    image = {'index': 0, 'tag': 'cats-inventory-qualification:image-000',
        'oci_digest': 'sha256:' + 'a' * 64, 'config_digest': 'sha256:' + 'b' * 64,
        'expected_stdout': qualification.marker(0).decode()}
    verified = image[identity_field]
    tag_binding = {image['tag']: verified}
    commands = []
    def fake_docker(command, **kwargs):
        commands.append(command)
        if command[:3] == ['docker', 'image', 'inspect']:
            inspected = tag_binding[command[-1]]
            # Simulate a concurrent load replacing the mutable tag immediately
            # after inspect. The replacement can print the same marker.
            tag_binding[image['tag']] = 'sha256:' + 'c' * 64
            return SimpleNamespace(stdout=inspected + '\n')
        resolved = tag_binding.get(command[-1], command[-1])
        assert resolved == verified, 'Execution must not resolve the reassigned tag'
        return SimpleNamespace(returncode=0, stdout=qualification.marker(0), stderr=b'')
    monkeypatch.setattr(qualification.subprocess, 'run', fake_docker)
    result = qualification.execute_runtime_image(image)
    assert result['passed'] and result['execution_image'] == verified
    assert commands[-1][:2] == ['docker', 'run'] and commands[-1][-1] == verified


def test_production_capture_keeps_identity_and_both_synthesized_histories(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    images = [{'index': index, 'reference': f'harbor.test/qualification/corpus@sha256:{index:064x}',
        'digest': 'sha256:' + f'{index:064x}'} for index in range(123)]
    ctx = SimpleNamespace(root=tmp_path, portable=portable_release)
    args = SimpleNamespace(service_key='bounded-capture-qualification')
    states = []
    for sequence in (1, 2):
        folder = tmp_path / str(sequence)
        folder.mkdir()
        path, *_ = qualification.capture(ctx, args, images, sequence, folder)
        with ZipFile(path) as archive:
            states.append(json.loads(archive.read('replica-service.json')))
            assert archive.read('QUALIFICATION-EVIDENCE.txt').decode() == qualification.LABEL
    first, successor = states
    assert first['records']['services'][0]['id'] == successor['records']['services'][0]['id']
    assert first['service_key'] == successor['service_key'] == args.service_key
    rows = successor['records']['service_images']
    assert len(rows) == 123
    assert sum(row['lifecycle_status'] == 'active' for row in rows) == 100
    assert sum(row['lifecycle_status'] == 'replaced' for row in rows) == 23
    assert sum(row['replacement_of_id'] is not None for row in rows) == 23
    assert len(successor['records']['executions']) == len(successor['records']['service_versions']) == 2
    assert successor['records']['executions'][0] == first['records']['executions'][0]
    assert len(first['activity']) == 1 and len(successor['activity']) == 2
    assert successor['extension']['approval_context']['qualification_evidence'] == qualification.LABEL
    assert all(row['raw_payload']['qualification_evidence'] == qualification.LABEL
               for row in successor['records']['executions'])
    # Simulate interruption after source commit but before frozen approval was
    # persisted. Retry must reuse the exact first archive, even after release2.
    original = (tmp_path / '1' / 'evidence.zip').read_bytes()
    qualification.capture(ctx, args, images, 1, tmp_path / '1')
    assert (tmp_path / '1' / 'evidence.zip').read_bytes() == original
    (tmp_path / '1' / 'evidence.zip').write_bytes(original + b'changed')
    with pytest.raises(AssertionError, match='checkpoint differs'):
        qualification.capture(ctx, args, images, 1, tmp_path / '1')


def test_workspace_plan_prevents_cross_source_or_namespace_retry(tmp_path):
    args = SimpleNamespace(source='https://source.test', target='https://target.test',
        namespace='qualification/run1', service_key='inventory', base_image='source.test/base@sha256:' + 'a' * 64)
    original = qualification.bind_workspace(tmp_path, args)
    assert qualification.bind_workspace(tmp_path, args) == original
    for field, value in [('source', 'https://other.test'), ('namespace', 'qualification/run2'),
                         ('service_key', 'another'), ('base_image', 'source.test/base@sha256:' + 'b' * 64)]:
        with pytest.raises(AssertionError, match='different publication plan'):
            qualification.bind_workspace(tmp_path, SimpleNamespace(**{**vars(args), field: value}))


def test_unbound_partial_workspace_is_rejected(tmp_path):
    (tmp_path / 'images.json').write_text('[]')
    args = SimpleNamespace(source='https://source.test', target='https://target.test',
        namespace='qualification/run1', service_key='inventory', base_image='source.test/base@sha256:' + 'a' * 64)
    with pytest.raises(AssertionError, match='Unbound partial'):
        qualification.bind_workspace(tmp_path, args)


def test_failed_checkpoint_replacement_preserves_previous_bytes(tmp_path, monkeypatch):
    path = tmp_path / 'checkpoint.json'
    qualification.write_json(path, {'committed': 1})
    original = path.read_bytes()
    def fail_replace(*args):
        raise OSError('simulated interruption before atomic replacement')
    monkeypatch.setattr(qualification.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='simulated interruption'):
        qualification.write_json(path, {'committed': 2})
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_runtime_sidecar_must_match_published_identity_before_docker_load(tmp_path, monkeypatch):
    archive = tmp_path / 'runtime-images.tar'
    archive.write_bytes(b'not loaded in this rejection check')
    images = [{'index': index, 'digest': 'sha256:' + f'{index:064x}',
        'config': {'digest': 'sha256:' + 'a' * 64}} for index in range(123)]
    qualification.write_json(tmp_path / 'expected.json', {'images': images, 'receipts': {
        'first': {'artifacts': [{'digest': item['digest']} for item in images[:100]]},
        'successor': {'artifacts': [{'digest': item['digest']} for item in images[23:]]}}})
    qualification.write_json(tmp_path / 'runtime-images.json', {
        'archive_digest': qualification.digest(archive.read_bytes()), 'images': [
            {'index': item['index'], 'tag': f"cats-inventory-qualification:image-{item['index']:03d}",
             'oci_digest': item['digest'], 'config_digest': 'sha256:' + 'b' * 64,
             'expected_stdout': qualification.marker(item['index']).decode()} for item in images]})
    monkeypatch.setattr(qualification.subprocess, 'run', lambda *a, **k: pytest.fail('Docker must not be invoked'))
    with pytest.raises(AssertionError, match='sidecar differs'):
        qualification.verify_runtime(tmp_path)
