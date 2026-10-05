import hashlib
import io
import json
import tarfile
from zipfile import ZipFile, ZipInfo

import pytest
import yaml

from app.deployment_bundle import build_bundle, validate_bundle, dependency_inventory, workload_images, file_digest, build_helm_archive, prepare_helm_archive


def chart():
    return {'helm/app/Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n',
            'helm/app/values.yaml': '{}', 'override.yaml': 'enabled: true'}


def build(tmp_path, **kwargs):
    return build_bundle(tmp_path / 'bundle.zip', bundle_type=kwargs.pop('bundle_type', 'offline-bundle'),
                        service={'id': 'app', 'version': '1.0.0'}, source_files=kwargs.pop('source_files', chart()),
                        chart_path='helm/app', values_files=['override.yaml'], rendered_manifests=kwargs.pop('rendered_manifests', ''), **kwargs)


def docker_archive(path, reference='local/app:fixed'):
    layer = b'layer tar bytes'
    digest = 'sha256:' + hashlib.sha256(layer).hexdigest()
    config = json.dumps({'rootfs': {'diff_ids': [digest]}}).encode()
    contents = {'config.json': config, 'layer.tar': layer,
                'manifest.json': json.dumps([{'Config': 'config.json', 'RepoTags': [reference], 'Layers': ['layer.tar']}]).encode()}
    with tarfile.open(path, 'w') as archive:
        for name, data in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return 'sha256:' + hashlib.sha256(config).hexdigest()


def test_deterministic_final_bundle_and_ordered_values(tmp_path):
    manifest = build(tmp_path, evidence={'status': 'not_run'})
    assert manifest['evidence'] == {'path': 'evidence.json'}
    extracted = tmp_path / 'extracted'
    assert validate_bundle(tmp_path / 'bundle.zip', destination=extracted, expected_digest=file_digest(tmp_path / 'bundle.zip')) == manifest
    assert manifest['deployment']['valuesFiles'] == ['override.yaml']
    other = tmp_path / 'other'
    other.mkdir()
    build(other, evidence={'status': 'not_run'})
    assert file_digest(other / 'bundle.zip') == file_digest(tmp_path / 'bundle.zip')


def test_offline_image_closure_and_actual_archive_identity(tmp_path):
    image = tmp_path / 'image.tar'
    identity = docker_archive(image)
    rendered = 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    image: local/app:fixed\n'
    with pytest.raises(ValueError, match='completely reconciled'):
        build(tmp_path, rendered_manifests=rendered)
    manifest = build(tmp_path, rendered_manifests=rendered, image_archives=[{'reference': 'local/app:fixed', 'source_path': image, 'archive_path': 'images/app.tar'}])
    assert manifest['images'][0]['digest'] == identity
    assert manifest['images'][0]['identityType'] == 'docker_config'


def test_standard_does_not_claim_image_containment(tmp_path):
    manifest = build(tmp_path, bundle_type='standard-bundle', rendered_manifests='kind: Pod\nspec:\n  initContainers:\n  - image: busybox:1\n')
    assert manifest['requiredImages'] == ['busybox:1']
    assert manifest['images'] == []


def test_recursive_vendored_dependency_and_lock(tmp_path):
    root = tmp_path / 'parent'
    child = root / 'charts' / 'child'
    child.mkdir(parents=True)
    (root / 'Chart.yaml').write_text(yaml.safe_dump({'name': 'parent', 'version': '1.0.0', 'dependencies': [{'name': 'child', 'version': '2.0.0', 'repository': 'oci://internal/charts'}]}))
    (root / 'Chart.lock').write_text(yaml.safe_dump({'digest': 'sha256:' + 'a' * 64, 'dependencies': [{'name': 'child', 'version': '2.0.0', 'repository': 'oci://internal/charts'}]}))
    (child / 'Chart.yaml').write_text('name: child\nversion: 2.0.0\n')
    result = dependency_inventory(root)
    assert result[0]['repository'] == 'oci://internal/charts'
    assert result[0]['lockDigest'] == 'sha256:' + 'a' * 64
    (child / 'Chart.yaml').write_text('name: child\nversion: 2.1.0\n')
    with pytest.raises(ValueError, match='vendored'):
        dependency_inventory(root)


@pytest.mark.parametrize('name', ['../escape', '/escape', 'a\\escape', 'C:escape', 'a//escape', 'CON/file'])
def test_unsafe_archive_paths_rejected(tmp_path, name):
    path = tmp_path / 'evil.zip'
    with ZipFile(path, 'w') as archive:
        entry = ZipInfo(name)
        entry.filename = name
        archive.writestr(entry, 'x')
    with pytest.raises(ValueError, match='Unsafe'):
        validate_bundle(path)


def test_hash_tampering_and_type_mismatch(tmp_path):
    build(tmp_path)
    with pytest.raises(ValueError, match='type mismatch'):
        validate_bundle(tmp_path / 'bundle.zip', expected_type='standard-bundle')
    with ZipFile(tmp_path / 'bundle.zip') as source, ZipFile(tmp_path / 'tampered.zip', 'w') as target:
        for entry in source.infolist():
            target.writestr(entry, b'tampered' if entry.filename == 'override.yaml' else source.read(entry))
    with pytest.raises(ValueError, match='integrity'):
        validate_bundle(tmp_path / 'tampered.zip')


def test_workload_discovery_includes_cronjobs_hooks_and_ephemeral():
    assert workload_images([{'kind': 'CronJob', 'spec': {'jobTemplate': {'spec': {'template': {'spec': {'containers': [{'image': 'cron:1'}]}}}}}},
                            {'kind': 'Pod', 'spec': {'initContainers': [{'image': 'init:1'}], 'ephemeralContainers': [{'image': 'debug:1'}]}},
                            {'kind': 'ConfigMap', 'data': {'image': 'not-container'}}]) == ['cron:1', 'debug:1', 'init:1']


def test_packaged_transitive_dependency_checked(tmp_path):
    root = tmp_path / 'parent'
    charts = root / 'charts'
    charts.mkdir(parents=True)
    (root / 'Chart.yaml').write_text('name: parent\nversion: 1.0.0\ndependencies:\n- name: child\n  version: 2.0.0\n')
    contents = {'child/Chart.yaml': b'name: child\nversion: 2.0.0\ndependencies:\n- name: grandchild\n  version: 3.0.0\n',
                'child/charts/grandchild/Chart.yaml': b'name: grandchild\nversion: 3.0.0\n'}
    with tarfile.open(charts / 'child-2.0.0.tgz', 'w:gz') as archive:
        for name, data in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    inventory = dependency_inventory(root)
    assert [d['name'] for d in inventory] == ['child', 'grandchild']
    assert inventory[1]['file'] == 'charts/child-2.0.0.tgz/charts/grandchild'


def test_raw_helm_transport_and_existing_output_preserved(tmp_path):
    sources = {'Chart.yaml': 'apiVersion: v2\nname: app\nversion: 1.0.0\n', 'first.yaml': 'x: 1', 'second.yaml': 'x: 2'}
    output = tmp_path / 'helm.zip'
    build_helm_archive(output, sources, ['second.yaml', 'first.yaml'], service={'id': 'app', 'version': '1.0.0'})
    prepared = prepare_helm_archive(output, tmp_path / 'extracted', file_digest(output))
    assert prepared['manifest']['validationType'] == 'helm-chart'
    assert [p.rsplit('\\', 1)[-1] for p in prepared['values_files']] == ['second.yaml', 'first.yaml']
    digest = file_digest(output)
    with pytest.raises(ValueError, match='already exists'):
        build_helm_archive(output, sources)
    assert file_digest(output) == digest
