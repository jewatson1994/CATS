import gzip
import hashlib
import io
import json
import tarfile

import pytest

from app.deployment_bundle import build_helm_archive, file_digest, image_archive_identity
from app.deployment_validation import ValidationConfig
from app.managed_validator_release import SCHEMA, load_release


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def image_archive(path, reference, *, containerd=False, corrupt=False):
    layer = b'verified layer contents'
    stored = gzip.compress(layer, mtime=0) if containerd else layer
    config = json.dumps({'rootfs': {'diff_ids': [digest(layer)]}}).encode()
    config_id = digest(config)
    config_path = 'blobs/sha256/' + config_id[7:]
    layer_path = 'blobs/sha256/' + digest(stored)[7:]
    contents = {config_path: config, layer_path: stored,
                'manifest.json': json.dumps([{'Config': config_path, 'RepoTags': [reference], 'Layers': [layer_path]}]).encode()}
    identity = config_id
    if containerd:
        manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': config_id, 'size': len(config)},
                               'layers': [{'digest': digest(stored), 'size': len(stored)}]}).encode()
        identity = digest(manifest)
        contents['blobs/sha256/' + identity[7:]] = manifest
        contents['index.json'] = json.dumps({'manifests': [{'digest': identity, 'size': len(manifest)}]}).encode()
    if corrupt:
        contents[layer_path] = gzip.compress(b'changed layer', mtime=0) if containerd else b'changed layer'
    with tarfile.open(path, 'w') as archive:
        for name, data in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return identity


@pytest.mark.parametrize('containerd', [False, True])
def test_release_verifies_real_image_archives(tmp_path, containerd):
    (tmp_path / 'images').mkdir()
    cats_reference = 'cats:test'
    cats_path = tmp_path / 'images/cats.tar'
    cats_id = image_archive(cats_path, cats_reference, containerd=containerd)
    node_path = tmp_path / 'images/node.tar'
    node_reference = ValidationConfig.kind_node_image
    node_id = image_archive(node_path, node_reference.split("@")[0], containerd=containerd)
    build_helm_archive(tmp_path / 'selftest.zip', {'Chart.yaml': 'apiVersion: v2\nname: selftest\nversion: 1.0.0\n',
        'templates/pod.yaml': 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: selftest\nspec:\n  containers:\n  - name: cats\n    image: cats:test\n'},
        service={'id': 'selftest', 'version': '1.0'})
    manifest = {'schema_version': SCHEMA,
        'cats_image': {'file': 'images/cats.tar', 'sha256': file_digest(cats_path), 'reference': cats_reference, 'image_id': cats_id},
        'node_image': {'file': 'images/node.tar', 'sha256': file_digest(node_path), 'reference': node_reference, 'image_id': node_id},
        'selftest': {'file': 'selftest.zip', 'sha256': file_digest(tmp_path / 'selftest.zip'), 'image_reference': cats_reference}}
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    assert load_release(tmp_path)['cats_image']['image_id'] == cats_id


@pytest.mark.parametrize('containerd', [False, True])
def test_expected_identity_cannot_bypass_archive_integrity(tmp_path, containerd):
    path = tmp_path / 'image.tar'
    identity = image_archive(path, 'cats:test', containerd=containerd)
    assert image_archive_identity(path, 'cats:test', expected_identity=identity) == identity
    with pytest.raises(ValueError, match='identity mismatch'):
        image_archive_identity(path, 'cats:test', expected_identity='sha256:' + '0' * 64)
    image_archive(path, 'cats:test', containerd=containerd, corrupt=True)
    with pytest.raises(ValueError, match='layer integrity mismatch'):
        image_archive_identity(path, 'cats:test', expected_identity=identity)
