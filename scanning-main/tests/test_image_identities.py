import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('image_identities', Path(__file__).parents[1] / 'scripts' / 'extract-image-identities.py')
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


def native():
    config = json.dumps({'os': 'linux', 'architecture': 'arm64', 'variant': 'v8'}).encode()
    digest_config = identity._digest(config)
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': {'digest': digest_config, 'size': len(config)}}).encode()
    digest = identity._digest(manifest)
    return {'source': {'type': 'image', 'metadata': {'manifest': base64.b64encode(manifest).decode(),
        'config': base64.b64encode(config).decode(), 'manifestDigest': digest,
        'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'imageID': digest_config,
        'os': 'linux', 'architecture': 'arm64', 'repoDigests': ['example/image@sha256:' + 'f' * 64]}}}, digest


def test_native_bytes_bind_actual_manifest_config_platform():
    document, digest = native()
    image = 'example/image@' + digest
    assert identity.image_identity(image, document) == {'image': image, 'digest': digest,
        'platform': 'linux/arm64/v8', 'media_type': 'application/vnd.oci.image.manifest.v1+json'}
    assert identity.image_identity('example/image@sha256:' + 'f' * 64, document) is None


@pytest.mark.parametrize('field,value', [('manifestDigest', 'sha256:'+'0'*64),
    ('mediaType', 'application/vnd.oci.image.index.v1+json'), ('architecture', 'amd64'),
    ('imageID', 'sha256:'+'0'*64), ('manifest', 'invalid'), ('config', 'invalid')])
def test_inconsistent_native_evidence_is_rejected(field, value):
    document, digest = native()
    document['source']['metadata'][field] = value
    assert identity.image_identity('example/image@' + digest, document) is None


def test_absent_metadata_does_not_invent_identity():
    assert identity.image_identity('example/image:tag', {'source': {'type': 'directory'}}) is None


def test_docker_descriptor_requires_manifest_and_repository_digest():
    provenance = {'imageID': 'sha256:'+'a'*64, 'os': 'linux', 'architecture': 'amd64',
                  'repoDigests': ['example/image@sha256:'+'b'*64],
                  'descriptor': {'digest': 'sha256:'+'b'*64, 'mediaType': 'application/vnd.oci.image.manifest.v1+json'}}
    source = {'source': {'type': 'directory'}}
    assert identity.image_identity('example/image:tag', source, provenance)['platform'] == 'linux/amd64'
    provenance['descriptor']['mediaType'] = 'application/vnd.oci.image.index.v1+json'
    assert identity.image_identity('example/image:tag', source, provenance) is None
    provenance.pop('descriptor')
    assert identity.image_identity('example/image:tag', source, provenance) is None


def test_merge_preserves_architecture_and_replaces_declared_identity(tmp_path):
    document, digest = native()
    (tmp_path/'image.image').write_text('example/image@'+digest)
    (tmp_path/'image.json').write_text(json.dumps(document))
    overview = {'workloads': [{'name': 'api'}], 'containers': [{'name': 'api'}],
                'images': [{'image': 'declared', 'digest': 'unverified'}]}
    merged = identity.merge_overview(tmp_path, overview)
    assert merged['workloads'] == overview['workloads'] and merged['containers'] == overview['containers']
    assert merged['declared_images'] == overview['images']
    assert merged['images'][0]['digest'] == digest
    assert overview['images'][0]['image'] == 'declared'


def test_duplicate_mappings_do_not_pass(tmp_path):
    document, digest = native()
    for name in ('first', 'second'):
        (tmp_path/(name+'.image')).write_text('example/image@'+digest)
        (tmp_path/(name+'.json')).write_text(json.dumps(document))
    assert identity.merge_overview(tmp_path, {})['images'] == []


def test_native_config_supplies_platform_when_syft_summary_is_empty(tmp_path):
    document, digest = native()
    document['source']['metadata'].update(os='', architecture='')
    (tmp_path/'image.image').write_text('example/image@'+digest)
    (tmp_path/'image.json').write_text(json.dumps(document))
    # No findings are required: the authenticated config bytes identify the scan.
    merged = identity.merge_overview(tmp_path, {'images': []})
    assert merged['images'] == [{'image': 'example/image@'+digest, 'digest': digest,
        'platform': 'linux/arm64/v8', 'media_type': 'application/vnd.oci.image.manifest.v1+json'}]
    document['source']['metadata']['architecture'] = 'amd64'
    assert identity.image_identity('example/image@'+digest, document) is None
