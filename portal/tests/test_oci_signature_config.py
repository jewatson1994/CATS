import hashlib
import json
from types import SimpleNamespace

import pytest
from app.oci_signatures import SIGNATURE_TYPE, verify_legacy_signature
from app.oci_transport import RegistryError

SUBJECT = 'sha256:' + 'a' * 64
MEDIA = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'

def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()

def fixture(tmp_path, config=None, media=CONFIG):
    payload = json.dumps({'critical': {'image': {'docker-manifest-digest': SUBJECT}, 'type': 'cosign container image signature'}}).encode()
    layer = {'digest': digest(payload), 'size': len(payload), 'mediaType': SIGNATURE_TYPE}
    if config == 'image':
        config = {'architecture': '', 'os': '', 'config': {}, 'rootfs': {'type': 'layers', 'diff_ids': [layer['digest']]}}
    config_raw = json.dumps({} if config is None else config).encode()
    document = {'schemaVersion': 2, 'mediaType': MEDIA, 'config': {'mediaType': media, 'digest': digest(config_raw), 'size': len(config_raw)}, 'layers': [layer]}
    blobs = {digest(payload): payload, digest(config_raw): config_raw}
    def fetch(repository, identity, cache):
        path = tmp_path / identity.split(':')[1]
        path.write_bytes(blobs[identity])
        return path
    def verify():
        raw = json.dumps(document).encode()
        return verify_legacy_signature(raw, MEDIA, digest(raw), SimpleNamespace(fetch_blob=fetch), 'repo', SUBJECT, None)
    return document, blobs, verify

@pytest.mark.parametrize('config', [None, 'image'])
def test_accepts_only_verified_inert_signature_config(tmp_path, config):
    document, blobs, verify = fixture(tmp_path, config)
    assert set(verify().blob_digests) == set(blobs)

@pytest.mark.parametrize('config,media', [({'secret': 'arbitrary data'}, CONFIG),
    ({'config': {'Env': ['SECRET=value']}}, CONFIG),
    ({'rootfs': {'type': 'layers', 'diff_ids': [SUBJECT]}}, CONFIG),
    ({}, 'application/octet-stream'),
    ({'architecture': 'amd64'}, CONFIG),
    ({'rootfs': {}}, 'application/vnd.oci.empty.v1+json')])
def test_rejects_arbitrary_config_content(tmp_path, config, media):
    _, _, verify = fixture(tmp_path, config, media)
    with pytest.raises(RegistryError):
        verify()

@pytest.mark.parametrize('mutation', ['bytes', 'size', 'url', 'wrong_subject'])
def test_checks_config_and_payload_integrity_before_returning_links(tmp_path, mutation):
    document, blobs, verify = fixture(tmp_path)
    if mutation == 'bytes':
        blobs[document['config']['digest']] = b'[]'
    elif mutation == 'size':
        document['config']['size'] += 1
    elif mutation == 'url':
        document['config']['urls'] = ['https://elsewhere.example/blob']
    else:
        layer = document['layers'][0]
        raw = blobs.pop(layer['digest']).replace(SUBJECT.encode(), ('sha256:' + 'b' * 64).encode())
        layer['digest'] = digest(raw)
        blobs[layer['digest']] = raw
    with pytest.raises(RegistryError):
        verify()


def test_duplicate_config_keys_cannot_hide_arbitrary_data(tmp_path):
    document, blobs, verify = fixture(tmp_path)
    raw = b'{"config":{"Env":["SECRET=value"]},"config":{},"rootfs":{"type":"layers","diff_ids":[]}}'
    document['config'].update(digest=digest(raw), size=len(raw))
    blobs[digest(raw)] = raw
    with pytest.raises(RegistryError):
        verify()
