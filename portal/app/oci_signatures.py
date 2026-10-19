"""Subject-bound transport for legacy cosign signature tags.

These checks prove association and byte integrity, never signer authenticity.
Consumers must verify signatures with their configured trust roots separately.
"""
from dataclasses import dataclass
import hashlib
import json
import re

from .oci_transport import DIGEST, RegistryError

SIGNATURE_TYPE = 'application/vnd.dev.cosign.simplesigning.v1+json'
MANIFEST_TYPES = {'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'}
MAX_PAYLOAD = 1024 * 1024
MAX_LAYERS = 64
CONFIG_TYPES = {'application/vnd.oci.empty.v1+json', 'application/vnd.oci.image.config.v1+json',
                'application/vnd.docker.container.image.v1+json'}


def legacy_subject(reference):
    match = re.fullmatch(r'sha256-([0-9a-f]{64})\.sig', reference or '')
    return 'sha256:' + match.group(1) if match else None


@dataclass(frozen=True)
class VerifiedSignature:
    raw: bytes
    media_type: str
    digest: str
    document: dict
    descriptor: dict
    blob_digests: tuple


class _BoundedCache:
    def __init__(self, cache):
        self.cache = cache

    def get(self, digest):
        path = self.cache.get(digest)
        if path is not None and path.stat().st_size > MAX_PAYLOAD:
            raise RegistryError('Signature payload exceeds size limit', 413)
        return path

    def store(self, digest, stream, max_bytes=None):
        return self.cache.store(digest, stream, min(max_bytes or MAX_PAYLOAD, MAX_PAYLOAD))


def _descriptor(item):
    if (not isinstance(item, dict) or not DIGEST.fullmatch(str(item.get('digest', '')))
            or type(item.get('size')) is not int or item['size'] < 0 or item.get('urls')
            or item['size'] > MAX_PAYLOAD):
        raise RegistryError('Invalid legacy signature descriptor')
    return item['digest']


def _payload(transport, repository, item, bounded):
    digest = _descriptor(item)
    path = transport.fetch_blob(repository, digest, bounded)
    try:
        with path.open('rb') as stream:
            payload = stream.read(MAX_PAYLOAD + 1)
    except OSError:
        raise RegistryError('Signature payload unavailable; retry request', 429) from None
    if (len(payload) != item['size'] or len(payload) > MAX_PAYLOAD
            or 'sha256:' + hashlib.sha256(payload).hexdigest() != digest):
        raise RegistryError('Signature payload integrity failure')
    return payload


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _config(transport, repository, item, layers, bounded):
    """Only inert empty/config metadata may accompany subject-bound signatures."""
    if item.get('mediaType') not in CONFIG_TYPES:
        raise RegistryError('Unsupported signature configuration type')
    payload = _payload(transport, repository, item, bounded)
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise ValueError()
        if value:
            if item['mediaType'] == 'application/vnd.oci.empty.v1+json':
                raise ValueError()
            if set(value) - {'architecture', 'os', 'config', 'rootfs'}:
                raise ValueError()
            if value.get('architecture', '') not in ('', 'unknown') or value.get('os', '') not in ('', 'unknown'):
                raise ValueError()
            if value.get('config', {}) != {}:
                raise ValueError()
            rootfs = value.get('rootfs')
            if rootfs != {'type': 'layers', 'diff_ids': [layer['digest'] for layer in layers]}:
                raise ValueError()
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise RegistryError('Signature configuration is not supported inert metadata') from None


def verify_legacy_signature(raw, media_type, digest, transport, repository, subject, cache):
    """Validate legacy signature manifest and every layer before exposing any link."""
    if not DIGEST.fullmatch(subject or ''):
        raise RegistryError('Invalid signature subject', 400)
    if digest != 'sha256:' + hashlib.sha256(raw).hexdigest():
        raise RegistryError('Legacy signature manifest digest mismatch')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RegistryError('Invalid legacy signature manifest') from None
    if (not isinstance(document, dict) or document.get('schemaVersion') != 2
            or document.get('mediaType', media_type) not in MANIFEST_TYPES
            or media_type not in MANIFEST_TYPES or 'manifests' in document):
        raise RegistryError('Invalid legacy signature manifest')
    if 'subject' in document and _descriptor(document['subject']) != subject:
        raise RegistryError('Signature manifest subject mismatch')
    layers = document.get('layers')
    if not isinstance(layers, list) or not 1 <= len(layers) <= MAX_LAYERS:
        raise RegistryError('Invalid legacy signature layer count')
    for item in layers:
        _descriptor(item)
        if item.get('mediaType') != SIGNATURE_TYPE:
            raise RegistryError('Legacy signature contains a non-signature layer')
    config_digest = _descriptor(document.get('config'))
    blobs = [config_digest]
    bounded = _BoundedCache(cache)
    _config(transport, repository, document['config'], layers, bounded)
    for item in layers:
        layer_digest = _descriptor(item)
        if item.get('mediaType') != SIGNATURE_TYPE:
            raise RegistryError('Legacy signature contains a non-signature layer')
        payload = _payload(transport, repository, item, bounded)
        try:
            content = json.loads(payload)
            critical = content['critical']
            if (critical['image']['docker-manifest-digest'] != subject
                    or critical.get('type') != 'cosign container image signature'):
                raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError):
            raise RegistryError('Signature payload does not bind the authorized subject') from None
        blobs.append(layer_digest)
    descriptor = {'mediaType': media_type, 'digest': digest, 'size': len(raw), 'artifactType': SIGNATURE_TYPE}
    return VerifiedSignature(raw, media_type, digest, document, descriptor, tuple(blobs))


def discover_legacy_signature(transport, repository, subject, cache):
    if not DIGEST.fullmatch(subject or ''):
        raise RegistryError('Invalid signature subject', 400)
    tag = subject.replace(':', '-', 1) + '.sig'
    try:
        raw, media_type, digest = transport.fetch_manifest(repository, tag)
    except RegistryError as exc:
        if exc.status == 404:
            return None
        raise
    return verify_legacy_signature(raw, media_type, digest, transport, repository, subject, cache)
