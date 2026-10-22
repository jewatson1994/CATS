import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from app.oci_signatures import discover_legacy_signature, legacy_subject, verify_legacy_signature, SIGNATURE_TYPE
from app.oci_transport import ContentCache, RegistryError


def digest(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()

def fixture(subject, bound_subject=None):
    payload = json.dumps({'critical': {'image': {'docker-manifest-digest': bound_subject or subject}, 'type': 'cosign container image signature'}}).encode()
    media = 'application/vnd.oci.image.manifest.v1+json'
    document = {'schemaVersion': 2, 'mediaType': media,
        'config': {'digest': digest(b'{}'), 'size': 2, 'mediaType': 'application/vnd.oci.image.config.v1+json'},
        'layers': [{'digest': digest(payload), 'size': len(payload), 'mediaType': SIGNATURE_TYPE}]}
    raw = json.dumps(document).encode()
    return raw, media, digest(raw), payload

class LegacySignatureTests(unittest.TestCase):
    def test_tag_parser(self):
        d = digest(b'image')
        self.assertEqual(legacy_subject(d.replace(':', '-') + '.sig'), d)
        for tag in ('latest', d, 'sha256-' + 'a'*64 + '.att', 'sha256-' + 'A'*64 + '.sig'):
            self.assertIsNone(legacy_subject(tag))

    def transport(self, root, subject, bound=None):
        raw, media, manifest_digest, payload = fixture(subject, bound)
        transport = Mock()
        transport.fetch_manifest.return_value = raw, media, manifest_digest
        transport.fetch_blob.side_effect = lambda repository, layer_digest, cache: cache.store(layer_digest, io.BytesIO(b'{}' if layer_digest == digest(b'{}') else payload))
        return transport, ContentCache(root), (raw, media, manifest_digest)

    def test_discovery_preserves_bytes_and_subject(self):
        subject = digest(b'image')
        with tempfile.TemporaryDirectory() as root:
            transport, cache, manifest = self.transport(root, subject)
            verified = discover_legacy_signature(transport, 'project/image', subject, cache)
            self.assertEqual((verified.raw, verified.media_type, verified.digest), manifest)
            self.assertEqual(verified.descriptor['artifactType'], SIGNATURE_TYPE)
            self.assertEqual(len(verified.blob_digests), 2)
            transport.fetch_manifest.assert_called_once_with('project/image', subject.replace(':', '-') + '.sig')

    def test_misbound_signature_denied(self):
        subject = digest(b'image')
        with tempfile.TemporaryDirectory() as root:
            transport, cache, _ = self.transport(root, subject, digest(b'other'))
            with self.assertRaisesRegex(RegistryError, 'authorized subject'):
                discover_legacy_signature(transport, 'project/image', subject, cache)

    def test_only_not_found_is_optional(self):
        transport = Mock()
        transport.fetch_manifest.side_effect = RegistryError('missing', 404)
        self.assertIsNone(discover_legacy_signature(transport, 'a', digest(b'image'), None))
        transport.fetch_manifest.side_effect = RegistryError('denied', 401)
        with self.assertRaises(RegistryError): discover_legacy_signature(transport, 'a', digest(b'image'), None)

    def test_no_unrelated_layers(self):
        subject = digest(b'image')
        with tempfile.TemporaryDirectory() as root:
            transport, cache, manifest = self.transport(root, subject)
            doc = json.loads(manifest[0]); doc['layers'][0]['mediaType'] = 'application/octet-stream'
            raw = json.dumps(doc).encode()
            with self.assertRaisesRegex(RegistryError, 'non-signature'):
                verify_legacy_signature(raw, manifest[1], digest(raw), transport, 'a', subject, cache)
            transport.fetch_blob.assert_not_called()

    def test_oversized_descriptor_denied_before_download(self):
        subject = digest(b'image')
        with tempfile.TemporaryDirectory() as root:
            transport, cache, manifest = self.transport(root, subject)
            doc = json.loads(manifest[0]); doc['layers'][0]['size'] = 1024*1024+1
            raw = json.dumps(doc).encode()
            with self.assertRaises(RegistryError): verify_legacy_signature(raw, manifest[1], digest(raw), transport, 'a', subject, cache)
            transport.fetch_blob.assert_not_called()

if __name__ == '__main__': unittest.main()
