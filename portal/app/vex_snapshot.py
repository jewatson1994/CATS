"""Offline snapshots authenticated with an independently configured Ed25519 key."""
import base64
import hashlib
import json
from sqlalchemy import select
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .vex_models import VexSource, VexDocument
from .vex_intelligence import _json, _parse, ingest_document, _VERIFIED, MAX_BYTES


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def export_snapshot(db, source_id, private_key):
    source = db.get(VexSource, source_id)
    if source is None:
        raise ValueError('Unknown source')
    key = serialization.load_pem_private_key(private_key, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Ed25519 signing key required')
    documents = [{'sha256': d.sha256, 'raw': base64.b64encode(d.raw_text.encode('utf-8')).decode('ascii')}
                 for d in db.scalars(select(VexDocument).where(VexDocument.source_id == source_id).order_by(VexDocument.id))]
    manifest = {'schema': 'cats-vex-snapshot/v1', 'source': source.name, 'allowed_hosts': sorted(source.allowed_hosts), 'authoritative_prefixes': sorted(source.authoritative_prefixes), 'documents': documents}
    payload = _canonical({'manifest': manifest, 'signature': base64.b64encode(key.sign(_canonical(manifest))).decode('ascii')})
    if len(payload) > MAX_BYTES:
        raise ValueError('Snapshot exceeds byte limit; split source repository')
    return payload


def import_snapshot(db, source_id, payload):
    source = db.get(VexSource, source_id)
    if source is None or not source.enabled or not source.public_key:
        raise ValueError('Configure an independently trusted pinned key before import')
    envelope = _json(payload)
    manifest = envelope.get('manifest')
    if not isinstance(manifest, dict) or not isinstance(envelope.get('signature'), str):
        raise ValueError('Snapshot requires a manifest object and signature string')
    if manifest.get('schema') != 'cats-vex-snapshot/v1' or manifest.get('source') != source.name or manifest.get('allowed_hosts') != sorted(source.allowed_hosts) or manifest.get('authoritative_prefixes') != sorted(source.authoritative_prefixes):
        raise ValueError('Snapshot source scope mismatch')
    try:
        key = serialization.load_pem_public_key(source.public_key.encode('ascii'))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError('Valid pinned Ed25519 verification key required') from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Ed25519 verification key required')
    try:
        key.verify(base64.b64decode(envelope['signature'], validate=True), _canonical(manifest))
    except Exception as exc:
        raise ValueError('Snapshot signature verification failed') from exc
    documents = manifest.get('documents')
    if not isinstance(documents, list) or len(documents) > 1000:
        raise ValueError('Invalid snapshot document count')
    validated = []
    for entry in documents:
        if not isinstance(entry, dict) or not isinstance(entry.get('raw'), str) or not isinstance(entry.get('sha256'), str):
            raise ValueError('Invalid snapshot document entry')
        raw = base64.b64decode(entry['raw'], validate=True)
        if hashlib.sha256(raw).hexdigest() != entry['sha256']:
            raise ValueError('Snapshot document hash mismatch')
        try:
            _parse(raw)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError('Invalid snapshot VEX document') from exc
        validated.append(raw)
    # Prevalidate everything and keep writes atomic, including when caller catches errors.
    with db.begin_nested():
        ids = [ingest_document(db, source_id, raw, verification='signature', _proof=_VERIFIED).id for raw in validated]
    return {'status': 'imported', 'document_ids': ids, 'count': len(ids)}
