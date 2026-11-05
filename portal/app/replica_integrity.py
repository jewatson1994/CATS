"""Authenticate verified local projections independently of mutable registry tags."""
import hashlib
import hmac
import json
from .release_validity import utc
from .secrets import encrypt_secret, decrypt_secret


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def _payload(row):
    return dict(manifest_digest=row.manifest_digest, artifacts=row.artifacts,
                publisher=row.publisher, key_fingerprint=row.key_fingerprint,
                service_id=row.service_id, source_release_id=row.source_release_id,
                sequence=row.sequence, approved_at=utc(row.approved_at).isoformat(),
                expires_at=utc(row.expires_at).isoformat() if row.expires_at else None,
                revoked_at=utc(row.revoked_at).isoformat() if row.revoked_at else None,
                revocation_reason=row.revocation_reason or '',
                evidence_digest=row.evidence_state_digest or '')


def seal_record(row):
    if not row.evidence_state_digest:
        row.evidence_state_digest = digest(row.evidence_state)
    row.integrity_seal = encrypt_secret(canonical(_payload(row)).decode())


def verify_record(row):
    try:
        return (row.verified and row.complete and row.manifest_digest == digest(row.manifest)
                and hmac.compare_digest(decrypt_secret(row.integrity_seal), canonical(_payload(row)).decode()))
    except (ValueError, TypeError, AttributeError):
        return False
