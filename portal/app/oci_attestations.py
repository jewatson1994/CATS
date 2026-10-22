"""Typed OCI attestations through the existing Cosign key and command boundary.

Offline verification disables transparency-log access; OCI registry access is still
required. Evidence values are SHA-256 digests of retained, independently checked
bytes, never claims that this module itself ran a scanner or deployment.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from . import signing

PREDICATE_TYPES = {purpose: f"https://cats.security/attestations/{purpose}/v1" for purpose in (
    "scan", "patch", "deployment-validation", "cyber-approval", "release")}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REFERENCE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_MAX = 1024 * 1024


class AttestationError(RuntimeError):
    pass


def _predicate(reference, purpose, evidence):
    if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference) or reference.startswith('-'):
        raise AttestationError("Attestations require an immutable OCI reference")
    if purpose not in PREDICATE_TYPES:
        raise AttestationError("Unsupported attestation purpose")
    if (not isinstance(evidence, dict) or not evidence or len(evidence) > 64
            or any(not isinstance(k, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', k)
                   or not isinstance(v, str) or not _DIGEST.fullmatch(v) for k, v in evidence.items())):
        raise AttestationError("Attestations require named SHA-256 evidence digests")
    return {"schemaVersion": 1, "subject": reference, "purpose": purpose, "evidence": dict(evidence)}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _verified_statement(output, reference, purpose, predicate):
    if not isinstance(output, str) or len(output.encode()) > _MAX:
        raise ValueError("Invalid verification output")
    # Cosign 2.x emits one verified DSSE envelope per line.
    envelopes = [json.loads(line, object_pairs_hook=_unique) for line in output.splitlines() if line.strip()]
    if not envelopes:
        raise ValueError("No verified attestations")
    digest = reference.rsplit('@', 1)[1].split(':', 1)[1]
    for envelope in envelopes:
        if not isinstance(envelope, dict) or envelope.get('payloadType') != 'application/vnd.in-toto+json':
            continue
        raw = base64.b64decode(envelope['payload'], validate=True)
        statement = json.loads(raw, object_pairs_hook=_unique)
        if (statement.get('_type') not in ('https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1')
                or statement.get('predicateType') != PREDICATE_TYPES[purpose]
                or statement.get('predicate') != predicate):
            continue
        subjects = statement.get('subject')
        if (isinstance(subjects, list) and len(subjects) == 1 and isinstance(subjects[0], dict)
                and subjects[0].get('digest') == {'sha256': digest}):
            return
    raise ValueError("No attestation binds expected subject, purpose and evidence")


def verify_attestation(reference: str, purpose: str, evidence: dict, public_key: bytes,
                       expected_fingerprint: str, env: dict | None = None) -> dict:
    """Verify registry attestations against an independently configured trust root.

    A key distributed with the artifact is not an independently configured root.
    Missing trust, evidence, signature, or binding is always a hard failure.
    """
    predicate = _predicate(reference, purpose, evidence)
    try:
        pem, fingerprint = signing.public_key(public_key)
        if not expected_fingerprint or fingerprint != expected_fingerprint:
            raise ValueError("Untrusted signer")
        cosign = shutil.which('cosign')
        if not cosign:
            raise ValueError("Cosign unavailable")
        with tempfile.TemporaryDirectory(prefix='cats-attestation-verify-') as folder:
            public = Path(folder) / 'public.pem'
            public.write_text(pem, encoding='utf-8')
            result = signing._command([cosign, 'verify-attestation', '--key', str(public),
                '--type', PREDICATE_TYPES[purpose], '--insecure-ignore-tlog=true', '--offline', reference],
                signing.clean_environment(dict(os.environ) if env is None else env))
            _verified_statement(result.stdout, reference, purpose, predicate)
        return {'status': 'verified', 'subject': reference, 'purpose': purpose,
                'predicate_type': PREDICATE_TYPES[purpose], 'evidence': dict(evidence),
                'key_fingerprint': fingerprint, 'generator': 'cosign', 'transparency_log': False}
    except Exception:
        raise AttestationError('Attestation verification failed') from None


def attest_and_verify(reference: str, purpose: str, evidence: dict,
                      signing_material: tuple[dict, dict], env: dict | None = None) -> dict:
    """Publish a native Cosign attestation and read it back through pinned verification."""
    predicate = _predicate(reference, purpose, evidence)
    config, credentials = signing_material
    try:
        if config.get('signing_enabled') is not True:
            raise ValueError('Signing required')
        pem, fingerprint = signing.public_key(config['signing_public_key'].encode())
        if fingerprint != config['signing_fingerprint']:
            raise ValueError('Fingerprint mismatch')
        cosign = shutil.which('cosign')
        if not cosign:
            raise ValueError('Cosign unavailable')
        private = base64.b64decode(credentials[signing.SECRET_ENV[0]], validate=True)
        if not private or len(private) > signing.MAX_KEY_BYTES:
            raise ValueError('Invalid key')
        clean = signing.clean_environment(dict(os.environ) if env is None else env)
        with tempfile.TemporaryDirectory(prefix='cats-attestation-sign-') as folder:
            key, document = Path(folder) / 'cosign.key', Path(folder) / 'predicate.json'
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(private)
            document.write_text(json.dumps(predicate, sort_keys=True, separators=(',', ':')), encoding='utf-8')
            signing_env = dict(clean, COSIGN_PASSWORD=credentials.get(signing.SECRET_ENV[1], ''))
            signing._command([cosign, 'attest', '--yes', '--key', str(key), '--tlog-upload=false',
                              '--type', PREDICATE_TYPES[purpose], '--predicate', str(document), reference], signing_env)
        return verify_attestation(reference, purpose, evidence, pem.encode(), fingerprint, clean)
    except Exception:
        raise AttestationError('Attestation publication or verification failed') from None


def attest_patch_evidence(reference: str, before_path: Path, after_path: Path,
                          archive_path: Path, signing_material: tuple[dict, dict],
                          env: dict | None = None) -> list[dict]:
    """Attest retained technical patch evidence; never grant deployment approval."""
    import hashlib
    def digest(path):
        with Path(path).open('rb') as stream:
            return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
    evidence = {'grype-before.json': digest(before_path), 'grype-after.json': digest(after_path),
                'patched-image.tar': digest(archive_path)}
    receipts = [attest_and_verify(reference, 'scan', {'grype-after.json': evidence['grype-after.json']},
                                 signing_material, env),
                attest_and_verify(reference, 'patch', evidence, signing_material, env)]
    # Ensure retained bytes still match the claims before reporting completion.
    for name, path in [('grype-before.json', before_path), ('grype-after.json', after_path),
                       ('patched-image.tar', archive_path)]:
        if digest(path) != evidence[name]:
            raise AttestationError('Retained patch evidence changed during attestation')
    return receipts
