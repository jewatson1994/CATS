"""Authenticated publisher continuity, with immutable per-service sequence cutovers."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import re
import tempfile
from pathlib import Path

from sqlalchemy import select, text

from . import signing, release_signing
from .replica_integrity import canonical, digest
from .secrets import encrypt_secret, decrypt_secret

FORMAT = 'cats-publisher-key-transition-v1'
MAX_CHAIN = 32
MAX_SERVICES = 10000
MAX_BYTES = 4 * 1024 * 1024
FINGERPRINT = re.compile(r'sha256:[0-9a-f]{64}\Z')
FIELDS = {'format', 'publisher_root', 'generation', 'previous_digest', 'from_fingerprint',
          'to_fingerprint', 'from_public_key', 'to_public_key', 'service_cutovers'}


def lock_configuration(db):
    """Shared transaction lock, acquired before sequence/service locks."""
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': 731126111709})
    elif db.get_bind().dialect.name == 'sqlite':
        connection = db.connection()
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql('BEGIN IMMEDIATE')
    from .models import PortalSetting
    db.scalars(select(PortalSetting).where(PortalSetting.key == signing.SETTING)
               .with_for_update().execution_options(populate_existing=True)).all()


def _verify(content, signature, public):
    if not isinstance(signature, str) or not 1 <= len(signature) <= 16384:
        raise ValueError('Invalid key transition signature')
    with tempfile.TemporaryDirectory(prefix='cats-key-transition-check-') as folder:
        root = Path(folder)
        (root / 'certificate.json').write_bytes(content)
        (root / 'signature').write_text(signature, encoding='utf-8')
        (root / 'public.pem').write_text(public, encoding='utf-8')
        result = release_signing.verify_release_manifest(root / 'certificate.json', root / 'signature', root / 'public.pem')
        if result.get('status') != 'verified':
            raise ValueError('Publisher key transition signature verification failed')


def validate_chain(chain, *, verify=True):
    """Validate canonical, bounded certificates; return root and ordered keys."""
    if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_CHAIN or len(canonical(chain)) > MAX_BYTES:
        raise ValueError('Publisher key transition chain is invalid or exceeds its limit')
    previous, keys, root = None, [], None
    prior_cutovers = {}
    for number, entry in enumerate(chain, 1):
        if not isinstance(entry, dict) or set(entry) != {'certificate', 'from_signature', 'to_signature'}:
            raise ValueError('Malformed publisher key transition')
        certificate = entry['certificate']
        if not isinstance(certificate, dict) or set(certificate) != FIELDS:
            raise ValueError('Malformed publisher key transition certificate')
        if (certificate['format'] != FORMAT or type(certificate['generation']) is not int
                or certificate['generation'] != number or certificate['previous_digest'] != previous):
            raise ValueError('Publisher key transition order or predecessor mismatch')
        for field in ('publisher_root', 'from_fingerprint', 'to_fingerprint'):
            if not isinstance(certificate[field], str) or not FINGERPRINT.fullmatch(certificate[field]):
                raise ValueError('Invalid publisher key fingerprint')
        for prefix in ('from', 'to'):
            pem = certificate[prefix + '_public_key']
            if not isinstance(pem, str) or len(pem) > signing.MAX_KEY_BYTES:
                raise ValueError('Invalid publisher transition public key')
            normalized, fingerprint = signing.public_key(pem.encode())
            if normalized != pem or fingerprint != certificate[prefix + '_fingerprint']:
                raise ValueError('Publisher transition public key does not match its fingerprint')
        if number == 1:
            root = certificate['publisher_root']
            if root != certificate['from_fingerprint']:
                raise ValueError('Publisher transition does not begin at its trust anchor')
            keys.append(root)
        if (certificate['publisher_root'] != root or certificate['from_fingerprint'] != keys[-1]
                or certificate['to_fingerprint'] in keys):
            raise ValueError('Publisher transition identity is discontinuous or reused')
        cutovers = certificate['service_cutovers']
        if (not isinstance(cutovers, dict) or len(cutovers) > MAX_SERVICES
                or any(not isinstance(service, str) or not 1 <= len(service) <= 120
                       or type(sequence) is not int or not 1 <= sequence <= 2147483647
                       for service, sequence in cutovers.items())
                or any(service not in cutovers or cutovers[service] < sequence
                       for service, sequence in prior_cutovers.items())):
            raise ValueError('Invalid or regressing service sequence cutover')
        if verify:
            content = canonical(certificate)
            _verify(content, entry['from_signature'], certificate['from_public_key'])
            _verify(content, entry['to_signature'], certificate['to_public_key'])
        keys.append(certificate['to_fingerprint'])
        previous, prior_cutovers = digest(entry), cutovers
    return root, keys


def _sequence_allowed(chain, signer, service, sequence):
    root, keys = validate_chain(chain, verify=False)
    if signer not in keys:
        return False
    generation = keys.index(signer)
    lower = chain[generation - 1]['certificate']['service_cutovers'].get(service, 1) if generation else 1
    upper = chain[generation]['certificate']['service_cutovers'].get(service, 1) if generation < len(chain) else None
    return sequence >= lower and (upper is None or sequence < upper)


def verify_identity(manifest, public, trusted_fingerprints):
    _, signer = signing.public_key(public)
    chain = manifest.get('signing_key_chain', [])
    if chain:
        root, keys = validate_chain(chain)
        if manifest.get('publisher_root') != root or keys[-1] != signer:
            raise ValueError('Release signer is not the certified current publisher key')
        metadata = manifest.get('portable', {})
        sequence, service = metadata.get('release_sequence'), metadata.get('service_uuid')
        if type(sequence) is not int or not isinstance(service, str) or not _sequence_allowed(chain, signer, service, sequence):
            raise ValueError('Release sequence is outside the certified signing key interval')
    else:
        if chain != [] or manifest.get('publisher_root', signer) != signer:
            raise ValueError('Release publisher identity has no authenticated continuity')
        root, keys = signer, [signer]
    if root not in trusted_fingerprints:
        raise ValueError('Release publisher trust anchor is not independently trusted')
    return {'publisher_root': root, 'key_fingerprint': signer,
            'key_generation': len(keys) - 1, 'key_chain': deepcopy(chain)}


def _sign(certificate, configuration):
    material = signing.job_material({signing.SETTING: json.dumps({**configuration, 'enabled': True})}, 'push')
    with tempfile.TemporaryDirectory(prefix='cats-key-transition-sign-') as folder:
        root = Path(folder)
        source = root / 'certificate.json'
        source.write_bytes(canonical(certificate))
        result = release_signing.sign_release_manifest(source, root, material)
        if result.get('signature_status') != 'verified':
            raise ValueError('Unable to sign and verify publisher key continuity; the configured key was not changed')
        return (root / release_signing.SIGNATURE_FILENAME).read_text(encoding='utf-8')


def _configured_identity(configuration):
    chain = configuration.get('signing_key_chain', [])
    if chain:
        root, keys = validate_chain(chain)
        if configuration.get('publisher_root') != root or keys[-1] != configuration.get('fingerprint'):
            raise ValueError('Configured signing key continuity is inconsistent')
    elif chain != [] or configuration.get('publisher_root', configuration.get('fingerprint')) != configuration.get('fingerprint'):
        raise ValueError('Configured signing key continuity is inconsistent')
    else:
        root, keys = configuration.get('fingerprint'), [configuration.get('fingerprint')]
    return root, keys, chain


def prepare_configuration(db, previous, current):
    """Called by the administrator key upload before replacing either private key."""
    lock_configuration(db)
    from .models import PortalSetting
    configured = db.scalar(select(PortalSetting).where(PortalSetting.key == signing.SETTING))
    if configured is not None and signing.configuration({signing.SETTING: configured.value}).get('fingerprint') != previous.get('fingerprint'):
        raise ValueError('Signing configuration changed during key replacement; reload and retry.')
    root, keys, previous_chain = _configured_identity(previous)
    if not previous.get('fingerprint') or previous.get('fingerprint') == current.get('fingerprint'):
        if previous_chain:
            current = {**current, 'publisher_root': previous['publisher_root'],
                       'signing_key_chain': deepcopy(previous_chain)}
        return current
    from .cyber_approvals import CyberApproval
    # A reserved publication must finish while its approved signing key exists.
    for approval in db.scalars(select(CyberApproval).where(CyberApproval.status == 'approved')):
        portable = (approval.snapshot or {}).get('portable_release')
        revocation = (approval.publication or {}).get('revocation', {})
        if portable and ((not approval.revoked_at and approval.publish_status != 'published')
                         or (revocation and revocation.get('status') != 'published')):
            raise ValueError('Complete or retry all reserved release and revocation publications before rotating the signing key.')
    chain = deepcopy(previous_chain)
    if len(chain) >= MAX_CHAIN:
        raise ValueError('Publisher key transition limit reached; configure a new independently trusted publisher.')
    from .models import Service
    from .replica_models import ReleasePublicationSequence
    cutovers = {service: sequence + 1 for service, sequence in db.execute(
        select(Service.service_key, ReleasePublicationSequence.sequence)
        .join(ReleasePublicationSequence, ReleasePublicationSequence.service_id == Service.id))}
    certificate = dict(format=FORMAT, publisher_root=root, generation=len(chain) + 1,
        previous_digest=digest(chain[-1]) if chain else None,
        from_fingerprint=previous['fingerprint'], to_fingerprint=current['fingerprint'],
        from_public_key=signing.public_key(previous['public_key'].encode())[0],
        to_public_key=signing.public_key(current['public_key'].encode())[0], service_cutovers=cutovers)
    chain.append(dict(certificate=certificate, from_signature=_sign(certificate, previous),
                      to_signature=_sign(certificate, current)))
    validate_chain(chain)
    return {**current, 'publisher_root': root, 'signing_key_chain': chain}


def manifest_identity(settings, service_key, sequence):
    configuration = signing.configuration(settings)
    root, keys, chain = _configured_identity(configuration)
    if not chain:
        return {}
    if not _sequence_allowed(chain, keys[-1], service_key, sequence):
        raise ValueError('Publication is outside the configured signing key sequence interval')
    return {'publisher_root': root, 'signing_key_chain': deepcopy(chain)}


def authorized_successor(settings, predecessor):
    configuration = signing.configuration(settings)
    root, keys, chain = _configured_identity(configuration)
    if configuration.get('fingerprint') == predecessor:
        return True
    if not chain:
        return False
    return predecessor in keys[:-1]


def _trust_payload(row):
    return {'source_id': row.source_id, 'publisher_root': row.publisher_root,
            'key_chain': row.key_chain, 'generation': row.generation,
            'current_fingerprint': row.current_fingerprint}


def seal_trust(row):
    row.integrity_seal = encrypt_secret(canonical(_trust_payload(row)).decode())


def verify_trust(row):
    try:
        return hmac.compare_digest(decrypt_secret(row.integrity_seal), canonical(_trust_payload(row)).decode())
    except (ValueError, TypeError, AttributeError):
        return False


def reconcile_trust(db, source, identity, service, sequence, *, replay=False):
    """Update only inside the same transaction that successfully imports evidence."""
    from .replica_models import ReplicaPublisherTrust, ReplicaRelease, ReplicaServiceState
    root, chain, signer = identity['publisher_root'], identity.get('key_chain', []), identity['key_fingerprint']
    if chain:
        actual_root, keys = validate_chain(chain, verify=False)
        if actual_root != root or keys[-1] != signer or identity.get('key_generation') != len(chain):
            raise ValueError('Verified publisher identity and transition chain differ')
    elif signer != root:
        raise ValueError('Publisher continuity proof is missing')
    if root not in source.trusted_publishers:
        raise ValueError('Publisher trust anchor was removed')
    row = db.get(ReplicaPublisherTrust, (source.id, root), with_for_update=True, populate_existing=True)
    generation = len(chain)
    if row:
        if not verify_trust(row):
            raise ValueError('Retained publisher continuity integrity check failed')
        common = min(row.generation, generation)
        if row.key_chain[:common] != chain[:common]:
            raise ValueError('Conflicting publisher key transition chain')
        effective_chain = chain if generation >= row.generation else row.key_chain
        if effective_chain and not _sequence_allowed(effective_chain, signer, service, sequence):
            raise ValueError('Publisher key cannot authorize this service sequence')
    if not row:
        # Legacy installations and a newly configured source have no continuity
        # row yet. Existing successor-signed history from this source proves that
        # a missing row instead lost an established trust high-water mark.
        retained_successor = db.scalar(select(ReplicaRelease.id)
            .join(ReplicaServiceState, ReplicaServiceState.service_id == ReplicaRelease.service_id)
            .where(ReplicaServiceState.source_id == source.id,
                   ReplicaRelease.publisher == root, ReplicaRelease.key_fingerprint != root)
            .limit(1))
        if retained_successor is not None:
            raise ValueError('Retained publisher continuity record is missing; restore trusted continuity before importing')
        row = ReplicaPublisherTrust(source_id=source.id, publisher_root=root, key_chain=chain,
                                    generation=generation, current_fingerprint=signer)
        db.add(row)
    elif generation > row.generation:
        row.key_chain, row.generation, row.current_fingerprint = chain, generation, signer
    seal_trust(row)
    db.flush()
    return row
