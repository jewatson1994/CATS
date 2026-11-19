"""Distribute an approved release and its evidence to the service manager's reviewed OCI destination."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile

from fastapi import HTTPException
from sqlalchemy import ForeignKey, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from . import release_oci, release_validity
from .cyber_release_publication import _Transport, _repository_component, failure_diagnostic
from .database import Base
from .delivery_execution import delivery_lock
from .durable_jobs import DurableJob, JobError, submit
from .imported_services import is_imported_service
from .portable_release import fetch_release, release_tag
from .release_documentation import registry_environment
from .service_oci import ServiceOCIDestination
from .secrets import decrypt_secret
from .trusted_ca import configured_certificates


class AdditionalReleaseDelivery(Base):
    __tablename__ = 'additional_release_deliveries'
    approval_id: Mapped[int] = mapped_column(ForeignKey('cyber_approvals.id'), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    job_id: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    reference: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)


def selectable(auth, service_id):
    return auth.has('service.edit', service_id) and auth.has('service.export', service_id)


def public_target(row):
    return {'id': str(row.id), 'name': row.name, 'endpoint': row.endpoint, 'namespace': row.namespace}


def options(db, service_id):
    return [public_target(row) for row in db.scalars(select(ServiceOCIDestination).where(
        ServiceOCIDestination.service_id == service_id).order_by(ServiceOCIDestination.name, ServiceOCIDestination.id))]


def _target(db, service_id, target_id):
    value = str(target_id)
    if not value.isascii() or not value.isdecimal() or len(value) > 10 or int(value) > 2147483647:
        return None
    return db.scalar(select(ServiceOCIDestination).where(ServiceOCIDestination.id == int(value),
                                                         ServiceOCIDestination.service_id == service_id))


def _namespace(target):
    return target.get('namespace') or 'cyber-approved'


def reject_duplicate(primary, additional):
    if primary and additional and (release_oci._origin(primary['endpoint']) == release_oci._origin(additional['endpoint'])
                                   and _namespace(primary) == _namespace(additional)):
        raise HTTPException(422, 'Select a destination different from the Cyber publication destination')


def freeze_target(db, auth, service_id, target_id, primary):
    if target_id is None:
        return None
    if not selectable(auth, service_id):
        raise HTTPException(403, 'Service management and export permission required to add a release destination')
    row = _target(db, service_id, target_id)
    if not row:
        raise HTTPException(422, 'Choose an OCI destination saved for this service')
    frozen = {**public_target(row), 'ca_digest': hashlib.sha256(row.ca_pem.encode()).hexdigest()}
    reject_duplicate(primary, frozen)
    return frozen


def can_retry(auth, approval, kind):
    permitted = auth.has('approval.decide', approval.service_id) or selectable(auth, approval.service_id)
    if not permitted or approval.status != 'approved':
        return False
    if kind == 'revocation':
        return bool(approval.revoked_at)
    return not approval.revoked_at and release_validity.summary(approval)['validity_status'] in ('valid', 'expiring_soon')


def details(db, auth, approval):
    if not approval.snapshot.get('additional_destination'):
        return []
    rows = db.scalars(select(AdditionalReleaseDelivery).where(
        AdditionalReleaseDelivery.approval_id == approval.id).order_by(AdditionalReleaseDelivery.kind))
    return [{'kind': row.kind, 'status': row.status, 'reference': row.reference, 'error': row.error,
             'can_retry': row.status == 'failed' and can_retry(auth, approval, row.kind)} for row in rows]


def enqueue(db, approval, delivery, actor):
    job = submit(db, kind='cyber_release_publish', payload={'approval_id': approval.id, 'additional_delivery': delivery.kind},
                 service_id=approval.service_id, requested_by_id=actor, source_execution_id=approval.source_execution_id,
                 version=str(approval.snapshot.get('version', '')), max_attempts=1, commit=False)
    delivery.status, delivery.job_id, delivery.error = 'queued', job.id, None


def schedule(db, approval, kind):
    if not approval.snapshot.get('additional_destination') or db.get(AdditionalReleaseDelivery, (approval.id, kind)):
        return
    delivery = AdditionalReleaseDelivery(approval_id=approval.id, kind=kind, status='failed')
    db.add(delivery)
    # Commit delivery intent with the authoritative primary receipt even if the worker queue is at capacity.
    try:
        with db.begin_nested():
            enqueue(db, approval, delivery, approval.decided_by_id)
    except HTTPException as exc:
        if exc.status_code != 429:
            raise
        delivery.error = 'Background queue is full. Retry this additional delivery.'


def reconcile(db):
    pending = db.scalars(select(AdditionalReleaseDelivery).where(
        AdditionalReleaseDelivery.status.in_(('queued', 'publishing'))).with_for_update(skip_locked=True))
    for row in pending:
        job = db.get(DurableJob, row.job_id)
        if not job or job.status in ('failed', 'cancelled', 'completed'):
            row.status, row.error = 'failed', 'Delivery worker stopped before recording a verified copy. Retry this delivery.'


def _bound(row, frozen):
    return row and all(getattr(row, key) == frozen.get(key) for key in ('endpoint', 'namespace')) and (
        hashlib.sha256(row.ca_pem.encode()).hexdigest() == frozen.get('ca_digest'))


def _private(row):
    return {**public_target(row), 'username': decrypt_secret(row.username), 'password': row.password, 'ca_pem': row.ca_pem}


def _tag_digest(client, tag):
    try:
        _, _, raw = client.request('GET', client.api + '/manifests/' + tag)
    except release_oci._RegistryError as exc:
        if exc.status == 404:
            return None
        raise
    return release_oci._digest(raw)


def _native_alias(approval, transport, remote, local, signed, tag):
    # Serialize native tag updates for this service. A late replay must not roll back a successor's alias.
    locks = Path(approval.snapshot['evidence']['path']).parent.parent / '.distribution-signatures'
    with delivery_lock(locks, approval.snapshot['service_id'], wait=True) as owned:
        if not owned:
            raise JobError('Another worker is updating signature tags for this service. Retry this delivery.')
        current = _tag_digest(local, tag)
        if current == signed['digest'] or (current and _tag_digest(remote, tag) != signed['digest']):
            return
        raw = (transport.blobs / signed['digest'][7:]).read_bytes()
        status, _, _ = local.request('PUT', local.api + '/manifests/' + tag, body=raw, media_type=signed['mediaType'])
        if status != 201 or _tag_digest(local, tag) != signed['digest']:
            raise JobError('Additional destination did not verify a signature or attestation tag')


def _copy(approval, receipt, source, target, certificates, check):
    """Copy exact signed OCI graphs. Publish the immutable discovery tag only after independent target verification."""
    manifest = receipt['manifest']
    if manifest.get('snapshot_digest') != approval.snapshot_digest or manifest.get('release_key') != approval.release_key:
        raise JobError('Primary publication differs from the reviewed approval')
    service = _repository_component(approval.snapshot['service_key'])
    source_host, target_host = (d['endpoint'].removeprefix('https://') for d in (source, target))
    source_prefix = _namespace(source) + '/' + service + '/'
    target_prefix = _namespace(target) + '/' + service + '/'
    release = receipt['release']
    expected_source = source_host + '/' + source_prefix + 'releases@' + release['digest']
    if release['reference'] != expected_source:
        raise JobError('Primary release reference is outside its reviewed repository')
    with (registry_environment(source, certificates) as source_env, registry_environment(target, certificates) as target_env,
          tempfile.TemporaryDirectory(prefix='cats-release-distribution-') as directory):
        trust = [manifest.get('publisher_root') or approval.snapshot['signing_fingerprint']]
        original = fetch_release(expected_source, source_env, trust)
        if original['manifest'] != manifest:
            raise JobError('Primary publication record differs from the signed registry manifest')
        signer = approval.snapshot['signing_fingerprint']
        if manifest['portable'].get('kind') == 'revocation':
            # The portable verifier authenticates every transition, including both endpoint signatures.
            authorized_keys = [original['key_fingerprint'], *(entry['certificate']['from_fingerprint']
                               for entry in original['key_chain'])]
        else:
            authorized_keys = [original['key_fingerprint']]
        if signer not in authorized_keys:
            raise JobError('Primary publication was not signed by the approved publisher or its certified successor')
        del original  # Release the in-memory evidence archive before transport and destination verification.
        transport = _Transport(Path(directory) / 'oci', target_env)

        def copy_item(item):
            host, repository, digest = release_oci._reference(item['reference'])
            if host != source_host or not repository.startswith(source_prefix) or digest != item['digest']:
                raise JobError('Publication contains an unexpected primary artifact location')
            remote = release_oci._Client(host, repository, source_env, pull_only=True)
            local = release_oci._Client(target_host, target_prefix + repository[len(source_prefix):], target_env)
            descriptor = transport.graph(remote, digest, local)
            for field, suffix in (('signature', '.sig'), ('attestation', '.att')):
                attachment = item.get(field)
                if attachment:
                    signed = transport.graph(remote, attachment['digest'], local)
                    transport.tag(local, signed, 'cats-' + field + '-' + signed['digest'][7:])
                    _native_alias(approval, transport, remote, local, signed, digest.replace(':', '-', 1) + suffix)
            return local, descriptor

        for artifact in manifest['artifacts']:
            check()
            local, descriptor = copy_item(artifact)
            transport.tag(local, descriptor, artifact['tag'])
        check()
        local, descriptor = copy_item(release)
        reference = target_host + '/' + target_prefix + 'releases@' + descriptor['digest']
        verified = fetch_release(reference, target_env, trust, repository_prefix=_namespace(target))
        if verified['manifest'] != manifest or not verified['complete'] or not verified['verified']:
            raise JobError('The additional destination did not verify the complete signed release')
        check(lock=True)
        transport.tag(local, descriptor, release_tag(manifest['portable']))
        return reference


def run(ctx, payload):
    from .cyber_approvals import ApprovedReleaseDestination, CyberApproval, _eligible, digest, record_audit
    from .models import Service
    kind = payload['additional_delivery']
    with ctx.session_factory() as db:
        row = db.get(CyberApproval, payload['approval_id'])
        delivery = db.get(AdditionalReleaseDelivery, (payload['approval_id'], kind))
        if not row or not delivery or delivery.job_id != ctx.job.id or kind not in ('release', 'revocation'):
            raise JobError('Additional delivery is unavailable')
        try:
            def check(*, lock=False):
                ctx.check()
                db.refresh(row, with_for_update=True if lock else None)
                db.refresh(delivery)
                if delivery.job_id != ctx.job.id or row.status != 'approved' or bool(row.revoked_at) != (kind == 'revocation'):
                    raise JobError('Additional delivery authorization changed')
                if kind == 'release':
                    try:
                        release_validity.require_current(row)
                    except ValueError as exc:
                        raise JobError(str(exc)) from None

            check()
            if is_imported_service(db, row.service_id) or digest(row.snapshot) != row.snapshot_digest:
                raise JobError('The retained Cyber approval is unavailable for distribution')
            frozen = row.snapshot.get('additional_destination') or {}
            secondary = _target(db, row.service_id, frozen.get('id'))
            primary = db.get(ApprovedReleaseDestination, row.destination_id)
            if not _bound(secondary, frozen) or not _bound(primary, row.destination):
                raise JobError('Restore the reviewed destination endpoint, namespace and CA before retrying delivery')
            if not primary.enabled or (kind == 'release' and not _eligible(primary, db.get(Service, row.service_id))):
                raise JobError('Cyber publication destination is disabled or outside the service scope')
            receipt = row.publication if kind == 'release' else (row.publication or {}).get('revocation', {})
            if receipt.get('signature_status') != 'verified' or receipt.get('verification_status') != 'verified' or receipt.get('status') != 'published':
                raise JobError('A verified Cyber publication is required for additional delivery')
            delivery.status = 'publishing'
            db.commit()
            ctx.stage('Distributing signed ' + kind + ' to the service destination', 10)
            delivery.reference = _copy(row, receipt, _private(primary), _private(secondary), configured_certificates(db), check)
            delivery.status = 'published'
            record_audit(db, None, 'cyber_release.additional.published', 'cyber_approval', row.id,
                         delivery_kind=kind, destination_id=frozen['id'])
            db.commit()
            return {'result_url': f'/approved-releases?id={row.id}', 'approval_id': row.id}
        except Exception as exc:
            db.rollback()
            error = str(exc) if isinstance(exc, JobError) else failure_diagnostic(exc, 'Additional release delivery')['cause']
            if delivery.job_id == ctx.job.id:
                delivery.status, delivery.error = 'failed', error
                db.commit()
            raise JobError(error) from None
