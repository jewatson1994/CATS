"""Real offline image validation with registry-manifest to runtime-content binding."""
from __future__ import annotations
import json
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy import select
from . import deployment_bundle, validator_client, validator_management
from .artifact_catalog import ArtifactLocation, GlobalArtifact, ServiceArtifactAssignment
from .models import DeploymentValidationRun, ServiceVersion


def bind_bundle(path, *, service, reference, digest, settings):
    """Reject a bundle whose runtime image differs from the selected OCI bytes."""
    from .cyber_release_publication import image_source, _source_environments
    from . import release_oci
    if not reference.endswith('@' + digest):
        raise ValueError('An exact immutable image reference is required')
    manifest = deployment_bundle.validate_bundle(path, expected_type='offline-bundle')
    if manifest.get('service') != service or len(manifest['images']) != 1:
        raise ValueError('A single-image bundle for the exact service version is required')
    host, repository, selected = image_source(reference)
    with _source_environments(settings) as (base, environments):
        client = release_oci._Client(host, repository, environments.get(host, base))
        _, _, raw = client.request('GET', client.api + '/manifests/' + selected,
                                   limit=release_oci.MAX_MANIFEST_BYTES)
    if release_oci._digest(raw) != digest:
        raise ValueError('Registry returned a different immutable manifest')
    document = json.loads(raw)
    # Multi-platform indexes require an explicit platform manifest selection.
    config = document.get('config', {}).get('digest')
    if not config or manifest['images'][0]['digest'] != config:
        raise ValueError('Bundle runtime image does not match the selected registry manifest')
    return {'manifest_digest': digest, 'config_digest': config,
            'runtime_reference': manifest['images'][0]['reference'],
            'bundle_digest': deployment_bundle.file_digest(path)}


def validate_image(db, auth, service, artifact_id, version_id, reference, upload):
    from .main import get_global_configuration
    from .cyber_approvals import CyberApproval
    from .auth import record_audit
    artifact = db.get(GlobalArtifact, artifact_id)
    assignment = db.scalar(select(ServiceArtifactAssignment.id).where(
        ServiceArtifactAssignment.service_id == service.id, ServiceArtifactAssignment.artifact_id == artifact_id))
    version = db.get(ServiceVersion, version_id)
    if not artifact or not assignment or not version or version.service_id != service.id:
        raise HTTPException(404, 'Assigned artifact and service version required')
    if len(reference) > 240 or not reference.endswith('@' + artifact.digest):
        raise HTTPException(422, 'Exact immutable image reference required')
    known = db.scalar(select(ArtifactLocation.id).where(ArtifactLocation.artifact_id == artifact.id,
                                                        ArtifactLocation.reference == reference))
    if not known:
        for approval in db.scalars(select(CyberApproval).where(CyberApproval.service_id == service.id,
                                                              CyberApproval.publish_status == 'published')):
            if any(item.get('reference') == reference and item.get('digest') == artifact.digest
                   for item in (approval.publication or {}).get('artifacts', [])):
                known = True
                break
    if not known:
        raise HTTPException(409, 'Reference is not retained for this artifact')
    settings = get_global_configuration(db)
    config = validator_management.select_configuration(db, json.loads(settings.get('validator_configuration') or '{}'), 'offline-bundle')
    if not config.get('endpoint'):
        raise HTTPException(409, 'No offline deployment validator configured')
    identity = {'id': service.service_key, 'version': version.version}
    with tempfile.TemporaryDirectory(prefix='cats-image-validation-') as directory:
        path = Path(directory) / 'bundle.zip'
        count = 0
        with path.open('xb') as output:
            while chunk := upload.file.read(1024 * 1024):
                count += len(chunk)
                if count > deployment_bundle.MAX_BYTES:
                    raise HTTPException(413, 'Validation bundle exceeds size limit')
                output.write(chunk)
        try:
            binding = bind_bundle(path, service=identity, reference=reference, digest=artifact.digest, settings=settings)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        declaration = {'schema_version': 'cats.validation/v2', 'request_id': uuid.uuid4().hex,
            'validation_type': 'offline-bundle', 'service': identity,
            'artifact': {'reference': reference, 'digest': binding['bundle_digest']},
            'deployment': {'type': 'helm', 'namespace': 'cats-validation'}, 'validation_profile': 'default'}
        run = DeploymentValidationRun(run_key='DV-' + uuid.uuid4().hex[:20].upper(),
            service_id=service.id, requested_by_id=auth.user.id, artifact_type='IMAGE',
            artifact_reference=reference, status='RUNNING', phase='PREFLIGHT',
            started_at=datetime.now(timezone.utc), cleanup_status='UNKNOWN',
            diagnostics={'image_binding': binding, 'request': declaration})
        db.add(run); db.flush()
        record_audit(db, auth, 'deployment_validation.started', 'deployment_validation', str(run.id), artifact_id=artifact.id)
        db.commit()
        try:
            result = validator_client.validate(config, declaration, artifact_path=path)
            if (result.get('service') != identity or result.get('artifact_digest') != binding['bundle_digest']
                    or result.get('artifact', {}).get('reference') != reference):
                raise ValueError('Validator identity does not match the requested image bundle')
            if result.get('status') == 'VERIFIED' and (result.get('offlineVerified') is not True
                                                       or result.get('cleanup_status') != 'COMPLETE'):
                raise ValueError('Verified offline execution and cleanup required')
        except Exception as exc:
            result = {'status': 'COULD_NOT_VALIDATE', 'reason_category': 'IMAGE_VALIDATION_ERROR',
                      'reason': 'Image validation could not establish exact runtime evidence (' + type(exc).__name__ + ')',
                      'cleanup_status': 'UNKNOWN'}
        db.refresh(run)
        run.status = result.get('status', 'COULD_NOT_VALIDATE')
        run.phase = 'COMPLETE'; run.completed_at = datetime.now(timezone.utc)
        run.cleanup_status = result.get('cleanup_status', 'UNKNOWN')
        run.reason = result.get('reason'); run.reason_category = result.get('reason_category')
        run.diagnostics = {'image_binding': binding, 'request': declaration, 'validator_result': result}
        if run.status == 'VERIFIED':
            from .artifact_catalog import enqueue_recommendation_reconciliation
            enqueue_recommendation_reconciliation(db, validation_run_id=run.id)
        record_audit(db, auth, 'deployment_validation.completed', 'deployment_validation', str(run.id), status=run.status)
        db.commit()
        return {'id': run.id, 'run_key': run.run_key, 'status': run.status, 'artifact_reference': reference,
                'cleanup_status': run.cleanup_status, 'reason': run.reason}
