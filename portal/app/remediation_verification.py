"""Independent validation of exact immutable final OCI charts, never reconstructed sources."""
from __future__ import annotations
import hmac
from pathlib import Path
import re
from zipfile import ZipFile
from sqlalchemy.orm import object_session
from .deployment_bundle import file_digest
from .remediation_delivery import checked_inventory
from .validator_client import validate as run_remote
from .validator_protocol import REQUEST_SCHEMA_VERSION, validate_request


def verify_delivery(record, result, validator_config, root):
    response = {"status": "not_verified", "artifact_digest": result.get("materialized_digest"),
                "evidence_scope": "immutable_oci_delivery", "validation_type": "oci", "results": []}
    try:
        root_path = Path(root).resolve()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", record.job_key or ""):
            raise ValueError("Invalid retained delivery identity")
        expected = root_path / record.job_key
        path = Path(result.get("artifact_path") or "")
        if (path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file()
                or path.resolve().parent != expected.resolve() or expected.resolve().parent != root_path):
            raise ValueError("Delivery artifact ownership mismatch")
        digest = result.get("materialized_digest")
        if not isinstance(digest, str) or not hmac.compare_digest(file_digest(path), digest):
            raise ValueError("Delivery integrity mismatch")
        with ZipFile(path) as archive:
            checked_inventory(archive)
        service = result.get("service")
        if not isinstance(service, dict) or service.get("id") != record.service.service_key or not service.get("version"):
            raise ValueError("Retained service version identity required")
        if hasattr(record, '_sa_instance_state'):
            from .models import ServiceVersion
            session = object_session(record)
            version = session.get(ServiceVersion, record.source_version_id) if session and record.source_version_id else None
            if not version or version.service_id != record.service_id or version.version != service['version']:
                raise ValueError("Service version identity mismatch")
        response['service'] = dict(service)
        identities = [identity for identity in result.get('artifact_identities', [])
                      if identity.get('kind') == 'helm' and identity.get('identity_type') == 'oci_manifest']
        if not identities:
            raise ValueError("No final immutable OCI deployment chart")
        requests, seen = [], set()
        for identity in identities:
            reference, digest = identity.get('reference'), identity.get('digest')
            if not isinstance(reference, str) or not isinstance(digest, str) or not reference.endswith('@' + digest):
                raise ValueError("Mutable OCI identity")
            reference = reference if reference.startswith('oci://') else 'oci://' + reference
            if reference in seen:
                raise ValueError("Ambiguous OCI deployment identity")
            seen.add(reference)
            request = {'schema_version': REQUEST_SCHEMA_VERSION, 'validation_type': 'oci', 'service': service,
                       'artifact': {'reference': reference, 'digest': digest},
                       'deployment': {'type': 'helm', 'namespace': 'cats-validation'}, 'validation_profile': 'default'}
            validate_request(request)
            requests.append(request)
        if not validator_config or not validator_config.get('endpoint'):
            return {**response, 'status': 'verification_unavailable', 'remote_status': 'COULD_NOT_VALIDATE',
                    'detail': 'Independent OCI runtime validator unavailable'}
        results = []
        for request in requests:
            remote = run_remote(validator_config, request)
            if (not isinstance(remote, dict) or remote.get('status') not in {'VERIFIED', 'PARTIALLY_VERIFIED', 'COULD_NOT_VALIDATE', 'FAILED', 'ERROR', 'CANCELLED', 'TIMED_OUT'}
                    or remote.get('artifact_digest') != request['artifact']['digest'] or remote.get('service') != service or remote.get('validation_type') != 'oci'):
                raise ValueError("Validator returned evidence for a different final artifact")
            results.append({'reference': request['artifact']['reference'], 'digest': request['artifact']['digest'], 'result': remote})
            response['results'] = results
        if file_digest(path) != result['materialized_digest']:
            raise ValueError('Retained delivery changed during verification')
        verified = all(item['result']['status'] == 'VERIFIED' for item in results)
        return {**response, 'status': 'verified' if verified else 'not_verified',
                'remote_status': 'VERIFIED' if verified else next(item['result']['status'] for item in results if item['result']['status'] != 'VERIFIED')}
    except Exception as exc:
        return {**response, 'status': 'not_verified', 'remote_status': 'COULD_NOT_VALIDATE',
                'detail': f'Exact OCI delivery verification could not be established ({type(exc).__name__})'}
