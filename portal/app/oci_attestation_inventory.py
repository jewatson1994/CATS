"""Resolve attestation objects from the release granting this specific pull."""
from urllib.parse import urlsplit

from sqlalchemy import select


def _artifacts(db, mapping, decision):
    from .operating_mode import is_replica
    if is_replica():
        from .replica_models import ReplicaRelease
        release = db.get(ReplicaRelease, decision.release_id, populate_existing=True)
        return release.artifacts if release is not None else []
    from .cyber_approvals import CyberApproval
    identity = getattr(decision, 'approval_id', None)
    approval = db.get(CyberApproval, identity, populate_existing=True) if identity else None
    if approval is None:
        return []
    receipt = approval.publication or {}
    manifest = receipt.get('manifest') or {}
    if (approval.publish_status != 'published' or receipt.get('verification_status') != 'verified'
            or receipt.get('signature_status') != 'verified'
            or manifest.get('approval_id') != approval.id
            or manifest.get('snapshot_digest') != approval.snapshot_digest
            or manifest.get('artifacts') != receipt.get('artifacts')):
        return []
    return receipt.get('artifacts', [])


def inventory(db, mapping, subject, decision):
    """The caller must use a freshly allowed decision for this exact subject."""
    if not decision.allowed:
        return None
    from .release_oci import _reference
    matches = []
    for artifact in _artifacts(db, mapping, decision):
        if artifact.get('digest') != subject:
            continue
        try:
            host, repository, digest = _reference(artifact['reference'])
        except (KeyError, ValueError):
            continue
        if repository != mapping.upstream_repository or host != urlsplit(mapping.upstream.endpoint).netloc:
            continue
        value = artifact.get('attestation')
        if isinstance(value, dict):
            matches.append(value)
    return matches[0] if len(matches) == 1 else None


def candidate_subjects(db, mapping, object_digest):
    """Find cold digest candidates; live authorization still grants no authority here."""
    from .operating_mode import is_replica
    if is_replica():
        from .replica_models import ReplicaRelease
        query = select(ReplicaRelease.artifacts)
        if mapping.service_id is not None:
            query = query.where(ReplicaRelease.service_id == mapping.service_id)
        groups = db.scalars(query)
    else:
        from .cyber_approvals import CyberApproval
        query = select(CyberApproval.publication)
        if mapping.service_id is not None:
            query = query.where(CyberApproval.service_id == mapping.service_id)
        groups = ((row or {}).get('artifacts', []) for row in db.scalars(query))
    return {item['digest'] for group in groups for item in group
            if isinstance(item.get('attestation'), dict)
            and item['attestation'].get('digest') == object_digest}
