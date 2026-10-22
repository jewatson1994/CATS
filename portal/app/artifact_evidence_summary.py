"""Present retained verified image counters without estimating service posture."""
from sqlalchemy import select
from .artifact_catalog import ArtifactPatchLineage, GlobalArtifact, _verified_receipt
from .models import PatchExecution


def vulnerability_evidence(db, *, source_id=None, target_id=None, patch_id=None):
    query = select(ArtifactPatchLineage)
    if source_id is not None:
        query = query.where(ArtifactPatchLineage.source_artifact_id == source_id)
    if target_id is not None:
        query = query.where(ArtifactPatchLineage.output_artifact_id == target_id)
    if patch_id is not None:
        query = query.where(ArtifactPatchLineage.patch_execution_id == patch_id)
    for lineage in db.scalars(query.order_by(ArtifactPatchLineage.id.desc())):
        patch = db.get(PatchExecution, lineage.patch_execution_id)
        source = db.get(GlobalArtifact, lineage.source_artifact_id)
        target = db.get(GlobalArtifact, lineage.output_artifact_id)
        if patch and source and target and _verified_receipt(patch, target):
            receipt = patch.summary['artifact_receipt']
            if not str(receipt.get('source_image') or '').endswith('@' + source.digest):
                continue
            return {'before': receipt['vulnerabilities_before'], 'after': receipt['vulnerabilities_after'],
                    'source_digest': source.digest, 'target_digest': target.digest,
                    'scope': 'retained_image_patch'}
    return None
