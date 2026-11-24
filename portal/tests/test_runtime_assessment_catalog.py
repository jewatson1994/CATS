"""Service-scoped, read-only catalog evidence for digest-verified runtime scans."""
from sqlalchemy import func, select

from app.artifact_catalog import GlobalArtifact, ServiceArtifactAssignment, assign_artifact, register_artifact
from app.discovery_helm_network import CHART_LAYER
from app.models import Service
from app.runtime_candidate_assessment import process
from app.runtime_candidates import assessment_for_review, reconcile
from app.runtime_image_manifests import IMAGE_TYPES
from app.scan_coordination import ScanJob
from test_runtime_candidates import PIN, application, complete, runtime


def test_catalog_correlation_uses_existing_scoped_digest_records(runtime):
    db, _, service, env, _ = runtime
    other = Service(service_key='other-service', name='Other service', lifecycle_status='active')
    db.add(other)
    db.flush()
    digest = PIN.split('@')[1]
    image_media = IMAGE_TYPES[0]
    def catalog(media, platform, content=digest):
        return register_artifact(db, digest=content, media_type=media, platform=platform)
    arm = catalog(image_media, 'linux/arm64')
    amd = catalog(image_media, 'linux/amd64')
    other_only = catalog(image_media, 'linux/s390x')
    chart = catalog(CHART_LAYER, 'unknown')
    unrelated = catalog(image_media, 'linux/amd64', 'sha256:' + 'b' * 64)
    for owner, artifact, role in ((service, arm, 'source'), (service, amd, 'source'), (service, arm, 'release'),
                                  (other, arm, 'patched'), (other, other_only, 'source'), (service, chart, 'release'),
                                  (service, unrelated, 'patched')):
        assign_artifact(db, service_id=owner.id, artifact_id=artifact.id, role=role)
    candidate = reconcile(db, env, service, [application(PIN)], 'default')
    unverified = process(db, candidate)['runtime_evidence']['assessments'][0]
    assert 'catalog_matches' not in unverified
    job = db.get(ScanJob, candidate.jobs[PIN])
    execution = complete(db, job, service)
    review = process(db, candidate)
    assert review['ready'], review['blockers']
    receipt, = review['runtime_evidence']['assessments']
    assert receipt['catalog_matches'] == [
        {'artifact_id': arm.id, 'media_type': image_media, 'platform': 'linux/arm64', 'roles': ['release', 'source']},
        {'artifact_id': amd.id, 'media_type': image_media, 'platform': 'linux/amd64', 'roles': ['source']},
    ]
    assert db.scalar(select(func.count()).select_from(GlobalArtifact)) == 5
    assert db.scalar(select(func.count()).select_from(ServiceArtifactAssignment)) == 7

    execution.payload_digest = 'invalid'
    db.flush()
    blocked = assessment_for_review(db, candidate, service)
    assert not blocked['ready']
    invalid, = blocked['runtime_evidence']['assessments']
    assert 'integrity' in invalid['reason'] and 'catalog_matches' not in invalid
