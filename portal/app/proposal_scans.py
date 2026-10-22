"""Dispatch and retain isolated, digest-pinned amendment scans."""
import json
import re
from sqlalchemy import select
from .durable_jobs import submit, JobError
from . import proposal_assessments as assessments


def inventory(db, row):
    from .artifact_catalog import GlobalArtifact, ArtifactLocation
    artifacts = [db.get(GlobalArtifact, i) for i in row.intent['release_revision']['artifact_ids']]
    if any(a is None for a in artifacts) or len({a.digest for a in artifacts}) != len(artifacts):
        raise ValueError('Ambiguous proposed artifact inventory')
    source = db.get(GlobalArtifact, row.intent.get('source_artifact_id')) if row.intent.get('source_artifact_id') else None
    target = db.get(GlobalArtifact, row.intent.get('target_artifact_id')) if row.intent.get('target_artifact_id') else None
    by_digest = {a.digest: a for a in artifacts}
    result = []
    for item in row.intent.get('previous_artifacts') or []:
        if item.get('kind', 'image') != 'image' or item.get('archive_path'):
            raise ValueError('Automatic proposed assessment requires registry images; retained chart/archive reconstruction is unavailable')
        digest = target.digest if source and target and item.get('digest') == source.digest else item.get('digest')
        artifact = by_digest.get(digest)
        if artifact is None:
            raise ValueError('Proposed inventory differs from original requested inputs')
        locations = list(db.scalars(select(ArtifactLocation.reference).where(ArtifactLocation.artifact_id == artifact.id).order_by(ArtifactLocation.id)))
        if digest == item.get('digest'):
            locations.insert(0, str(item.get('reference') or ''))
        pinned = next((r for r in locations if re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', r) and r.endswith('@'+digest)), None)
        if not pinned:
            raise ValueError('An immutable registry location is required for every proposed image')
        for reference in item.get('source_references') or [item.get('reference')]:
            if not reference or any(r['reference'] == reference for r in result):
                raise ValueError('Ambiguous original reference mapping')
            result.append(dict(reference=reference, scan_reference=pinned, digest=digest, platform=artifact.platform, media_type=artifact.media_type))
    if {r['digest'] for r in result} != set(by_digest):
        raise ValueError('Every proposed artifact must have a requested input mapping')
    return result


def latest_dispatch(db, identity):
    from sqlalchemy import func
    from .durable_jobs import DurableJob
    return db.scalar(select(DurableJob).where(DurableJob.kind == 'proposal_assessment',
        DurableJob.payload['proposal_id'].as_integer() == identity).order_by(
        func.coalesce(DurableJob.payload['generation'].as_integer(), 0).desc(),
        DurableJob.created_at.desc(), DurableJob.id.desc()).limit(1)
        .execution_options(populate_existing=True))


def require_current_dispatch(db, identity, dispatch_id):
    current = latest_dispatch(db, identity)
    if current is None or current.id != dispatch_id:
        raise ValueError('Proposal scan superseded by a newer assessment request')
    if current.cancel_requested or current.status == 'cancelled':
        raise ValueError('Proposal assessment request was cancelled')



def evidence_inputs_token(db, service_id):
    from . import main
    from .service_posture import _intelligence_token, config_digest, resolve_configurations
    from .native_vex_models import VexDispositionService
    configuration = resolve_configurations(db, [service_id], main.get_global_configuration(db))[service_id]
    from .risk_profiles import resolve_policy, DEFAULT_POLICY
    policy, assignment = resolve_policy(db, service_id)
    vex = db.get(VexDispositionService, service_id)
    return assessments.payload_digest({'intelligence': _intelligence_token(db),
        'configuration': config_digest(configuration), 'vex_generation': vex.generation if vex else 0,
        'risk_policy': {'configuration': policy.configuration if policy else DEFAULT_POLICY,
                        'policy_id': policy.id if policy else None, 'assignment': assignment}})


def require_assessment_dispatch(db, row, execution_key):
    """Tie accepted evidence to the persisted scan of the latest request."""
    from .scan_coordination import ScanJob
    current = latest_dispatch(db, row.id)
    if current is None:
        return  # Retained evidence predating automatic dispatch remains readable.
    require_current_dispatch(db, row.id, current.id)
    scan_id = execution_key.removeprefix('proposal:') if execution_key.startswith('proposal:') else None
    scan = db.scalar(select(ScanJob).where(ScanJob.id == scan_id)
        .execution_options(populate_existing=True)) if scan_id else None
    context = (scan.payload or {}).get('proposal_context', {}) if scan else {}
    if (scan is None or scan.status in {'cancelled', 'error', 'incomplete'}
            or context.get('dispatch_id') != current.id
            or context.get('proposal_id') != row.id
            or scan.service_key != db.get(assessments.Service, row.service_id).service_key
            or context.get('inputs') != inventory(db, row)):
        raise ValueError('Proposal assessment does not match the latest persisted scan request')


def freshness_deadline(raw):
    from datetime import datetime, timedelta
    import os
    from .release_validity import utc
    hours = int(os.environ.get('CATS_PROPOSAL_ASSESSMENT_MAX_AGE_HOURS', '24'))
    if hours < 1:
        raise ValueError('Proposal assessment maximum age must be positive')
    return utc(datetime.fromisoformat(raw['scanned_at'])) + timedelta(hours=hours)


def proposal_inputs_token(db, row):
    """Bind review to material proposal evidence, excluding its own scan output."""
    from .artifact_catalog import GlobalArtifact, ArtifactPatchLineage
    from .models import PatchExecution, DeploymentValidationRun
    ids = sorted(set((row.intent.get('release_revision') or {}).get('artifact_ids', [])))
    artifacts = []
    references = set()
    for artifact_id in ids:
        artifact = db.get(GlobalArtifact, artifact_id)
        receipts = []
        for lineage in db.scalars(select(ArtifactPatchLineage).where(
                ArtifactPatchLineage.output_artifact_id == artifact_id).order_by(ArtifactPatchLineage.id)):
            patch = db.get(PatchExecution, lineage.patch_execution_id)
            receipt = (patch.summary or {}).get('artifact_receipt') if patch else None
            if isinstance(receipt, dict) and receipt.get('immutable_destination'):
                references.add(receipt['immutable_destination'])
            receipts.append({'lineage': lineage.id, 'status': patch.status if patch else None,
                             'receipt': receipt})
        artifacts.append({'id': artifact_id, 'digest': artifact.digest if artifact else None,
                          'receipts': receipts})
    references.update(item.get('reference') for item in row.intent.get('previous_artifacts', [])
                      if item.get('reference'))
    validations = []
    if references:
        for run in db.scalars(select(DeploymentValidationRun).where(
                DeploymentValidationRun.service_id == row.service_id,
                DeploymentValidationRun.artifact_reference.in_(sorted(references)))
                .order_by(DeploymentValidationRun.id)):
            validations.append({'id': run.id, 'reference': run.artifact_reference,
                'status': run.status, 'phase': run.phase, 'reason': run.reason_category,
                'conditions': run.conditions, 'helm_result': run.helm_result})
    return assessments.payload_digest({'intent': row.intent, 'artifacts': artifacts,
                                       'validations': validations})


def maintenance(db):
    """Supersede changed inputs and refresh expired evidence once per generation."""
    from datetime import datetime, timezone
    from .release_revisions import ReleaseAmendmentProposal, ServiceActiveRelease
    from .models import Service
    from .scan_coordination import ScanJob
    rows = db.scalars(select(ReleaseAmendmentProposal).join(ServiceActiveRelease,
        (ServiceActiveRelease.service_id == ReleaseAmendmentProposal.service_id)
        & (ServiceActiveRelease.revision_id == ReleaseAmendmentProposal.base_revision_id))
        .join(Service, Service.id == ReleaseAmendmentProposal.service_id)
        .where(Service.lifecycle_status == 'active')).all()
    for row in rows:
        try:
            assessments.proposal(db, row.id, row.service_id)
        except assessments.InactiveProposalBase:
            # Activation may have changed the pointer after the candidate query.
            # Leave obsolete proposals historical and continue other services.
            continue
        current = latest_dispatch(db, row.id)
        if current is None or current.cancel_requested or current.status == 'cancelled':
            continue
        # Changed inputs invalidate even unfinished or failed scans. The new
        # generation prevents their late results from becoming review evidence.
        if (current.payload.get('evidence_inputs_token') != evidence_inputs_token(db, row.service_id)
                or current.payload.get('proposal_inputs_token') != proposal_inputs_token(db, row)):
            enqueue(db, row, current.requested_by_id, fresh=True)
            continue
        evidence = assessments.latest(db, row.id)
        if current.status != 'completed' or evidence is None:
            continue
        try:
            require_assessment_dispatch(db, row, evidence.execution_key)
        except ValueError:
            # Older evidence can remain while the current scanner is running.
            # Do not repeatedly supersede that in-flight generation.
            continue
        scan = db.get(ScanJob, evidence.execution_key.removeprefix('proposal:'))
        if scan is None or scan.status != 'complete':
            continue
        try:
            if freshness_deadline(evidence.raw_payload) > datetime.now(timezone.utc):
                continue
        except (ValueError, KeyError, TypeError):
            # A completed, bound scan with unusable freshness evidence is not
            # reviewable. Recover with a new generation, retaining its history.
            pass
        enqueue(db, row, current.requested_by_id, fresh=True)
    db.commit()


def enqueue(db, row, actor_id, *, fresh=False):
    # Serialize generations with proposal admission and result retention.
    assessments.proposal(db, row.id, row.service_id)
    previous = latest_dispatch(db, row.id)
    if previous is not None and not fresh:
        return previous
    generation = int((previous.payload or {}).get('generation', 0)) + 1 if previous else 1
    return submit(db, kind='proposal_assessment', payload={'proposal_id': row.id, 'generation': generation,
        'evidence_inputs_token': evidence_inputs_token(db, row.service_id),
        'proposal_inputs_token': proposal_inputs_token(db, row)}, service_id=row.service_id,
        requested_by_id=actor_id, dedupe_key=f'proposal-assessment:{row.id}:generation:{generation}', max_attempts=1, commit=False)


def handle(ctx, payload):
    from . import main
    from .models import User, Service
    from .auth import AuthContext
    from .scan_coordination import ScanJob
    ctx.check()
    with main.SessionLocal() as db:
        service = db.get(Service, ctx.job.service_id)
        user = db.get(User, ctx.job.requested_by_id)
        auth = AuthContext(user=user, session=None) if user and user.enabled else None
        if not service or service.lifecycle_status != 'active' or not auth or any(not auth.has(p, service.id) for p in ('service.edit','approval.request')):
            raise JobError('Proposal owner no longer has service edit and approval request access')
        row = assessments.proposal(db, payload['proposal_id'], service.id)
        require_current_dispatch(db, row.id, ctx.job.id)
        # Recover a submission persisted before dispatcher completion.
        existing = db.scalar(select(ScanJob).where(ScanJob.payload['proposal_context']['dispatch_id'].as_string() == ctx.job.id))
        if existing:
            return {'scan_id': existing.id, 'proposal_id': row.id}
        inputs = inventory(db, row)
        from .service_posture import resolve_configurations
        configuration = resolve_configurations(db, [service.id], main.get_global_configuration(db))[service.id]
        trusted_cas = main.parse_json(configuration.get('trusted_ca_certificates'), [])
        ctx.check()
        scan_id = main._start_public_scan('\n'.join(sorted({r['scan_reference'] for r in inputs})),
            ingest_service_id=service.service_key, owner_user_id=user.id, ingest_scope='service',
            ingest_service_version=f'amendment-{row.id}',
            trusted_ca_certificates=trusted_cas if isinstance(trusted_cas, list) else [],
            proposal_context={'proposal_id':row.id, 'dispatch_id':ctx.job.id, 'inputs':inputs})
        return {'scan_id':scan_id, 'proposal_id':row.id}


def ingest(db, job_id, job, output):
    from .schemas import ExecutionPayload
    from .models import Service
    context = job['proposal_context']
    service = db.scalar(select(Service).where(Service.service_key == job['ingest_service_id']))
    if service is None:
        raise ValueError('Proposal service unavailable')
    row = assessments.proposal(db, context['proposal_id'], service.id)
    require_current_dispatch(db, row.id, context.get('dispatch_id'))
    inputs = inventory(db, row)
    if inputs != context['inputs']:
        raise ValueError('Proposed scan inventory changed')
    if job.get('returncode') != 0 or (output/'scan-failure.json').exists():
        raise ValueError('Proposed scanner phase failed')
    data = json.loads((output/'portal-result.json').read_text(encoding='utf-8'))
    overview = data.get('service_overview') or {}
    if (output/'service-overview.json').exists():
        overview = {**overview, **json.loads((output/'service-overview.json').read_text(encoding='utf-8'))}
    images = overview.get('images') or []
    actual = {i.get('image') or i.get('reference'):i for i in images if isinstance(i, dict)}
    if len(actual) != len(images) or set(actual) != {i['scan_reference'] for i in inputs}:
        raise ValueError('Scanner evidence must include every immutable proposed image')
    mapped = []
    for item in inputs:
        evidence = actual[item['scan_reference']]
        if any(evidence.get(key) != item[key] for key in ('digest','platform','media_type')):
            raise ValueError('Scanner digest, platform or media type differs from proposed inventory')
        mapped.append({**evidence, 'image':item['scan_reference'],
                       'requested_reference':item['reference']})
    overview['images'] = mapped
    data.update(service_overview=overview, execution_id=f'proposal:{job_id}',
        service={'id':service.service_key,'name':service.name,'version':job['ingest_service_version']}, fixable_only=True)
    data['findings'] = [i for i in data.get('findings',[]) if str(i.get('fixed_version') or '').strip() not in {'','—','-'}]
    if any(finding.get('image') not in actual for finding in data['findings']):
        raise ValueError('Finding references an image outside the proposed inventory')
    # Scope/completeness, timestamps and skipped inputs remain scanner assertions.
    retained = assessments.retain(db, row.id, ExecutionPayload.model_validate(data))
    return retained


def state(db, identity):
    from .durable_jobs import DurableJob
    from .scan_coordination import ScanJob
    dispatch = latest_dispatch(db, identity)
    scan = db.scalar(select(ScanJob).where(ScanJob.payload['proposal_context']['dispatch_id'].as_string() == (dispatch.id if dispatch else ''))
        .order_by(ScanJob.created_at.desc()).limit(1))
    return {'assessment_job_id': dispatch.id if dispatch else None,
        'assessment_status': scan.status if scan else dispatch.status if dispatch else 'not_requested',
        'assessment_scan_id': scan.id if scan else None,
        'assessment_error': (scan.payload or {}).get('error') if scan else dispatch.error if dispatch else None}
