"""Durable remediation plans and dispatch for existing candidate/delivery records.

Only redacted review material enters job results. The worker reconstructs and
checks the exact retained source again before applying any approved decision.
"""
from contextvars import ContextVar
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import load_only

from .models import Execution, Service, RemediationExecution
from .durable_jobs import DurableJob, submit

worker_context = ContextVar("remediation_worker_context", default=None)

# Bump whenever planning semantics change; persisted previews must not survive
# changes to the decisions or evidence that a user is asked to approve.
PLAN_REVISION = 2
PLAN_REVIEW_REQUIRED = "The remediation planner has changed. Open Remediate from the service to review and confirm a new plan."
PLAN_CHANGED = "The retained source or remediation plan no longer matches your confirmation. Open Remediate from the service to review and confirm a new plan."


class PlanReviewRequired(ValueError):
    """Only fixed, safe review guidance may be exposed in job diagnostics."""

    def __init__(self, *, revision=False):
        super().__init__(PLAN_REVIEW_REQUIRED if revision else PLAN_CHANGED)


def check_worker():
    context = worker_context.get()
    if context is not None:
        context.check()


KINDS = ("cyber_release_publish", "remediation_plan", "remediation_execute", "remediation_validate", "remediation_deliver")


def _source(db, service_id, source_id=None):
    query = select(Execution).options(load_only(Execution.id, Execution.service_id,
        Execution.service_version_id, Execution.payload_digest, Execution.execution_key))
    query = query.where(Execution.service_id == service_id)
    query = query.where(Execution.id == source_id) if source_id else query.order_by(Execution.scanned_at.desc(), Execution.id.desc())
    row = db.scalar(query.limit(1))
    if row is None:
        raise HTTPException(422, "No retained source assessment is available")
    return row


def request_plan(db, service, actor_id, finding_type=None, finding_id=None, preview=False):
    source = _source(db, service.id)
    vex_token = native_vex_token(db, service.id)
    # Exact execution and finding scope: previews share the service plan's worker
    # result, never a second synchronous planner or an unbound newer snapshot.
    payload = {"native_vex_token": vex_token, "planner_revision": PLAN_REVISION, "source_execution_id": source.id, "source_version_id": source.service_version_id,
               "finding_type": finding_type, "finding_id": finding_id}
    key = f"plan:v{PLAN_REVISION}:{service.id}:{actor_id}:{source.id}:{source.payload_digest}:{finding_type}:{finding_id}:{vex_token}"
    job = submit(db, kind="remediation_plan", payload=payload, service_id=service.id,
        requested_by_id=actor_id, source_execution_id=source.id, dedupe_key=key)
    state = {"job_id": job.id, "status": job.status, "stage": job.stage,
             "progress": job.progress, "pending": job.status in {"queued", "running"},
             "status_url": f"/api/v1/jobs/{job.id}", "error": job.error}
    if job.status == "completed":
        result = job.result or {}
        return {**(result.get("preview", {}) if preview else result.get("plan", {})), **state}
    return state


def confirmed_plan(db, service, source_id, digest, finding_type, finding_id):
    try:
        source = _source(db, service.id, source_id)
    except HTTPException:
        raise HTTPException(409, "The confirmed source assessment is no longer available") from None
    jobs = db.scalars(select(DurableJob).where(DurableJob.kind == "remediation_plan",
        DurableJob.service_id == service.id, DurableJob.source_execution_id == source_id,
        DurableJob.status == "completed", DurableJob.result["plan"]["plan_digest"].as_string() == digest))
    for job in jobs:
        payload = job.payload or {}
        if (payload.get("finding_type"), payload.get("finding_id"), payload.get("source_version_id")) != (finding_type, finding_id, source.service_version_id):
            continue
        if payload.get("native_vex_token") != native_vex_token(db, service.id):
            continue
        plan = (job.result or {}).get("plan") or {}
        if payload.get("planner_revision") != PLAN_REVISION or plan.get("planner_revision") != PLAN_REVISION:
            continue
        if plan.get("source_execution_id") == source_id:
            return source, plan
    raise HTTPException(409, "The completed source plan is unavailable or has changed. Open Remediate from the service to review and confirm a new plan.")


def enqueue_record(db, record, kind, attempt_id=None, requested_by_id=None):
    # The queue insert commits the existing domain record in the same transaction.
    payload = {"record_id": record.id}
    if attempt_id is not None:
        from .remediation_delivery import DeliveryAttempt
        attempt = db.get(DeliveryAttempt, attempt_id)
        payload["attempt_id"] = attempt_id
        payload["required_permissions"] = ["service.export"]
        if attempt and (attempt.result or {}).get("delivery_mode") == "oci":
            payload["required_permissions"].append("artifact.publish")
    key = f"{kind}:{attempt_id or record.id}"
    if kind == "remediation_validate":
        # An explicit new validation after a completed attempt is a new request.
        import uuid
        key += ":" + uuid.uuid4().hex
    return submit(db, kind=kind, payload=payload, service_id=record.service_id,
        requested_by_id=requested_by_id or record.requested_by_id, source_execution_id=record.source_execution_id,
        version=str(record.source_version_id or ""), dedupe_key=key, max_attempts=3)


def native_vex_token(db, service_id, now=None):
    """Bind prospective work to currently effective evidence, including expiry."""
    from . import native_vex as nv
    from .risk_profiles import utcnow, digest
    from .native_vex_models import VexDispositionEvaluation as Evaluation, VexDispositionService as State, VexDispositionPolicy as Policy
    evaluation = db.scalar(select(Evaluation.id).select_from(Evaluation).join(State, State.service_id == Evaluation.service_id)
        .join(Policy, Policy.id == 1).where(Evaluation.service_id == service_id, *nv.current_evaluation(now or utcnow())))
    return digest({'policy': nv.cache_token(db), 'evaluation': evaluation})


def filter_native_vex_images(db, service_id, execution_id, plan, now=None):
    """Filter new image proposals only; retained scanner/job evidence is immutable.

    An image is removed when every observation or every proposed entry is excluded. Mixed
    images remain patch candidates; scanner entries are removed only on an exact
    CVE/package/version/image match with no unresolved duplicate observation.
    """
    from . import native_vex as nv
    from .risk_profiles import utcnow
    from .models import Finding, FindingObservation as Observation
    now = now or utcnow()
    rows = db.execute(select(Observation, Finding.cve, nv.observation_excluded(Observation.id, now))
        .join(Finding, Finding.id == Observation.finding_id).where(Finding.service_id == service_id,
            Observation.execution_id == execution_id)).all()
    images, identities = {}, {}
    for observation, cve, excluded in rows:
        image = str(observation.image or '').strip()
        images.setdefault(image, []).append(bool(excluded))
        key = (image, cve, observation.package, observation.installed_version)
        identities.setdefault(key, []).append(bool(excluded))
    kept = []
    for image in plan.get('images', []):
        reference = str(image.get('original') or '').strip()
        payload_entries = image.get('vulnerabilities', [])
        payload_verified = all(identities.get((reference, item.get('cve'), item.get('package'), item.get('installed_version')))
            for item in payload_entries)
        if images.get(reference) and all(images[reference]) and payload_verified:
            continue
        if 'vulnerabilities' in image:
            image['vulnerabilities'] = [item for item in image['vulnerabilities']
                if not (identities.get((reference, item.get('cve'), item.get('package'), item.get('installed_version')))
                    and all(identities[(reference, item.get('cve'), item.get('package'), item.get('installed_version'))]))]
        # An emptied scoped proposal must never become an unrestricted image patch.
        if payload_entries and not image.get('vulnerabilities'):
            continue
        kept.append(image)
    plan['images'] = kept
    return plan
