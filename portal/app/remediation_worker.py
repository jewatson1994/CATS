"""Remediation orchestration process. Image patching remains in patch-worker.

Run with ``python -m app.remediation_worker``. Runtime validation is delegated
by the retained validation workflow to the enrolled remote validator.
"""
from sqlalchemy import select
from .durable_jobs import JobError, run_worker
from .remediation_jobs import KINDS


def _fail_record(db, job, payload, detail):
    """Do not strand a domain action when its durable dispatcher terminates."""
    from . import main
    from .models import RemediationExecution
    from .remediation_delivery import DeliveryAttempt
    record = db.get(RemediationExecution, payload.get("record_id")) if payload.get("record_id") else None
    if not record or record.service_id != job.service_id:
        return
    if job.kind == "remediation_execute" and record.status in {"queued", "running"}:
        record.status = record.remediation_status = record.phase = "failed"
        record.failure_reason = detail
        record.completed_at = main.utcnow()
    elif job.kind == "remediation_validate" and record.verification_status in {"queued", "running"}:
        prior = (record.validation_results or {}).get("deployment") or {}
        record.verification_status = "unavailable"
        record.validation_results = {**(record.validation_results or {}), "deployment": {
            **prior, "status": "UNAVAILABLE", "cleanup_status": "UNKNOWN" if prior.get("request_id") else "NOT_REQUIRED", "detail": detail}}
    elif job.kind == "remediation_deliver":
        attempt = db.get(DeliveryAttempt, payload.get("attempt_id"))
        if attempt and attempt.remediation_id == record.id and attempt.status in {"queued", "running", "staged", "publishing"}:
            attempt.status = record.delivery_status = "failed"
            attempt.completed_at = main.utcnow()
            attempt.result = {**(attempt.result or {}), "error": detail}
    db.commit()


def _handle(ctx, payload):
    from . import main
    from .auth import AuthContext
    from .models import User, Service, Execution, RemediationExecution
    from .remediation_delivery import DeliveryAttempt
    ctx.check()
    with main.SessionLocal() as db:
        actor = db.get(User, ctx.job.requested_by_id)
        auth = AuthContext(user=actor, session=None) if actor and actor.enabled else None
        service = db.get(Service, ctx.job.service_id)
        permission = "service.export" if ctx.job.kind == "remediation_deliver" else "remediation.execute"
        if (not service or service.lifecycle_status != "active" or not auth or not auth.has(permission, ctx.job.service_id)
                or any(not auth.has(required, ctx.job.service_id) for required in payload.get("required_permissions", []))):
            detail = "Service or remediation access is unavailable. An authorized manager must submit a new request."
            _fail_record(db, ctx.job, payload, detail)
            raise JobError(detail)
    if ctx.job.kind == "remediation_plan":
        ctx.stage("Resolving retained evidence and chart mappings", 10)
        with main.SessionLocal() as db:
            service = db.get(Service, ctx.job.service_id)
            execution = db.get(Execution, payload["source_execution_id"])
            if not service or not execution or execution.service_id != service.id or execution.service_version_id != payload.get("source_version_id"):
                raise JobError("The selected assessment/version is no longer available. Select a retained assessment and rebuild the plan.")
            _, plan = main._retained_remediation_plan(db, service, execution,
                payload.get("finding_type"), payload.get("finding_id"))
            public = {**main._public_remediation_plan(db, execution, plan), "plan_digest": main.plan_digest(plan)}
            preview = {"images": len({row.get("original") for row in plan.get("images", [])}),
                "charts": len(public.get("charts", [])),
                "configuration_changes": sum(row.get("classification") == "AUTO-REMEDIABLE" for row in plan.get("configuration_changes", [])),
                "manual_review": sum(row.get("classification") == "REVIEW REQUIRED" for row in plan.get("configuration_changes", []))}
            url = f"/services/{service.service_key}?view=remediations"
        ctx.check()
        return {"plan": public, "preview": preview, "result_url": url}
    with main.SessionLocal() as db:
        record = db.get(RemediationExecution, payload["record_id"])
        if not record or record.service_id != ctx.job.service_id or record.source_execution_id != ctx.job.source_execution_id:
            raise JobError("The retained remediation record is no longer available.")
        url = f"/services/{record.service.service_key}/remediations/{record.job_key}"
        if ctx.job.kind == "remediation_execute":
            # Candidate creation can invoke external patch/publication operations.
            # Never repeat an interrupted orchestration blindly. Preserve receipts
            # and require the existing explicit retry workflow after reconciliation.
            if record.status == "running":
                record.status = record.remediation_status = record.phase = "failed"
                record.failure_reason = "Worker interrupted during candidate preparation. Review retained patch receipts, then explicitly retry this exact source."
                record.completed_at = main.utcnow()
                db.commit()
                raise JobError(record.failure_reason)
            if record.status == "failed":
                raise JobError(record.failure_reason or "Candidate preparation failed; review its results.")
            if record.status != "queued":
                return {"result_url": url, "record_id": record.id}
            if main.cleanup_remediation_artifacts(db, main.REMEDIATION_JOB_ROOT)["over_quota"]:
                _fail_record(db, ctx.job, payload, "Retained remediation storage is full. Free expired outputs before retrying.")
                raise JobError("Retained remediation storage is full. Free expired outputs before retrying.")
            db.commit()
        elif ctx.job.kind == "remediation_validate":
            if record.verification_status == "running":
                prior = (record.validation_results or {}).get("deployment") or {}
                if not prior.get("validation_id"):
                    record.verification_status = "unavailable"
                    record.validation_results = {**(record.validation_results or {}), "deployment": {
                        **prior, "status": "UNAVAILABLE", "cleanup_status": "UNKNOWN",
                        "detail": "Worker interrupted before remote validation identity was retained; reconcile validator cleanup before retrying."}}
                    db.commit()
                    raise JobError("Validation was interrupted. Reconcile remote cleanup before retrying.")
                record.verification_status = "queued"
                record.validation_results = {**(record.validation_results or {}), "deployment": {**prior, "cleanup_status": "UNKNOWN"}}
                db.commit()
        elif ctx.job.kind == "remediation_deliver":
            attempt = db.get(DeliveryAttempt, payload["attempt_id"])
            if not attempt or attempt.remediation_id != record.id:
                raise JobError("The retained delivery attempt is unavailable.")
            if attempt.status in {"running", "staged", "publishing"}:
                attempt.status = record.delivery_status = "failed"
                attempt.completed_at = main.utcnow()
                attempt.result = {**(attempt.result or {}), "interrupted": True,
                    "error": "Worker interrupted. Review retained publication receipts before explicitly retrying delivery."}
                db.commit()
                raise JobError("Delivery interrupted; review publication receipts before retrying.")
    ctx.checkpoint({"result_url": url, "record_id": payload["record_id"]})
    ctx.check()
    if ctx.job.kind == "remediation_execute":
        ctx.stage("Preparing candidate, coordinating patch-worker and scanning changes", 15)
        main._run_remediation_job(payload["record_id"])
    elif ctx.job.kind == "remediation_validate":
        ctx.stage("Coordinating remote candidate validation", 20)
        main._run_retained_remediation_validation(payload["record_id"])
    elif ctx.job.kind == "remediation_deliver":
        ctx.stage("Assembling retained delivery and verifying publication", 20)
        main._run_delivery_attempt(payload["attempt_id"])
    with main.SessionLocal() as db:
        record = db.get(RemediationExecution, payload["record_id"])
        if ctx.job.kind == "remediation_execute" and record.status == "failed":
            raise JobError(record.failure_reason or "Candidate preparation failed. Review its results.")
        if ctx.job.kind == "remediation_validate" and record.verification_status not in {"verified", "passed", "complete"}:
            raise JobError("Candidate validation did not pass. Review the retained validation diagnostics.")
        if ctx.job.kind == "remediation_deliver":
            attempt = db.get(DeliveryAttempt, payload["attempt_id"])
            if attempt.status not in {"published", "download_ready"}:
                raise JobError("Delivery did not complete. Review the retained delivery and validation diagnostics.")
    return {"result_url": url, "record_id": payload["record_id"]}


def handle(ctx, payload):
    from . import main
    from .remediation_jobs import worker_context
    from .delivery_execution import delivery_lock
    token = worker_context.set(ctx)
    try:
        if ctx.job.kind == "cyber_release_publish":
            from .cyber_approvals import publish_job
            return publish_job(ctx, payload)
        if ctx.job.kind == "remediation_plan":
            return _handle(ctx, payload)
        # A lease-expired process can still be alive. The OS lock prevents its
        # replacement from mutating the same domain record while it unwinds.
        with delivery_lock(main.REMEDIATION_JOB_ROOT / ".worker-locks", payload["record_id"]) as owned:
            if not owned:
                raise RuntimeError("Previous remediation owner is still releasing its lock")
            return _handle(ctx, payload)
    finally:
        worker_context.reset(token)


def maintenance():
    """Adopt pre-upgrade work and reconcile dispatchers that exhausted leases."""
    from . import main
    from .durable_jobs import DurableJob
    from .models import RemediationExecution
    from .remediation_delivery import DeliveryAttempt
    from .remediation_jobs import enqueue_record
    from .delivery_execution import delivery_lock
    with main.SessionLocal() as db:
        from .cyber_approvals import reconcile_jobs
        reconcile_jobs(db)
        records = db.scalars(select(RemediationExecution).where(
            (RemediationExecution.status.in_(["queued", "running"])) |
            (RemediationExecution.verification_status.in_(["queued", "running"])) |
            (RemediationExecution.delivery_status.in_(["queued", "running", "staged", "publishing"]))).limit(200)).all()
        for record in records:
            with delivery_lock(main.REMEDIATION_JOB_ROOT / ".worker-locks", record.id) as owned:
                if not owned:
                    continue
                db.refresh(record)
                work = []
                if record.status in {"queued", "running"}:
                    work.append(("remediation_execute", None, record.requested_by_id))
                if record.verification_status in {"queued", "running"}:
                    work.append(("remediation_validate", None, record.requested_by_id))
                attempts = db.scalars(select(DeliveryAttempt).where(DeliveryAttempt.remediation_id == record.id,
                    DeliveryAttempt.status.in_(["queued", "running", "staged", "publishing"]))).all()
                work.extend(("remediation_deliver", item.id, item.actor_id) for item in attempts)
                for kind, attempt_id, actor_id in work:
                    query = select(DurableJob).where(DurableJob.kind == kind,
                        DurableJob.service_id == record.service_id,
                        DurableJob.payload["record_id"].as_integer() == record.id)
                    if attempt_id:
                        query = query.where(DurableJob.payload["attempt_id"].as_integer() == attempt_id)
                    job = db.scalar(query.order_by(DurableJob.created_at.desc()).limit(1))
                    if job is None:
                        enqueue_record(db, record, kind, attempt_id, actor_id)
                    elif job.status in {"failed", "cancelled"}:
                        _fail_record(db, job, job.payload,
                            "Worker recovery could not complete this action. Review retained results and publication or cleanup receipts before explicitly retrying.")


if __name__ == "__main__":
    run_worker(KINDS, handle, maintenance=maintenance)
