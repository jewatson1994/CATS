"""Durable boundary and recovery checks; load fixture is synthetic, not production."""
from datetime import timedelta
from time import perf_counter
import json

import pytest
from sqlalchemy import event, select

from app import main, durable_jobs, remediation_jobs, remediation_worker
from app.models import Execution, RemediationExecution, User
from app.remediation_delivery import DeliveryAttempt
from test_remediation_workflow_routes import workflow, start, candidate


def claimed(kind):
    job = durable_jobs.claim((kind,), "remediation-test", main.SessionLocal)
    assert job is not None
    return job, durable_jobs.JobContext(job, main.SessionLocal)


def test_synthetic_95_charts_1700_findings_queue_without_loading_or_planning(workflow, monkeypatch):
    db, service, execution, auth, _, _ = workflow
    files = {}
    for index in range(95):
        files[f"chart-{index}/Chart.yaml"] = f"apiVersion: v2\nname: chart-{index}\nversion: 1.0.0\n"
        files[f"chart-{index}/templates/config.yaml"] = f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config-{index}\ndata:\n  value: retained\n"
    execution.raw_payload = {"artifact_type": "helm", "helm_source_files": files,
        "policy_findings": [{"finding": "CUSTOM", "title": "Synthetic configuration evidence", "severity": "High",
            "target": f"ConfigMap/config-{index % 95}", "type": "configuration", "description": "Retained finding " + str(index)}
            for index in range(1700)]}
    db.commit(); db.expire_all()
    statements = []
    listener = lambda conn, cursor, sql, params, context, many: statements.append(sql)
    event.listen(db.bind, "before_cursor_execute", listener)
    real_planner = main._retained_remediation_plan
    monkeypatch.setattr(main, "_retained_remediation_plan", lambda *_args, **_kwargs: pytest.fail("Planner ran in portal request"))
    service_id, execution_id, service_key = service.id, execution.id, service.service_key
    db.expire_all()
    # Resolve the small service/auth objects before timing the request boundary.
    service = db.get(type(service), service_id)
    statements.clear()
    started = perf_counter()
    response = main.remediation_plan(service_key, db=db, auth=auth)
    preview = main.service_remediation_preview(service_key, db=db, auth=auth)
    elapsed = perf_counter() - started
    event.remove(db.bind, "before_cursor_execute", listener)
    assert response["status"] == "queued" and response["pending"]
    assert json.loads(preview.body)["job_id"] == response["job_id"]
    source_queries = [sql for sql in statements if "FROM executions" in sql]
    assert source_queries and all("raw_payload" not in sql for sql in source_queries)
    assert elapsed < 1.0, f"Synthetic enqueue + preview took {elapsed:.3f}s"
    # A replacement process can find and complete the same request after all
    # request sessions have expired. The expensive source inspection happens here.
    monkeypatch.setattr(main, "_retained_remediation_plan", real_planner)
    job, ctx = claimed("remediation_plan")
    result = remediation_worker.handle(ctx, job.payload)
    ctx.finish(result)
    assert result["plan"]["source_execution_id"] == execution_id
    assert len(result["plan"]["charts"]) == 95
    assert len(result["plan"]["configuration_changes"]) == 1700
    assert "helm_source_files" not in json.dumps(result)
    with main.SessionLocal() as fresh:
        durable = fresh.get(durable_jobs.DurableJob, response["job_id"])
        assert durable.status == "completed" and durable.result["plan"]["plan_digest"]
    print(f"Synthetic 95 charts / 1700 findings: enqueue+preview={elapsed:.3f}s")


def test_plan_worker_uses_bound_source_after_newer_scan(workflow):
    db, service, source, auth, _, _ = workflow
    response = main.remediation_plan(service.service_key, db=db, auth=auth)
    newer = Execution(service_id=service.id, execution_key="newer", scanned_at=main.utcnow() + timedelta(seconds=1),
                      complete=True, raw_payload={"artifact_type": "helm"})
    db.add(newer); db.commit()
    job, ctx = claimed("remediation_plan")
    result = remediation_worker.handle(ctx, job.payload)
    ctx.finish(result)
    assert result["plan"]["source_execution_id"] == source.id != newer.id
    assert job.id == response["job_id"]


@pytest.mark.parametrize("revocation", ["actor", "service"])
def test_revoked_work_fails_before_effects_and_releases_domain(workflow, monkeypatch, revocation):
    db, service, _, auth, _, _ = workflow
    start(workflow)
    record = db.scalar(select(RemediationExecution))
    if revocation == "actor":
        auth.user.enabled = False
    else:
        service.lifecycle_status = "archived"
    db.commit()
    monkeypatch.setattr(main, "_run_remediation_job", lambda *_: pytest.fail("Revoked work executed"))
    job, ctx = claimed("remediation_execute")
    with pytest.raises(durable_jobs.JobError, match="access is unavailable"):
        remediation_worker.handle(ctx, job.payload)
    db.refresh(record)
    assert record.status == "failed" and record.completed_at


def test_interrupted_candidate_does_not_repeat_external_patches(workflow, monkeypatch):
    db, _, _, _, _, _ = workflow
    start(workflow)
    record = db.scalar(select(RemediationExecution)); record.status = "running"; db.commit()
    monkeypatch.setattr(main, "_run_remediation_job", lambda *_: pytest.fail("Interrupted patch repeated"))
    job, ctx = claimed("remediation_execute")
    with pytest.raises(durable_jobs.JobError, match="explicitly retry"):
        remediation_worker.handle(ctx, job.payload)
    db.refresh(record)
    assert record.status == "failed"


def test_interrupted_validation_resumes_bound_remote_identity(workflow, monkeypatch):
    db, _, _, _, _, _ = workflow
    record = candidate(workflow)
    record.verification_status = "running"
    record.validation_results = {"deployment": {"validation_id": "remote-retained", "request_id": "retained-request"}}
    remediation_jobs.enqueue_record(db, record, "remediation_validate")
    observed = []
    def validate(record_id):
        with main.SessionLocal() as session:
            row = session.get(RemediationExecution, record_id)
            observed.append(row.validation_results["deployment"])
            row.verification_status = "verified"; session.commit()
    monkeypatch.setattr(main, "_run_retained_remediation_validation", validate)
    job, ctx = claimed("remediation_validate")
    result = remediation_worker.handle(ctx, job.payload)
    ctx.finish(result)
    assert observed == [{"validation_id": "remote-retained", "request_id": "retained-request", "cleanup_status": "UNKNOWN"}]


def test_exhausted_dispatcher_releases_domain_without_erasing_receipts(workflow):
    db, _, _, auth, _, _ = workflow
    record = candidate(workflow)
    attempt = DeliveryAttempt(remediation_id=record.id, actor_id=auth.user.id, status="publishing",
        content_digest=record.artifact_digest, result={"receipt": "retained"})
    db.add(attempt); db.flush(); record.delivery_status = "publishing"
    job = remediation_jobs.enqueue_record(db, record, "remediation_deliver", attempt.id)
    job.status = "failed"; db.commit()
    remediation_worker.maintenance()
    db.refresh(record); db.refresh(attempt)
    assert record.delivery_status == attempt.status == "failed"
    assert attempt.result["receipt"] == "retained"


def test_worker_lease_fences_patch_commands(workflow, monkeypatch):
    token = remediation_jobs.worker_context.set(type("Lost", (), {"check": lambda self: (_ for _ in ()).throw(durable_jobs.LeaseLost())})())
    try:
        monkeypatch.setattr(main, "_run_patch_job", lambda *_: pytest.fail("Lost owner dispatched a patch"))
        with pytest.raises(durable_jobs.LeaseLost):
            main._run_remediation_image_patches(None, None, None, {"images": []})
    finally:
        remediation_jobs.worker_context.reset(token)
