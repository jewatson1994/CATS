"""Cancellation wins when ingestion releases a transaction lock."""
from sqlalchemy import event
import pytest

from test_scan_worker_coordination import (
    database, protocol, enqueue, coordination, result_content, submit_result,
)


@pytest.mark.parametrize("job_kind", ["scan", "sbom"])
def test_cancel_after_source_publication_prevents_ingestion(database, protocol, tmp_path, job_kind):
    worker_protocol, main = protocol
    enqueue()
    coordination.DurableJobs().update_job("job", {"job_kind": job_kind})
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    submit_result(worker_protocol, claim, result_content(tmp_path, claim))
    sources = main.PUBLIC_JOB_ROOT / "job" / "attempts" / claim["attempt_id"] / "sources"
    sources.mkdir()
    (sources / "Chart.yaml").write_text("name: fixture\nversion: 1.0.0\n")
    ingestions = []
    main.ingest_public_scan = lambda **kwargs: ingestions.append(kwargs)
    cancelled = False

    def cancel_after_commit(session):
        nonlocal cancelled
        if cancelled or not (main.PUBLIC_JOB_ROOT / "job" / "input" / "worker-charts").exists():
            return
        cancelled = True
        coordination.DurableJobs().update_job("job", {"status": "cancelled"})

    event.listen(database.class_, "after_commit", cancel_after_commit)
    try:
        worker_protocol.ingest_one()
    finally:
        event.remove(database.class_, "after_commit", cancel_after_commit)
    assert cancelled
    assert coordination.DurableJobs()["job"]["status"] == "cancelled"
    assert ingestions == []
