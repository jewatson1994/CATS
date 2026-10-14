"""Exercise real queued export generation before inspecting downloaded bytes."""
import os
from tempfile import TemporaryDirectory
from unittest.mock import patch


def completed_export(client, url, **kwargs):
    from app.durable_jobs import DurableJob, claim, execute
    from app.export_worker import generate
    from test_portal import SessionLocal

    response = client.get(url, **kwargs)
    if response.status_code != 202:
        return response
    identifier = response.json()["job_id"]
    with TemporaryDirectory(prefix="cats-export-test-") as root:
        with patch.dict(os.environ, {"CATS_EXPORT_JOB_ROOT": root}):
            job = claim(("export",), "export-regression", SessionLocal)
            assert job and job.id == identifier
            execute(job, generate, SessionLocal)
            with SessionLocal() as db:
                completed = db.get(DurableJob, identifier)
                assert completed.status == "completed", completed.error
                return client.get(completed.result["download_url"])
