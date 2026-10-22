"""Actual claimant termination against PostgreSQL in a disposable schema."""
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from test_portal import Base
from app.durable_jobs import DurableJob, JobContext, LeaseLost, claim, now, recover, submit


@pytest.mark.skipif(not os.getenv("CATS_TEST_POSTGRES_URL"), reason="Requires disposable PostgreSQL")
def test_killed_claimant_restarts_with_checkpoint_and_fences_old_owner(tmp_path):
    url = os.environ["CATS_TEST_POSTGRES_URL"]
    engine = create_engine(url)
    schema = "cats_restart_" + uuid.uuid4().hex
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated = create_engine(url, connect_args={"options": f"-c search_path={schema}"})
    sessions = sessionmaker(bind=isolated, expire_on_commit=False)
    process = None
    try:
        Base.metadata.create_all(isolated)
        with sessions() as db:
            submitted = submit(db, kind="restart-test", payload={}, dedupe_key="one-attempt")
        ready = tmp_path / "claimed.json"
        script = """
import json, os, time
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import models
from app.durable_jobs import claim, JobContext
engine=create_engine(os.environ['CATS_TEST_POSTGRES_URL'], connect_args={'options': '-c search_path='+os.environ['RESTART_SCHEMA']})
sessions=sessionmaker(bind=engine, expire_on_commit=False)
job=claim(('restart-test',), 'killed-worker', sessions)
assert job is not None
JobContext(job, sessions).checkpoint({'receipt': 'retained-external-attempt'})
Path(os.environ['RESTART_READY']).write_text(json.dumps({'job_id': job.id}))
while True: time.sleep(1)
"""
        env = dict(os.environ, RESTART_SCHEMA=schema, RESTART_READY=str(ready),
                   PYTHONPATH=os.pathsep.join(sys.path))
        errors = (tmp_path / "claimant-error.log").open("w")
        process = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-c", script],
                                   env=env, stdout=subprocess.DEVNULL, stderr=errors)
        errors.close()
        deadline = time.monotonic() + 20
        while not ready.exists() and time.monotonic() < deadline:
            assert process.poll() is None, process.communicate()
            time.sleep(0.02)
        assert ready.exists(), (tmp_path / "claimant-error.log").read_text()
        assert json.loads(ready.read_text())["job_id"] == submitted.id
        with sessions() as db:
            old_row = db.get(DurableJob, submitted.id)
            stale = JobContext(old_row, sessions)
        process.kill()
        process.wait(timeout=10)
        # Death alone does not bypass the database lease.
        assert claim(("restart-test",), "replacement", sessions) is None
        with sessions() as db:
            row = db.get(DurableJob, submitted.id)
            row.lease_until = now() - timedelta(seconds=1)
            db.commit()
            recover(db, ("restart-test",))
            row.available_at = now() - timedelta(seconds=1)
            db.commit()
        replacement = claim(("restart-test",), "replacement", sessions)
        assert replacement.attempts == 2
        assert replacement.result == {"receipt": "retained-external-attempt"}
        with pytest.raises(LeaseLost):
            stale.finish({"stale": True})
        JobContext(replacement, sessions).finish({"complete": True})
        with sessions() as db:
            assert db.get(DurableJob, submitted.id).status == "completed"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()

@pytest.mark.skipif(not os.getenv("CATS_TEST_POSTGRES_URL"), reason="Requires disposable PostgreSQL")
@pytest.mark.parametrize("cancel_requested", [False, True])
def test_postgres_production_worker_recovery(tmp_path, cancel_requested):
    """Production patch subprocess + real PG; controlled Docker, test coordinator.

    Supplements rather than replaces real Copa and full campaign integration.
    """
    from concurrent.futures import ThreadPoolExecutor
    from test_patch_service_recovery import test_real_patch_worker_kill_and_supervisor_restart
    url = os.environ["CATS_TEST_POSTGRES_URL"]
    schema = "cats_combined_" + uuid.uuid4().hex
    engine = create_engine(url)
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated = create_engine(url, connect_args={"options": f"-c search_path={schema}"})
    sessions = sessionmaker(bind=isolated, expire_on_commit=False)
    try:
        Base.metadata.create_all(isolated)
        with sessions() as db:
            submitted = submit(db, kind="patch-integration", payload={}, dedupe_key="combined")
        owned = claim(("patch-integration",), "patch-coordinator", sessions)
        context = JobContext(owned, sessions)
        context.checkpoint({"patch_job_id": "realworker"})
        # Runs the actual production worker, kills its entire process tree,
        # restarts the service reader and rejects replay of the retained attempt.
        test_real_patch_worker_kill_and_supervisor_restart(tmp_path)
        with sessions() as db:
            row = db.get(DurableJob, submitted.id)
            assert row.result == {"patch_job_id": "realworker"}
            assert submit(db, kind="patch-integration", payload={}, dedupe_key="combined").id == row.id
            row.cancel_requested = cancel_requested
            db.commit()
        assert claim(("patch-integration",), "premature", sessions) is None
        with sessions() as db:
            row = db.get(DurableJob, submitted.id)
            row.lease_until = now() - timedelta(seconds=1)
            db.commit()
            recover(db, ("patch-integration",))
            row.available_at = now() - timedelta(seconds=1)
            db.commit()
        with ThreadPoolExecutor(max_workers=4) as pool:
            contenders = list(pool.map(lambda n: claim(("patch-integration",), str(n), sessions), range(4)))
        winners = [job for job in contenders if job is not None]
        assert len(winners) == (0 if cancel_requested else 1)
        with pytest.raises(LeaseLost):
            context.finish({"stale_success": True})
        if winners:
            replacement = JobContext(winners[0], sessions)
            assert winners[0].attempts == 2
            assert winners[0].result == {"patch_job_id": "realworker"}
            replacement.finish(error="Retained patch worker stopped")
            with pytest.raises(LeaseLost):
                replacement.finish({"duplicate_success": True})
        with sessions() as db:
            row = db.get(DurableJob, submitted.id)
            assert row.status == ("cancelled" if cancel_requested else "failed")
            assert row.result == {"patch_job_id": "realworker"}
    finally:
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


@pytest.mark.skipif(not os.getenv("CATS_TEST_POSTGRES_URL"), reason="Requires disposable PostgreSQL")
@pytest.mark.parametrize("interruption", ["kill", "cancel"])
def test_actual_campaign_dispatch_interruption_postgres(tmp_path, monkeypatch, interruption):
    """Real campaign/dispatcher/patch subprocess; controlled Docker blocks pull."""
    from pathlib import Path
    from types import SimpleNamespace
    from sqlalchemy import select, func
    from fastapi import HTTPException
    from app import patch_campaigns as campaign
    from app.auth import AuthContext
    from app.models import User, Role, UserRoleAssignment, Service, ServiceImage, PatchExecution
    url = os.environ["CATS_TEST_POSTGRES_URL"]
    schema = "cats_campaign_restart_" + uuid.uuid4().hex
    engine = create_engine(url)
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated = create_engine(url, connect_args={"options": f"-c search_path={schema}"})
    sessions = sessionmaker(bind=isolated, expire_on_commit=False)
    process = None
    commands = tmp_path / "commands"
    commands.mkdir()
    interpreter = getattr(sys, "_base_executable", sys.executable)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), RESTART_SCHEMA=schema,
               CATS_PATCH_JOB_ROOT=str(tmp_path / "jobs"), CATS_PATCH_WORKER_URL="",
               CATS_PATCH_CLEAN_IMAGES="false", PATH=str(commands) + os.pathsep + os.environ["PATH"],
               CATS_TEST_TOOL_PID=str(tmp_path / "tool.pid"), CATS_TEST_PUBLICATION=str(tmp_path / "late-publication"))
    def stop():
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
        else:
            import signal
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
    try:
        if os.name == "nt":
            compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
            if not compiler.exists():
                pytest.skip("Controlled executable requires .NET compiler")
            source = commands / "Docker.cs"
            # A tool that would publish later exposes cancellation descendant leaks.
            source.write_text('class Docker { static void Main() { '
                'System.IO.File.WriteAllText(' + json.dumps(str(tmp_path / "tool.pid")) + ', System.Diagnostics.Process.GetCurrentProcess().Id.ToString()); '
                'System.Threading.Thread.Sleep(15000); '
                'System.IO.File.WriteAllText(' + json.dumps(str(tmp_path / "late-publication")) + ', "published"); } }')
            subprocess.run([str(compiler), "/nologo", "/out:" + str(commands / "docker.exe"), str(source)], check=True, capture_output=True)
        else:
            executable = commands / "docker"
            import shlex
            executable.write_text("#!/bin/sh\necho $$ > " + shlex.quote(str(tmp_path / "tool.pid")) + "\nsleep 5\necho published > " + shlex.quote(str(tmp_path / "late-publication")) + "\n")
            executable.chmod(0o755)
        Base.metadata.create_all(isolated)
        with sessions() as db:
            user = User(username="campaign-owner", display_name="Campaign Owner")
            role = Role(name="Campaign integration", permissions=["service.view", "scan.ingest", "remediation.execute"])
            service = Service(service_key="campaign-integration", name="Campaign Integration")
            db.add_all([user, role, service]); db.flush()
            db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, service_id=service.id))
            image = ServiceImage(service_id=service.id, image_reference="registry.example/test:latest", image_digest="sha256:" + "a" * 64)
            db.add(image); db.commit()
            auth = AuthContext(user, None)
            record = campaign.submit_campaign(db, auth, service, {"image_ids": [image.id], "destination_registry_id": "test", "destination_prefix": "patched"}, {"test": {"endpoint": "registry.example"}})
            db.commit()
            item = db.scalar(select(campaign.PatchCampaignItem))
            job_id, campaign_id, item_id, user_id = item.job_id, record.id, item.id, user.id
        script = """
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import main, patch_campaigns
from app.durable_jobs import claim, execute
from app.remediation_worker import handle
engine=create_engine(os.environ['CATS_TEST_POSTGRES_URL'], connect_args={'options': '-c search_path='+os.environ['RESTART_SCHEMA']})
sessions=sessionmaker(bind=engine, expire_on_commit=False)
main.SessionLocal=sessions
import shutil
print('controlled executable:', shutil.which('docker'), flush=True)
# Configuration fixture only: production authorization, handler, dispatcher,
# durable execution, persistence and worker remain unmodified.
patch_campaigns._registries=lambda db: {'test': {'endpoint': 'registry.example'}}
job=claim((patch_campaigns.KIND,), 'actual-campaign-worker', sessions)
assert job is not None
execute(job, handle, sessions)
"""
        with (tmp_path / "campaign.log").open("w") as log:
            process = subprocess.Popen([interpreter, "-c", script], env=env, stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 30
        state = None
        while time.monotonic() < deadline:
            assert process.poll() is None, (tmp_path / "campaign.log").read_text()
            candidates = list((tmp_path / "jobs").glob("*/output/patch-state.json"))
            if candidates:
                try:
                    if json.loads(candidates[0].read_text()).get("phase") == "acquiring_image":
                        state = candidates[0]
                        break
                except ValueError:
                    pass
            time.sleep(0.05)
        assert state is not None, (tmp_path / "campaign.log").read_text()
        deadline = time.monotonic() + 20
        while not (tmp_path / "tool.pid").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert (tmp_path / "tool.pid").exists(), (tmp_path / "campaign.log").read_text()
        with sessions() as db:
            row = db.get(DurableJob, job_id)
            stale = JobContext(row, sessions)
            assert row.kind == campaign.KIND and row.max_attempts == 1
            patch_id = db.get(campaign.PatchCampaignItem, item_id).patch_execution_id
            assert patch_id is not None
            assert db.scalar(select(func.count()).select_from(PatchExecution)) == 1
            if interruption == "cancel":
                monkeypatch.setattr(campaign, "_csrf", lambda *args: None)
                auth = AuthContext(db.get(User, user_id), None)
                campaign.item_action(campaign_id, item_id, "cancel", None, db, auth)
        if interruption == "kill":
            stop()
            assert claim((campaign.KIND,), "too-early", sessions) is None
            with sessions() as db:
                db.get(DurableJob, job_id).lease_until = now() - timedelta(seconds=1)
                db.commit()
            # The production one-attempt policy refuses redispatch after death.
            assert claim((campaign.KIND,), "replacement", sessions) is None
        else:
            process.wait(timeout=25)
            assert process.returncode == 0, (tmp_path / "campaign.log").read_text()
        with pytest.raises(LeaseLost):
            stale.finish({"patch_status": "PATCHED"})
        with sessions() as db:
            row = db.get(DurableJob, job_id)
            assert row.status == ("failed" if interruption == "kill" else "cancelled")
            assert row.result.get("patch_status") is None
            assert row.attempts == 1
            assert db.get(campaign.PatchCampaignItem, item_id).patch_execution_id == patch_id
            assert db.scalar(select(func.count()).select_from(PatchExecution)) == 1
            monkeypatch.setattr(campaign, "_csrf", lambda *args: None)
            with pytest.raises(HTTPException) as error:
                campaign.item_action(campaign_id, item_id, "retry", None, db, AuthContext(db.get(User, user_id), None))
            assert error.value.status_code == 409
        if interruption == "cancel":
            assert json.loads(state.read_text())["status"] == "cancelled"
            tool_pid = int((tmp_path / "tool.pid").read_text())
            if os.name == "nt":
                import ctypes
                kernel = ctypes.windll.kernel32
                kernel.OpenProcess.restype = ctypes.c_void_p
                handle = kernel.OpenProcess(0x1000, False, tool_pid)
                if handle:
                    code = ctypes.c_ulong()
                    assert kernel.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
                    kernel.CloseHandle(ctypes.c_void_p(handle))
                    assert code.value != 259, "Patch tool survived cancellation"
            else:
                with pytest.raises(ProcessLookupError):
                    os.kill(tool_pid, 0)
            # Beyond the controlled publication deadline, cancellation must not
            # permit the orphan tool to perform its delayed side effect.
            time.sleep(15.2)
            assert not (tmp_path / "late-publication").exists()
        assert not (state.parent / "patch-result.json").exists()
    finally:
        if process is not None and process.poll() is None:
            stop()
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
