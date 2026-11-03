import json
import urllib.request
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app import daily_security_data as daily, scan_intelligence, security_data
from app.durable_jobs import DurableJob, JobContext, JobError, LeaseLost, claim
from app.models import AuditEvent, PortalSetting, SecurityDataSource
from test_portal import SessionLocal, setup_function


def next_job():
    job = claim((daily.KIND,), "test-worker", SessionLocal)
    return JobContext(job, SessionLocal)


def test_scheduling_is_daily_deduplicated_and_can_be_disabled(monkeypatch):
    today = daily.now()
    for day in (today, today, today + timedelta(days=1)):
        monkeypatch.setattr(daily, "now", lambda: day)
        daily.maintenance()
    with SessionLocal() as db:
        rows = db.scalars(select(DurableJob)).all()
        assert len(rows) == 8 and {row.payload["key"] for row in rows} == security_data.SOURCE_KEYS
        db.add(PortalSetting(key=daily.AUTO_SETTING, value="false"))
        db.commit()
    monkeypatch.setattr(daily, "now", lambda: today + timedelta(days=2))
    daily.maintenance()
    monkeypatch.setattr(daily, "now", lambda: today)
    context = next_job()
    assert daily.handler(context, context.job.payload) == {"outcome": "skipped"}
    with SessionLocal() as db:
        assert len(list(db.scalars(select(DurableJob)))) == 8
        assert not db.scalar(select(AuditEvent).where(AuditEvent.action == "security_data.refresh_requested"))


def test_mirror_failure_retains_evidence_and_source_jobs_are_independent(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    previous = daily.now() - timedelta(days=2)
    old = b'{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}'
    (tmp_path / "kev.json").write_bytes(old)
    mirror = "https://private.example/kev.json"
    with SessionLocal() as db:
        db.add(SecurityDataSource(key="kev", source=mirror, installed_version="previous", last_success_at=previous))
        db.commit()
    requested = []
    def download(source, bundle):
        requested.append(source)
        if source == mirror:
            raise OSError("offline")
        return b"cve,epss\nCVE-2026-0001,0.5\n"
    monkeypatch.setattr(security_data, "_download", download)
    daily.maintenance()
    kev = next_job()
    with pytest.raises(JobError, match="KEV"):
        daily.handler(kev, kev.job.payload)
    with SessionLocal() as db:
        record = db.get(SecurityDataSource, "kev")
        assert record.status == "FAILED" and "offline" in record.failure_reason
        assert record.installed_version == "previous" and record.last_success_at.date() == previous.date()
        assert db.get(DurableJob, kev.job.id).result == {"outcome": "failed"}
    assert (tmp_path / "kev.json").read_bytes() == old
    epss = next_job()
    assert daily.handler(epss, epss.job.payload) == {"outcome": "updated"}
    assert requested == [mirror, security_data.DEFAULT_SOURCES["epss"]]
    assert "CVE-2026-0001,0.5" in (tmp_path / "epss.csv").read_text()
    with SessionLocal() as db:
        # Simulate a reclaimed job whose source committed before worker loss.
        result = db.get(DurableJob, epss.job.id).result
        epss.job.result = dict(result)
        assert db.get(SecurityDataSource, "epss").status == "READY"
    assert daily.handler(epss, epss.job.payload) == result
    assert len(requested) == 2


def test_worker_losing_lease_cannot_publish(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    daily.maintenance()
    context = next_job()
    def download(source, bundle):
        context.lost.set()
        return b'{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}'
    monkeypatch.setattr(security_data, "_download", download)
    with pytest.raises(LeaseLost):
        daily.handler(context, context.job.payload)
    assert not (tmp_path / "kev.json").exists()
    with SessionLocal() as db:
        assert not db.get(DurableJob, context.job.id).result


def test_refresh_yields_to_changed_mirror_on_sqlite(tmp_path, monkeypatch):
    with SessionLocal() as db:
        if db.get_bind().dialect.name != "sqlite":
            pytest.skip("PostgreSQL serializes this change via its source row lock")
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    daily.maintenance()
    context = next_job()
    def download(source, bundle):
        with SessionLocal() as db:
            db.get(SecurityDataSource, "kev").source = "https://mirror.example/kev"
            db.commit()
        return b'{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}'
    monkeypatch.setattr(security_data, "_download", download)
    assert daily.handler(context, context.job.payload) == {"outcome": "skipped"}
    assert not (tmp_path / "kev.json").exists()
    with SessionLocal() as db:
        assert db.get(SecurityDataSource, "kev").source == "https://mirror.example/kev"


def test_only_official_epss_redirect_is_allowed():
    request = urllib.request.Request(security_data.DEFAULT_SOURCES["epss"])
    handler = security_data._FeedRedirect()
    target = "https://epss.empiricalsecurity.com/epss_scores-2026-11-02.csv.gz"
    assert handler.redirect_request(request, None, 302, "Found", {}, target).full_url == target
    for url in (target.replace("https:", "http:"), target.replace(".com/", ".com.evil/"), target + "?token=hidden"):
        with pytest.raises(ValueError, match="redirected"):
            handler.redirect_request(request, None, 302, "Found", {}, url)


def test_daily_retention_preserves_manual_import_and_pinned_scan(tmp_path):
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    stage.mkdir()
    env = {"CATS_SCAN_GRYPE_SOURCE": str(source), "CATS_SCAN_TRIVY_SOURCE": str(tmp_path / "empty")}
    ids = []
    for number in range(6):
        (stage / "vulnerability.db").write_text(str(number))
        manifest = scan_intelligence.publish_generation(stage, source, "grype", {}, before_activate=(lambda: None) if number else None)
        ids.append(manifest["generation"])
        if number == 1:
            scan_intelligence.pin_databases(env, tmp_path / "scan")
    scan_intelligence.prune_scheduled(source)
    assert {directory.name for directory in (source / scan_intelligence.GENERATIONS).iterdir()} == {ids[0], *ids[-3:]}
    assert (Path(env["GRYPE_DB_CACHE_DIR"]) / "vulnerability.db").read_text() == "1"
    assert json.loads((source / scan_intelligence.POINTER).read_text())["generation"] == ids[-1]
