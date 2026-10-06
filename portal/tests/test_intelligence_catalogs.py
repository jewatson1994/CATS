"""EPSS/KEV catalog loading: metadata, validation, refresh and visible failure states."""
import gzip
import json
import os

import pytest

from app import policy_data, security_data

FIRST_FEED = (
    "#model_version:v2026.06.15,score_date:2026-06-29T12:00:29Z\n"
    "cve,epss,percentile\n"
    "CVE-2026-0001,0.97,0.999\n"
    "cve-2026-0002,0.01,0.20\n"
)


@pytest.fixture
def catalog_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_data, "DATA_DIR", tmp_path)
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    policy_data.kev_cves.cache_clear()
    policy_data.epss_scores.cache_clear()
    yield tmp_path
    policy_data.kev_cves.cache_clear()
    policy_data.epss_scores.cache_clear()


def _bump(path):
    """Force a distinct file signature even on coarse filesystem timestamps."""
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))


def test_published_feed_with_model_metadata_loads_every_record(catalog_dir):
    (catalog_dir / "epss.csv").write_bytes(gzip.compress(FIRST_FEED.encode()))
    scores = policy_data.epss_scores()
    assert dict(scores) == {"CVE-2026-0001": 0.97, "CVE-2026-0002": 0.01}
    assert policy_data.epss_percentiles()["CVE-2026-0001"] == 0.999
    status = policy_data.intelligence_status()["epss"]
    assert status["state"] == "LOADED" and status["records"] == 2 and status["rejected"] == 0
    assert status["metadata"] == {"model_version": "v2026.06.15", "score_date": "2026-06-29T12:00:29Z"}
    assert policy_data.risk_metadata("cve-2026-0001") == (False, 0.97)


def test_bundled_catalog_is_not_empty():
    bundled = os.path.join(os.path.dirname(__file__), "..", "..", "cats-image", "policy", "epss.csv")
    if not os.path.exists(bundled):
        pytest.skip("bundled catalog not present in this checkout")
    with open(bundled, "rb") as handle:
        catalog = policy_data.parse_epss(handle.read(), strict=True)
    # No population size is hard-coded; the bundled feed must simply be usable.
    assert catalog.records > 0 and catalog.metadata.get("model_version")


@pytest.mark.parametrize("feed", [
    "cve,epss\nCVE-1,1.5\n", "cve,epss\nCVE-1,abc\n", "cve,epss\n,0.5\n",
    "cve,epss,percentile\nCVE-1,0.5,2\n", "cve,epss\nCVE-1,nan\n",
])
def test_strict_validation_rejects_malformed_records(feed):
    with pytest.raises(ValueError):
        policy_data.parse_epss(feed.encode(), strict=True)


@pytest.mark.parametrize("feed", ["", "#model_version:v1\n", "cve,epss\n", "name,score\nCVE-1,0.5\n"])
def test_empty_or_headerless_feeds_are_rejected(feed):
    with pytest.raises(ValueError):
        policy_data.parse_epss(feed.encode(), strict=False)


def test_runtime_skips_malformed_rows_without_blanking_catalog(catalog_dir):
    (catalog_dir / "epss.csv").write_text("cve,epss\nCVE-1,0.5\nCVE-2,bad\n\nCVE-3,0.25\n")
    assert dict(policy_data.epss_scores()) == {"CVE-1": 0.5, "CVE-3": 0.25}
    assert policy_data.intelligence_status()["epss"]["rejected"] == 1


def test_unusable_installed_catalog_is_reported_not_silently_empty(catalog_dir):
    (catalog_dir / "epss.csv").write_text("#model_version:v1\nnot,a,feed\n")
    (catalog_dir / "kev.json").write_text('{"vulnerabilities": []}')
    assert policy_data.epss_scores() == {} and policy_data.kev_cves() == frozenset()
    status = policy_data.intelligence_status()
    assert status["epss"]["state"] == "INVALID" and status["kev"]["state"] == "INVALID"
    (catalog_dir / "epss.csv").unlink(); policy_data.epss_scores.cache_clear()
    assert policy_data.intelligence_status()["epss"]["state"] == "MISSING"


def test_changed_catalog_file_is_reloaded_and_changes_token(catalog_dir, monkeypatch):
    monkeypatch.setattr(policy_data, "STAT_INTERVAL_SECONDS", 0)
    path = catalog_dir / "epss.csv"
    path.write_text("cve,epss\nCVE-1,0.1\n")
    token = policy_data.risk_catalog_token()
    path.write_text(FIRST_FEED); _bump(path)
    assert policy_data.epss_scores()["CVE-2026-0001"] == 0.97
    assert policy_data.risk_catalog_token() != token


def test_refresh_accepts_published_format_and_runtime_reads_it(catalog_dir):
    version = security_data.refresh("epss", "", gzip.compress(FIRST_FEED.encode()))
    assert version == "2 records (model v2026.06.15, scored 2026-06-29T12:00:29Z)"
    assert policy_data.epss_scores()["CVE-2026-0002"] == 0.01
    with pytest.raises(ValueError):
        security_data.refresh("epss", "", b"#model_version:v2\ncve,epss\n")
    assert policy_data.epss_scores()["CVE-2026-0002"] == 0.01


def test_kev_metadata_and_validation(catalog_dir):
    feed = {"catalogVersion": "2026.06.25", "dateReleased": "2026-06-25", "vulnerabilities": [{"cveID": "cve-2026-9"}]}
    assert security_data.refresh("kev", "", json.dumps(feed).encode()) == "2026-06-25"
    assert policy_data.kev_cves() == frozenset({"CVE-2026-9"})
    assert policy_data.intelligence_status()["kev"]["metadata"]["catalog_version"] == "2026.06.25"
    with pytest.raises(ValueError):
        security_data.refresh("kev", "", b'{"vulnerabilities": [{"name": "missing id"}]}')
