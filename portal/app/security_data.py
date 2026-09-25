"""Configured runtime security-data adapters with staged activation."""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import urllib.parse
import urllib.request
import uuid


SOURCE_KEYS = {"kev", "epss", "grype", "trivy"}
MAX_UPLOAD = 1024 * 1024 * 1024


def _validate_feed(key: str, data: bytes) -> str:
    if key == "kev":
        payload = json.loads(data)
        rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) or not row.get("cveID") for row in rows):
            raise ValueError("KEV feed must contain vulnerability records with cveID")
        return str(payload.get("dateReleased") or payload.get("catalogVersion") or len(rows))[:240]
    if key == "epss":
        decoded = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
        lines = (line for line in decoded.decode("utf-8-sig").splitlines() if not line.startswith("#"))
        rows = list(csv.DictReader(lines))
        if not rows or any(not row.get("cve") or not row.get("epss") or not 0 <= float(row["epss"]) <= 1 for row in rows):
            raise ValueError("EPSS feed must contain CVE and score columns")
        return str(len(rows)) + " records"
    raise ValueError("Unknown intelligence feed")


def _activate_file(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".cats-update-", delete=False) as stream:
        staged = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(staged, destination)
    finally:
        staged.unlink(missing_ok=True)


def _activate_directory(staged: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup = destination.with_name(destination.name + ".backup-" + uuid.uuid4().hex)
    moved_old = False
    try:
        if destination.exists():
            destination.rename(backup)
            moved_old = True
        staged.rename(destination)
    except Exception:
        if moved_old and not destination.exists():
            backup.rename(destination)
        raise
    finally:
        if backup.exists() and destination.exists():
            shutil.rmtree(backup, ignore_errors=True)


def _run(command: list[str], env: dict[str, str]) -> str:
    completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=600)
    if completed.returncode:
        raise ValueError(f"{Path(command[0]).name} rejected the candidate database")
    return completed.stdout


def _check_sqlite(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("Candidate database file is missing or empty")
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Candidate database integrity check failed")


def _refresh_scanner(key: str, source: str, uploaded: bytes | None, ca_bundle: str | None) -> str:
    if key == "grype":
        destination = Path(os.getenv("GRYPE_DB_CACHE_DIR", "/opt/catscan/grype-db"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        binary = shutil.which("grype")
        if not binary:
            raise ValueError("Grype is unavailable")
        with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
            stage = Path(temporary) / "db"
            stage.mkdir()
            archive = Path(temporary) / "candidate.tar.zst"
            if uploaded is not None:
                archive.write_bytes(uploaded)
            else:
                archive.write_bytes(_download(source, ca_bundle))
            env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(stage), GRYPE_DB_AUTO_UPDATE="false",
                       GRYPE_DB_REQUIRE_UPDATE_CHECK="false", GRYPE_DB_VALIDATE_AGE="false")
            _run([binary, "db", "import", str(archive)], env)
            status = _run([binary, "db", "status", "-o", "json"], env)
            databases = list(stage.rglob("vulnerability.db"))
            if not databases:
                raise ValueError("Grype candidate has no vulnerability.db")
            _check_sqlite(databases[0])
            try:
                metadata = json.loads(status)
                version = str(metadata.get("built") or metadata.get("schemaVersion") or "Imported Grype database")[:240]
            except (ValueError, TypeError):
                version = "Imported Grype database"
            _activate_directory(stage, destination)
        return version
    if key == "trivy":
        if uploaded is not None:
            raise ValueError("Trivy offline upload is unsupported; configure an OCI DB repository mirror")
        destination = Path(os.getenv("TRIVY_CACHE_DIR", "/opt/catscan/trivy-cache"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        binary = shutil.which("trivy")
        if not binary:
            raise ValueError("Trivy is unavailable")
        with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
            stage = Path(temporary) / "cache"
            stage.mkdir()
            from .trusted_ca import write_additive_bundle
            bundle = write_additive_bundle(Path(temporary) / "ca.pem", [{"pem": ca_bundle}]) if ca_bundle else None
            environment = dict(os.environ, TRIVY_SKIP_CHECK_UPDATE="true")
            if bundle:
                environment["SSL_CERT_FILE"] = str(bundle)
            _run([binary, "image", "--download-db-only", "--db-repository", source,
                  "--cache-dir", str(stage)], environment)
            if not (stage / "db" / "trivy.db").is_file() or not (stage / "db" / "metadata.json").is_file():
                raise ValueError("Trivy candidate has no native database")
            _check_sqlite(stage / "db" / "trivy.db")
            try:
                metadata = json.loads((stage / "db" / "metadata.json").read_text(encoding="utf-8"))
                version = str(metadata.get("Version") or metadata.get("UpdatedAt") or "Downloaded Trivy database")[:240]
            except (OSError, ValueError, TypeError):
                version = "Downloaded Trivy database"
            _activate_directory(stage, destination)
        return version
    raise ValueError("Unknown scanner database")


def _download(source: str, ca_bundle: str | None) -> bytes:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError("Configured source must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Source references cannot contain credentials, query strings, or fragments")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Remote sources must use HTTPS")
    context = ssl.create_default_context()
    if ca_bundle:
        context.load_verify_locations(cadata=ca_bundle)
    request = urllib.request.Request(source, headers={"User-Agent": "CATS-security-data/1"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("Configured source redirected; configure the final endpoint explicitly")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect)
    with opener.open(request, timeout=30) as response:
        data = response.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise ValueError("Security data download exceeds size limit")
    return data


def refresh(key: str, source: str, uploaded: bytes | None = None, ca_bundle: str | None = None) -> str:
    if key not in SOURCE_KEYS:
        raise ValueError("Unknown security data source")
    if uploaded is not None and len(uploaded) > MAX_UPLOAD:
        raise ValueError("Security data upload exceeds size limit")
    if key in {"grype", "trivy"}:
        return _refresh_scanner(key, source, uploaded, ca_bundle)
    data = uploaded if uploaded is not None else _download(source, ca_bundle)
    version = _validate_feed(key, data)
    policy_dir = Path(os.getenv("CATS_POLICY_DATA_DIR", "/app/policy"))
    _activate_file(policy_dir / ("kev.json" if key == "kev" else "epss.csv"), data)
    from .policy_data import kev_cves, epss_scores
    kev_cves.cache_clear()
    epss_scores.cache_clear()
    return version
