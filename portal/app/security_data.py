"""Configured runtime security-data adapters with staged activation."""

from __future__ import annotations

from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import tarfile
from typing import BinaryIO
import urllib.parse
import urllib.request
import uuid

from .scan_intelligence import publish_generation


DEFAULT_SOURCES = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "grype": "https://grype.anchore.io/databases/v6/latest.json",
    "trivy": "ghcr.io/aquasecurity/trivy-db",
}
SOURCE_KEYS = set(DEFAULT_SOURCES)
MAX_UPLOAD = 1024 * 1024 * 1024
MAX_GRYPE_LISTING = 1024 * 1024


def _validate_feed(key: str, data: bytes) -> str:
    # The runtime readers in policy_data use these same parsers, so an
    # accepted feed can never install as an apparently empty catalog.
    from .policy_data import parse_epss, parse_kev
    if key == "kev":
        catalog = parse_kev(data, strict=True)
        return str(catalog.metadata.get("date_released") or catalog.metadata.get("catalog_version")
                   or catalog.records)[:240]
    if key == "epss":
        catalog = parse_epss(data, strict=True)
        details = [value for value in (catalog.metadata.get("model_version") and f"model {catalog.metadata['model_version']}",
                                       catalog.metadata.get("score_date") and f"scored {catalog.metadata['score_date']}") if value]
        return (f"{catalog.records} records" + (f" ({', '.join(details)})" if details else ""))[:240]
    raise ValueError("Unknown intelligence feed")


def _activate_file(destination: Path, data: bytes, before_activate=None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".cats-update-", delete=False) as stream:
        staged = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        if before_activate:
            before_activate()
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
    with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Candidate database integrity check failed")


def _parse_grype_listing(raw: bytes) -> dict:
    if len(raw) > MAX_GRYPE_LISTING:
        raise ValueError("Grype latest.json exceeds size limit")
    try:
        listing = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError) as exc:
        raise ValueError("Grype latest.json is invalid JSON") from exc
    fields = ("schemaVersion", "built", "path")
    if (not isinstance(listing, dict) or not all(isinstance(listing.get(field), str) and listing[field] for field in fields)
            or not re.fullmatch(r"v?6\.[0-9]+\.[0-9]+", listing["schemaVersion"])):
        raise ValueError("Grype latest.json must describe a v6 database archive")
    checksum = listing.get("checksum")
    if not isinstance(checksum, str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", checksum):
        raise ValueError("Grype latest.json must contain a SHA-256 archive checksum")
    return listing


def _stage_grype_archive(archive: Path, stream: BinaryIO, listing: dict | None) -> None:
    digest = hashlib.sha256() if listing is not None else None
    total = 0
    with archive.open("xb") as output:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD:
                raise ValueError("Grype database archive exceeds size limit")
            output.write(chunk)
            if digest is not None:
                digest.update(chunk)
    if listing is not None and listing["checksum"].lower() != "sha256:" + digest.hexdigest():
        raise ValueError("Grype archive SHA-256 checksum does not match latest.json")


def _refresh_scanner(key: str, source: str, uploaded: bytes | BinaryIO | None, ca_bundle: str | None,
                     grype_listing: bytes | None, before_activate) -> str:
    if key == "grype":
        destination = Path(os.getenv("GRYPE_DB_CACHE_DIR", "/opt/catscan/grype-db"))
        destination.mkdir(parents=True, exist_ok=True)
        binary = shutil.which("grype")
        if not binary:
            raise ValueError("Grype is unavailable")
        with tempfile.TemporaryDirectory(dir=destination, prefix=".cats-import-") as temporary:
            stage = Path(temporary) / "db"
            stage.mkdir()
            archive = Path(temporary) / "candidate.tar.zst"
            listing = _parse_grype_listing(grype_listing) if grype_listing is not None else None
            if uploaded is not None:
                stream = io.BytesIO(uploaded) if isinstance(uploaded, bytes) else uploaded
                _stage_grype_archive(archive, stream, listing)
            else:
                if urllib.parse.urlsplit(source).path.rsplit("/", 1)[-1] == "latest.json":
                    with _open_source(source, ca_bundle) as response:
                        listing = _parse_grype_listing(response.read(MAX_GRYPE_LISTING + 1))
                    # Grype v6 mirrors publish the named archive beside the listing.
                    filename = listing["path"]
                    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]*\.tar\.zst", filename):
                        raise ValueError("Grype latest.json must name a .tar.zst file in the same mirror directory")
                    source = source.rsplit("/", 1)[0] + "/" + filename
                with _open_source(source, ca_bundle) as response:
                    _stage_grype_archive(archive, response, listing)
            env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(stage), GRYPE_DB_AUTO_UPDATE="false",
                       GRYPE_DB_REQUIRE_UPDATE_CHECK="false", GRYPE_DB_VALIDATE_AGE="false",
                       GRYPE_CHECK_FOR_APP_UPDATE="false")
            _run([binary, "db", "import", str(archive)], env)
            status = _run([binary, "db", "status", "-o", "json"], env)
            databases = list(stage.rglob("vulnerability.db"))
            if not databases:
                raise ValueError("Grype candidate has no vulnerability.db")
            _check_sqlite(databases[0])
            try:
                metadata = json.loads(status)
                if not isinstance(metadata, dict):
                    raise ValueError("Grype candidate metadata is invalid")
                version = str(metadata.get("built") or metadata.get("schemaVersion") or "Imported Grype database")[:240]
            except (ValueError, TypeError) as exc:
                raise ValueError("Grype candidate metadata is invalid") from exc
            if listing is not None:
                if (listing["schemaVersion"].removeprefix("v") != str(metadata.get("schemaVersion")).removeprefix("v")
                        or listing["built"] != metadata.get("built")):
                    raise ValueError("Grype latest.json schema or build time does not match the imported database")
                # Reports read this fixed location from the pinned generation.
                with (stage / "latest.json").open("x", encoding="utf-8") as output:
                    json.dump(listing, output, allow_nan=False)
            publish_generation(stage, destination, key, metadata, before_activate=before_activate)
        return version
    if key == "trivy":
        destination = Path(os.getenv("TRIVY_CACHE_DIR", "/opt/catscan/trivy-cache"))
        destination.mkdir(parents=True, exist_ok=True)
        binary = shutil.which("trivy")
        if not binary:
            raise ValueError("Trivy is unavailable")
        with tempfile.TemporaryDirectory(dir=destination, prefix=".cats-import-") as temporary:
            stage = Path(temporary) / "cache"
            stage.mkdir()
            from .trusted_ca import write_additive_bundle
            bundle = write_additive_bundle(Path(temporary) / "ca.pem", [{"pem": ca_bundle}]) if ca_bundle else None
            environment = dict(os.environ, TRIVY_SKIP_CHECK_UPDATE="true", TRIVY_SKIP_DB_UPDATE="false")
            if bundle:
                environment["SSL_CERT_FILE"] = str(bundle)
            if uploaded is not None:
                _extract_trivy_database(uploaded, stage)
            else:
                _run([binary, "image", "--download-db-only", "--db-repository", source,
                      "--cache-dir", str(stage)], environment)
            if not (stage / "db" / "trivy.db").is_file() or not (stage / "db" / "metadata.json").is_file():
                raise ValueError("Trivy candidate has no native database")
            # Trivy uses bbolt, not SQLite. Let the native scanner open and
            # validate the staged database, with all update paths disabled.
            probe = Path(temporary) / "probe"
            probe.mkdir()
            (probe / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
            environment.update(TRIVY_SKIP_DB_UPDATE="true", TRIVY_SKIP_JAVA_DB_UPDATE="true")
            _run([binary, "filesystem", "--cache-dir", str(stage), "--skip-db-update",
                  "--skip-java-db-update", "--offline-scan", "--scanners", "vuln",
                  "--format", "json", str(probe)], environment)
            try:
                metadata = json.loads((stage / "db" / "metadata.json").read_text(encoding="utf-8"))
                if not isinstance(metadata, dict):
                    raise ValueError("Trivy candidate metadata is invalid")
                version = str(metadata.get("Version") or metadata.get("UpdatedAt") or "Downloaded Trivy database")[:240]
            except (OSError, ValueError, TypeError) as exc:
                raise ValueError("Trivy candidate metadata is invalid") from exc
            if not isinstance(metadata, dict) or not metadata.get("Version") or not metadata.get("UpdatedAt"):
                raise ValueError("Trivy candidate metadata is incomplete")
            publish_generation(stage, destination, key, metadata, before_activate=before_activate)
        return version
    raise ValueError("Unknown scanner database")


def _extract_trivy_database(data: bytes, stage: Path) -> None:
    """Accept the official offline DB tarball without arbitrary extraction."""
    expected = {"trivy.db", "metadata.json"}
    seen = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if member.isdir() and name.rstrip("/") == "db":
                continue
            name = name.removeprefix("db/")
            if name not in expected or name in seen or not member.isfile():
                raise ValueError("Trivy DB archive contains an invalid member")
            total += member.size
            if total > MAX_UPLOAD:
                raise ValueError("Trivy DB archive exceeds expanded size limit")
            target = stage / "db" / name
            target.parent.mkdir(exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Trivy DB archive member is unreadable")
            with stream, target.open("wb") as output:
                shutil.copyfileobj(stream, output, length=1024 * 1024)
            seen.add(name)
    if seen != expected:
        raise ValueError("Trivy DB archive is incomplete")


class _FeedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # FIRST's stable link points to the day's gzip on the same HTTPS host.
        if (request.full_url == DEFAULT_SOURCES["epss"]
                and re.fullmatch(r"https://epss\.empiricalsecurity\.com/epss_scores-\d{4}-\d{2}-\d{2}\.csv\.gz", newurl)):
            return super().redirect_request(request, fp, code, msg, headers, newurl)
        raise ValueError("Configured source redirected; configure the final endpoint explicitly")


def _open_source(source: str, ca_bundle: str | None) -> BinaryIO:
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
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _FeedRedirect)
    return opener.open(request, timeout=30)


def _download(source: str, ca_bundle: str | None) -> bytes:
    with _open_source(source, ca_bundle) as response:
        data = response.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise ValueError("Security data download exceeds size limit")
    return data


def refresh(key: str, source: str, uploaded: bytes | BinaryIO | None = None, ca_bundle: str | None = None,
            grype_listing: bytes | None = None, *, before_activate=None) -> str:
    if key not in SOURCE_KEYS:
        raise ValueError("Unknown security data source")
    if grype_listing is not None and (key != "grype" or uploaded is None):
        raise ValueError("Grype latest.json requires an uploaded Grype database archive")
    if uploaded is not None and not isinstance(uploaded, bytes) and key != "grype":
        raise ValueError("Only Grype database archives support streamed uploads")
    if isinstance(uploaded, bytes) and len(uploaded) > MAX_UPLOAD:
        raise ValueError("Security data upload exceeds size limit")
    if key in {"grype", "trivy"}:
        return _refresh_scanner(key, source, uploaded, ca_bundle, grype_listing, before_activate)
    data = uploaded if uploaded is not None else _download(source, ca_bundle)
    version = _validate_feed(key, data)
    policy_dir = Path(os.getenv("CATS_POLICY_DATA_DIR", "/app/policy"))
    _activate_file(policy_dir / ("kev.json" if key == "kev" else "epss.csv"), data, before_activate)
    from .policy_data import kev_cves, epss_scores
    kev_cves.cache_clear()
    epss_scores.cache_clear()
    return version
