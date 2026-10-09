"""Independent scan execution process: no Portal imports or database access."""
import concurrent.futures
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import logging
from datetime import datetime, timezone
from .scan_intelligence import pin_databases, intelligence_status
from . import scan_runtime
from pathlib import Path

import requests
import re
from .scan_artifacts import digest, pack, unpack
from .scan_acquisition import _download_public_chart
from .helm_archives import extract_chart
from .helm_downloads import close_downloads

STOP = threading.Event()
_UID_LOCK = threading.Lock()
_ACTIVE_UIDS = set()

ROOT = Path(os.getenv("CATS_SCAN_JOB_ROOT", "/var/lib/cats-scan"))


class Worker:
    def __init__(self):
        token = os.getenv("CATS_SCAN_WORKER_TOKEN", "").strip()
        if len(token) < 32 or any(word in token.lower() for word in ("replace", "change-me", "placeholder", "example")):
            raise ValueError("CATS_SCAN_WORKER_TOKEN must contain at least 32 characters")
        self.url = os.getenv("CATS_SCAN_PORTAL_URL", "http://portal-control:8001").rstrip("/") + "/internal/scan-worker"
        if not self.url.startswith(("http://", "https://")):
            raise ValueError("Invalid Portal URL")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["Authorization"] = "Bearer " + token
        self.worker_id = os.getenv("CATS_SCAN_WORKER_ID", "scan-worker")
        self.session.headers.update({"X-Worker-ID": self.worker_id, "Accept-Encoding": "identity"})

    def request(self, method, suffix, **kwargs):
        response = self.session.request(method, self.url + suffix, timeout=kwargs.pop("timeout", (5, 15)), **kwargs)
        response.raise_for_status()
        return response

    def claim(self):
        return self.request("POST", "/claim", json={"worker_id": self.worker_id}).json()

    def execute(self, job):
        # Concurrent attempts have separate UIDs, preventing cross-job /proc and
        # private registry-file access. Only the broker retains control secrets.
        uid = None
        if os.name != "nt" and os.geteuid() == 0:
            with _UID_LOCK:
                uid = int(os.getenv("CATS_SCAN_SCANNER_UID", "10002"))
                while uid in _ACTIVE_UIDS: uid += 1
                _ACTIVE_UIDS.add(uid)
        try:
            return self._execute(job, uid)
        finally:
            if uid is not None:
                with _UID_LOCK: _ACTIVE_UIDS.discard(uid)

    def _execute(self, job, uid):
        job_id, attempt = job["job_id"], job["attempt_id"]
        suffix = f"/{job_id}/{attempt}"
        headers = {"X-Attempt-Token": job["attempt_token"]}
        phase = ["prepare"]
        log_tail = [""]
        lost = threading.Event()
        finished = threading.Event()
        deadline = time.monotonic() + int(os.getenv("CATS_SCAN_JOB_TIMEOUT", "3600"))
        lease_seconds = int(os.getenv("CATS_SCAN_LEASE_SECONDS", "90"))
        lease_deadline = [time.monotonic() + lease_seconds]
        if job.get("lease_until"):
            lease_deadline[0] = time.monotonic() + max(0, (datetime.fromisoformat(job["lease_until"]).replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds())
        def authorized():
            if STOP.is_set() or lost.is_set() or time.monotonic() >= deadline or time.monotonic() >= lease_deadline[0]:
                raise RuntimeError("Scan interrupted or attempt lease lost")
        def renew():
            interval = max(1, lease_seconds // 3)
            backoff = 1
            while not finished.is_set() and not STOP.is_set():
                remaining = lease_deadline[0] - time.monotonic()
                if remaining <= 0 or time.monotonic() >= deadline:
                    lost.set()
                    return
                try:
                    response = self.request("POST", suffix + "/heartbeat", headers=headers,
                        timeout=(min(3, remaining / 4), min(5, remaining / 4)),
                        json={"phase": phase[0], "log_tail": log_tail[0]}).json()
                    if not isinstance(response, dict):
                        raise ValueError("Invalid lease response")
                    if response.get("lease_until"):
                        remaining = (datetime.fromisoformat(response["lease_until"]).replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds()
                        lease_deadline[0] = time.monotonic() + max(0, remaining)
                    else:
                        lease_deadline[0] = time.monotonic() + lease_seconds
                    (ROOT / "readiness").touch()
                    backoff = 1
                    finished.wait(interval)
                except (ValueError, TypeError, KeyError):
                    logging.getLogger(__name__).warning("Invalid lease renewal response; fencing attempt %s", attempt)
                    lost.set()
                    return
                except requests.RequestException as exc:
                    status = getattr(getattr(exc, "response", None), "status_code", None)
                    if status in (401, 403, 409, 404):
                        lost.set()
                        return
                    # A network outage does not surrender a still-valid lease.
                    finished.wait(min(backoff, max(0, lease_deadline[0] - time.monotonic())))
                    backoff = min(backoff * 2, 5)
        heartbeat = threading.Thread(target=renew, daemon=True)
        process = None
        temporary = tempfile.TemporaryDirectory(prefix=attempt + "-", dir=ROOT)
        heartbeat.start()
        runtime = None
        try:
            directory = Path(temporary.name)
            archive = directory / "input.tar.gz"
            with self.request("GET", suffix + "/input", headers=headers, stream=True) as response, archive.open("wb") as target:
                size = 0
                for chunk in response.iter_content(1024 * 1024):
                    authorized()
                    size += len(chunk)
                    if size > int(os.getenv("CATS_SCAN_DISK_BYTES", str(8 * 1024**3))):
                        raise ValueError("Input exceeds worker disk budget")
                    target.write(chunk)
            if digest(archive) != job["input_digest"]:
                raise ValueError("Input identity verification failed")
            inputs, output = directory / "input", directory / "evidence" / "output"
            unpack(archive, inputs, {"job_id": job_id})
            archive.unlink()
            output.mkdir(parents=True)
            payload = job["job"]
            environment = scan_runtime.sanitized_environment()
            environment["HOME"] = str(directory)
            tmp = directory / "tmp"
            tmp.mkdir()
            environment["TMPDIR"] = str(tmp)
            environment["TMP"] = str(tmp)
            environment["TEMP"] = str(tmp)
            for key in ("HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME"):
                target = directory / key.lower()
                target.mkdir()
                environment[key] = str(target)
            auth_dir = directory / "registry-auth"
            auth_dir.mkdir()
            if payload.get("credential_policy") == "service":
                config = Path(os.getenv("DOCKER_CONFIG", "/opt/catscan/registry-auth")) / "config.json"
                if config.is_file():
                    credentials = json.loads(config.read_text(encoding="utf-8"))
                    # Copy only explicitly referenced registries, never site-wide helpers.
                    references = list(str(payload.get("image_list") or "").splitlines())
                    references += [str(component.get("reference") or component.get("repository") or "") for component in payload.get("definition_components", [])]
                    component = payload.get("definition_component") or {}
                    references += [str(component.get("reference") or component.get("repository") or ""), str(payload.get("chart_url") or "")]
                    import urllib.parse
                    hosts = {urllib.parse.urlsplit(ref.replace("oci://", "https://")).netloc if "://" in ref else ref.split("/")[0] for ref in references if ref}
                    scoped = {host: value for host, value in credentials.get("auths", {}).items()
                              if host in hosts or urllib.parse.urlsplit(host).netloc in hosts}
                    (auth_dir / "config.json").write_text(json.dumps({"auths": scoped}), encoding="utf-8")
            environment["DOCKER_CONFIG"] = str(auth_dir)
            environment["HELM_REGISTRY_CONFIG"] = str(auth_dir / "config.json")
            provenance = {"started_at": time.time(), "tools": {}, "databases": pin_databases(environment, directory)}
            for key in list(environment):
                if key.startswith(("CATS_SCAN_", "CATS_PORTAL_")) or key in {"DATABASE_URL", "CATS_CONFIG_ENCRYPTION_KEY", "CATS_PATCH_WORKER_TOKEN"}:
                    environment.pop(key)
            runtime = scan_runtime.identity(uid, environment)
            runtime.__enter__()
            if uid is not None:
                for path in [directory, *directory.rglob("*")]:
                    if not path.is_symlink():
                        os.chown(path, 0, 0)
                        path.chmod(0o770 if path.is_dir() else 0o660)
                        os.chown(path, uid, 0)

            trust = inputs / ".cats-trust" / "ca-bundle.pem"
            certificates = [{"pem": trust.read_text(encoding="utf-8")}] if trust.exists() else []
            skipped = list(payload.get("skipped_charts") or [])
            components = list(payload.get("definition_components") or [])
            if payload.get("definition_component"):
                components.append(payload["definition_component"])
            for component in components:
                authorized()
                from .definition_acquisition import acquire_component
                charts = []
                try:
                    source_url, files, actual_name, actual_version, charts = acquire_component(component, certificates)
                    for stream, filename in charts:
                        if hasattr(stream, "seek"): stream.seek(0)
                        extract_chart(stream, filename, inputs / "charts")
                    if payload.get("definition_component"):
                        (output / "definition-component.json").write_text(json.dumps({"source_url": source_url, "actual_name": actual_name, "actual_version": actual_version}), encoding="utf-8")
                except Exception as exc:
                    diagnostic = getattr(exc, "diagnostic", {})
                    reason = str(exc) if isinstance(exc, ValueError) and str(exc).startswith(("Requested chart", "Retrieved chart")) else "Chart acquisition failed; review worker connectivity and trust"
                    skipped.append(reason)
                    if payload.get("definition_component"):
                        (output / "definition-acquisition-failure.json").write_text(json.dumps({"reason": reason, "diagnostic": diagnostic}), encoding="utf-8")
                finally:
                    close_downloads(charts)
            for url in str(payload.get("chart_url") or "").splitlines():
                authorized()
                charts = []
                try:
                    charts = _download_public_chart(url, certificates)
                    for stream, filename in charts:
                        extract_chart(stream, filename, inputs / "charts")
                except Exception:
                    skipped.append("Declared Helm chart could not be acquired; review worker connectivity and trust")
                finally:
                    close_downloads(charts)
            if skipped:
                (inputs / "skipped_charts.txt").write_text("\n".join(skipped) + "\n", encoding="utf-8")
            # Worker-control credentials never reach scanner processes.
            for key in list(environment):
                if key.startswith(("CATS_SCAN_", "CATS_PORTAL_")) or key in {"DATABASE_URL", "CATS_CONFIG_ENCRYPTION_KEY"}:
                    environment.pop(key)
            environment["CATS_JOB_MODE"] = payload.get("job_kind", "scan")
            environment["SBOM_FORMATS"] = ",".join(payload.get("sbom_formats") or ["syft-json"])
            environment["SBOM_CYCLONEDX_SPEC_VERSION"] = payload.get("cyclonedx_spec_version", "1.5")
            trust = inputs / ".cats-trust" / "ca-bundle.pem"
            if trust.exists():
                for key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
                    environment[key] = str(trust)
            if uid is not None:
                for path in directory.rglob("*"):
                    if not path.is_symlink():
                        os.chown(path, 0, 0)
                        path.chmod(0o770 if path.is_dir() else 0o660)
                        os.chown(path, uid, 0)
            runner = os.getenv("CATS_SCANNER_RUNNER", "cats-scan")
            for tool, arguments in (("syft", ["version"]), ("grype", ["version"]),
                                    ("trivy", ["--version"]), ("dockle", ["--version"]),
                                    ("helm", ["version", "--short"])):
                authorized()
                executable = shutil.which(tool)
                if not executable:
                    provenance["tools"][tool] = {"status": "unavailable"}
                    continue
                try:
                    version = subprocess.run([executable, *arguments], env=environment,
                                             capture_output=True, text=True, timeout=10, **scan_runtime.privileges())
                    provenance["tools"][tool] = {"exit_code": version.returncode,
                                                 "version": redact(version.stdout[:4096])}
                except (OSError, subprocess.TimeoutExpired):
                    provenance["tools"][tool] = {"status": "unavailable"}
            authorized()
            with (output / "worker.log").open("w", encoding="utf-8") as log:
                command = [runner, str(inputs), str(output)]
                if sys.platform == "linux":
                    command = [sys.executable, "-m", "app.scan_runner", str(os.getpid()), *command]
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                           env=environment, start_new_session=os.name != "nt", **scan_runtime.privileges())
                while process.poll() is None:
                    if STOP.is_set() or lost.is_set() or time.monotonic() > deadline:
                        raise RuntimeError("Scan interrupted or attempt lease lost")
                    size = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file() and not p.is_symlink())
                    if size > int(os.getenv("CATS_SCAN_DISK_BYTES", str(8 * 1024**3))):
                        raise RuntimeError("Worker disk budget exceeded")
                    for name in ("prepare_inputs", "generate_sboms", "scan_sboms", "configuration_scan", "report_results"):
                        marker = output / f"phase-{name}.json"
                        if marker.exists():
                            try:
                                state = json.loads(marker.read_text(encoding="utf-8"))
                                if state.get("status") == "running":
                                    phase[0] = name
                                    break
                            except (ValueError, OSError): pass
                    with (output / "worker.log").open("rb") as progress:
                        progress.seek(max(0, progress.seek(0, 2) - 8192))
                        log_tail[0] = redact(progress.read().decode("utf-8", errors="replace"))
                    time.sleep(0.5)
            scan_runtime.reclaim(directory)
            for log_path in output.rglob("*.log"):
                if not log_path.is_file() or log_path.is_symlink():
                    continue
                sanitized = log_path.with_suffix(".redacted")
                with log_path.open(encoding="utf-8", errors="replace") as source, sanitized.open("w", encoding="utf-8") as target:
                    for line in source: target.write(redact(line))
                os.replace(sanitized, log_path)
            evidence = directory / "evidence"
            provenance["completed_at"] = time.time()
            provenance["intelligence_status"] = intelligence_status(provenance["databases"], os.environ)
            provenance["image_digests"] = {path.name: path.read_text(encoding="utf-8").strip()
                                            for path in (output / "sboms").glob("*.digest")
                                            if path.is_file() and path.stat().st_size <= 4096}
            (output / "worker-provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
            # Uploaded inputs remain immutable; only acquired sources are returned.
            if (components or payload.get("chart_url")) and (inputs / "charts").exists():
                shutil.copytree(inputs / "charts", evidence / "sources")
            # Scanner preparation uses working copies; remove original upload bytes
            # from returned evidence while retaining generated SBOMs/reports.
            for name in ("image-archives", ".cats-trust", "charts"):
                candidate = output / name
                if candidate.is_dir(): shutil.rmtree(candidate)
            results = directory / "results.tar.gz"
            identity = {key: job[key] for key in ("job_id", "attempt_id", "input_digest", "service_key", "service_version")}
            identity.update(returncode=process.returncode, worker_id=self.worker_id,
                            completed_at=time.time())
            pack(evidence, results, identity)
            phase[0] = "transfer"
            if lost.is_set() or STOP.is_set():
                raise RuntimeError("Attempt is no longer authorized")
            with results.open("rb") as source:
                self.request("PUT", suffix + "/results", headers={**headers, "Content-Type": "application/x-tar"}, data=source, timeout=(5, 300))
        except Exception as exc:
            message = redact(str(exc))[:2000]
            logging.getLogger(__name__).error("Scan attempt %s failed: %s: %s", attempt, type(exc).__name__, message)
            status = getattr(getattr(exc, "response", None), "status_code", None)
            category = "evidence_transfer" if isinstance(exc, requests.RequestException) and status not in (400, 401, 403, 409, 422) else "scanner_execution"
            if isinstance(exc, (ValueError, json.JSONDecodeError)): category = "invalid_output"
            if "disk" in message.lower(): category = "insufficient_storage"
            if time.monotonic() > deadline: category = "scanner_timeout"
            if not lost.is_set() and not STOP.is_set():
                try:
                    self.request("POST", suffix + "/failure", headers=headers,
                        json={"category": category, "reason": message, "log_tail": log_tail[0]})
                except requests.RequestException:
                    logging.getLogger(__name__).warning("Failure report unavailable; fenced lease recovery will retry %s", attempt)
            raise
        finally:
            if runtime: runtime.__exit__(None, None, None)
            if process and process.poll() is None:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if os.name != "nt": os.killpg(process.pid, signal.SIGKILL)
                    else: process.kill()
                    process.wait()
            finished.set()
            heartbeat.join(timeout=10)
            scan_runtime.reclaim(Path(temporary.name))
            # Windows may retain a terminated process's inherited file handle
            # briefly after wait(). Keep cleanup strict, with bounded retries.
            for retry in range(6):
                try:
                    temporary.cleanup()
                    break
                except PermissionError:
                    if os.name != "nt" or retry == 5:
                        raise
                    time.sleep(0.1 * (retry + 1))


def redact(value):
    value = re.sub(r"(?i)(authorization[\s:=]+)(?:Bearer|Basic)\s+\S+", r"\1[redacted]", value)
    value = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[redacted]@", value)
    value = re.sub(r"(?i)(authorization|password|token|secret)([\s:=]+)\S+", r"\1\2[redacted]", value)
    return re.sub(r"(?i)(https?://[^\s?]+)\?[^\s]+", r"\1?[redacted]", value)


def initialize():
    ROOT.mkdir(parents=True, exist_ok=True)
    if os.name != "nt": ROOT.chmod(0o711)
    (ROOT / "heartbeat").touch()


def main():
    if "--healthcheck" in sys.argv or "--readiness" in sys.argv:
        stamp = ROOT / ("readiness" if "--readiness" in sys.argv else "heartbeat")
        return 0 if stamp.exists() and time.time() - stamp.stat().st_mtime < 120 else 1
    initialize()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_args: STOP.set())
    worker = Worker()
    maximum = max(1, int(os.getenv("CATS_SCAN_CONCURRENCY", "2")))
    with concurrent.futures.ThreadPoolExecutor(max_workers=maximum) as pool:
        active = set()
        while not STOP.is_set():
            (ROOT / "heartbeat").touch()
            for future in list(active):
                if future.done():
                    active.remove(future)
                    try: future.result()
                    except Exception as exc: print("Scan attempt failed: " + type(exc).__name__ + ": " + redact(str(exc)), file=sys.stderr)
            if len(active) < maximum:
                try:
                    job = worker.claim()
                    (ROOT / "readiness").touch()
                    if job: active.add(pool.submit(worker.execute, job))
                except requests.RequestException as exc:
                    status = getattr(getattr(exc, "response", None), "status_code", None)
                    print("Worker authentication rejected" if status in (401,403) else "Portal unavailable; waiting to claim scans", file=sys.stderr)
            STOP.wait(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
