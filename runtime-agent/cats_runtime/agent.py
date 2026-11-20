"""Standard-library runtime collector. Only allowlisted metadata leaves the host."""

from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import __version__
from .report_pages import MAX_REPORT_BYTES, MAX_WORKLOADS, send_report

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
COLLECTION_BUDGET_SECONDS = 120
DIGEST = re.compile(r"sha256:[a-fA-F0-9]{64}\Z")
REPOSITORY_PART = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")
REGISTRY = re.compile(r"(?:[a-zA-Z0-9]+(?:[.-][a-zA-Z0-9-]+)*|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?\Z")
FIELDS = ("uid", "namespace", "pod", "workload", "workload_kind", "container", "container_kind", "node", "image_ref",
          "image_id", "state", "chart_name", "chart_version", "helm_release")
STATES = {"running", "waiting", "terminated", "unknown", "paused", "restarting",
          "exited", "created", "dead", "removing"}


class AgentError(Exception):
    """A safe diagnostic code, never a raw HTTP/body/credential exception."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def encode_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def read_response(response, limit_code):
    deadline = time.monotonic() + 20
    body = bytearray()
    while time.monotonic() < deadline:
        part = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(body)))
        if not part:
            try:
                return json.loads(body)
            except (ValueError, RecursionError):
                raise AgentError("response_invalid") from None
        body.extend(part)
        if len(body) > MAX_RESPONSE_BYTES:
            raise AgentError(limit_code)
    raise AgentError("response_timeout")


def read_secret(path):
    try:
        with open(path, encoding="utf-8") as stream:
            value = stream.read(8193).strip()
        if not value or len(value) > 8192 or "\n" in value or "\r" in value:
            raise AgentError("credential_invalid")
        return value
    except OSError:
        raise AgentError("credential_unreadable") from None


def https_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise AgentError("https_url_required")
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AgentError("redirect_rejected")


class HTTPSClient:
    def __init__(self, base_url, ca_file=None):
        self.base_url = https_url(base_url)
        try:
            self.context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError):
            raise AgentError("ca_invalid") from None
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=self.context))

    def request(self, method, path, body=None, token=None):
        if not path.startswith("/") or path.startswith("//"):
            raise AgentError("request_path_invalid")
        headers = {"Accept": "application/json", "User-Agent": f"cats-runtime/{__version__}"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=encode_json(body)
                                         if body is not None else None,
                                         headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                return read_response(response, "response_too_large")
        except urllib.error.HTTPError as exc:
            raise AgentError(f"http_{exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            raise AgentError("transport_failed") from None


class StateStore:
    """One owner per state directory; atomically persist credentials and pending work."""

    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise AgentError("state_symlink_rejected")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "state.json"
        if self.path.is_symlink():
            raise AgentError("state_symlink_rejected")
        self.lock_stream = None

    def __enter__(self):
        lock_path = self.directory / "agent.lock"
        if lock_path.is_symlink():
            raise AgentError("state_symlink_rejected")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.lock_stream = os.fdopen(fd, "r+b", buffering=0)
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    self.lock_stream.write(b"0")
                self.lock_stream.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock_stream.close()
            raise AgentError("state_already_in_use") from None
        return self

    def __exit__(self, *args):
        self.lock_stream.close()

    def load(self):
        if not self.path.exists():
            state = {"source_id": str(uuid.uuid4()), "next_sequence": 1, "pending": None}
            self.save(state)
            return state
        try:
            os.chmod(self.path, 0o600)
            with self.path.open("rb") as stream:
                raw = stream.read(MAX_REPORT_BYTES + 65537)
            if len(raw) > MAX_REPORT_BYTES + 65536:
                raise ValueError()
            state = json.loads(raw)
            uuid.UUID(state["source_id"])
            if type(state["next_sequence"]) is not int or state["next_sequence"] < 1:
                raise ValueError()
            if state.get("pending") and state["pending"]["sequence"] != state["next_sequence"]:
                raise ValueError()
            if "last_acked_observed_at" in state and datetime.fromisoformat(state["last_acked_observed_at"]).utcoffset() is None:
                raise ValueError()
            return state
        except (OSError, ValueError, KeyError, TypeError):
            raise AgentError("state_invalid") from None

    def save(self, state):
        fd, name = tempfile.mkstemp(prefix=".state-", dir=self.directory)
        try:
            os.chmod(name, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encode_json(state))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            if os.name != "nt":
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def record(**values):
    result = {}
    for field in FIELDS:
        value = values.get(field, "")
        limit = 512 if field == "uid" else 1024 if field in ("image_ref", "image_id") else 255
        if (not isinstance(value, str) or len(value) > limit or
                any(ord(char) < 32 for char in value)):
            raise AgentError("inventory_field_invalid")
        if field == "image_ref" and value:
            # Runtimes can echo an invalid submitted image name containing URL
            # credentials. Preserve the container observation without that text.
            if (not re.fullmatch(r"[A-Za-z0-9_.:/@+\[\]-]+", value) or "://" in value
                    or ("@" in value and not re.fullmatch(r"[^@]+@sha256:[0-9a-fA-F]{64}", value))):
                value = ""
        result[field] = value
    if any(not result[field].strip() for field in ("uid", "container", "state")):
        raise AgentError("inventory_required_field_missing")
    if result["state"] not in STATES:
        raise AgentError("inventory_state_invalid")
    return result


def observed_manifest(value):
    """An image spec/tag or a CRI/config-only ID cannot establish a manifest."""
    if not isinstance(value, str) or len(value) > 1024:
        return ""
    for prefix in ("docker-pullable://", "containerd://", "cri-o://", "docker://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    repository, separator, digest = value.partition("@")
    if not separator or not DIGEST.fullmatch(digest):
        return ""
    host, slash, path = repository.partition("/")
    if not slash or not REGISTRY.fullmatch(host):
        return ""
    # Only a repository digest proves the runtime manifest. Drop any tag
    # qualifier, which can change independently of the reported digest.
    before, colon, tag = path.rpartition(":")
    if colon:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
            return ""
        path = before
    if len(path) > 255 or not all(REPOSITORY_PART.fullmatch(part) for part in path.split("/")):
        return ""
    return f"{host.lower()}/{path}@{digest.lower()}"


def check_collection_deadline(deadline):
    if time.monotonic() >= deadline:
        raise AgentError("inventory_timeout")


def pod_image_identity(actual, declared, state):
    requested = declared.get("image", "")
    reference = actual.get("image") or requested
    if state != "running":
        return reference, ""
    image_id = actual.get("imageID")
    manifest = observed_manifest(image_id)
    if manifest or not isinstance(image_id, str) or not DIGEST.fullmatch(image_id):
        return reference, manifest
    # Some kubelets report only a hash. Keep that raw observation alongside
    # the spec pin for independent release verification, without inventing a
    # repository for a CRI configuration ID or resolving a mutable tag.
    if isinstance(requested, str) and "://" not in requested:
        pin = observed_manifest(requested)
        host = pin.partition("/")[0]
        if pin and (host == "localhost" or "." in host or ":" in host) and pin.endswith("@" + image_id.lower()):
            try:
                authority = urllib.parse.urlsplit("https://" + host)
                if authority.hostname and authority.port != 0:
                    return requested, image_id.lower()
            except ValueError:
                pass
    return reference, ""


def pod_records(pod):
    metadata, spec, status = pod["metadata"], pod.get("spec", {}), pod.get("status", {})
    if (not isinstance(metadata.get("uid"), str) or not metadata["uid"] or
            not isinstance(spec.get("containers"), list) or not spec["containers"]):
        raise AgentError("kubernetes_pod_invalid")
    labels = metadata.get("labels", {})
    owners = metadata.get("ownerReferences", [])
    controllers = [owner for owner in owners if owner.get("controller") is True]
    pod_name = metadata.get("name", "")
    owner = controllers[0] if len(controllers) == 1 else {}
    workload = owner.get("name", pod_name)
    workload_kind = owner.get("kind", "") if owner else "Pod"
    chart = re.fullmatch(r"(.+?)-(\d+\.\d+.*)", labels.get("helm.sh/chart", ""))
    for kind, spec_key, status_key in (
            ("regular", "containers", "containerStatuses"),
            ("init", "initContainers", "initContainerStatuses"),
            ("ephemeral", "ephemeralContainers", "ephemeralContainerStatuses")):
        declared = spec.get(spec_key, [])
        observed = status.get(status_key, [])
        specs = {item["name"]: item for item in declared}
        statuses = {item["name"]: item for item in observed}
        if len(specs) != len(declared) or len(statuses) != len(observed):
            raise AgentError("inventory_duplicate")
        for name in dict.fromkeys((*specs, *statuses)):
            container = specs.get(name, {})
            actual = statuses.get(name, {})
            states = [state for state in ("running", "waiting", "terminated")
                      if isinstance(actual.get("state", {}).get(state), dict)]
            state = states[0] if len(states) == 1 else "waiting" if not actual else "unknown"
            if state == "running" and status.get("phase") in ("Succeeded", "Failed"):
                state = "unknown"
            image_ref, image_id = pod_image_identity(actual, container, state)
            yield record(uid=f"{metadata['uid']}:{kind}:{name}",
                         namespace=metadata.get("namespace", ""), pod=pod_name,
                         workload=workload, workload_kind=workload_kind, container_kind=kind,
                         container=name, node=spec.get("nodeName", ""),
                         image_ref=image_ref, image_id=image_id,
                         state=state,
                         chart_name=chart.group(1) if chart else "",
                         chart_version=chart.group(2) if chart else "",
                         helm_release=labels.get("app.kubernetes.io/instance", ""))


class KubernetesCollector:
    def __init__(self, client, token_file):
        self.client, self.token_file = client, token_file

    def collect(self):
        records, errors, continuation, seen, pages = [], [], "", set(), set()
        snapshot_version = None
        limit, restarts = 100, 0
        resized_cursor = False
        deadline = time.monotonic() + COLLECTION_BUDGET_SECONDS
        try:
            while True:
                check_collection_deadline(deadline)
                path = f"/api/v1/pods?limit={limit}"
                if continuation:
                    path += "&continue=" + urllib.parse.quote(continuation, safe="")
                try:
                    page = self.client.request("GET", path, token=read_secret(self.token_file))
                except AgentError as exc:
                    if exc.code == "response_too_large" and limit > 1:
                        limit = max(1, limit // 2)
                        resized_cursor = bool(continuation)
                        continue
                    # Expired cursors (or a server rejecting a changed limit)
                    # require a fresh LIST so no rows cross snapshot boundaries.
                    if continuation and restarts < 2 and (exc.code == "http_410" or
                                                          (resized_cursor and exc.code == "http_400")):
                        restarts += 1
                        records.clear()
                        seen.clear()
                        pages.clear()
                        continuation, snapshot_version, resized_cursor = "", None, False
                        continue
                    raise
                resized_cursor = False
                if not isinstance(page.get("items"), list) or not isinstance(page.get("metadata"), dict):
                    raise AgentError("kubernetes_inventory_invalid")
                version = page["metadata"].get("resourceVersion")
                if continuation and version != snapshot_version:
                    raise AgentError("kubernetes_snapshot_changed")
                snapshot_version = version
                for pod in page["items"]:
                    for item in pod_records(pod):
                        if len(records) >= MAX_WORKLOADS:
                            raise AgentError("inventory_limit")
                        if item["uid"] in seen:
                            raise AgentError("inventory_duplicate")
                        seen.add(item["uid"])
                        records.append(item)
                next_page = page["metadata"].get("continue", "")
                if next_page == "":
                    break
                if not isinstance(next_page, str) or len(next_page) > 8192 or next_page in pages or len(pages) >= 1000:
                    raise AgentError("kubernetes_pagination_invalid")
                pages.add(next_page)
                continuation = next_page
        except AgentError as exc:
            errors.append(exc.code)
        except (KeyError, TypeError, AttributeError, ValueError):
            errors.append("kubernetes_inventory_invalid")
        return records, errors


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__("localhost", timeout=15)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class DockerClient:
    def __init__(self, socket_path):
        self.socket_path = socket_path

    def get(self, path):
        try:
            with contextlib.closing(UnixHTTPConnection(self.socket_path)) as connection:
                connection.request("GET", path, headers={"Accept": "application/json"})
                response = connection.getresponse()
                if response.status != 200:
                    raise AgentError(f"docker_http_{response.status}")
                return read_response(response, "docker_response_too_large")
        except (OSError, ValueError, http.client.HTTPException):
            raise AgentError("docker_transport_failed") from None


def docker_identity(config_id, image, image_ref=""):
    if not isinstance(config_id, str) or not DIGEST.fullmatch(config_id):
        return ""
    fallback = "config://" + config_id
    if image.get("Id") != config_id:
        return fallback
    values = image.get("RepoDigests") or []
    if not isinstance(values, list):
        return fallback
    normalized = [observed_manifest(value) for value in values]
    if not normalized or not all(normalized):
        return fallback
    candidates = set(normalized)
    if len(candidates) == 1:
        return candidates.pop()
    digests = {value.rsplit("@", 1)[1] for value in candidates}
    if len(digests) == 1 and isinstance(image_ref, str):
        target = observed_manifest(image_ref if "@" in image_ref else f"{image_ref}@{digests.pop()}")
        if target in candidates:
            return target
    return fallback


class DockerCollector:
    def __init__(self, client):
        self.client = client

    def collect(self):
        records, errors, cache, seen = [], [], {}, set()
        deadline = time.monotonic() + COLLECTION_BUDGET_SECONDS

        def get(path):
            check_collection_deadline(deadline)
            return self.client.get(path)

        try:
            version = get("/version").get("ApiVersion", "")
            if not isinstance(version, str) or not re.fullmatch(r"1\.\d+", version):
                raise AgentError("docker_version_invalid")
            prefix = "/v" + version
            node = get(prefix + "/info").get("Name", "")
            containers = get(prefix + "/containers/json?all=1")
            if not isinstance(containers, list):
                raise AgentError("docker_inventory_invalid")
            for index, container in enumerate(containers):
                if index >= MAX_WORKLOADS:
                    raise AgentError("inventory_limit")
                try:
                    uid = container["Id"]
                    if not isinstance(uid, str) or not re.fullmatch(r"[a-f0-9]{64}", uid):
                        raise AgentError("docker_container_id_invalid")
                    actual = get(prefix + "/containers/" + uid + "/json")
                    if actual["Id"] != uid or uid in seen:
                        raise AgentError("docker_container_identity_mismatch")
                    seen.add(uid)
                    config_id = actual.get("Image", "")
                    if not DIGEST.fullmatch(config_id):
                        raise AgentError("docker_image_id_invalid")
                    if config_id not in cache:
                        cache[config_id] = get(prefix + "/images/" +
                                               urllib.parse.quote(config_id, safe="") + "/json")
                    config = actual.get("Config", {})
                    labels = config.get("Labels") or {}
                    name = actual.get("Name", "").lstrip("/")
                    records.append(record(uid=uid, namespace=labels.get("com.docker.compose.project", ""),
                                          workload=labels.get("com.docker.compose.service", name),
                                          container=name, node=node, image_ref=config.get("Image", ""),
                                          image_id=docker_identity(config_id, cache[config_id], config.get("Image", "")),
                                          state=actual.get("State", {}).get("Status", "unknown")))
                except AgentError as exc:
                    errors.append(exc.code)
                    if exc.code == "inventory_timeout":
                        break
        except AgentError as exc:
            errors.append(exc.code)
        except (KeyError, TypeError, AttributeError, ValueError):
            errors.append("docker_inventory_invalid")
        return records, sorted(set(errors))


def make_report(collector, sequence, last_acked_observed_at=None):
    observed = datetime.now(timezone.utc)
    if last_acked_observed_at and observed < datetime.fromisoformat(last_acked_observed_at):
        raise AgentError("clock_behind_last_report")
    workloads, errors = collector.collect()
    errors = sorted(set(errors))
    if len(workloads) > MAX_WORKLOADS:
        workloads = workloads[:MAX_WORKLOADS]
        errors.append("inventory_limit")
    report = {"sequence": sequence, "observed_at": observed.isoformat(),
              "complete": not errors, "errors": errors, "workloads": workloads}
    if len(encode_json(report)) > MAX_REPORT_BYTES:
        report.update(complete=False, errors=sorted(set(errors + ["report_size_limit"])), workloads=[])
    return report


def enroll(store, state, client, name, linking_key_file, kind="docker"):
    if state.get("agent_token"):
        if state.get("cats_url") != client.base_url:
            raise AgentError("enrollment_url_mismatch")
        if state.get("source_kind", kind) != kind:
            raise AgentError("enrollment_source_mismatch")
        return state
    if kind not in ("docker", "kubernetes"):
        raise AgentError("enrollment_source_invalid")
    if not linking_key_file:
        raise AgentError("linking_key_file_required")
    if (not isinstance(name, str) or not name.strip() or len(name) > 160 or
            any(ord(char) < 32 for char in name)):
        raise AgentError("agent_name_required")
    key = read_secret(linking_key_file)
    pending = state.get("pending_enrollment")
    if pending is None:
        # The server stores only a hash. Persist the proposed secret before a
        # link can consume the bootstrap key, including across a lost response.
        pending = {"cats_url": client.base_url, "kind": kind, "name": name,
                   "version": __version__, "agent_token": "cats-agent-" + secrets.token_urlsafe(32)}
        store.save({**state, "pending_enrollment": pending})
        state["pending_enrollment"] = pending
    if (not isinstance(pending, dict) or pending.get("cats_url") != client.base_url or pending.get("kind") != kind
            or not isinstance(pending.get("name"), str) or not isinstance(pending.get("version"), str)
            or not re.fullmatch(r"cats-agent-[A-Za-z0-9_-]{43}", str(pending.get("agent_token", "")))):
        raise AgentError("enrollment_state_mismatch")
    response = client.request("POST", "/api/runtime/link", {
        "linking_key": key, "name": pending["name"], "kind": kind, "agent_token": pending["agent_token"],
        "source_id": state["source_id"], "version": pending["version"]})
    if (not isinstance(response, dict) or not isinstance(response.get("agent_id"), str)
            or not 0 < len(response["agent_id"]) <= 160 or response.get("agent_token") != pending["agent_token"]
            or type(response.get("environment_id")) is not int or response["environment_id"] < 1):
        raise AgentError("link_response_invalid")
    interval = response.get("report_interval_seconds", 60)
    if type(interval) is not int or not 10 <= interval <= 3600:
        raise AgentError("link_response_invalid")
    updated = {**state, "agent_id": response["agent_id"], "agent_token": pending["agent_token"],
               "cats_url": client.base_url, "source_kind": kind, "report_interval_seconds": interval,
               "environment_id": response["environment_id"], "environment_name": response.get("environment_name", "")}
    del updated["pending_enrollment"]
    store.save(updated)
    state.clear()
    state.update(updated)
    return state


def send_once(store, state, client, collector):
    if not state.get("agent_token") or state.get("cats_url") != client.base_url:
        raise AgentError("enrollment_required")
    if not state.get("pending"):
        state["pending"] = make_report(collector, state["next_sequence"], state.get("last_acked_observed_at"))
        store.save(state)
    # A retry uses exactly the same persisted timestamp, sequence and inventory.
    ack = send_report(client, state["agent_token"], state["pending"])
    if (not isinstance(ack, dict) or ack.get("accepted") is not True or type(ack.get("sequence")) is not int
            or ack["sequence"] != state["next_sequence"]):
        raise AgentError("report_ack_invalid")
    updated = {**state, "next_sequence": state["next_sequence"] + 1, "pending": None,
               "last_acked_observed_at": state["pending"]["observed_at"]}
    store.save(updated)
    state.update(updated)


def parser():
    result = argparse.ArgumentParser(description="CATS read-only runtime inventory agent")
    result.add_argument("mode", choices=("link", "run"))
    result.add_argument("--cats-url", default=os.environ.get("CATS_URL"))
    result.add_argument("--ca-file", default=os.environ.get("CATS_CA_FILE"))
    result.add_argument("--state-dir", default="/var/lib/cats-runtime/state")
    result.add_argument("--name", default=os.environ.get("CATS_AGENT_NAME"))
    result.add_argument("--linking-key-file", default=os.environ.get("CATS_LINKING_KEY_FILE"))
    result.add_argument("--source", choices=("docker", "kubernetes"), default="docker")
    result.add_argument("--docker-socket", default="/var/run/docker.sock")
    result.add_argument("--kubernetes-url", default="https://kubernetes.default.svc")
    result.add_argument("--kubernetes-token-file", default="/var/run/secrets/kubernetes.io/serviceaccount/token")
    result.add_argument("--kubernetes-ca-file", default="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    result.add_argument("--once", action="store_true", help="Send one report, then exit")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not args.cats_url:
            raise AgentError("cats_url_required")
        client = HTTPSClient(args.cats_url, args.ca_file)
        with StateStore(args.state_dir) as store:
            state = store.load()
            if args.mode == "link":
                enroll(store, state, client, args.name, args.linking_key_file, args.source)
                print("cats-runtime: linked", flush=True)
                return 0
            collector = (KubernetesCollector(HTTPSClient(args.kubernetes_url, args.kubernetes_ca_file),
                                             args.kubernetes_token_file) if args.source == "kubernetes"
                         else DockerCollector(DockerClient(args.docker_socket)))
            failures = 0
            while True:
                try:
                    linked = bool(state.get("agent_token"))
                    enroll(store, state, client, args.name, args.linking_key_file, args.source)
                    if not linked:
                        print("cats-runtime: linked", flush=True)
                    send_once(store, state, client, collector)
                    failures = 0
                    print("cats-runtime: report_accepted", flush=True)
                except AgentError as exc:
                    print("cats-runtime: " + exc.code, file=sys.stderr, flush=True)
                    failures += 1
                    if args.once or exc.code in ("http_400", "http_401", "http_403", "http_413", "http_422",
                            "enrollment_url_mismatch", "enrollment_source_mismatch", "enrollment_state_mismatch",
                            "linking_key_file_required", "agent_name_required", "enrollment_required"):
                        return 1
                if args.once:
                    return 0
                time.sleep(min(300, 5 * 2 ** min(failures - 1, 6)) if failures
                           else state.get("report_interval_seconds", 60))
    except KeyboardInterrupt:
        return 0
    except AgentError as exc:
        print("cats-runtime: " + exc.code, file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError):
        print("cats-runtime: local_configuration_or_state_failed", file=sys.stderr)
        return 1
