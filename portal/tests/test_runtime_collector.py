"""Collector boundaries: observed identity, incomplete inventory, durable delivery."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import ssl
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime-agent"))
from cats_runtime import agent as runtime

DIGEST = "sha256:" + "a" * 64
CONFIG = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64
IMAGE = "registry.example/app@" + DIGEST
CONTAINER = "d" * 64


def pod():
    return {
        "metadata": {"uid": "pod-uid", "name": "pod-name", "namespace": "production",
                     "labels": {"helm.sh/chart": "my-chart-1.2.3-beta.1",
                                "app.kubernetes.io/instance": "my-release",
                                "private-label": "do-not-upload"},
                     "annotations": {"secret": "do-not-upload"},
                     "ownerReferences": [{"name": "app-replicaset", "kind": "ReplicaSet", "controller": True}]},
        "spec": {"nodeName": "node-1", "containers": [
            {"name": "app", "image": "registry.example/app:latest",
             "env": [{"name": "PASSWORD", "value": "do-not-upload"}]},
            {"name": "pending", "image": "registry.example/app@" + OTHER}],
            "initContainers": [{"name": "setup", "image": "setup:latest"}],
            "ephemeralContainers": [{"name": "debug", "image": "debug:latest"}]},
        "status": {
            "containerStatuses": [{"name": "app", "imageID": "docker-pullable://" + IMAGE,
                                   "state": {"running": {}}}],
            "initContainerStatuses": [{"name": "setup", "imageID": "containerd://" + CONFIG,
                                       "state": {"terminated": {"exitCode": 0}}}],
            "ephemeralContainerStatuses": [{"name": "debug", "imageID": IMAGE,
                                            "state": {"waiting": {"message": "do-not-upload"}}}]}}


def test_pods_include_container_kinds_actual_states_and_only_allowlisted_metadata():
    rows = list(runtime.pod_records(pod()))
    assert [row["state"] for row in rows] == ["running", "waiting", "terminated", "waiting"]
    assert [row["uid"] for row in rows] == ["pod-uid:regular:app", "pod-uid:regular:pending",
                                           "pod-uid:init:setup", "pod-uid:ephemeral:debug"]
    assert rows[0]["image_id"] == IMAGE
    assert rows[1]["image_id"] == ""  # Even a digest in the desired spec is not runtime evidence.
    assert rows[2]["image_id"] == ""
    assert rows[0]["chart_name"] == "my-chart"
    assert rows[0]["chart_version"] == "1.2.3-beta.1"
    assert rows[0]["helm_release"] == "my-release"
    assert rows[0]["workload"] == "app-replicaset"
    assert rows[0]["workload_kind"] == "ReplicaSet" and rows[0]["pod"] == "pod-name"
    assert [row["container_kind"] for row in rows] == ["regular", "regular", "init", "ephemeral"]
    assert all(row["image_id"] == "" for row in rows if row["state"] != "running")
    assert all(set(runtime.BASE_FIELDS) <= set(row) <= set(runtime.FIELDS) for row in rows)
    assert "do-not-upload" not in json.dumps(rows)


@pytest.mark.parametrize("value", [CONFIG, "containerd://" + CONFIG, "docker://" + CONFIG,
                                    "app:latest", "repo@sha256:short", None])
def test_unproven_manifest_identity_stays_unknown(value):
    assert runtime.observed_manifest(value) == ""


def test_only_live_status_identifies_running_bytes_for_all_three_container_kinds():
    value = pod()
    actual = value["status"]
    actual["initContainerStatuses"][0].update(state={"running":{}}, image="registry.example/app:previous",
                                               imageID="containerd://" + IMAGE.upper().replace("SHA256", "sha256").replace("/APP", "/app"))
    actual["ephemeralContainerStatuses"][0].update(state={"running":{}}, imageID="cri-o://"+IMAGE)
    rows = list(runtime.pod_records(value))
    assert [row["image_id"] for row in rows] == [IMAGE, "", IMAGE, IMAGE]
    assert rows[2]["image_ref"] == "registry.example/app:previous"
    actual["ephemeralContainerStatuses"][0].update(state={"waiting":{}}, lastState={"running":{}})
    actual["phase"] = "Succeeded"
    assert not any(row["image_id"] or row["state"] == "running" for row in runtime.pod_records(value))


def test_uncontrolled_pod_and_actual_status_missing_from_spec():
    value = pod()
    del value["metadata"]["ownerReferences"]
    value["status"]["ephemeralContainerStatuses"].append({
        "name": "lingering", "state": {"running": {}}, "image": "registry.example/app:1", "imageID": IMAGE})
    row = list(runtime.pod_records(value))[-1]
    assert (row["namespace"], row["pod"], row["workload"], row["workload_kind"], row["node"]) == (
        "production", "pod-name", "pod-name", "Pod", "node-1")
    assert row["image_id"] == IMAGE and row["container_kind"] == "ephemeral"


@pytest.mark.parametrize("spec, observed, state, expected", [
    ("cats.example/cyber-approved/42/api@" + DIGEST, DIGEST, "running", DIGEST),
    ("registry:5000/team/api:release@" + DIGEST, "sha256:" + "A"*64, "running", DIGEST),
    ("localhost/team/api@" + DIGEST, DIGEST, "running", DIGEST),
    ("cats.example/team/api:latest", DIGEST, "running", ""),
    ("team/api@" + DIGEST, DIGEST, "running", ""),
    ("api@" + DIGEST, DIGEST, "running", ""),
    ("cats.example/team/api@" + OTHER, DIGEST, "running", ""),
    (IMAGE, "containerd://" + DIGEST, "running", ""),
    (IMAGE, "config://" + DIGEST, "running", ""),
    (IMAGE, DIGEST, "waiting", ""),
    (IMAGE, DIGEST, "terminated", ""),
    ("https://" + IMAGE, DIGEST, "running", ""),
    ("registry:65536/team/api@" + DIGEST, DIGEST, "running", ""),
])
def test_bare_kubelet_id_requires_matching_qualified_spec_pin(spec, observed, state, expected):
    value = pod()
    value["spec"]["containers"][0]["image"] = spec
    value["status"]["containerStatuses"][0].update(imageID=observed, state={state:{}}, image="app:latest")
    row = next(runtime.pod_records(value))
    assert row["image_id"] == expected
    assert row["image_ref"] == (spec if expected else "app:latest")


def test_status_pin_cannot_replace_absent_spec_pin_for_bare_kubelet_id():
    value = pod()
    value["status"]["containerStatuses"][0].update(imageID=DIGEST, image=IMAGE)
    assert next(runtime.pod_records(value))["image_id"] == ""


@pytest.mark.parametrize("value", ["https://"+IMAGE, "user:password@registry.example/app@"+DIGEST,
                                  "registry.example/a?secret=x@"+DIGEST, "sha256:"+("a"*64)+"@"+DIGEST])
def test_malformed_runtime_urls_are_not_image_identity(value):
    assert runtime.observed_manifest(value) == ""


class KubernetesAPI:
    def __init__(self, pages):
        self.pages, self.calls = list(pages), []

    def request(self, method, path, body=None, token=None):
        if not path.startswith("/api/v1/pods?"):
            return {"items": [], "metadata": {"resourceVersion": "10"}}
        self.calls.append((method, path, token))
        response = self.pages.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_kubernetes_pagination_rotates_token_and_fails_incomplete(tmp_path):
    token = tmp_path / "token"
    token.write_text("private-kubernetes-token")
    client = KubernetesAPI([{"items": [pod()], "metadata": {"continue": "opaque/+token"}},
                            runtime.AgentError("http_403")])
    original = client.request

    def rotating_request(*args, **kwargs):
        response = original(*args, **kwargs)
        token.write_text("rotated-private-kubernetes-token")
        return response

    client.request = rotating_request
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert len(report["workloads"]) == 4
    assert report["complete"] is False
    assert report["errors"] == ["http_403"]
    assert client.calls[1][1] == "/api/v1/pods?limit=100&continue=opaque%2F%2Btoken"
    assert all(call[0] == "GET" for call in client.calls)
    assert client.calls[1][2] == "rotated-private-kubernetes-token"
    assert "private-kubernetes-token" not in json.dumps(report)


def test_empty_complete_snapshot_is_distinct_from_failed_snapshot(tmp_path):
    token = tmp_path / "token"
    token.write_text("token")
    success = runtime.make_report(runtime.KubernetesCollector(
        KubernetesAPI([{"items": [], "metadata": {}}]), token), 1)
    failure = runtime.make_report(runtime.KubernetesCollector(
        KubernetesAPI([{}]), token), 2)
    assert success["workloads"] == failure["workloads"] == []
    assert success["complete"] is True
    assert failure["complete"] is False


def test_oversized_pod_page_retries_same_cursor_and_reduces_following_pages(tmp_path):
    token = tmp_path / "token"
    token.write_text("token")
    client = KubernetesAPI([
        {"items": [pod()], "metadata": {"continue": "cursor/1", "resourceVersion": "51"}},
        runtime.AgentError("response_too_large"), runtime.AgentError("response_too_large"),
        {"items": [], "metadata": {"continue": "cursor/2", "resourceVersion": "51"}},
        {"items": [], "metadata": {"resourceVersion": "51"}},
    ])
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert report["complete"] and len(report["workloads"]) == 4
    assert [call[1] for call in client.calls] == [
        "/api/v1/pods?limit=100", "/api/v1/pods?limit=100&continue=cursor%2F1",
        "/api/v1/pods?limit=50&continue=cursor%2F1", "/api/v1/pods?limit=25&continue=cursor%2F1",
        "/api/v1/pods?limit=25&continue=cursor%2F2",
    ]


@pytest.mark.parametrize("failure", ["http_410", "http_400"])
def test_unusable_continuation_restarts_with_only_fresh_namespaces(tmp_path, failure):
    token = tmp_path / "token"
    token.write_text("token")
    old = pod()
    old["metadata"]["namespace"] = "deleted"
    responses = [{"items": [old], "metadata": {"continue": "cursor", "resourceVersion": "51"}}]
    if failure == "http_400":
        responses.append(runtime.AgentError("response_too_large"))
    client = KubernetesAPI(responses + [
        runtime.AgentError(failure),
        {"items": [pod()], "metadata": {"continue": "cursor", "resourceVersion": "60"}},
        {"items": [], "metadata": {"resourceVersion": "60"}},
    ])
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert report["complete"] and len(report["workloads"]) == 4
    assert {row["namespace"] for row in report["workloads"]} == {"production"}
    limit = 50 if failure == "http_400" else 100
    assert [call[1] for call in client.calls[-2:]] == [
        f"/api/v1/pods?limit={limit}", f"/api/v1/pods?limit={limit}&continue=cursor"]


def test_pod_list_restarts_and_individual_oversized_pods_are_bounded(tmp_path):
    token = tmp_path / "token"
    token.write_text("token")
    client = KubernetesAPI([runtime.AgentError("response_too_large")] * 7)
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert not report["complete"] and report["errors"] == ["response_too_large"]
    assert len(client.calls) == 7 and client.calls[-1][1] == "/api/v1/pods?limit=1"
    client = KubernetesAPI([{"items": [], "metadata": {"continue": "expired", "resourceVersion": "1"}},
                            runtime.AgentError("http_410")] * 3)
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert not report["complete"] and report["errors"] == ["http_410"]
    assert len(client.calls) == 6


@pytest.mark.parametrize("final, reason", [
    ({"continue":"again", "resourceVersion":"51"}, "kubernetes_pagination_invalid"),
    ({"resourceVersion":"52"}, "kubernetes_snapshot_changed"),
    ({"continue":None, "resourceVersion":"51"}, "kubernetes_pagination_invalid"),
])
def test_inconsistent_or_looping_pod_page_never_completes(tmp_path, final, reason):
    token = tmp_path / "token"
    token.write_text("cluster-token")
    client = KubernetesAPI([{"items":[pod()], "metadata":{"continue":"again", "resourceVersion":"51"}},
                            {"items":[], "metadata":final}])
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert not report["complete"] and report["errors"] == [reason] and len(client.calls) == 2


@pytest.mark.parametrize("metadata,expected", [
    ({"Id": CONFIG, "RepoDigests": [IMAGE]}, IMAGE),
    ({"Id": CONFIG, "RepoDigests": [IMAGE, "mirror/app@" + DIGEST]}, "config://" + CONFIG),
    ({"Id": CONFIG, "RepoDigests": [IMAGE, "registry.example/app@" + OTHER]}, "config://" + CONFIG),
    ({"Id": CONFIG, "RepoDigests": []}, "config://" + CONFIG),
    ({"Id": OTHER, "RepoDigests": [IMAGE]}, "config://" + CONFIG),
    ({"Id": CONFIG, "RepoDigests": ["not-a-digest"]}, "config://" + CONFIG),
])
def test_docker_manifest_requires_matching_config_and_unambiguous_digest(metadata, expected):
    assert runtime.docker_identity(CONFIG, metadata) == expected


def test_docker_preserves_the_actual_repository_when_one_digest_has_aliases():
    image = {"Id": CONFIG, "RepoDigests": [IMAGE, "mirror/app@"+DIGEST]}
    assert runtime.docker_identity(CONFIG, image, "registry.example/app:latest") == IMAGE
    assert runtime.docker_identity(CONFIG, image, "unrelated/app:latest") == "config://"+CONFIG


class DockerAPI:
    def __init__(self):
        self.paths = []
        self.data = {
            "/version": {"ApiVersion": "1.45"},
            "/v1.45/info": {"Name": "docker-host", "sensitive": "do-not-upload"},
            "/v1.45/containers/json?all=1": [{"Id": CONTAINER, "Image": "app:latest"}],
            "/v1.45/containers/" + CONTAINER + "/json": {
                "Id": CONTAINER, "Name": "/app", "Image": CONFIG,
                "Config": {"Image": "app:latest", "Env": ["PASSWORD=do-not-upload"],
                           "Labels": {"com.docker.compose.project": "project",
                                      "com.docker.compose.service": "web"}},
                "State": {"Status": "exited"}},
            "/v1.45/images/" + CONFIG.replace(":", "%3A") + "/json": {
                "Id": CONFIG, "RepoDigests": [IMAGE], "Config": {"Env": ["do-not-upload"]}}}

    def get(self, path):
        self.paths.append(path)
        return self.data[path]


def test_docker_includes_stopped_and_inspects_immutable_id_never_tag():
    client = DockerAPI()
    report = runtime.make_report(runtime.DockerCollector(client), 1)
    assert report["complete"] is True
    row, = report["workloads"]
    assert row["state"] == "exited"
    assert row["image_id"] == IMAGE
    assert row["workload"] == "web" and row["namespace"] == "project"
    assert not any("latest" in path for path in client.paths)
    assert "do-not-upload" not in json.dumps(report)


def test_inventory_and_size_limits_never_claim_complete(monkeypatch):
    rows = list(runtime.pod_records(pod()))
    collector = SimpleNamespace(collect=lambda: (rows, []))
    monkeypatch.setattr(runtime, "MAX_WORKLOADS", 2)
    limited = runtime.make_report(collector, 1)
    assert len(limited["workloads"]) == 2 and not limited["complete"]
    assert "inventory_limit" in limited["errors"]
    monkeypatch.setattr(runtime, "MAX_REPORT_BYTES", 500)
    large = runtime.make_report(collector, 2)
    assert large["workloads"] == [] and not large["complete"]
    assert "report_size_limit" in large["errors"]


def test_kubernetes_collection_deadline_stops_before_next_request(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("private-token")
    client = KubernetesAPI([{"items": [pod()], "metadata": {"continue": "more"}}])
    times = iter([10, 10, 131])
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(times))
    report = runtime.make_report(runtime.KubernetesCollector(client, token), 1)
    assert len(client.calls) == 1
    assert report["complete"] is False and report["errors"] == ["inventory_timeout"]
    assert len(report["workloads"]) == 4


def test_docker_collection_deadline_stops_before_next_request(monkeypatch):
    client = DockerAPI()
    times = iter([10, 10, 11, 12, 13, 131])
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(times))
    report = runtime.make_report(runtime.DockerCollector(client), 1)
    assert len(client.paths) == 4  # version, host, list and container; no late image inspect.
    assert report["complete"] is False and report["errors"] == ["inventory_timeout"]


def test_observed_timestamp_precedes_collection_work(monkeypatch):
    start = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
    clock = SimpleNamespace(value=start)
    monkeypatch.setattr(runtime, "datetime", SimpleNamespace(now=lambda tz: clock.value))

    def collect():
        clock.value += timedelta(minutes=2)
        return [], []

    report = runtime.make_report(SimpleNamespace(collect=collect), 1)
    assert report["observed_at"] == start.isoformat()
    assert report["observed_at"] != clock.value.isoformat()


class ReportingAPI:
    base_url = "https://cats.example"

    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def request(self, method, path, body=None, token=None):
        self.calls.append((method, path, deepcopy(body), token))
        if self.fail:
            raise runtime.AgentError("transport_failed")
        return {"accepted": True, "sequence": body["sequence"]} if path.endswith("/reports") else {}


def test_report_retry_survives_restart_and_sequence_advances_only_after_ack(tmp_path):
    collector = SimpleNamespace(collect=lambda: (list(runtime.pod_records(pod())), []))
    failure = ReportingAPI(fail=True)
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        state.update(agent_token="private-cats-token", cats_url=failure.base_url)
        store.save(state)
        source_id = state["source_id"]
        with pytest.raises(runtime.AgentError, match="transport_failed"):
            runtime.send_once(store, state, failure, collector)
        assert store.load()["next_sequence"] == 1
        assert store.load()["pending"] == failure.calls[0][2]
    success = ReportingAPI()
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        assert state["source_id"] == source_id
        no_recollect = SimpleNamespace(collect=lambda: pytest.fail("Retry must use saved snapshot"))
        runtime.send_once(store, state, success, no_recollect)
        assert success.calls[0][2] == failure.calls[0][2]
        assert store.load()["next_sequence"] == 2
        assert store.load()["pending"] is None
        runtime.send_once(store, state, success, collector)
        assert success.calls[1][2]["sequence"] == 2
    assert "private-cats-token" not in json.dumps(success.calls[0][2])
    assert success.calls[0][3] == "private-cats-token"


def test_private_atomic_state_and_exclusive_owner(tmp_path):
    path = tmp_path / "state"
    with runtime.StateStore(path) as store:
        store.load()
        with pytest.raises(runtime.AgentError, match="state_already_in_use"):
            with runtime.StateStore(path):
                pass
        assert not list(path.glob(".state-*"))
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o700
            assert (path / "state.json").stat().st_mode & 0o777 == 0o600


def test_backward_clock_never_persists_unsendable_snapshot_and_recovers(tmp_path, monkeypatch):
    clock = SimpleNamespace(value=datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc))
    class TestClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.value
    monkeypatch.setattr(runtime, "datetime", TestClock)
    client = ReportingAPI()
    collector = SimpleNamespace(collect=lambda: ([], []))
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        state.update(cats_url=client.base_url, agent_token="test")
        runtime.send_once(store, state, client, collector)
        assert store.load()["last_acked_observed_at"] == clock.value.isoformat()
    clock.value -= timedelta(seconds=20)
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        with pytest.raises(runtime.AgentError, match="clock_behind_last_report"):
            runtime.send_once(store, state, client, SimpleNamespace(collect=lambda: pytest.fail("Clock behind")))
        assert len(client.calls) == 1 and store.load()["pending"] is None and state["next_sequence"] == 2
        clock.value += timedelta(seconds=20)
        runtime.send_once(store, state, client, collector)
        assert client.calls[-1][2]["sequence"] == 2 and store.load()["next_sequence"] == 3


def test_broken_state_is_not_silently_reenrolled(tmp_path):
    store = runtime.StateStore(tmp_path / "state")
    store.path.write_text("broken")
    with pytest.raises(runtime.AgentError, match="state_invalid"):
        store.load()


@pytest.mark.parametrize("url", ["http://cats.example", "https://user:password@cats.example",
                                 "https://cats.example/?token=secret", "https://cats.example/#x"])
def test_https_required_and_credentials_cannot_be_embedded_in_endpoint(url):
    with pytest.raises(runtime.AgentError):
        runtime.HTTPSClient(url)


def test_tls_verification_and_redirect_rejection():
    client = runtime.HTTPSClient("https://cats.example")
    assert client.context.verify_mode == ssl.CERT_REQUIRED
    assert client.context.check_hostname is True
    with pytest.raises(runtime.AgentError, match="redirect_rejected"):
        runtime.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example")


def test_enrollment_uses_key_file_then_reuses_persisted_identity(tmp_path):
    key = tmp_path / "key"
    key.write_text("private-linking-key")
    client = ReportingAPI()
    original = client.request

    def request(method, path, body=None, token=None):
        original(method, path, body, token)
        return {"agent_id": "agent-123", "agent_token": body["agent_token"],
                "environment_id": 1, "environment_name": "Production", "report_interval_seconds": 60}

    client.request = request
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        runtime.enroll(store, state, client, "Production Kubernetes", key)
        key.unlink()
        runtime.enroll(store, state, client, "Production Kubernetes", key)
        assert len(client.calls) == 1
        assert client.calls[0][2]["linking_key"] == "private-linking-key"
        saved = store.path.read_text()
        assert "private-linking-key" not in saved
        assert state["agent_token"].startswith("cats-agent-") and state["agent_token"] in saved
        assert state["source_id"] == client.calls[0][2]["source_id"]


def test_state_is_bound_to_enrolled_cats_url(tmp_path):
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        state.update(agent_token="secret", cats_url="https://different.example")
        with pytest.raises(runtime.AgentError, match="enrollment_required"):
            runtime.send_once(store, state, ReportingAPI(), None)


def test_lost_link_response_retries_identical_identity_after_restart(tmp_path):
    key = tmp_path / "key"
    key.write_text("bootstrap-key")
    client = ReportingAPI(fail=True)
    directory = tmp_path / "state"
    with runtime.StateStore(directory) as store:
        state = store.load()
        with pytest.raises(runtime.AgentError, match="transport_failed"):
            runtime.enroll(store, state, client, "production", key, "kubernetes")
        pending = store.load()["pending_enrollment"]
        assert pending["agent_token"] == client.calls[0][2]["agent_token"]
        assert "bootstrap-key" not in store.path.read_text()
        assert "agent_token" not in store.load()
    sent = client.calls[0][2]
    with runtime.StateStore(directory) as store:
        state = store.load()
        with pytest.raises(runtime.AgentError, match="enrollment_state_mismatch"):
            runtime.enroll(store, state, client, "new-name", key, "docker")
        def replay(method, path, body, token=None):
            assert body == sent and body["kind"] == "kubernetes"
            return {"agent_id":"agent-123", "agent_token":body["agent_token"], "environment_id":1}
        client.request = replay
        runtime.enroll(store, state, client, "new-name", key, "kubernetes")
        key.unlink()
        assert "pending_enrollment" not in store.load() and store.load()["agent_token"] == sent["agent_token"]
        runtime.enroll(store, state, client, "new-name", key, "kubernetes")
        with pytest.raises(runtime.AgentError, match="enrollment_source_mismatch"):
            runtime.enroll(store, state, client, "new-name", key, "docker")


@pytest.mark.parametrize("ack", [None, {}, {"accepted":False, "sequence":1},
                                  {"accepted":True, "sequence":2}, {"accepted":True, "sequence":True}])
def test_invalid_ack_keeps_pending_snapshot_for_replay(tmp_path, ack):
    client = ReportingAPI()
    client.request = lambda *args, **kwargs: ack
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        state.update(cats_url=client.base_url, agent_token="test")
        store.save(state)
        with pytest.raises(runtime.AgentError, match="report_ack_invalid"):
            runtime.send_once(store, state, client, SimpleNamespace(collect=lambda: ([], [])))
        assert store.load()["pending"]["sequence"] == 1 and store.load()["next_sequence"] == 1


def test_run_retries_transient_initial_link_and_then_reports(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_text("bootstrap-key")
    bodies, sleeps = [], []
    def request(method, path, body=None, token=None):
        if path.endswith("/link"):
            bodies.append(dict(body))
            if len(bodies) == 1:
                raise runtime.AgentError("http_503")
            return {"agent_id":"one", "environment_id":1, "agent_token":body["agent_token"]}
        assert token == bodies[0]["agent_token"]
        return {"accepted":True, "sequence":body["sequence"]}
    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise KeyboardInterrupt()
    client = SimpleNamespace(base_url="https://cats.example", request=request)
    monkeypatch.setattr(runtime, "HTTPSClient", lambda *args: client)
    monkeypatch.setattr(runtime, "DockerCollector", lambda *args: SimpleNamespace(collect=lambda: ([], [])))
    monkeypatch.setattr(runtime.time, "sleep", sleep)
    assert runtime.main(["run", "--cats-url", client.base_url, "--state-dir", str(tmp_path / "state"),
                         "--name", "install", "--linking-key-file", str(key)]) == 0
    assert sleeps == [5, 60] and bodies[0] == bodies[1]
    with runtime.StateStore(tmp_path / "state") as store:
        assert store.load()["next_sequence"] == 2
