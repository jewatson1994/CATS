"""Real collector payloads cross the enrollment/report HTTP and storage boundary."""

from copy import deepcopy
from datetime import datetime
import json
from types import SimpleNamespace

import pytest

from app.runtime_models import RuntimeAgent
from test_runtime_collector import DockerAPI, KubernetesAPI, pod, runtime
from test_runtime_routes import context, post


class RouterTransport:
    """Only the network transport is replaced; the collector and router are real."""

    base_url = "https://cats.example"

    def __init__(self, client):
        self.client = client
        self.drop_next_enrollment_ack = False
        self.drop_next_report_ack = False
        self.reports = []
        self.acknowledgements = []

    def request(self, method, path, body=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        response = self.client.request(method, path, content=runtime.encode_json(body), headers=headers)
        if response.status_code >= 400:
            raise runtime.AgentError(f"http_{response.status_code}")
        if path == "/api/runtime/link" and self.drop_next_enrollment_ack:
            self.drop_next_enrollment_ack = False
            raise runtime.AgentError("transport_failed")
        if path == "/api/runtime/reports":
            self.reports.append(deepcopy(body))
            self.acknowledgements.append(response.json())
            if self.drop_next_report_ack:
                self.drop_next_report_ack = False
                raise runtime.AgentError("transport_failed")
        return response.json()


def collector_for(kind, token_file, *, incomplete=False, empty=False):
    if kind == "kubernetes":
        value = pod()
        if incomplete:
            value["metadata"]["uid"] = "partial-pod-must-not-replace-inventory"
        pages = [{"items": [] if empty else [value],
                  "metadata": {"continue": "more"} if incomplete else {}}]
        if incomplete:
            pages.append(runtime.AgentError("http_403"))
        return runtime.KubernetesCollector(KubernetesAPI(pages), token_file)
    api = DockerAPI()
    inventory = api.data["/v1.45/containers/json?all=1"]
    if empty:
        inventory.clear()
    if incomplete:
        inventory.append({"Id": "e" * 64})
        for path, value in api.data.items():
            if path.startswith("/v1.45/containers/") and path.endswith("/json"):
                value["Name"] = "/partial-name-must-not-replace-inventory"
        original = api.get

        def get(path):
            if path == "/v1.45/containers/" + "e" * 64 + "/json":
                raise runtime.AgentError("docker_http_404")
            return original(path)

        api.get = get
    return runtime.DockerCollector(api)


@pytest.mark.parametrize("kind", ["kubernetes", "docker"])
def test_collector_enrollment_reports_ack_loss_restart_and_incomplete_reconciliation(context, tmp_path, kind):
    client, db, _ = context
    environment = post(client, "environments", {"name": "Production " + kind,
                                                "kind": kind, "service_ids": [1]})
    assert environment.status_code == 200
    env_id = environment.json()["id"]
    key = post(client, f"environments/{env_id}/link-tokens").json()["linking_key"]
    key_file, token_file = tmp_path / "link-key", tmp_path / "kube-token"
    key_file.write_text(key)
    token_file.write_text("private-service-account-token")
    transport = RouterTransport(client)
    transport.drop_next_enrollment_ack = True

    with runtime.StateStore(tmp_path / "agent-state") as store:
        state = store.load()
        source_id = state["source_id"]
        with pytest.raises(runtime.AgentError, match="transport_failed"):
            runtime.enroll(store, state, transport, "Production collector", key_file, kind=kind)
        state = store.load()
        runtime.enroll(store, state, transport, "Production collector", key_file, kind=kind)
        assert state["environment_id"] == env_id
        assert state["report_interval_seconds"] == 60
        agent_id = state["agent_id"]
        transport.drop_next_report_ack = True
        with pytest.raises(runtime.AgentError, match="transport_failed"):
            runtime.send_once(store, state, transport, collector_for(kind, token_file))
        assert store.load()["next_sequence"] == 1
        first = deepcopy(store.load()["pending"])
        assert first == transport.reports[0]
        assert datetime.fromisoformat(first["observed_at"]).utcoffset() is not None
        assert "private-service-account-token" not in json.dumps(first)
        assert state["agent_token"] not in json.dumps(first)

    db.expire_all()
    stored = db.get(RuntimeAgent, agent_id)
    received = stored.last_seen_at
    assert stored.last_sequence == 1 and stored.workloads == first["workloads"]
    assert stored.source_id == source_id
    overview = client.get("/api/runtime").json()
    assert overview["agents"][0]["coverage"] == "fresh"
    assert overview["agents"][0]["inventory_observed_at"] == first["observed_at"]
    assert {row["state"] for row in overview["workloads"]} == (
        {"running", "waiting", "terminated"} if kind == "kubernetes" else {"exited"})

    key_file.unlink()  # Restart uses the saved enrollment and snapshot.
    with runtime.StateStore(tmp_path / "agent-state") as store:
        state = store.load()
        runtime.enroll(store, state, transport, "Production collector", key_file, kind=kind)
        runtime.send_once(store, state, transport, SimpleNamespace(
            collect=lambda: pytest.fail("An unacknowledged snapshot must be replayed unchanged")))
        assert transport.reports[1] == first
        assert transport.acknowledgements[1] == {"accepted": True, "duplicate": True, "sequence": 1}
        db.expire_all()
        assert db.get(RuntimeAgent, agent_id).last_seen_at == received
        assert store.load()["next_sequence"] == 2 and store.load()["pending"] is None

        runtime.send_once(store, state, transport, collector_for(kind, token_file, incomplete=True))
        partial = transport.reports[-1]
        assert partial["sequence"] == 2 and partial["complete"] is False
        assert partial["workloads"] != first["workloads"] and partial["workloads"]
        overview = client.get("/api/runtime").json()
        assert overview["agents"][0]["coverage"] == "incomplete"
        assert overview["agents"][0]["inventory_observed_at"] == first["observed_at"]
        assert all(row["compliance"] == {"status": "unverified", "reason": "coverage_incomplete"}
                   for row in overview["workloads"])
        db.expire_all()
        assert db.get(RuntimeAgent, agent_id).workloads == first["workloads"]

        runtime.send_once(store, state, transport, collector_for(kind, token_file, empty=True))
        assert transport.reports[-1]["sequence"] == 3
        overview = client.get("/api/runtime").json()
        assert overview["agents"][0]["coverage"] == "fresh"
        assert overview["workloads"] == []
        assert store.load()["next_sequence"] == 4


def test_collector_invalid_metadata_becomes_accepted_incomplete_report(context, tmp_path):
    client, _, _ = context
    environment = post(client, "environments", {"name": "Docker host", "kind": "docker"}).json()
    key = post(client, f"environments/{environment['id']}/link-tokens").json()["linking_key"]
    key_file = tmp_path / "key"
    key_file.write_text(key)
    transport = RouterTransport(client)
    api = DockerAPI()
    for path, value in api.data.items():
        if path.startswith("/v1.45/containers/") and path.endswith("/json"):
            value["Config"]["Labels"]["com.docker.compose.project"] = "invalid\nmetadata"
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        with pytest.raises(runtime.AgentError, match="agent_name_required"):
            runtime.enroll(store, state, transport, "x" * 161, key_file)
        runtime.enroll(store, state, transport, "x" * 160, key_file)
        runtime.send_once(store, state, transport, runtime.DockerCollector(api))
        assert state["next_sequence"] == 2
        assert transport.reports[0]["complete"] is False
        assert transport.reports[0]["errors"] == ["inventory_field_invalid"]
        assert transport.reports[0]["workloads"] == []
    assert client.get("/api/runtime").json()["agents"][0]["coverage"] == "incomplete"
