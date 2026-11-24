"""Kubernetes discovery keeps declared and running inventory distinct across rollouts."""
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from test_runtime_collector import pod, runtime, ReportingAPI


RESOURCES = runtime.kube_workloads.RESOURCES
DIGEST = "sha256:" + "b4" * 32


def owner(kind, name, uid):
    return {"kind": kind, "name": name, "uid": uid, "controller": True}


def workload(kind, name, parent=None):
    template = {"metadata": {}, "spec": {"containers": [{"name": "api", "image": "example/api:v1"}],
                "initContainers": [{"name": "schema", "image": "example/schema:v1"}]}}
    meta = {"namespace": "production", "name": name, "uid": name + "-id"}
    if parent:
        meta["ownerReferences"] = [parent]
    spec = {"template": template}
    return {"metadata": meta, "spec": {"jobTemplate": {"spec": spec}} if kind == "CronJob" else spec}


class InventoryAPI:
    def __init__(self, resources):
        self.resources = resources
        self.lists = []
        self.watches = []

    def request(self, method, path, body=None, token=None):
        endpoint = urlsplit(path).path
        kind = next(kind for kind, resource in RESOURCES.items() if resource == endpoint)
        self.lists.append((method, kind))
        items = self.resources.get(kind, [])
        if isinstance(items, Exception):
            raise items
        return {"items": deepcopy(items), "metadata": {"resourceVersion": "123"}}

    def watch_change(self, path, version, seconds, token):
        self.watches.append((path, version, token))
        return path == RESOURCES["Deployment"]


def collector_for(tmp_path, resources):
    token = tmp_path / "service-account-token"
    token.write_text("workload-token")
    api = InventoryAPI(resources)
    return runtime.KubernetesCollector(api, token), api


def test_list_projection_owner_chains_and_complete_template_inventory(tmp_path, monkeypatch):
    deploy = workload("Deployment", "store")
    deploy["metadata"].update(labels={"app.kubernetes.io/part-of": "shop", "app.kubernetes.io/version": "3.2"},
        annotations={"cats.io/service-id": "27", "cats.io/chart-digest": DIGEST,
                     "meta.helm.sh/release-name": "commerce", "meta.helm.sh/release-namespace": "releases"})
    rs = workload("ReplicaSet", "store-7a", owner("Deployment", "store", "store-id"))
    job = workload("Job", "scheduled-8", owner("CronJob", "scheduled", "scheduled-id"))
    web = pod()
    web["metadata"].update(labels={}, ownerReferences=[owner("ReplicaSet", "store-7a", "store-7a-id")])
    runner = deepcopy(web)
    runner["metadata"].update(name="runner", uid="runner-id", ownerReferences=[owner("Job", "scheduled-8", "scheduled-8-id")])
    independent = deepcopy(web)
    independent["metadata"].update(name="one-off", uid="one-off-id", ownerReferences=[])
    resources = {"Deployment": [deploy], "ReplicaSet": [rs], "StatefulSet": [workload("StatefulSet", "db")],
        "DaemonSet": [workload("DaemonSet", "logs")], "Job": [job, workload("Job", "batch")],
        "CronJob": [workload("CronJob", "scheduled")], "Pod": [web, runner, independent],
        "Namespace": [{"metadata": {"name": "production", "uid": "prod-id"}}]}
    collector, api = collector_for(tmp_path, resources)
    report = runtime.make_report(collector, 1)
    assert report["complete"] and report["discovery_version"] == 1
    assert set(api.lists) == {("GET", kind) for kind in RESOURCES}
    rows = report["workloads"]
    desired = [row for row in rows if row["state"] == "desired"]
    assert {(r["workload"], r["container_kind"]) for r in desired} == {
        (name, category) for name in ("store", "db", "logs", "batch", "scheduled") for category in ("regular", "init")}
    assert all(r["desired_image"] and not (r["pod"] or r["image_id"]) for r in desired)
    assert all(r["namespace_uid"] == "prod-id" for r in rows)
    app = next(r for r in rows if r.get("pod_uid") == "pod-uid" and r["container"] == "app")
    assert (app["workload_kind"], app["workload"], app["workload_uid"]) == ("Deployment", "store", "store-id")
    assert (app["controller_kind"], app["controller_name"], app["controller_uid"]) == ("ReplicaSet", "store-7a", "store-7a-id")
    assert (app["app_part_of"], app["app_version"], app["service_hint"]) == ("shop", "3.2", "27")
    assert (app["helm_release"], app["helm_namespace"], app["chart_digest"]) == ("commerce", "releases", DIGEST)
    assert {r["workload"] for r in rows if r.get("pod_uid") == "runner-id"} == {"scheduled"}
    assert {r["workload_kind"] for r in rows if r.get("pod_uid") == "one-off-id"} == {"Pod"}
    assert {r["container_kind"] for r in rows if r.get("pod_uid") == "pod-uid"} == {"init", "regular", "ephemeral"}
    assert "do-not-upload" not in json.dumps(report)

    monkeypatch.setattr(runtime.time, "sleep", lambda _: None)
    collector.wait_for_change(10)
    assert set(api.watches) == {(path, "123", "workload-token") for path in RESOURCES.values()}
    resources["DaemonSet"] = []
    reconciled = runtime.make_report(collector, 2)
    assert reconciled["complete"] and all(r["workload"] != "logs" for r in reconciled["workloads"])


def test_cluster_binding_survives_restart_and_rejects_moved_state(tmp_path):
    namespaces = [{"metadata": {"name": "kube-system", "uid": "original-id"}}]
    collector, _ = collector_for(tmp_path, {"Namespace": namespaces})
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        collector.bind_cluster(store, state)
        assert store.load()["kubernetes_cluster_uid"] == "original-id"
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        collector.bind_cluster(store, state)
        namespaces[0]["metadata"]["uid"] = "replacement-id"
        with pytest.raises(runtime.AgentError, match="kubernetes_cluster_identity_mismatch"):
            collector.bind_cluster(store, state)
        namespaces.clear()
        with pytest.raises(runtime.AgentError, match="kubernetes_cluster_identity_unavailable"):
            collector.bind_cluster(store, state)
        assert store.load()["kubernetes_cluster_uid"] == "original-id"


def test_recreated_owner_and_incomplete_lists(tmp_path):
    dep = workload("Deployment", "app")
    old = pod()
    old["metadata"]["ownerReferences"] = [owner("ReplicaSet", "rs", "old-rs")]
    rs = workload("ReplicaSet", "rs", owner("Deployment", "app", "app-id"))
    resources = {"Deployment": [dep], "ReplicaSet": [rs], "Pod": [old]}
    collector, _ = collector_for(tmp_path, resources)
    rows, errors = collector.collect()
    assert not errors
    replaced = deepcopy(rows)
    next(r for r in replaced if r["state"] == "desired")["workload_uid"] = "replacement"
    assert runtime.inventory_signature({"workloads": rows}) != runtime.inventory_signature({"workloads": replaced})
    assert {r["workload_uid"] for r in rows if r["pod"]} == {"old-rs"}
    resources["CronJob"] = runtime.AgentError("http_403")
    failed = runtime.make_report(collector, 2)
    assert not failed["complete"] and failed["errors"] == ["http_403"]
    assert collector.versions == {}
    resources.clear()
    report = runtime.make_report(collector, 3)
    assert report["discovery_version"] == 1 and report["complete"] and report["workloads"] == []


@pytest.mark.parametrize(("event", "changed"), [({"type": "MODIFIED"}, True),
    ({"type": "ERROR", "object": {"code": 410}}, True), ({"type": "BOOKMARK"}, False)])
def test_watch_sends_versioned_read_only_metadata_request(event, changed):
    def open_request(request, timeout):
        assert request.get_method() == "GET"
        params = parse_qs(urlsplit(request.full_url).query)
        assert params["watch"] == ["true"] and params["resourceVersion"] == ["v4"]
        assert "PartialObjectMetadata" in request.get_header("Accept")
        return io.BytesIO(json.dumps(event).encode())
    api = SimpleNamespace(base_url="https://kubernetes.default.svc", opener=SimpleNamespace(open=open_request))
    assert runtime.HTTPSClient.watch_change(api, RESOURCES["Pod"], "v4", 5, "token") is changed


def test_offline_outbox_ignores_replica_churn_and_replays_changes_after_restart(tmp_path, monkeypatch):
    collector, api = collector_for(tmp_path, {"Deployment": [workload("Deployment", "store")], "Pod": [pod()]})
    api.resources["Pod"][0]["metadata"]["ownerReferences"] = [owner("Deployment", "store", "store-id")]
    receiver = ReportingAPI(fail=True)
    monkeypatch.setattr(runtime, "MAX_OFFLINE_REPORTS", 2)
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        state.update(agent_token="agent-credential", cats_url=receiver.base_url)
        with pytest.raises(runtime.AgentError, match="transport_failed"):
            runtime.send_once(store, state, receiver, collector)
        initial = deepcopy(state["pending"])
        restarted = deepcopy(api.resources["Pod"][0])
        restarted["metadata"].update(name="replacement", uid="replacement-id")
        api.resources["Pod"].append(restarted)
        runtime.capture_offline(store, state, collector)
        assert not state.get("offline")
        for tag in ("2", "3", "4"):
            api.resources["Deployment"][0]["spec"]["template"]["spec"]["containers"][0]["image"] = "example/api:v" + tag
            runtime.capture_offline(store, state, collector)
        assert state["pending"] == initial and len(state["offline"]) == 2
    receiver.fail = False
    with runtime.StateStore(tmp_path / "state") as store:
        state = store.load()
        while state["pending"]:
            runtime.send_once(store, state, receiver, collector)
    reports = [call[2] for call in receiver.calls[1:]]
    assert [r["sequence"] for r in reports] == [1, 2, 3] and reports[0] == initial
    images = [next(row["desired_image"] for row in r["workloads"] if row["state"] == "desired" and row["container"] == "api") for r in reports]
    assert images == ["example/api:v1", "example/api:v2", "example/api:v4"]


def test_wire_digest_and_legacy_validation(tmp_path):
    from app.runtime_routes import validate_report
    from fastapi import HTTPException

    deployment = workload("Deployment", "store")
    deployment["metadata"]["annotations"] = {"cats.io/chart-digest": DIGEST.upper()}
    collector, _ = collector_for(tmp_path, {"Deployment": [deployment]})
    report = runtime.make_report(collector, 1)
    timestamp = datetime.now(timezone.utc)
    assert all("chart_digest" not in row for row in validate_report(report, timestamp)[2])
    report["workloads"][0]["chart_digest"] = DIGEST.upper()
    with pytest.raises(HTTPException, match="lowercase"):
        validate_report(report, timestamp)
    report["workloads"][0]["chart_digest"] = DIGEST
    assert validate_report(report, timestamp)[2][0]["chart_digest"] == DIGEST
    del report["discovery_version"]
    with pytest.raises(HTTPException, match="Desired template"):
        validate_report(report, timestamp)
    report["workloads"] = [{"uid": "old", "container": "main", "state": "running"}]
    assert "workload_uid" not in validate_report(report, timestamp)[2][0]
