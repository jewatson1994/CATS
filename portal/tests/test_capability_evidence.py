import json

import pytest

from app.capability_evidence import detect_requirements, resolve_capabilities, workload_evidence


def test_configuration_detection_includes_init_sidecar_projection_without_values():
    pod = {"kind": "Pod", "metadata": {"name": "app"}, "spec": {
        "volumes": [{"projected": {"sources": [{"secret": {"name": "mounted"}}]}}],
        "initContainers": [{"name": "sidecar", "restartPolicy": "Always", "envFrom": [{"configMapRef": {"name": "settings"}}]}],
        "containers": [{"env": [{"name": "PASSWORD", "value": "do-not-copy"}, {"valueFrom": {"secretKeyRef": {"name": "credential", "key": "password"}}}]}]}}
    rows = detect_requirements([pod])
    assert {row["evidence"]["dependency_name"] for row in rows} == {"mounted", "settings", "credential"}
    assert "do-not-copy" not in json.dumps(rows)
    assert "password" not in json.dumps(rows)
    resolve_capabilities(rows, [pod], [{"kind": "Secret", "metadata": {"name": "credential", "namespace": "ns"}, "data": {"password": "secret"}}], "ns")
    credential = next(row for row in rows if row["evidence"]["dependency_name"] == "credential")
    assert credential["status"] == "AVAILABLE"
    assert credential["evidence"]["values_collected"] is False
    assert "password" not in json.dumps(rows)


def test_bound_other_claim_cannot_verify_missing_requested_claim():
    row = {"capability": "Storage", "required": True, "source_resource": "PersistentVolumeClaim/wanted", "source_namespace": "ns"}
    resolve_capabilities([row], [], [{"kind": "PersistentVolumeClaim", "metadata": {"name": "other", "namespace": "ns"}, "status": {"phase": "Bound"}}], "ns")
    assert row["status"] == "UNEXERCISED"


def test_stateful_claim_template_requires_each_replica_in_correct_namespace():
    sts = {"kind": "StatefulSet", "metadata": {"name": "db", "namespace": "ns", "uid": "sts"}, "spec": {"replicas": 2, "volumeClaimTemplates": [{"metadata": {"name": "data"}}]}}
    rows = detect_requirements([sts])
    claims = [{"kind": "PersistentVolumeClaim", "metadata": {"name": f"data-db-{i}", "namespace": "ns", "uid": f"claim-{i}"},
               "spec": {"volumeName": f"pv-{i}", "storageClassName": "standard"}, "status": {"phase": "Bound"}} for i in range(2)]
    storage_class = {"kind": "StorageClass", "metadata": {"name": "standard"}, "provisioner": "rancher.io/local-path"}
    volumes = [{"kind": "PersistentVolume", "metadata": {"name": f"pv-{i}"},
                "spec": {"storageClassName": "standard", "claimRef": {"name": f"data-db-{i}", "namespace": "ns", "uid": f"claim-{i}"}},
                "status": {"phase": "Bound"}} for i in range(2)]
    pods = [{"kind": "Pod", "metadata": {"name": f"db-{i}", "namespace": "ns", "uid": f"pod-{i}", "ownerReferences": [{"uid": "sts"}]},
             "spec": {"nodeName": "node", "volumes": [{"persistentVolumeClaim": {"claimName": f"data-db-{i}"}}]},
             "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}} for i in range(2)]
    resolve_capabilities(rows, [sts], [sts, claims[0]], "ns")
    assert rows[0]["status"] == "UNEXERCISED"
    resolve_capabilities(rows, [sts], [sts, storage_class, *claims, *volumes, *pods], "ns")
    assert rows[0]["status"] == "VERIFIED"
    assert all(item["claim_ref_matched"] and item["provider_correlated"] and item["consumers_ready"] for item in rows[0]["evidence"]["claims"])


def test_bound_claim_requires_exact_pv_claimref_and_local_storageclass():
    row = {"capability": "Storage", "required": True, "source_resource": "PersistentVolumeClaim/data", "source_namespace": "ns"}
    claim = {"kind": "PersistentVolumeClaim", "metadata": {"name": "data", "namespace": "ns", "uid": "claim"},
             "spec": {"volumeName": "missing", "storageClassName": "standard"}, "status": {"phase": "Bound"}}
    resolve_capabilities([row], [claim], [claim], "ns")
    assert row["status"] == "UNEXERCISED"
    assert row["evidence"]["claims"][0]["claim_ref_matched"] is False


@pytest.mark.parametrize("kind,state", [("Deployment", {"readyReplicas": 1, "observedGeneration": 1}), ("StatefulSet", {"readyReplicas": 1, "observedGeneration": 1}), ("DaemonSet", {"desiredNumberScheduled": 1, "numberReady": 1, "observedGeneration": 1}), ("Job", {"conditions": [{"type": "Complete", "status": "True"}]})])
def test_kind_specific_workload_readiness(kind, state):
    owner = {"kind": kind, "metadata": {"name": "app", "namespace": "ns", "uid": "owner", "generation": 1}, "spec": {}, "status": state}
    pod = {"kind": "Pod", "metadata": {"name": "child", "namespace": "ns", "ownerReferences": [{"uid": "owner"}]}, "spec": {"nodeName": "node"}}
    result = workload_evidence(owner, [owner, pod])
    assert result["ready"] and result["scheduled"]


def test_cronjob_without_executed_owned_job_not_verified():
    cron = {"kind": "CronJob", "metadata": {"name": "scheduled", "namespace": "ns", "uid": "cron"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"nodeSelector": {"type": "worker"}}}}}}}
    evidence = workload_evidence(cron, [cron])
    assert evidence["ready"] and evidence["configured"]
    assert not evidence["execution_observed"]
    unrelated_job = {"kind": "Job", "metadata": {"name": "other", "namespace": "ns"}, "status": {"conditions": [{"type": "Complete", "status": "True"}]}}
    assert not workload_evidence(cron, [cron, unrelated_job])["execution_observed"]


def test_init_failure_and_unready_native_sidecar_override_pod_readiness():
    pod = {"kind": "Pod", "metadata": {"name": "app"}, "spec": {"nodeName": "n", "initContainers": [{"name": "sidecar", "restartPolicy": "Always"}]},
           "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}], "initContainerStatuses": [
               {"name": "sidecar", "ready": False, "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "secret=never-copy"}}}]}}
    result = workload_evidence(pod, [])
    assert not result["ready"]
    assert result["containers"][0]["role"] == "sidecar"
    assert "never-copy" not in json.dumps(result)


def test_cloud_and_gpu_rows_remain_unchanged_and_storageclass_top_level_checked():
    gpu = {"capability": "GPU / extended resources", "required": True, "status": "UNAVAILABLE"}
    row = {"capability": "Storage", "required": True, "source_resource": "StorageClass/cloud"}
    storage = {"kind": "StorageClass", "metadata": {"name": "cloud"}, "provisioner": "ebs.csi.aws.com"}
    resolve_capabilities([gpu, row], [storage], [storage], "ns")
    assert gpu == {"capability": "GPU / extended resources", "required": True, "status": "UNAVAILABLE"}
    assert row["status"] == "PROVIDER_SPECIFIC"
