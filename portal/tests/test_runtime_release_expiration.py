"""Re-evaluate the very same running Pod when its release expires between reports."""
from datetime import timedelta

from app import runtime_routes
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.execution_summaries import payload_digest
from app.models import Execution
from app.release_validity import new_validity
from app.runtime_models import RuntimeAgent, now
from test_runtime_routes import context, enroll, report, snapshot


def test_fresh_pod_becomes_namespace_issue_at_signed_expiry_without_another_report(context, monkeypatch):
    client, db, _ = context
    linked, _ = enroll(client)
    sampled = now()
    approved_at = sampled - timedelta(days=1) + timedelta(seconds=10)
    execution = Execution(service_id=1, execution_key="runtime-expiry", scanned_at=approved_at,
                          complete=True, scan_scope="service", raw_payload={})
    db.add(execution)
    db.flush()
    ref = "registry.example/project/api"
    image_digest = "sha256:" + "a" * 64
    evidence = dict(service_id=1, source_execution_id=execution.id, source_version_id=None,
                    source_payload_digest=payload_digest({}), approval_validity=new_validity(
                        approved_at, {"cyber_approval_validity_days": "1"}),
                    artifacts=[{"kind": "image", "reference": ref + "@" + image_digest, "digest": image_digest}])
    approval = CyberApproval(service_id=1, source_execution_id=execution.id, variant="current",
                             status="approved", snapshot=evidence, snapshot_digest=snapshot_digest(evidence),
                             decided_at=approved_at)
    db.add(approval)
    db.commit()
    original_digest = approval.snapshot_digest
    value = snapshot(observed_at=sampled.isoformat())
    value["workloads"][0].update(namespace="mission-apps", pod="api-7b96d", workload="api",
                                 image_ref=ref + ":1.2", image_id=ref + "@" + image_digest)
    monkeypatch.setattr(runtime_routes, "now", lambda: sampled)
    assert report(client, linked, value).status_code == 200
    first = client.get("/api/runtime").json()
    assert first["workloads"][0]["compliance"]["status"] == "approved"
    assert first["issues"] == []
    monkeypatch.setattr(runtime_routes, "now", lambda: sampled + timedelta(seconds=10))
    later = client.get("/api/runtime").json()
    issue, = later["issues"]
    assert (issue["reason"], issue["namespace"], issue["pod"], issue["container"]) == (
        "release_expired", "mission-apps", "api-7b96d", "api")
    assert later["agents"][0]["coverage"] == "fresh"
    assert later["workloads"][0]["observed_at"] == first["workloads"][0]["observed_at"]
    assert db.get(RuntimeAgent, linked["agent_id"]).last_sequence == 1
    db.refresh(approval)
    assert approval.snapshot_digest == original_digest and approval.revoked_at is None
