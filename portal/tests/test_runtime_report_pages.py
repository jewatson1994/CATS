"""Large agent inventories must appear atomically even after lost responses or restarts."""
from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.runtime_models import RuntimeAgent
from app.runtime_report_pages import RuntimeReportPage, digest
from test_runtime_collector import runtime
from test_runtime_routes import context, enroll, post, report, snapshot
from cats_runtime.report_pages import send_report


def send_page(client, linked, envelope):
    return client.post("/api/runtime/reports/pages", json=envelope,
                       headers={"Authorization": "Bearer " + linked["agent_token"]})


def pages(value):
    meta = {k: v for k, v in value.items() if k != "workloads"}
    return [{**meta, "workloads": [row], "page": i, "pages": len(value["workloads"]),
             "snapshot_sha256": digest(value)} for i, row in enumerate(value["workloads"])]


def test_collector_resumes_large_snapshot_after_lost_acks(context):
    client, db, _ = context
    linked, _ = enroll(client)
    previous = snapshot()
    assert report(client, linked, previous).status_code == 200
    latest = snapshot(sequence=2)
    sample = latest["workloads"][0]
    latest["workloads"] = [dict(sample, uid=f"pod-{i}:main:app") for i in range(2051)]

    class Transport:
        def __init__(self):
            self.drop_partial = self.drop_final = True
            self.acknowledged_pages = []

        def request(self, method, path, envelope, token):
            assert method == "POST" and path.endswith("/pages") and token == linked["agent_token"]
            response = send_page(client, linked, envelope)
            assert response.status_code == 200, response.text
            ack = response.json()
            self.acknowledged_pages.append(envelope["page"])
            if ack.get("received") and self.drop_partial:
                self.drop_partial = False
                raise runtime.AgentError("transport_failed")
            if ack.get("accepted") and self.drop_final:
                self.drop_final = False
                raise runtime.AgentError("transport_failed")
            return ack

    transport = Transport()
    with pytest.raises(runtime.AgentError, match="transport_failed"):
        send_report(transport, linked["agent_token"], latest)
    db.expire_all()
    agent = db.get(RuntimeAgent, linked["agent_id"])
    assert agent.last_sequence == 1 and len(agent.workloads) == 1
    with pytest.raises(runtime.AgentError, match="transport_failed"):
        send_report(transport, linked["agent_token"], latest)
    db.refresh(agent)
    assert agent.last_sequence == 2 and len(agent.workloads) == 2051
    seen = agent.last_seen_at
    assert send_report(transport, linked["agent_token"], latest) == {
        "accepted": True, "duplicate": True, "sequence": 2}
    db.refresh(agent)
    assert agent.last_seen_at == seen and transport.acknowledged_pages[-1] == 0
    assert db.scalar(select(func.count()).select_from(RuntimeReportPage)) == 0


def test_conflicting_corrupt_and_revoked_pages_preserve_last_inventory(context):
    client, db, _ = context
    linked, _ = enroll(client)
    previous = snapshot()
    assert report(client, linked, previous).status_code == 200
    value = snapshot(sequence=2)
    value["workloads"].append(dict(value["workloads"][0], uid="second"))
    first, second = pages(value)
    assert send_page(client, linked, second).status_code == 200
    tampered = deepcopy(second)
    tampered["workloads"][0]["uid"] = "changed"
    assert send_page(client, linked, tampered).status_code == 409
    tampered = deepcopy(first)
    tampered["workloads"][0]["uid"] = "changed"
    assert send_page(client, linked, tampered).status_code == 409
    db.expire_all()
    assert db.get(RuntimeAgent, linked["agent_id"]).last_sequence == 1
    assert post(client, f"agents/{linked['agent_id']}/revoke").status_code == 200
    assert send_page(client, linked, first).status_code == 401
    assert db.scalar(select(func.count()).select_from(RuntimeReportPage)) == 0


def test_direct_delivery_cannot_overwrite_competing_pages(context):
    client, db, _ = context
    linked, _ = enroll(client)
    value = snapshot(sequence=3)
    value["workloads"].append(dict(value["workloads"][0], uid="second"))
    assert send_page(client, linked, pages(value)[0]).status_code == 200
    backwards = deepcopy(value)
    backwards.update(sequence=4, observed_at=(datetime.fromisoformat(value["observed_at"])
                                              - timedelta(minutes=1)).isoformat())
    assert send_page(client, linked, pages(backwards)[0]).status_code == 409
    assert report(client, linked, backwards).status_code == 409
    assert report(client, linked, snapshot(sequence=2)).status_code == 409
    conflict = deepcopy(value)
    conflict["workloads"][1]["uid"] = "different"
    assert report(client, linked, conflict).status_code == 409
    db.expire_all()
    assert db.get(RuntimeAgent, linked["agent_id"]).last_sequence == 0
    assert db.scalar(select(func.count()).select_from(RuntimeReportPage)) == 1
    assert report(client, linked, value).json() == {"accepted": True, "duplicate": False, "sequence": 3}
    assert db.scalar(select(func.count()).select_from(RuntimeReportPage)) == 0
    assert send_page(client, linked, pages(value)[1]).json() == {"accepted": True, "duplicate": True, "sequence": 3}
    assert send_page(client, linked, pages(backwards)[0]).status_code == 409
