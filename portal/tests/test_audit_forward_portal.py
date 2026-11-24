"""Exercise the production page, session, router, audit writer, and delivery worker together."""
from app.audit_forward_store import upgrade_connection
from app.audit_forward_worker import deliver_one
from app.database import SessionLocal, engine
from app.frontend import PAGE_MEDIA_TYPE
from app.component_log_ingest import upgrade_connection as upgrade_ingest
from test_portal import csrf, new_client, setup_function


def test_global_admin_can_forward_a_real_login_and_search_a_test_event():
    # The standard portal fixture rebuilds all tables after the app startup migrations.
    with engine.begin() as connection:
        upgrade_connection(connection)
    client = new_client()
    destinations = "/api/admin/log-forwarding/destinations"
    for path in ("/admin/general-policy", "/admin/audit"):
        page = client.get(path, headers={"Accept": PAGE_MEDIA_TYPE})
        assert page.status_code == 200
        data = page.json()["data"]
        assert data["may_manage_log_forwarding"] is True
    headers = {"X-CSRF-Token": data["csrf_token"]}
    created = client.post(destinations, headers=headers, json={
        "name": "Local collector", "kind": "syslog", "enabled": True,
        "config": {"host": "syslog.example"}, "audit": True,
    })
    assert created.status_code == 201, created.text
    destination_id = created.json()["id"]
    tested = client.post(f"{destinations}/{destination_id}/test", headers=headers)
    assert tested.status_code == 202
    new_client().close()  # An independent session emits an auth.login event.

    received = []
    while deliver_one(SessionLocal, sender=lambda kind, config, secret, event: received.append(event)):
        pass
    login, = [e for e in received if e["category"] == "audit" and e["data"]["action"] == "auth.login"]
    assert login["data"]["actor_username"] == "admin"
    assert any(e["event_id"] == tested.json()["event_id"] and e["category"] == "test" for e in received)
    status, = client.get(destinations).json()["destinations"]
    assert status["pending"] == 0 and status["last_sent_at"]
    client.close()


def test_component_is_visible_at_hq_before_external_delivery():
    with engine.begin() as connection:
        upgrade_connection(connection)
        upgrade_ingest(connection)
    client = new_client()
    prefix = "/api/admin/log-forwarding"
    headers = {"X-CSRF-Token": csrf(client)}
    created = client.post(prefix + "/destinations", headers=headers, json={
        "name": "HQ SIEM", "kind": "syslog", "enabled": True, "operational": True, "audit": False,
        "config": {"host": "logs.example"},
    })
    assert created.status_code == 201, created.text
    source = client.post(prefix + "/sources", headers=headers, json={"name": "Site B"})
    assert source.status_code == 201, source.text
    assert source.json()["source"]["last_received_at"] is None
    source_auth = {"Authorization": "Bearer " + source.json()["token"]}
    reported = {"category": "operational", "timestamp": "2026-01-02T12:00:00Z", "event_id": "site-b:1",
                "data": {"component": "scan-worker", "message": "Scan finished " + source.json()["token"]}}
    for expected in ("accepted", "duplicate"):
        posted = client.post("/api/v1/component-logs/events", json=reported, headers=source_auth)
        assert posted.json()["status"] == expected
    seen = client.get(prefix + "/components").json()["components"]
    assert client.get(prefix + "/sources").json()["sources"][0]["last_received_at"]
    assert len(seen) == 1 and seen[0]["source_name"] == "Site B"
    assert seen[0]["last_event_id"] == reported["event_id"]
    events = client.get(prefix + "/components/events", params={"source_id": seen[0]["source_id"]}).json()["events"]
    assert len(events) == 1 and events[0]["data"]["component"] == "scan-worker"
    assert source.json()["token"] not in str(events)
    pending, = client.get(prefix + "/destinations").json()["destinations"]
    assert pending["pending"] == 1 and pending["last_sent_at"] is None
    delivered = []
    assert deliver_one(SessionLocal, sender=lambda kind, config, secret, event: delivered.append(event))
    assert delivered[0]["data"]["event_id"] == seen[0]["last_event_id"]
    assert not deliver_one(SessionLocal, sender=lambda *_: None)
    client.close()
