"""Exercise the production page, session, router, audit writer, and delivery worker together."""
from app.audit_forward_store import upgrade_connection
from app.audit_forward_worker import deliver_one
from app.database import SessionLocal, engine
from app.frontend import PAGE_MEDIA_TYPE
from test_portal import new_client, setup_function


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
