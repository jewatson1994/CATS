from app.offline_schema import validate_resources


def test_valid_resource_uses_bundled_schema_without_network(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network access")))
    result = validate_resources([{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "example"}, "data": {"value": "text"}}])
    assert result["status"] == "PASS"
    assert "offline" in result["detail"]


def test_invalid_resource_fails():
    result = validate_resources([{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "example"}, "data": {"value": False}}])
    assert result["status"] == "FAIL"


def test_unknown_schema_is_not_a_pass():
    assert validate_resources([{"apiVersion": "example.internal/v1", "kind": "CustomThing", "metadata": {"name": "example"}}])["status"] == "NOT RUN"
    assert validate_resources([])["status"] == "FAIL"
