import io
import json
import urllib.error
import urllib.parse

import pytest

from app import oidc_directory as directory


CONFIG = {"issuer": "https://identity.example/auth/realms/company", "client_id": "cats", "client_secret": "private-secret", "scopes": "openid groups"}


def mapper(kind, path, **config):
    return {"protocolMapper": kind, "config": {"claim.name": path, "id.token.claim": "true", "multivalued": "true", **config}}


def install_provider(monkeypatch, overrides=None):
    calls = []
    data = {
        "/clients": [{"id": "login-id", "clientId": "cats"}],
        "/clients/login-id/protocol-mappers/models": [mapper("oidc-usermodel-realm-role-mapper", "realm_access.roles", **{"usermodel.realmRoleMapping.rolePrefix": "realm:"})],
        "/clients/login-id/default-client-scopes": [{"id": "roles", "name": "roles"}],
        "/clients/login-id/optional-client-scopes": [{"id": "groups", "name": "groups"}, {"id": "ignored", "name": "unrequested"}],
        "/client-scopes/roles/protocol-mappers/models": [mapper("oidc-usermodel-client-role-mapper", "resource_access.${client_id}.roles")],
        "/client-scopes/groups/protocol-mappers/models": [mapper("oidc-group-membership-mapper", "teams", **{"full.path": "true"})],
        "/groups": [{"id": "parent", "name": "Engineering", "path": "/Engineering", "subGroupCount": 1, "subGroups": []}],
        "/groups/parent/children": [{"id": "child", "name": "Security", "path": "/Engineering/Security", "subGroupCount": 0}],
        "/roles": [{"name": "reviewer"}],
        "/clients/login-id/roles": [{"name": "maintainer"}],
    }
    data.update(overrides or {})

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert 0 < timeout <= 10
            parsed = urllib.parse.urlsplit(request.full_url)
            if parsed.path.endswith("/protocol/openid-connect/token"):
                body = urllib.parse.parse_qs(request.data.decode())
                assert body["grant_type"] == ["client_credentials"]
                assert body["client_secret"] == ["private-secret"]
                return io.BytesIO(json.dumps({"access_token": "secret-token"}).encode())
            assert request.get_header("Authorization") == "Bearer secret-token"
            assert parsed.netloc == "identity.example"
            assert parsed.path.startswith("/auth/admin/realms/company/")
            path = parsed.path.removeprefix("/auth/admin/realms/company")
            value = data[path]
            if isinstance(value, Exception):
                raise value
            if callable(value):
                value = value(urllib.parse.parse_qs(parsed.query))
            return io.BytesIO(json.dumps(value).encode())

    handlers = []
    def build_opener(*args):
        handlers.extend(args)
        return Opener()
    monkeypatch.setattr(directory.urllib.request, "build_opener", build_opener)
    return calls, handlers


def test_discovers_nested_groups_roles_and_active_scope_mappers(monkeypatch):
    calls, handlers = install_provider(monkeypatch)
    result = directory.discover_oidc_directory(CONFIG)
    assert result["provider"] == "keycloak"
    assert {(item["kind"], item["claim_path"], item["expected_value"]) for item in result["candidates"]} == {
        ("group", "teams", "/Engineering"), ("group", "teams", "/Engineering/Security"),
        ("realm_role", "realm_access.roles", "realm:reviewer"),
        ("client_role", "resource_access.cats.roles", "maintainer"),
    }
    assert len(result["warnings"]) == 1
    assert all("ignored" not in request.full_url for request in calls)
    assert all(request.get_method() == "GET" for request in calls[1:])
    redirect = next(handler for handler in handlers if isinstance(handler, directory._NoRedirect))
    assert redirect.redirect_request(None, None, 302, "", {}, "https://attacker.example") is None


def test_paginates_groups_children_and_roles(monkeypatch):
    monkeypatch.setattr(directory, "PAGE_SIZE", 1)
    def paged(items):
        return lambda query: items[int(query["first"][0]):int(query["first"][0]) + int(query["max"][0])]
    overrides = {
        "/clients": paged([{"id": "login-id", "clientId": "cats"}]),
        "/groups": paged([{"id": "p", "name": "P", "path": "/P", "subGroupCount": 2}]),
        "/groups/p/children": paged([{"id": str(i), "name": str(i), "path": "/P/" + str(i), "subGroupCount": 0} for i in range(2)]),
        "/roles": paged([{"name": "a"}, {"name": "b"}]),
        "/clients/login-id/roles": paged([]),
    }
    calls, _ = install_provider(monkeypatch, overrides)
    result = directory.discover_oidc_directory(CONFIG)
    assert len(result["candidates"]) == 5
    assert any("/groups/p/children?first=2&max=1" in call.full_url for call in calls)
    assert any("/roles?first=2&max=1" in call.full_url for call in calls)


def test_missing_id_token_mappers_does_not_guess_claims(monkeypatch):
    install_provider(monkeypatch, {
        "/clients/login-id/protocol-mappers/models": [mapper("oidc-usermodel-realm-role-mapper", "roles", **{"id.token.claim": "false"})],
        "/client-scopes/roles/protocol-mappers/models": [mapper("oidc-usermodel-client-role-mapper", "roles", **{"multivalued": "false"})],
    })
    result = directory.discover_oidc_directory({**CONFIG, "scopes": "openid"})
    assert result["candidates"] == []
    assert len(result["warnings"]) == 4


def test_group_leaf_names_and_client_role_prefix(monkeypatch):
    install_provider(monkeypatch, {
        "/client-scopes/groups/protocol-mappers/models": [mapper("oidc-group-membership-mapper", "groups", **{"full.path": "false"})],
        "/client-scopes/roles/protocol-mappers/models": [mapper("oidc-usermodel-client-role-mapper", "app.roles", **{"usermodel.clientRoleMapping.rolePrefix": "${client_id}:"})],
    })
    candidates = directory.discover_oidc_directory(CONFIG)["candidates"]
    assert any(item["expected_value"] == "Security" for item in candidates)
    assert any(item["expected_value"] == "cats:maintainer" for item in candidates)


@pytest.mark.parametrize("issuer", ["https://example/oidc", "https://user:pass@example/realms/x", "https://example/realms/x?query=1", "https://example/realms/%2e%2e"])
def test_unsupported_issuer_never_sends_credentials(issuer, monkeypatch):
    calls, _ = install_provider(monkeypatch)
    with pytest.raises(directory.OidcDirectoryError):
        directory.discover_oidc_directory({**CONFIG, "issuer": issuer})
    assert not calls


@pytest.mark.parametrize("status,match", [(403, "read access"), (302, "redirects are disabled"), (404, "HTTP 404")])
def test_safe_provider_errors(monkeypatch, status, match):
    install_provider(monkeypatch, {"/clients": urllib.error.HTTPError("https://example/private-secret", status, "secret-token", {}, io.BytesIO(b"private-secret"))})
    with pytest.raises(directory.OidcDirectoryError, match=match) as exc:
        directory.discover_oidc_directory(CONFIG)
    assert "private-secret" not in str(exc.value)
    assert "secret-token" not in str(exc.value)


def test_custom_ca_and_request_budget(monkeypatch):
    loaded = []
    class Context:
        def load_verify_locations(self, **kwargs):
            loaded.append(kwargs)
    monkeypatch.setattr(directory.ssl, "create_default_context", Context)
    monkeypatch.setattr(directory, "MAX_REQUESTS", 1)
    install_provider(monkeypatch)
    with pytest.raises(directory.OidcDirectoryError, match="request or time limit"):
        directory.discover_oidc_directory(CONFIG, "-----BEGIN CERTIFICATE----- test")
    assert loaded == [{"cadata": "-----BEGIN CERTIFICATE----- test"}]


def test_invalid_json_response(monkeypatch):
    install_provider(monkeypatch, {"/clients": {"unexpected": "private-secret"}})
    with pytest.raises(directory.OidcDirectoryError, match="unexpected directory response"):
        directory.discover_oidc_directory(CONFIG)


def test_unsavable_paths_and_values_are_omitted_with_warnings(monkeypatch):
    install_provider(monkeypatch, {
        "/client-scopes/roles/protocol-mappers/models": [mapper("oidc-usermodel-client-role-mapper", "app/roles")],
        "/roles": [{"name": " spaces "}, {"name": "x" * 301}],
    })
    result = directory.discover_oidc_directory(CONFIG)
    assert all(item["kind"] == "group" for item in result["candidates"])
    assert any("claim path cannot be represented" in warning for warning in result["warnings"])
    assert any("value cannot be represented" in warning for warning in result["warnings"])


def test_missing_full_path_flag_uses_names(monkeypatch):
    install_provider(monkeypatch, {
        "/client-scopes/groups/protocol-mappers/models": [mapper("oidc-group-membership-mapper", "groups")],
    })
    result = directory.discover_oidc_directory(CONFIG)
    assert {item["expected_value"] for item in result["candidates"] if item["kind"] == "group"} == {"Engineering", "Security"}


def test_response_size_limit_is_actionable(monkeypatch):
    install_provider(monkeypatch)
    monkeypatch.setattr(directory, "MAX_RESPONSE_BYTES", 5)
    with pytest.raises(directory.OidcDirectoryError, match="size limit"):
        directory.discover_oidc_directory(CONFIG)
