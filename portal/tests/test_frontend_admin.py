from datetime import datetime
from types import SimpleNamespace
import json

from app.frontend_admin import project_admin


def test_account_projection_retains_access_chains_not_credentials():
    user = SimpleNamespace(id=7, username="jane", display_name="Jane", auth_source="local", enabled=True,
                           last_login_at=datetime(2026, 9, 30), password_hash="TOP_SECRET", sessions=["TOP_SECRET"])
    context = {"current_user": user, "users": [user], "user_rows": [{"user": user,
        "assignments": [{"id": 2, "role": "Analyst", "group": "Team", "service": "App", "token": "TOP_SECRET"}],
        "permissions": ["audit.view", "TOP_SECRET"]}], "roles": [SimpleNamespace(id=1, name="Analyst", secret="TOP_SECRET")],
        "permission_catalog": {"audit.view": "Review events"}}
    result = project_admin({"csrf_token": "csrf"}, "admin.html", context, lambda permission: permission == "user.manage",
                           {"cats_datetime": lambda _: "30 Sep 2026"})
    assert result["user_rows"][0]["user"]["is_self"] is True
    assert result["user_rows"][0]["user"]["last_login_at"] == "30 Sep 2026"
    assert result["user_rows"][0]["assignments"][0]["service"] == "App"
    assert result["user_rows"][0]["permissions"] == ["audit.view"]
    assert result["can"]["role.manage"] == {"*": False}
    assert result["csrf_token"] == "csrf" and "TOP_SECRET" not in json.dumps(result)


def test_configuration_projection_never_copies_global_secret_store():
    context = {"configuration": {"display_timezone": "UTC", "identity_mode": "both", "oidc_configuration": "TOP_SECRET"},
        "oidc": {"provider_name": "Organization", "client_id": "public-client", "client_secret_configured": True,
                 "client_secret": "TOP_SECRET", "id_token": "TOP_SECRET"},
        "validator": {"endpoint": "https://validator", "client_key_configured": True, "client_key": "TOP_SECRET"},
        "signing": {"enabled": True, "fingerprint": "public-fingerprint", "private_key": "TOP_SECRET", "key_password": "TOP_SECRET"},
        "registries": [{"id": "reg", "username": "scanner", "secret_configured": True, "password": "TOP_SECRET", "token": "TOP_SECRET"}],
        "oidc_mappings": [SimpleNamespace(id=4, claim_path="groups", expected_value="engineering", role_id=1,
            group_id=2, service_id=None, global_scope=False, enabled=True, role=SimpleNamespace(id=1, name="Analyst"),
            group=SimpleNamespace(id=2, name="Team", secrets="TOP_SECRET"), service=None)],
        "security_data_sources": {"kev": SimpleNamespace(status="UPDATED", source="https://data", last_success_at=datetime(2026, 9, 30))},
        "os_definitions": {"linux": {"name": "Linux", "package_manager": "apt", "password": "TOP_SECRET"}},
        "repository_policies": {"linux": {"mode": "custom", "url": "https://mirror", "verify_tls": False, "secret": "TOP_SECRET"}}}
    result = project_admin({}, "configuration.html", context, lambda _: True, {"cats_date": lambda _: "30 Sep 2026"})
    assert result["oidc"]["client_secret_configured"] is True
    assert result["registries"][0]["username"] == "scanner"
    assert result["oidc_mappings"][0]["group"] == {"id": 2, "name": "Team"}
    assert result["repository_policies"]["linux"]["verify_tls"] is False
    assert result["security_data_sources"]["kev"]["last_success_at"] == "30 Sep 2026"
    assert "TOP_SECRET" not in json.dumps(result)


def test_audit_projection_keeps_actor_and_documented_detail_without_nested_payloads():
    event = SimpleNamespace(id=2, action="configuration.updated", target_type="portal", target_id="global",
        created_at=datetime(2026, 9, 30), actor=None, detail={"actor_username": "former-admin", "registry_id": "reg",
        "changed": ["display_timezone"], "password": "TOP_SECRET", "configuration": {"client_secret": "TOP_SECRET"}})
    result = project_admin({}, "audit.html", {"events": [event], "configuration": {"audit_retention_days": "365", "secret": "TOP_SECRET"}})
    assert result["events"][0]["actor"] == "former-admin"
    assert result["events"][0]["detail"]["changed"] == ["display_timezone"]
    assert "TOP_SECRET" not in json.dumps(result)


def test_staging_only_projects_eligible_group_names_and_ids():
    result = project_admin({}, "staging.html", {"stage_groups": [SimpleNamespace(id=2, name="Team", token="TOP_SECRET")], "saved": True})
    assert result["stage_groups"] == [{"id": 2, "name": "Team"}]
    assert result["saved"] is True
