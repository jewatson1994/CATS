from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.auth import matching_claim_mappings, oidc_identity_key, provision_oidc_user
from app.database import Base
from app.models import Group, Role, User, UserRoleAssignment


def mapping(path, value, *, enabled=True, global_scope=False, service_id=1):
    return SimpleNamespace(claim_path=path, expected_value=value, enabled=enabled,
                           global_scope=global_scope, service_id=service_id, group_id=None)


def test_string_array_nested_missing_disabled_and_multiple_claims():
    candidates = [mapping("groups", "security"), mapping("custom.roles", "assessor"),
                  mapping("custom.roles", "disabled", enabled=False)]
    assert matching_claim_mappings({"groups": "security"}, candidates) == candidates[:1]
    assert matching_claim_mappings({"groups": ["security"], "custom": {"roles": ["assessor", "disabled"]}}, candidates) == candidates[:2]
    assert matching_claim_mappings({"groups": ["unmapped"]}, candidates) == []
    assert matching_claim_mappings({}, candidates) == []


def test_legacy_group_claim_stays_group_scoped_and_stale_oidc_grants_are_removed(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    monkeypatch.setenv("CATS_OIDC_ROLE_MAP", "{}")
    monkeypatch.setenv("CATS_OIDC_GROUP_ROLE_MAP", '{"engineering": "Service Manager"}')
    monkeypatch.setenv("CATS_OIDC_DEFAULT_ROLE", "")
    configuration = {"roles_claim": "realm_access.roles", "groups_claim": "groups",
                     "account_links": {oidc_identity_key("", "subject-1"): "person"}}
    with Session(engine) as db:
        manager = Role(name="Service Manager", permissions=["service.view"])
        local_role = Role(name="Local Recovery", permissions=["service.view"])
        group = Group(name="engineering")
        db.add_all([manager, local_role, group])
        db.flush()
        user = User(username="person", display_name="Person", auth_source="oidc",
                    external_subject="subject-1", must_change_password=False)
        db.add(user)
        db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=local_role.id, source="local"))
        db.add(UserRoleAssignment(user_id=user.id, role_id=manager.id, source="oidc"))
        db.commit()

        provision_oidc_user(db, {"sub": "subject-1", "preferred_username": "person",
                                 "groups": ["engineering"]}, configuration)
        db.commit()
        assignments = db.scalars(select(UserRoleAssignment).where(
            UserRoleAssignment.user_id == user.id)).all()

        assert any(item.source == "local" and item.role_id == local_role.id for item in assignments)
        assert any(item.source == "oidc" and item.role_id == manager.id
                   and item.group_id == group.id and item.service_id is None for item in assignments)
        assert not any(item.source == "oidc" and item.role_id == manager.id
                       and item.group_id is None and item.service_id is None for item in assignments)
        # Repeated login in the same session must not mistake deleted grants
        # left in an ORM relationship for the newly synchronized projection.
        provision_oidc_user(db, {"sub": "subject-1", "preferred_username": "person",
                                 "groups": ["engineering"]}, configuration)
        db.commit()
        assignments = db.scalars(select(UserRoleAssignment).where(
            UserRoleAssignment.user_id == user.id)).all()
        assert len(assignments) == 2
        assert any(item.source == "oidc" and item.group_id == group.id for item in assignments)
