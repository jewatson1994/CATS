"""Reviewable mapping transitions, preserving administrator-owned scope grants."""
import hashlib
import json
from types import SimpleNamespace

from sqlalchemy import or_, select

from .auth import AuthContext, PERMISSIONS
from .models import OidcRoleEligibility, Service, User, UserRoleAssignment


def mapping_grants(db, mapping):
    # Older grants have no mapping provenance. Match the exact former scope;
    # never remove a local grant or a different role's scope.
    return db.scalars(select(UserRoleAssignment).where(
        UserRoleAssignment.source == "oidc",
        or_(UserRoleAssignment.oidc_mapping_id == mapping.id, UserRoleAssignment.oidc_mapping_id.is_(None)),
        UserRoleAssignment.role_id == mapping.role_id,
        UserRoleAssignment.service_id == mapping.service_id,
        UserRoleAssignment.group_id == mapping.group_id,
    )).all()


def mapping_preview(db, mapping, proposed):
    grants = mapping_grants(db, mapping)
    eligibilities = db.scalars(select(OidcRoleEligibility).where(OidcRoleEligibility.mapping_id == mapping.id)).all()
    user_ids = {row.user_id for row in grants + eligibilities}
    services = db.scalars(select(Service).order_by(Service.id)).all()
    same_claim = (mapping.claim_path, mapping.expected_value, mapping.role_id) == (proposed["claim_path"], proposed["expected_value"], proposed["role_id"])
    simulated_mapping = SimpleNamespace(id=mapping.id, **proposed)
    removed = {row.id for row in grants}

    def access(user):
        auth = AuthContext(user, None)
        return {"application_permissions": [p for p in PERMISSIONS if auth.has(p)],
                "services": [{"id": s.id, "name": s.name,
                              "permissions": [p for p in PERMISSIONS if auth.has(p, s.id)]}
                             for s in services if auth.has("service.view", s.id)]}

    rows = []
    for user_id in sorted(user_ids):
        user = db.get(User, user_id)
        before = access(user)
        keep = [e for e in user.oidc_eligibilities if e.mapping_id != mapping.id]
        if same_claim and proposed["enabled"] and proposed["scope_mode"] == "cats_managed":
            keep.append(SimpleNamespace(mapping=simulated_mapping))
        assignments = [a for a in user.role_assignments if a.id not in removed]
        # Fixed-scope edits fail closed until a newly validated login. A
        # managed-scope conversion can retain the already validated match.
        after = access(SimpleNamespace(role_assignments=assignments, oidc_eligibilities=keep))
        rows.append({"user_id": user.id, "username": user.username, "before": before, "after": after})
    payload = {"mapping_id": mapping.id, "proposed": proposed, "users": rows,
               "removed_grants": sorted(removed), "same_claim": same_claim}
    token = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {"token": token, "users": rows,
            "note": "Local grants are preserved. CATS-managed scope requires a current matching role and a role-specific CATS assignment. Changed claims and fixed scopes require another validated login."}


def retire_mapping_projection(db, mapping, *, preserve_eligibility=False):
    grants = mapping_grants(db, mapping)
    existing = db.scalars(select(OidcRoleEligibility).where(OidcRoleEligibility.mapping_id == mapping.id)).all()
    if preserve_eligibility:
        seen = {row.user_id for row in existing}
        for grant in grants:
            if grant.user_id not in seen:
                db.add(OidcRoleEligibility(user_id=grant.user_id, mapping_id=mapping.id))
                seen.add(grant.user_id)
    else:
        for row in existing:
            db.delete(row)
    for grant in grants:
        db.delete(grant)
