from types import SimpleNamespace

from app.auth import matching_claim_mappings


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
