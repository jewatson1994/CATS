from portal.app.frontend_validators import validators_data


def test_validator_projection_strips_credentials_at_every_boundary():
    projected = validators_data({"validator_management_allowed": True, "validators": [{
        "id": 3, "name": "Dedicated host", "password": "secret", "private_key": "secret",
        "preflight": {"status": "ready", "facts": {"os_version": "22.04", "sudo_password": "secret"},
                      "checks": {"docker": True}, "warnings": ["Resource warning"]},
        "certificate": {"subject": "validator-3", "expires_at": "tomorrow", "private_key": "secret"},
        "history": [{"id": 1, "status": "done", "credentials": {"password": "secret"}}],
    }], "image_readiness": {"ready": True, "image_reference": "cats:current", "password": "secret"}})
    assert "secret" not in repr(projected)
    assert projected["validators"][0]["preflight"]["facts"] == {"os_version": "22.04"}
    assert projected["validators"][0]["preflight"]["checks"] == {"docker": True}
    assert projected["validator_permissions"]["validator.provision"] == {"*": True}


def test_validator_permissions_fail_closed_without_global_admin_flag():
    assert all(value == {"*": False} for value in validators_data({})["validator_permissions"].values())

def test_initial_projection_preserves_actual_preflight_evidence():
    checks = {'architecture_compatible': True, 'cgroup': True, 'cgroup_driver': True, 'daemon': True, 'runtime': True}
    facts = {'cgroup_version': '2', 'default_runtime': 'runc', 'cgroup_driver_name': 'systemd'}
    result = validators_data({'validators': [{'preflight': {'checks': checks, 'facts': facts}}]})
    assert result['validators'][0]['preflight'] == {'checks': checks, 'facts': facts}