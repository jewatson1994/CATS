"""Explicit public projection for managed validator settings; never expose credentials."""
from collections.abc import Mapping

_FIELDS = {
    "id", "name", "host", "ssh_port", "ssh_username", "api_port", "status", "fingerprint",
    "created_at", "updated_at", "last_contact_at", "fingerprint_confirmed", "active_operation_id", "image", "image_id", "reference", "last_seen", "last_health", "health", "last_self_test", "self_test",
    "preflight", "certificate", "history", "operations", "action", "phase", "started_at",
    "finished_at", "error", "message", "checks", "facts", "warnings", "subject", "expires_at",
    "checked_at", "active_jobs", "cleanup_status", "helm_result", "install", "release_status", "resource_summary", "pods", "expected", "issuer", "serial", "validator_id", "server_fingerprint", "client_fingerprint", "ready", "reason", "image_reference", "operation_id", "cancel_requested",
}
_FACTS = {"os", "os_version", "version", "disk_free_bytes", "socket_available", "architecture", "cpus", "memory_bytes", "disk_bytes", "sudo", "root",
          "cgroup_version", "default_runtime", "cgroup_driver_name", "runtime", "daemon", "systemd", "api_port_available", "existing_service", "cgroup_v2", "docker_version",
          "docker_api_version", "docker_present", "docker_running", "docker_socket", "kind_capacity"}
_CHECKS = {"platform", "architecture", "cpu", "memory", "disk", "sudo", "ssh", "systemd", "cgroup_v2",
           "time", "api_port", "socket", "docker_running", "docker", "docker_installed", "docker_daemon", "docker_version",
           "daemon", "architecture_compatible", "cgroup", "cgroup_driver", "runtime", "docker_socket", "resources", "port", "docker_load", "docker_run", "kind_capacity"}

def _public(value, permitted=_FIELDS):
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _public(item, _FACTS if key == "facts" else _CHECKS if key == "checks" else _FIELDS)
                for key, item in value.items() if key in permitted}
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    return None

def validators_data(context):
    allowed = context.get("validator_management_allowed") is True
    return {"validators": _public(context.get("validators", [])),
            "image_readiness": _public(context.get("image_readiness", {})),
            "validator_management_allowed": allowed,
            "validator_permissions": {"validator." + action: {"*": allowed}
                for action in ("view", "add", "preflight", "provision", "test", "selftest", "cancel", "remove")}}