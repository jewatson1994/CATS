"""Small, private appliance settings store; never contains production credentials."""
import json
import os
from pathlib import Path
import tempfile


def state_dir():
    path = Path(os.getenv("CATS_VALIDATOR_STATE_DIR", str(Path(tempfile.gettempdir()) / "cats-validator")))
    if path.is_symlink():
        raise RuntimeError("State directory cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        if path.stat().st_uid != os.geteuid():
            raise RuntimeError("State directory must belong to the worker")
        os.chmod(path, 0o700)
    return path


def read_settings():
    path = state_dir() / "appliance-settings.json"
    if not path.exists():
        return {}
    if path.is_symlink() or path.stat().st_size > 131072:
        raise RuntimeError("Invalid appliance settings")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Invalid appliance settings")
    return value


def write_settings(value):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=state_dir(), delete=False) as stream:
        os.chmod(stream.name, 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
        staged = Path(stream.name)
    os.replace(staged, state_dir() / "appliance-settings.json")


def fingerprints():
    return read_settings().get("client_fingerprints", os.getenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", ""))


def execution_settings():
    # Managed execution is configured by CATS provisioning. The persistent
    # appliance store may contain settings from an older release. Keep those
    # overrides only for independently administered appliances.
    saved = {} if os.getenv("CATS_MANAGED_VALIDATOR_ID", "").strip() else read_settings()
    mode = saved.get("execution_mode", os.getenv("CATS_VALIDATOR_EXECUTION_MODE", "strict"))
    if mode not in ("strict", "permissive"):
        raise RuntimeError("Execution mode must be strict or permissive")
    return {"execution_mode": mode,
            "allow_network_egress": saved.get("allow_network_egress", os.getenv("CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS", "false").lower() == "true"),
            "require_local_images": saved.get("require_local_images", os.getenv("CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES", "true").lower() == "true"),
            "node_image": saved.get("node_image", os.getenv("CATS_DEPLOYMENT_KIND_NODE_IMAGE", ""))}
