"""Read-only deployment check for the scan broker's mounted registry credentials."""
import json
import os
from pathlib import Path


class RegistryConfigurationError(RuntimeError):
    pass


def load_registry_credentials():
    config = Path(os.getenv("DOCKER_CONFIG", "/opt/catscan/registry-auth")) / "config.json"
    try:
        text = config.read_text(encoding="utf-8")
    except FileNotFoundError:
        # An empty registry-auth mount supports anonymous pulls.
        return {}
    except PermissionError:
        raise RegistryConfigurationError(
            "Registry credentials are unreadable by the scan worker. Check ownership and "
            "permissions of the host directory configured by CATS_SCAN_REGISTRY_AUTH_SOURCE "
            "and its config.json. For the default rootful Docker deployment, use root:root "
            "ownership, directory mode 700 and file mode 600. With user namespaces, use the "
            "mapped broker UID. Retry the scan after fixing access; do not make credentials "
            "world-readable or add worker capabilities."
        ) from None
    except UnicodeError:
        raise RegistryConfigurationError(
            "Registry config.json must be valid UTF-8 JSON. Repair the host registry "
            "configuration and retry the scan."
        ) from None
    except OSError:
        raise RegistryConfigurationError(
            "Cannot read registry config.json. Check that CATS_SCAN_REGISTRY_AUTH_SOURCE "
            "mounts an existing directory and config.json is a readable regular file."
        ) from None
    try:
        credentials = json.loads(text)
        if not isinstance(credentials, dict) or not isinstance(credentials.get("auths", {}), dict):
            raise ValueError("Expected an object")
    except (ValueError, TypeError):
        raise RegistryConfigurationError(
            "Registry config.json must contain a valid JSON object with an auths object "
            "when present. Repair the host registry configuration and retry the scan."
        ) from None
    return credentials
