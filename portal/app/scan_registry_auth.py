"""Read-only deployment check for the scan broker's mounted registry credentials."""
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


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


# Keep this parser local to the standalone scan broker (no portal/database imports).
_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_REPOSITORY = re.compile(rf"{_COMPONENT}(?:/{_COMPONENT})*")
_AUTHORITY = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?")
_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io"}


def _registry(host):
    if not _AUTHORITY.fullmatch(host):
        raise ValueError("Invalid registry host")
    parts = urlsplit("https://" + host)
    port = parts.port
    if port == 0:
        raise ValueError("Invalid registry port")
    host = parts.hostname
    if host in _HUB:
        host = "docker.io"
    if ":" in host:
        host = "[" + host + "]"
    return host if port in (None, 443) else f"{host}:{port}"


def _repository(reference, *, prefix=False):
    if not isinstance(reference, str) or not 0 < len(reference) <= 512:
        raise ValueError("Invalid registry repository")
    if prefix:
        name = reference.removesuffix("/")
    else:
        # Only remove valid tag/digest suffixes. Reject all stray URI syntax.
        name = re.sub(r"@sha256:[0-9a-f]{64}$", "", reference)
        name = re.sub(r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", "", name)
    authority, slash, tail = name.partition("/")
    explicit = slash and (authority.lower() == "localhost" or "." in authority or ":" in authority)
    if explicit:
        host, path = _registry(authority), tail
    elif prefix:
        raise ValueError("A prefix needs an explicit registry and repository")
    else:
        host, path = "docker.io", name
    if not _REPOSITORY.fullmatch(path):
        raise ValueError("Invalid registry repository path")
    if host == "docker.io" and "/" not in path and not prefix:
        # Docker Hub shorthand adds library/. A literal registry API hostname
        # or port can instead address the repository exactly as written.
        if explicit and authority.lower() not in ("docker.io", "index.docker.io"):
            return host, ""  # Ambiguous namespace excludes credentials for this host.
        path = "library/" + path
    return host, path


def topic_registry_prefixes():
    raw = os.getenv("CATS_TOPIC_SCAN_REGISTRY_PREFIXES", "")
    try:
        return {_repository(entry, prefix=True) for entry in re.split(r"[,\s]+", raw) if entry}
    except ValueError:
        raise RegistryConfigurationError(
            "CATS_TOPIC_SCAN_REGISTRY_PREFIXES requires explicit registry/repository prefixes without tags or wildcards."
        ) from None


def topic_credential_hosts(claim, inputs):
    """Require a server-bound, image-only input and authorize complete host groups."""
    payload = claim["job"]
    if (claim.get("topic_intake_verified") is not True or payload.get("job_kind") != "scan"
            or any(payload.get(key) for key in ("chart_url", "compose_enabled", "compose_preview",
                                                "definition_component", "definition_components"))):
        raise RegistryConfigurationError("Topic scan does not have a verified image-only intake.")
    prefixes = topic_registry_prefixes()
    if not prefixes:
        return set()
    images = payload.get("image_list")
    if not isinstance(images, str) or not images:
        raise RegistryConfigurationError("Topic scan is missing its verified image inventory.")
    # A runner may also process OCI charts, Compose and uploaded archives when
    # present. Only the image list and the portal's public TLS trust are supported.
    permitted = {"images.txt", ".cats-trust", ".cats-trust/ca-bundle.pem"}
    if any(path.relative_to(inputs).as_posix() not in permitted for path in inputs.rglob("*")):
        raise RegistryConfigurationError("Topic scan contains unexpected input alongside its image list.")
    listed = inputs / "images.txt"
    # The producer writes exactly this list plus a final newline. Accept both
    # supported platforms' line endings without recognizing other separators.
    expected = (images + "\n").encode("utf-8")
    crlf = expected.replace(b"\n", b"\r\n")
    if (not listed.is_file() or listed.stat().st_size not in (len(expected), len(crlf))
            or listed.read_bytes() not in (expected, crlf)):
        raise RegistryConfigurationError("Topic scan image file differs from its verified inventory.")
    try:
        repositories = {_repository(ref) for ref in images.split("\n")}
    except ValueError:
        raise RegistryConfigurationError("Topic scan contains an invalid image reference.") from None
    # Docker credentials are keyed by registry. One out-of-scope repository on
    # a host excludes that host's credentials from the entire attempt.
    denied = {host for host, path in repositories if not any(
        host == allowed and (path == scope or path.startswith(scope + "/")) for allowed, scope in prefixes)}
    return {host for host, _ in repositories} - denied


def topic_auth_entries(credentials, hosts):
    scoped = {}
    for key, value in credentials.get("auths", {}).items():
        try:
            normalized = urlsplit(key if "://" in key else "https://" + key)
            if (normalized.scheme != "https" or normalized.username is not None or normalized.password is not None
                    or normalized.path not in ("", "/", "/v1/", "/v2/") or normalized.query or normalized.fragment):
                continue
            host = _registry(normalized.netloc)
        except ValueError:
            continue
        if host in hosts:
            scoped[key] = value
    return scoped
