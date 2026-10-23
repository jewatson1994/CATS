"""Resolve publication targets without Docker's implicit registry defaults."""
from urllib.parse import urlsplit
import re


def resolve_destination(image: str, registry: dict) -> str:
    image = image.strip()
    endpoint = str(registry.get("endpoint") or "").strip()
    parsed = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("Selected destination registry must have a valid host endpoint without credentials or a path.")
    host = parsed.netloc
    if not ("." in host or ":" in host or host == "localhost"):
        raise ValueError("Destination registry must use a fully qualified hostname, localhost, or an explicit port to avoid implicit Docker Hub publication.")
    prefix = str(registry.get("namespace") or "").strip().strip("/")
    if not image or image.startswith("/") or "://" in image or "@" in image or re.search(r"\s", image):
        raise ValueError("Enter a destination repository and tag, without a URL scheme or digest.")
    first = image.split("/", 1)[0]
    qualified = "/" in image and ("." in first or ":" in first or first == "localhost")
    if qualified:
        if first.lower() != host.lower():
            raise ValueError("Destination image host must match the selected registry.")
        return image
    return "/".join(part for part in (host, prefix, image) if part)


def publication_error(error: str, destination: str) -> str:
    if "read-only file system" in error.lower() or "read-only filesystem" in error.lower():
        return (f"Publication to {destination} failed: the registry reported read-only storage. "
                "A registry administrator must restore writable repository storage before retrying. "
                "The patched archive and scan results are retained. " + error)
    return f"Publication to {destination} failed: {error}"
