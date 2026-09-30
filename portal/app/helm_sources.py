"""Validation for explicitly selected Helm sources, never generic YAML detection."""
import re
from urllib.parse import urlsplit


def normalize_chart_reference(value: str) -> str:
    value = value.strip()
    if not value or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError("Invalid Helm source reference")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "oci"} or not parsed.hostname:
            raise ValueError("Unsupported Helm source scheme; use http, https, or oci")
        if parsed.username or parsed.password:
            raise ValueError("Helm source must not contain credentials")
        if parsed.scheme != "oci":
            return value
        candidate = value[6:]
    else:
        candidate = value
    # Only explicit Helm inputs may use registry shorthand. Require a qualified
    # registry host and a chart path; arbitrary scalar discovery must not use this.
    if not re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::[0-9]+)?/(?:[a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*(?::[A-Za-z0-9_][A-Za-z0-9_.+-]*)?", candidate):
        raise ValueError("Invalid OCI Helm chart reference")
    host = candidate.split("/", 1)[0]
    if not value.startswith("oci://") and "." not in host and ":" not in host and host != "localhost":
        raise ValueError("Registry-style Helm sources require a qualified registry host")
    return "oci://" + candidate


def oci_pull_arguments(reference: str) -> list[str]:
    reference = normalize_chart_reference(reference)
    if not reference.startswith("oci://"):
        raise ValueError("Expected an OCI chart reference")
    tail = reference.rsplit("/", 1)[-1]
    if ":" in tail:
        base, version = reference.rsplit(":", 1)
        # OCI chart tags are chart versions, not a literal "latest" tag.
        # Helm resolves the newest available version when --version is absent.
        if version == "latest":
            return [base]
        return [base, "--version", version]
    return [reference]
