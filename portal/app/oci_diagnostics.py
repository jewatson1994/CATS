"""Credential-safe, structured diagnostics for OCI Helm acquisition."""

from fastapi import HTTPException

from .helm_sources import oci_pull_arguments


_FAILURES = (
    ("authentication_denied", "OCI registry authentication required or denied", ("unauthorized", "authentication required", "access denied", "401 unauthorized", "403 forbidden", "insufficient_scope")),
    ("tls_trust_failure", "OCI registry TLS certificate trust failed", ("x509", "certificate verify", "certificate signed", "tls handshake")),
    ("registry_rate_limit", "OCI registry rate limit was reached", ("toomanyrequests", "too many requests", "rate limit", "429")),
    ("timeout", "OCI registry request timed out", ("timed out", "timeout", "deadline exceeded")),
    ("dns_network_failure", "OCI registry network or DNS connection failed", ("no such host", "could not resolve", "name resolution", "network is unreachable", "connection refused", "connection reset", "temporary failure in name resolution")),
    ("malformed_reference", "OCI chart reference is malformed", ("invalid reference", "invalid uri", "invalid chart reference", "invalid repository name")),
    ("version_not_found", "Requested OCI chart version was not found", ("tag not found", "unknown tag", "version not found", "no matching version")),
    ("chart_reference_not_found", "OCI chart or reference was not found", ("manifest unknown", "name unknown", "repository not found", "not found", "404")),
)


class OciPullFailure(HTTPException):
    def __init__(self, reference: str, *, exit_code: int | None = None,
                 stderr: str = "", stdout: str = "", category: str | None = None,
                 ca_file_used: bool = False):
        output = f"{stderr}\n{stdout}".casefold()
        if category is None:
            category = next((key for key, _, terms in _FAILURES if any(term in output for term in terms)),
                            "unknown_acquisition_failure")
        messages = {key: message for key, message, _ in _FAILURES}
        messages.update(helm_execution_failure="Helm could not be executed",
                        unknown_acquisition_failure="OCI Helm pull failed; inspect the registry and chart reference")
        message = messages[category]
        command = ["helm", "pull", *oci_pull_arguments(reference), "--destination", "<temporary directory>"]
        if ca_file_used:
            command.extend(["--ca-file", "<trusted CA file>"])
        self.diagnostic = {
            "attempted_reference": reference,
            "acquisition_stage": "helm_pull",
            "helm_command": command,
            "helm_exit_code": exit_code,
            "safe_stderr_summary": message if stderr else "",
            "safe_stdout_summary": message if stdout and not stderr else "",
            "failure_category": category,
        }
        super().__init__(status_code=408 if category == "timeout" else 400, detail=message)
