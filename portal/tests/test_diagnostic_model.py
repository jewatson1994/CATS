"""Portable diagnostics must be safe even when worker output is hostile."""
import json
import subprocess

import pytest

from app.diagnostics import build_diagnostic, public_diagnostic, sanitize, valid_correlation


@pytest.mark.parametrize("error,code", [
    ("Service must have exactly one owning group", "CAT-SVC-OWNERSHIP-001"),
    ("x509: certificate signed by unknown authority", "CAT-REGISTRY-TLS-001"),
    ("401 Unauthorized", "CAT-REGISTRY-AUTH-001"),
    ("manifest unknown", "CAT-OCI-MISSING-001"),
    ("Invalid service bundle", "CAT-BUNDLE-INVALID-001"),
    ("Unsupported chart", "CAT-CHART-INVALID-001"),
    ("Missing scan-worker credentials", "CAT-SCAN-CREDENTIALS-001"),
    ("No space left on device", "CAT-STORAGE-FULL-001"),
    ("Input exceeds worker disk budget", "CAT-STORAGE-FULL-001"),
    ("Worker disk budget exceeded during scan", "CAT-STORAGE-FULL-001"),
    ("Validator unavailable", "CAT-VALIDATOR-CONNECTION-001"),
    ("Signature verification failed", "CAT-SIGNATURE-001"),
    ("No approved release", "CAT-RELEASE-APPROVAL-001"),
    ("Worker lease expired", "CAT-WORKER-LOST-001"),
    ("Incomplete release replication", "CAT-REPLICA-SYNC-001"),
    ("Scan timed out", "CAT-TIMEOUT-001"),
])
def test_known_failures_are_actionable(error, code):
    item = build_diagnostic(RuntimeError(error), component="test worker", operation="test")
    assert item["code"] == code
    assert item["cause"] and item["resolution"]
    assert item["error_id"] and item["timestamp"]


def test_unknown_preserves_sanitized_chain_without_inventing_cause():
    try:
        try:
            raise ValueError("vendor error E567 password=do-not-show")
        except ValueError as error:
            raise RuntimeError("Publication stopped") from error
    except RuntimeError as error:
        item = build_diagnostic(error, component="publication", operation="publish", context={"stage": "publish", "endpoint": "https://internal.invalid"})
    assert item["cause"] is None
    assert item["code"] == "CAT-UNKNOWN-001"
    assert "E567" in json.dumps(item["technical"])
    assert "do-not-show" not in json.dumps(item)
    assert item["technical"]["exceptions"][1]["frames"]
    public = public_diagnostic(item)
    assert "technical" not in public
    assert public["context"] == {"stage": "publish"}


def test_unavailable_disk_measurement_does_not_claim_capacity_exhaustion():
    item = build_diagnostic(RuntimeError("Could not determine disk space"), component="scan worker", operation="measure")
    assert item["code"] == "CAT-UNKNOWN-001"
    assert item["cause"] is None


def test_redaction_covers_headers_nested_fields_cli_urls_and_tokens():
    item = {"Authorization": "Basic hidden1", "nested": {"client_secret": "hidden2"},
            "message": 'https://user:hidden3@registry.invalid/v2?auth=hidden4 Bearer hidden5 --password "hidden6" token=hidden7',
            "pem": "-----BEGIN PRIVATE KEY-----hidden8-----END PRIVATE KEY-----",
            "cookie": "hidden9", "raw": 'eyJabc.def.ghi', "bytes": b"hidden10"}
    result = json.dumps(sanitize(item))
    assert all(f"hidden{number}" not in result for number in range(1, 11))
    assert "eyJabc" not in result


def test_bounded_and_invalid_correlation():
    recursive = {"large": "x" * 50000}
    recursive["self"] = recursive
    result = sanitize(recursive)
    assert len(json.dumps(result)) < 35000
    assert valid_correlation("valid-id-123") == "valid-id-123"
    assert "\n" not in valid_correlation("bad\nheader")
    assert len(valid_correlation("x" * 500)) == 32
    assert len(valid_correlation("x" * 64)) == 32
    assert public_diagnostic({"context": "truncated", "technical": {"message": "private"}}) == {"context": {}}
    assert public_diagnostic({"context": ["invalid"]}) == {"context": {}}


def test_validation_input_and_sql_parameters_are_not_evidence():
    from fastapi.exceptions import RequestValidationError
    from sqlalchemy.exc import OperationalError
    validation = RequestValidationError([{"type": "value_error", "input": "bare-secret", "msg": "bad input"}])
    assert "bare-secret" not in json.dumps(build_diagnostic(validation, component="API", operation="validate"))
    error = OperationalError("SELECT secret FROM users", {"password": "bare-secret"}, RuntimeError("db unavailable"))
    item = build_diagnostic(error, component="API", operation="query")
    assert item["code"] == "CAT-DATABASE-001"
    assert "SELECT" not in json.dumps(item)
    assert "bare-secret" not in json.dumps(item)


def test_diagnostic_model_does_not_import_database_in_isolated_worker():
    # Explicit module boundary; building a diagnostic cannot open a connection.
    result = subprocess.run([__import__('sys').executable, '-c',
        "import sys; from app.diagnostics import build_diagnostic; build_diagnostic(ValueError('x'), component='worker', operation='x'); assert 'app.database' not in sys.modules"], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("tool,message,code", [
    ("trivy", "The first run cannot skip downloading DB", "CAT-SCANNER-DB-001"),
    ("trivy", "--skip-db-update cannot be specified on the first run", "CAT-SCANNER-DB-001"),
    ("trivy", "unable to initialize archive image: open /missing.tar: no such file or directory", "CAT-TOOL-INPUT-001"),
    ("grype", "unable to open file /missing.json: no such file or directory", "CAT-TOOL-INPUT-001"),
    ("dockle", 'opening file "/missing.tar": no such file or directory', "CAT-TOOL-INPUT-001"),
    ("copa", "report path /missing.json does not exist", "CAT-TOOL-INPUT-001"),
    ("syft", 'no source providers were able to resolve the input "/missing.tar"', "CAT-UNKNOWN-001"),
    ("other", "unable to open file /missing.json: no such file or directory", "CAT-UNKNOWN-001"),
])
def test_explicit_tool_evidence_is_classified_without_guessing(tool, message, code):
    from app.patching import ToolCommandError
    error = ToolCommandError(message, tool=tool, exit_code=1, timeout_seconds=30)
    item = build_diagnostic(error, component="worker", operation="command")
    assert item["code"] == code
    assert bool(item["cause"]) == (code != "CAT-UNKNOWN-001")
    assert item["resolution"]


@pytest.mark.parametrize("exception_type", [subprocess.TimeoutExpired, subprocess.CalledProcessError])
@pytest.mark.parametrize("wrapped", [False, True])
def test_subprocess_exception_argv_and_captured_output_are_never_serialized(exception_type, wrapped):
    command = ["grype", "--token", "argv-bare-secret", "--password", "another-bare-secret"]
    if exception_type is subprocess.TimeoutExpired:
        error = exception_type(command, 30, output="captured-stdout-secret", stderr="captured-stderr-secret")
    else:
        error = exception_type(7, command, output="captured-stdout-secret", stderr="captured-stderr-secret")
    if wrapped:
        try:
            raise RuntimeError("Tool wrapper stopped") from error
        except RuntimeError as wrapper:
            item = build_diagnostic(wrapper, component="worker", operation="command")
    else:
        item = build_diagnostic(error, component="worker", operation="command")
    encoded = json.dumps(item)
    assert not any(secret in encoded for secret in
                   ("argv-bare-secret", "another-bare-secret", "captured-stdout-secret", "captured-stderr-secret"))
    assert "--token" not in encoded and "--password" not in encoded
    assert item["technical"]["exceptions"][int(wrapped)]["type"] == exception_type.__name__
    assert item["code"] == ("CAT-TIMEOUT-001" if exception_type is subprocess.TimeoutExpired else "CAT-UNKNOWN-001")
