"""Safe native scanner diagnostics without launching tools or exposing inputs."""
from types import SimpleNamespace
import tempfile

import pytest

from app import rendering
from app.scanner_errors import ScannerDiagnostic, scanner_failure_detail, scanner_failure_message, scanner_failure_reason


SECRET = "SCANNER_SECRET_CANARY_6fae"


@pytest.fixture(autouse=True)
def stub_packaged_intelligence_startup():
    # These tests need only the standard-library action runner.
    pass


@pytest.fixture
def native_failure(monkeypatch):
    """Feed mock process streams through the real output and failure handling."""
    class ReadySelector:
        def __init__(self):
            self.keys = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def register(self, stream, events, data):
            self.keys[stream] = SimpleNamespace(fileobj=stream, data=data)

        def unregister(self, stream):
            del self.keys[stream]

        def get_map(self):
            return self.keys

        def select(self, timeout):
            return [(key, rendering.selectors.EVENT_READ) for key in list(self.keys.values())]

    monkeypatch.setattr(rendering, "child_seccomp", tempfile.TemporaryFile)
    monkeypatch.setattr(rendering, "supervised_command", lambda command, **kwargs: command)
    monkeypatch.setattr(rendering.selectors, "DefaultSelector", ReadySelector)

    def fail(tool, stderr, *, timeout=30, max_output=None, returncode=1):
        stdout_stream, stderr_stream = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        stdout_stream.write(("private native output: " + SECRET).encode())
        stderr_stream.write(stderr.encode())
        stdout_stream.seek(0)
        stderr_stream.seek(0)
        cleanup = []
        process = SimpleNamespace(
            pid=1234, stdout=stdout_stream, stderr=stderr_stream, returncode=returncode,
            poll=lambda: returncode, terminate=lambda: cleanup.append("terminated"),
            wait=lambda timeout: cleanup.append("reaped"),
        )
        monkeypatch.setattr(rendering.subprocess, "Popen", lambda *args, **kwargs: process)
        with pytest.raises(rendering.RendererError) as caught:
            rendering._execute(tool, ["mock-tool"], {}, timeout, max_output, None)
        assert cleanup == ["terminated", "reaped"]
        assert stdout_stream.closed and stderr_stream.closed
        return caught.value

    return fail


@pytest.mark.parametrize("diagnostic,expected", [
    ("runtime/cgo: pthread_create failed: Resource temporarily unavailable", "process_creation_failed"),
    ("runtime: failed to create new OS thread", "process_creation_failed"),
    ("fork: resource temporarily unavailable", "process_creation_failed"),
    ("write: no space left on device", "disk_space_exhausted"),
    ("write: disk quota exceeded", "disk_space_exhausted"),
    ("cannot allocate memory", "memory_exhausted"),
    ("runtime: out of memory", "memory_exhausted"),
    ("open: too many open files", "file_descriptor_limit"),
    ("database is too old", "scanner_database_expired"),
    ("vulnerability db exceeds max allowed age", "scanner_database_expired"),
    ("failed to load vulnerability db", "scanner_database_unavailable"),
    ("database disk image is malformed", "scanner_database_unavailable"),
    ("open: permission denied", "file_access_denied"),
    ("resource temporarily unavailable", "scanner_failed"),
    ("unrecognized native failure", "scanner_failed"),
])
def test_native_diagnostic_reduces_to_fixed_reason_and_message(diagnostic, expected):
    diagnostic += f"; path=/private/{SECRET}; token={SECRET}"
    reason = scanner_failure_reason(diagnostic)
    assert reason == expected
    message = scanner_failure_message(reason)
    assert message.startswith(f"[{expected}] ")
    assert SECRET not in message
    assert "/private/" not in message


@pytest.mark.parametrize("tool", ["grype", "syft", "trivy", "dockle"])
@pytest.mark.parametrize("diagnostic,expected", [
    ("runtime/cgo: pthread_create failed: Resource temporarily unavailable", "process_creation_failed"),
    ("unrecognized native failure", "scanner_failed"),
])
def test_scanner_execution_never_retains_native_values(native_failure, tool, diagnostic, expected):
    error = native_failure(tool, diagnostic + f"; .Values.{SECRET}; `{SECRET}`; password={SECRET}")
    assert error.reason == expected
    assert str(error) == scanner_failure_message(expected)
    assert error.value_paths == []
    assert not error.infrastructure
    assert SECRET not in repr(vars(error))
    assert SECRET not in scanner_failure_detail(error)


def test_isolation_failure_takes_precedence_over_scanner_diagnostic(native_failure):
    diagnostic = f"cannot allocate memory: {SECRET}\nbwrap: permission denied: /private/{SECRET}"
    error = native_failure("grype", diagnostic)
    assert error.reason == "isolation_unavailable"
    assert error.infrastructure
    assert error.value_paths == []
    assert str(error) == scanner_failure_message("isolation_unavailable")
    assert SECRET not in repr(vars(error))


def test_helm_required_value_classification_is_preserved(native_failure):
    error = native_failure("helm", f"nil pointer evaluating .Values.database.password; password={SECRET}")
    assert error.reason == "required_values"
    assert error.value_paths == ["database.password"]
    assert not error.infrastructure
    assert str(error) == "Offline tool failed; review the supplied inputs"
    assert SECRET not in repr(vars(error))


@pytest.mark.parametrize("options,expected", [
    ({"timeout": 0}, "time_limit_exceeded"),
    ({"max_output": 1}, "output_limit_exceeded"),
])
def test_scanner_limits_have_safe_reason_and_cleanup(native_failure, options, expected):
    error = native_failure("grype", f"private failure: {SECRET}", **options)
    assert error.reason == expected
    assert error.value_paths == []
    assert not error.infrastructure
    assert scanner_failure_detail(error) == scanner_failure_message(expected)
    assert SECRET not in str(error)
    assert SECRET not in repr(vars(error))


def test_unknown_native_failure_reaches_logs_with_exit_status(native_failure):
    error = native_failure("grype", "unable to open database: unsupported schema version 99", returncode=42)
    detail = scanner_failure_detail(error)
    assert "[scanner_failed]" in detail
    assert "Scanner: grype; exit code 42." in detail
    assert "unable to open database: unsupported schema version 99" in detail
    assert "private native output" not in detail
    assert SECRET not in detail


@pytest.mark.parametrize("returncode,status", [(-6, "signal 6"), (2, "exit code 2")])
def test_empty_native_stderr_still_reports_exit_status(native_failure, returncode, status):
    error = native_failure("syft", "", returncode=returncode)
    assert f"Scanner: syft; {status}." in scanner_failure_detail(error)
    assert "[scanner emitted no stderr]" in scanner_failure_detail(error)


@pytest.mark.parametrize("sensitive", [
    f"authorization: Bearer {SECRET}",
    f"Proxy-Authorization: Basic {SECRET}",
    f"token={SECRET}; next=public",
    f"client_secret: {SECRET}",
    f"api_key={SECRET}",
    f"https://user:{SECRET}@registry.example/test?token={SECRET}",
    f"/private/{SECRET}/inventory.json",
    f"C:\\private\\{SECRET}\\inventory.json",
    f".Values.{SECRET}",
    f"value='{SECRET}'",
    f'{{"password": "{SECRET}"}}',
    f"-----BEGIN PRIVATE KEY-----\n{SECRET}\n-----END PRIVATE KEY-----",
    f"\x1b]8;;https://example.test/{SECRET}\x07link\x1b]8;;\x07",
    f"password=\x1b[31m{SECRET}\x1b[0m",
    f"failed parsing credentials: password = {SECRET} with spaces",
    f"auth: token = {SECRET}",
    f"'password': {SECRET}",
    f'"api_key": {SECRET}',
    f"password = first {SECRET} last",
])
def test_native_diagnostics_redact_credentials_and_input_values(sensitive):
    diagnostic = ScannerDiagnostic("grype", 1, "database initialization failed\n" + sensitive)
    assert "database initialization failed" in diagnostic.detail()
    assert SECRET not in repr(diagnostic)
    assert SECRET not in diagnostic.detail()
    assert "\x1b" not in diagnostic.detail()


def test_long_diagnostic_preserves_cause_and_marks_omissions():
    diagnostic = ScannerDiagnostic("grype", 1, "initial failure\n" + "stack frame\n" * 200 + "final cause")
    assert diagnostic.stderr.startswith("initial failure\n")
    assert diagnostic.stderr.endswith("final cause")
    assert "[stderr lines omitted]" in diagnostic.stderr
    assert len(diagnostic.stderr.splitlines()) <= 24
    diagnostic = ScannerDiagnostic("trivy", 1, "initial failure " + "x" * 10000 + " final cause")
    assert diagnostic.stderr.startswith("initial failure ")
    assert diagnostic.stderr.endswith(" final cause")
    assert "[stderr truncated]" in diagnostic.stderr
    assert len(diagnostic.stderr) <= 4096


@pytest.mark.parametrize("prefix", ["a." * 500000, "password: " + "x" * 1000000,
                                   "-----BEGIN PRIVATE KEY-----\n" + "x" * 1000000],
                         ids=["punctuation", "credential", "private-key"])
def test_large_stderr_is_bounded_before_redaction(prefix):
    diagnostic = ScannerDiagnostic("grype", 1, "initial failure\n" + prefix + SECRET)
    assert diagnostic.stderr.startswith("initial failure\n")
    assert diagnostic.stderr.endswith("[remaining stderr omitted]")
    assert len(diagnostic.stderr) <= 4096
    assert SECRET not in diagnostic.stderr


def test_quoted_credential_key_does_not_hide_next_error_line():
    diagnostic = ScannerDiagnostic("grype", 1, f"'password': {SECRET}\nfinal failure")
    assert SECRET not in diagnostic.stderr
    assert diagnostic.stderr.endswith("final failure")


@pytest.mark.parametrize("credential", [
    f"token:\n  {SECRET}",
    f"password: |\n  {SECRET}",
    f'password="first\n{SECRET}"',
    f"password: first\n  {SECRET}",
    f"password: first\n\n  {SECRET}",
])
def test_multiline_credentials_are_not_published(credential):
    diagnostic = ScannerDiagnostic("grype", 1, "initial failure\n" + credential)
    assert diagnostic.stderr.startswith("initial failure\n")
    assert SECRET not in diagnostic.detail()


def test_untyped_diagnostic_and_exception_text_are_not_published():
    error = rendering.RendererError(SECRET, scanner_diagnostic=SECRET)
    assert scanner_failure_detail(error) == scanner_failure_message("scanner_failed")
