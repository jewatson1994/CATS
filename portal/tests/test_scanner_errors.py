"""Safe native scanner diagnostics without launching tools or exposing inputs."""
from types import SimpleNamespace
import tempfile

import pytest

from app import rendering
from app.scanner_errors import scanner_failure_detail, scanner_failure_message, scanner_failure_reason


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

    def fail(tool, stderr, *, timeout=30, max_output=None):
        stdout_stream, stderr_stream = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        stdout_stream.write(("private native output: " + SECRET).encode())
        stderr_stream.write(stderr.encode())
        stdout_stream.seek(0)
        stderr_stream.seek(0)
        cleanup = []
        process = SimpleNamespace(
            pid=1234, stdout=stdout_stream, stderr=stderr_stream, returncode=1,
            poll=lambda: 1, terminate=lambda: cleanup.append("terminated"),
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
