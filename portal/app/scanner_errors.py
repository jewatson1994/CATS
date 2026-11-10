"""Scanner failure categories and bounded, redacted native error excerpts."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import errno
import re


_SCANNERS = frozenset({"grype", "syft", "trivy", "dockle"})
_MAX_DIAGNOSTIC_CHARS = 4096
_MAX_DIAGNOSTIC_LINES = 24
_MAX_REDACTION_CHARS = 65536
_CREDENTIAL_WORDS = ("password", "passwd", "token", "secret", "credential",
                     "apikey", "accesskey", "auth")
_ASSIGNMENT = re.compile(r'''["'`]?[ \t]*[:=]''')


def _credential_may_continue(value: str) -> bool:
    if not value or re.fullmatch(r"[|>][0-9+-]*(?:\s*#.*)?|[\[{]", value):
        return True
    quote = None
    escaped = False
    for char in value:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'`":
            quote = char
    return quote is not None or escaped


def _redact_credential_lines(text: str) -> str:
    lines = []
    credential_indent = None
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip())
        if credential_indent is not None and (not line.strip() or indent > credential_indent):
            continue
        credential_indent = None
        # Scan each key once, including quoted JSON/YAML keys. Redact the whole
        # remainder, since credential values can contain spaces or nested keys.
        for token in re.finditer(r"[\w.-]+", line):
            key = token.group().lower().replace("_", "").replace("-", "")
            if (any(word in key for word in _CREDENTIAL_WORDS)
                    and _ASSIGNMENT.match(line, token.end())):
                value = line[_ASSIGNMENT.match(line, token.end()).end():].strip()
                start = token.start()
                if start and line[start - 1] in "\"'`":
                    start -= 1
                line = line[:start] + "[redacted credential]"
                if _credential_may_continue(value):
                    # The boundary of a multiline credential is ambiguous in
                    # native diagnostics. Omit the rest rather than expose it.
                    return "\n".join(lines + [line, "[remaining stderr omitted: multiline credential]"])
                credential_indent = indent
                break
        lines.append(line)
    return "\n".join(lines)


def _redact_stderr(stderr: str) -> str:
    # Bound redaction work before running patterns. Take only a prefix: a raw
    # tail could start halfway through a credential or private key block.
    clipped = len(stderr) > _MAX_REDACTION_CHARS
    text = stderr[:_MAX_REDACTION_CHARS]
    # Remove terminal controls before matching credentials (including OSC links).
    text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\|\Z))", "", text)
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]", "", text)
    text = re.sub(r"-----BEGIN [^-\n]+-----.*?(?:-----END [^-\n]+-----|\Z)",
                  "[redacted key material]", text, flags=re.DOTALL)
    text = re.sub(r"(?im)\b(?:proxy-)?authorization\s*[:=]\s*[^\n]+", "authorization: [redacted]", text)
    text = re.sub(r"(?i)\b(?:Bearer|Basic)\s+\S+", "[redacted authentication]", text)
    text = re.sub(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s<>]+", "[redacted URL]", text)
    text = _redact_credential_lines(text)
    # Quoted strings and paths can contain arbitrary supplied values. Preserve
    # the surrounding native error, never the scanner's stdout (which is evidence).
    text = re.sub(r'''"(?:\\.|[^"\\])*(?:"|\Z)|'(?:\\.|[^'\\])*(?:'|\Z)|`(?:\\.|[^`\\])*(?:`|\Z)''',
                  "[redacted value]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[redacted token]", text)
    text = re.sub(r"\.Values\.[\w.-]+", ".Values.[redacted]", text)
    text = re.sub(r'''(?<![\w/])(?:[A-Za-z]:[\\/]|\.{0,2}/)[^\s,;:'"`<>]+''', "[redacted path]", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # Runtime crashes can contain thousands of stack/register lines. Keep the
    # opening error and final cause with a visible omission marker in between.
    if len(lines) > _MAX_DIAGNOSTIC_LINES:
        lines = lines[:16] + ["[stderr lines omitted]"] + lines[-7:]
    text = "\n".join(lines)
    if len(text) > _MAX_DIAGNOSTIC_CHARS:
        text = text[:3000] + "\n[stderr truncated]\n" + text[-1000:]
    if clipped:
        text += "\n[remaining stderr omitted]"
    return text


@dataclass(frozen=True)
class ScannerDiagnostic:
    """Only sanitized stderr is retained on an exception or passed to job logs."""

    tool: str
    returncode: int
    stderr: str

    def __post_init__(self):
        if self.tool not in _SCANNERS or type(self.returncode) is not int:
            raise ValueError("Invalid scanner diagnostic metadata")
        object.__setattr__(self, "stderr", _redact_stderr(self.stderr))

    def detail(self) -> str:
        status = (f"signal {-self.returncode}" if self.returncode < 0
                  else f"exit code {self.returncode}")
        stderr = self.stderr or "[scanner emitted no stderr]"
        return f"Scanner: {self.tool}; {status}.\nScanner stderr (redacted):\n{stderr}"


_DETAILS = {
    "process_creation_failed": "The scanner could not create a process or thread. Check worker PID/thread usage and memory limits.",
    "disk_space_exhausted": "The scanner ran out of disk space or disk quota. Check worker scratch storage.",
    "memory_exhausted": "The scanner could not allocate memory. Check worker and host memory usage.",
    "file_descriptor_limit": "The scanner could not open another file. Check worker file descriptor usage and limits.",
    "file_access_denied": "The scanner could not access a required file. Check input and database permissions.",
    "file_unavailable": "A required scanner file is missing. Check retained inputs and the installed scanner tools.",
    "scanner_database_unavailable": "The retained vulnerability database could not be loaded or validated. Check the worker's intelligence snapshot.",
    "scanner_database_expired": "The retained vulnerability database exceeds the configured age policy. Refresh the intelligence snapshot or review the configured offline age policy.",
    "scanner_database_changed": "The retained vulnerability database changed during scanning. Retry with a stable intelligence snapshot.",
    "scanner_database_policy_invalid": "The scanner database age policy is invalid. Check the configured age and validation settings.",
    "invalid_scanner_evidence": "The scanner did not return valid, complete evidence.",
    "invalid_scanner_input": "The supplied scanner input is not a valid native SBOM.",
    "isolation_unavailable": "Worker isolation could not start. Check the host AppArmor and seccomp profiles.",
    "time_limit_exceeded": "The offline scanner exceeded its time limit.",
    "output_limit_exceeded": "The offline scanner exceeded its output limit.",
    "scanner_failed": "The offline scanner failed for an unclassified reason.",
}


def scanner_failure_reason(stderr: str) -> str:
    """Reduce known native errors to a fixed code without retaining their text."""
    text = stderr.lower()
    if any(line.startswith("bwrap:") for line in text.splitlines()):
        return "isolation_unavailable"
    if "no space left on device" in text or "disk quota exceeded" in text:
        return "disk_space_exhausted"
    if ("pthread_create failed" in text or "failed to create new os thread" in text
            or ("resource temporarily unavailable" in text
                and any(word in text for word in ("fork", "clone", "thread")))):
        return "process_creation_failed"
    if "cannot allocate memory" in text or "runtime: out of memory" in text:
        return "memory_exhausted"
    if "too many open files" in text:
        return "file_descriptor_limit"
    if ("database" in text or "vulnerability db" in text) and any(
            marker in text for marker in ("too old", "older than", "exceeds max allowed age")):
        return "scanner_database_expired"
    if any(marker in text for marker in (
            "failed to load vulnerability db", "vulnerability database is invalid",
            "database metadata not found", "database disk image is malformed",
            "failed to read db description")):
        return "scanner_database_unavailable"
    if "permission denied" in text:
        return "file_access_denied"
    return "scanner_failed"


def scanner_failure_message(reason: str | None) -> str:
    reason = reason if reason in _DETAILS else "scanner_failed"
    return f"[{reason}] {_DETAILS[reason]}"


_STAGES = {
    "input_validation": "validating the SBOM input",
    "database_validation": "validating the scanner database",
    "input_staging": "preparing private scanner inputs",
    "database_staging": "preparing the private scanner database",
    "scanner_execution": "running the offline scanner",
    "evidence_validation": "validating scanner evidence",
    "evidence_publication": "retaining scanner evidence",
}


@contextmanager
def scanner_stage(stage: str):
    """Keep the deepest failing step without publishing arbitrary exceptions."""
    try:
        yield
    except Exception as error:
        if not getattr(error, "scanner_stage", None):
            error.scanner_stage = stage
        raise


def scanner_os_error_reason(error: OSError) -> str | None:
    """Classify filesystem/process errors before wrappers discard their errno."""
    return {
        errno.EAGAIN: "process_creation_failed",
        errno.ENOMEM: "memory_exhausted",
        errno.ENOSPC: "disk_space_exhausted",
        errno.EDQUOT: "disk_space_exhausted",
        errno.EMFILE: "file_descriptor_limit",
        errno.ENFILE: "file_descriptor_limit",
        errno.EACCES: "file_access_denied",
        errno.EPERM: "file_access_denied",
        errno.ENOENT: "file_unavailable",
    }.get(error.errno)


def scanner_failure_detail(error: Exception) -> str:
    """Publish native errors only through the sanitizing diagnostic boundary."""
    reason = getattr(error, "reason", None)
    if reason not in _DETAILS:
        if isinstance(error, OSError):
            reason = scanner_os_error_reason(error)
        elif getattr(error, "infrastructure", False):
            reason = "isolation_unavailable"
    message = scanner_failure_message(reason)
    stage = _STAGES.get(getattr(error, "scanner_stage", None))
    if stage:
        message += "\nScanner stage: " + stage + "."
    diagnostic = getattr(error, "scanner_diagnostic", None)
    if isinstance(diagnostic, ScannerDiagnostic):
        message += "\n" + diagnostic.detail()
    return message
