"""Bounded, credential-redacted Kubernetes diagnostic messages."""
import re


def startup_message(value):
    if not isinstance(value, str):
        return ""
    message = value[:16000]
    message = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)", "[redacted private key]", message, flags=re.S)
    message = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[redacted]@", message)
    message = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [redacted]", message)
    message = re.sub(r"(?i)((?:password|passwd|token|api[_-]?key|client[_-]?secret|authorization|credential|signature)\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)", r"\1[redacted]", message)
    message = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[redacted token]", message)
    message = " ".join(message.split())
    return message[:2000] + ("… [truncated]" if len(message) > 2000 else "")
