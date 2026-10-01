#!/usr/bin/env python3
"""Summarize Helm failures without echoing arbitrary credential-bearing output."""
import re
import sys
from urllib.parse import urlsplit, urlunsplit


def summarize(output):
    lowered = output.lower()
    cases = (
        (("403", "forbidden"), "HTTP 403: dependency request rejected; check repository authorization and proxy/firewall policy"),
        (("401", "unauthorized"), "HTTP 401: dependency repository authentication required or denied"),
        (("x509", "certificate", "tls handshake"), "Dependency TLS trust failed; check the configured issuing CA"),
        (("429", "toomanyrequests", "too many requests"), "Dependency repository rate limit reached"),
        (("not found", "404", "manifest unknown"), "Required dependency chart/version was not found in its repository"),
        (("timeout", "timed out", "deadline exceeded"), "Dependency request timed out"),
        (("no such host", "name resolution", "connection refused", "network is unreachable"), "Dependency repository DNS/network connection failed"),
        (("HELM_ALLOW_NETWORK=false".lower(),), "Missing dependencies cannot be downloaded because HELM_ALLOW_NETWORK=false"),
    )
    message = next((message for terms, message in cases if any(term in lowered for term in terms)),
                   "Dependency preparation failed; check declared versions, repositories and vendored charts")
    missing = re.findall(r'Missing vendored dependency ([A-Za-z0-9_.-]+) ([A-Za-z0-9.*+~^<>=| -]+?) for ', output)
    if missing:
        message += "; missing vendored dependencies=" + ", ".join(f"{name} ({version})" for name, version in missing[:5])
    # Only expose structured references, never arbitrary stderr or URL credentials/query strings.
    references = []
    for value in re.findall(r'(?:https?|oci)://[^\s\"<>]+', output):
        try:
            parsed = urlsplit(value.rstrip(";,)'"))
            host = parsed.hostname
            if not host:
                continue
            reference = urlunsplit((parsed.scheme, host, parsed.path, "", ""))
            if reference not in references:
                references.append(reference)
        except ValueError:
            continue
    if references:
        message += "; reference=" + ", ".join(references[:3])
    return message[:1200]


if __name__ == "__main__":
    print(summarize(sys.stdin.read()))
