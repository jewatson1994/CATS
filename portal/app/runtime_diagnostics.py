"""Bounded, credential-redacted Kubernetes diagnostic messages."""
import re


def runtime_failure_details(evidence):
    """Explain observed startup failures without guessing when evidence is missing."""
    if not isinstance(evidence, dict):
        return []
    details, seen = [], set()

    def add(resource, reason, message):
        reason, message = startup_message(reason), startup_message(message)
        if not reason or (resource, reason, message) in seen:
            return
        seen.add((resource, reason, message))
        observed = (reason + " " + message).lower()
        if "runasnonroot" in observed:
            guidance = "Use an image that runs as a non-root user, or set an appropriate numeric securityContext.runAsUser in the chart. Ensure that user can write required directories; keep runAsNonRoot enabled."
        elif any(value in observed for value in ("imagepull", "errimage", "pull access denied")):
            guidance = "Check the image repository and tag, registry access from the validator, and any required imagePullSecrets."
        elif "failedscheduling" in observed or "unschedulable" in observed:
            guidance = "Compare resource requests, node selectors, affinity and tolerations with the validator's available nodes. Use the reported scheduling message to identify the constraint."
        elif "oomkilled" in observed:
            guidance = "Check application memory usage and increase the chart's memory limit if appropriate."
        elif "probe" in observed or "unhealthy" in observed:
            guidance = "Check the health probe's path, port and protocol, and allow enough startup time for the application."
        elif "configerror" in observed or "configmap" in observed or "secret" in observed:
            guidance = "Check the referenced Secrets, ConfigMaps and keys exist in the release namespace, and review the container security settings against the reported message."
        elif "mount" in observed or "volume" in observed:
            guidance = "Check volume references, storage classes and mount permissions against the reported message."
        elif resource.startswith("helm_"):
            guidance = "Check the reported chart file, values and dependency references. Correct the Helm error, package the updated chart and stage it before retrying validation."
        elif "crashloop" in observed or "error" in observed or "backoff" in observed:
            guidance = "Review container logs, the entrypoint, application configuration and filesystem permissions. Correct the startup error before running validation again."
        else:
            guidance = "Review the reported Kubernetes message and the affected resource's chart configuration, then run validation again after correcting the cause."
        details.append({"resource": startup_message(resource), "reason": reason,
                        "message": message or "The validator recorded this state without a detailed Kubernetes message.",
                        "guidance": guidance})

    for pod in (evidence.get("pods") or [])[:100]:
        for container in (pod.get("containers") or [])[:30]:
            if not container.get("ready") and container.get("reason") and container.get("reason") != "Completed":
                add(f"{pod.get('name', 'Pod')} / {container.get('name', 'container')}", container.get("reason"), container.get("message"))
    for event in (evidence.get("events") or [])[:200]:
        reason = str(event.get("reason") or "")
        if any(word in reason.lower() for word in ("failed", "error", "backoff", "unhealthy", "unschedulable")):
            add(event.get("object") or (event.get("involvedObject") or {}).get("name") or "Kubernetes resource", reason, event.get("message"))
    for failure in (evidence.get("helm_failures") or [])[:12]:
        add(failure.get("object") or "Helm chart", failure.get("reason"), failure.get("message"))
    return details[:12]


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
