from __future__ import annotations

import json
import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any, Callable


PATCH_PHASES = (
    "queued", "acquiring_image", "scanning_source", "patching_image",
    "scanning_patched", "preparing_output", "pushing_image", "signing_image", "completed",
)


def initial_patch_stages(output_mode: str = "download") -> dict[str, dict[str, str]]:
    """Return independent persisted stage records for a new patch job."""
    stages = {phase: {"status": "waiting"} for phase in PATCH_PHASES}
    if str(output_mode or "download").lower() == "download":
        stages["pushing_image"] = {"status": "skipped", "reason": "not_applicable"}
        stages["signing_image"] = {"status": "skipped", "reason": "not_applicable"}
    return stages


def advance_patch_stages(stages: dict | None, phase: str, job_status: str, output_mode: str = "download") -> dict[str, dict[str, str]]:
    """Advance one stage without erasing prior terminal states.

    ``waiting`` is retained for stages that have not been reached until a
    terminal job state, when they become explicit ``skipped``/not-reached
    records.  Download jobs mark OCI pushing as not applicable from the start.
    """
    current = initial_patch_stages(output_mode)
    if isinstance(stages, dict):
        for name in PATCH_PHASES:
            value = stages.get(name)
            if isinstance(value, dict) and value.get("status") in {"waiting", "running", "success", "failed", "skipped"}:
                current[name] = dict(value)
            elif isinstance(value, str) and value in {"waiting", "running", "success", "failed", "skipped"}:
                current[name] = {"status": value}
    if phase not in PATCH_PHASES:
        return current
    index = PATCH_PHASES.index(phase)
    status = str(job_status or "").lower()
    if status == "running":
        for prior in PATCH_PHASES[:index]:
            if current[prior].get("status") in {"waiting", "running"}:
                current[prior] = {"status": "success"}
        if current[phase].get("status") != "success":
            current[phase] = {"status": "running"}
    elif status == "complete":
        for prior in PATCH_PHASES[:index]:
            if current[prior].get("status") == "running":
                current[prior] = {"status": "success"}
        current[phase] = {"status": "success"}
        if phase == "completed":
            for stage_name in PATCH_PHASES:
                if current[stage_name].get("status") == "waiting":
                    current[stage_name] = {"status": "skipped", "reason": "not_reached"}
    elif status == "failed":
        for prior in PATCH_PHASES[:index]:
            if current[prior].get("status") == "running":
                current[prior] = {"status": "success"}
        current[phase] = {"status": "failed"}
        for downstream in PATCH_PHASES[index + 1:]:
            if current[downstream].get("status") in {"waiting", "running"}:
                current[downstream] = {"status": "skipped", "reason": "not_reached"}
    return current

_SECRET_KEYS = {"password", "token", "secret", "authorization", "private_key"}

PACKAGE_MANAGER_PROBE_ORDER = ("apk", "apt-get", "microdnf", "dnf", "yum")


def package_manager_probe_script() -> str:
    """Return a probe that succeeds as soon as one supported manager is found."""
    tools = " ".join(PACKAGE_MANAGER_PROBE_ORDER)
    return (
        "for tool in " + tools + "; do "
        "if command -v \"$tool\" >/dev/null 2>&1; then "
        "printf '%s\\n' \"$tool\"; exit 0; fi; "
        "done; exit 1"
    )


def normalize_package_manager(manager: str) -> str:
    """Map an executable name to the internal trust/repository strategy."""
    value = str(manager or "").strip().lower()
    if value == "apt-get":
        return "apt"
    if value in {"microdnf", "dnf", "yum"}:
        return "dnf"
    if value == "apk":
        return "apk"
    return ""


def package_ecosystem(manager: str) -> str:
    """Return the Copa/package ecosystem for a detected manager executable."""
    return {"apk": "apk", "apt-get": "deb", "microdnf": "rpm", "dnf": "rpm", "yum": "rpm"}.get(
        str(manager or "").strip().lower(), ""
    )


def redact(value: object, secrets: tuple[str, ...] = ()) -> str:
    text = str(value or "")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(password|token|authorization)(\s*[=:]\s*)\S+", r"\1\2[REDACTED]", text)
    return text


def safe_job_config(data: dict[str, Any]) -> dict[str, Any]:
    """Return durable job metadata with credential-like fields removed."""
    return {
        key: value
        for key, value in data.items()
        if not any(marker in key.lower() for marker in _SECRET_KEYS)
    }


def image_repository(reference: str) -> str:
    value = reference.split("@", 1)[0]
    slash = value.rfind("/")
    colon = value.rfind(":")
    return value[:colon] if colon > slash else value


def registry_host(reference: str) -> str:
    """Return the OCI registry host Docker expects for authentication."""
    value = str(reference or "").strip()
    if not value:
        raise ValueError("Image reference is required")
    if "/" not in value:
        return "docker.io"
    first = value.split("/", 1)[0]
    return first if "." in first or ":" in first or first == "localhost" else "docker.io"


def _safe_archive_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError("Image archive contains an unsafe member path")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or ".." in normalized.split("/"):
        raise ValueError("Image archive contains an unsafe member path")
    return normalized


def validate_image_archive(
    path: Path,
    expected_format: str | None = None,
    *,
    validate_layers: bool = True,
) -> str:
    """Validate a Docker/OCI image archive without extracting untrusted data.

    Structural metadata and every referenced config/blob are checked so an
    ordinary filesystem tar cannot be mistaken for a container archive.
    Docker layers are also opened as tar files unless the caller delegates
    layer compatibility validation to a Docker load round trip.
    """
    if path.suffix.lower() != ".tar" or not path.is_file():
        raise ValueError("Uploaded image must be a readable Docker or OCI .tar archive")
    try:
        with tarfile.open(path, "r") as bundle:
            members = {_safe_archive_name(item.name): item for item in bundle.getmembers()}
            names = set(members)
            if "manifest.json" in names:
                manifest = json.loads(bundle.extractfile(members["manifest.json"]).read())
                if not isinstance(manifest, list) or not manifest:
                    raise ValueError("Docker image archive has an empty or invalid manifest.json")
                for entry in manifest:
                    if not isinstance(entry, dict) or not isinstance(entry.get("Config"), str) or not isinstance(entry.get("Layers"), list):
                        raise ValueError("Docker image archive manifest is malformed")
                    referenced = [entry["Config"], *entry["Layers"]]
                    if not referenced or any(_safe_archive_name(name) not in names for name in referenced):
                        raise ValueError("Docker image archive references missing config or layer data")
                    # Docker's manifest points at layer tarballs.  Checking
                    # only the outer archive lets a corrupt layer reach
                    # Grype, which then fails later with the less actionable
                    # "docker-archive: invalid tar header" error.
                    if validate_layers:
                        for layer_name in entry["Layers"]:
                            layer_member = members[_safe_archive_name(layer_name)]
                            layer_stream = bundle.extractfile(layer_member)
                            if layer_stream is None:
                                raise ValueError("Docker image archive layer data could not be read")
                            try:
                                with tarfile.open(fileobj=io.BytesIO(layer_stream.read()), mode="r:"):
                                    pass
                            except (OSError, tarfile.TarError) as exc:
                                raise ValueError(f"Docker image archive layer is not a valid tar: {layer_name}") from exc
                    detected = "docker"
            elif "index.json" in names and "oci-layout" in names:
                layout = json.loads(bundle.extractfile(members["oci-layout"]).read())
                index = json.loads(bundle.extractfile(members["index.json"]).read())
                manifests = index.get("manifests") if isinstance(index, dict) else None
                if layout.get("imageLayoutVersion") != "1.0.0" or index.get("schemaVersion") != 2 or not isinstance(manifests, list) or not manifests:
                    raise ValueError("OCI image archive metadata is malformed")
                for descriptor in manifests:
                    digest = descriptor.get("digest", "") if isinstance(descriptor, dict) else ""
                    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
                        raise ValueError("OCI image archive manifest descriptor is invalid")
                    if f"blobs/sha256/{digest.split(':', 1)[1]}" not in names:
                        raise ValueError("OCI image archive references a missing manifest blob")
                detected = "oci"
            else:
                raise ValueError("Uploaded .tar is not a Docker or OCI image archive")
    except (OSError, tarfile.TarError, json.JSONDecodeError, AttributeError, KeyError, TypeError) as exc:
        raise ValueError("Uploaded .tar is not a valid image archive") from exc
    if expected_format and detected != expected_format:
        raise ValueError(f"Expected a {expected_format} image archive, found {detected}")
    return detected


def grype_archive_source(path: Path, archive_format: str) -> str:
    """Return an explicit Grype source URI for a validated image archive."""
    scheme = {"docker": "docker-archive", "oci": "oci-archive"}.get(archive_format)
    if not scheme:
        raise ValueError(f"Unsupported image archive format: {archive_format or 'unknown'}")
    return f"{scheme}:{path.resolve()}"


def archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patched_reference(reference: str, suffix: str = "cats-patched") -> tuple[str, str]:
    repository = image_repository(reference)
    value = reference.split("@", 1)[0]
    slash = value.rfind("/")
    colon = value.rfind(":")
    tag = value[colon + 1 :] if colon > slash else "latest"
    patched_tag = f"{tag}-{suffix}"
    return f"{repository}:{patched_tag}", patched_tag


def grype_records(report: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for match in report.get("matches") or []:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix = vulnerability.get("fix") or {}
        fixed = [str(value) for value in (fix.get("versions") or []) if str(value).strip()]
        records.append({
            "id": str(vulnerability.get("id") or "Unknown"),
            "severity": str(vulnerability.get("severity") or "Unknown"),
            "package": str(artifact.get("name") or "Unknown"),
            "installed_version": str(artifact.get("version") or "Unknown"),
            "package_type": str(artifact.get("type") or "Unknown"),
            "fixed_versions": fixed,
            "description": str(vulnerability.get("description") or ""),
        })
    return records


def copa_native_report(report: dict[str, Any], arch: str = "amd64", ecosystem: str = "") -> dict[str, Any]:
    distro = report.get("distro") or report.get("distribution") or {}
    allowed_types = {"apk": {"apk"}, "deb": {"deb", "dpkg"}, "rpm": {"rpm", "rpmdb"}}.get(ecosystem, set())
    updates = []
    for record in grype_records(report):
        if not record["fixed_versions"]:
            continue
        if allowed_types and record["package_type"].lower() not in allowed_types:
            continue
        updates.append({
            "name": record["package"],
            "installedVersion": record["installed_version"],
            "fixedVersion": record["fixed_versions"][-1],
            "vulnerabilityID": record["id"],
        })
    return {
        "apiVersion": "v1alpha1",
        "metadata": {
            "os": {"type": str(distro.get("name") or ""), "version": str(distro.get("version") or "")},
            "config": {"arch": arch or "amd64"},
        },
        "updates": updates,
    }


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_rows = grype_records(before)
    after_rows = grype_records(after)
    key = lambda row: (row["id"], row["package"])
    after_keys = {key(row) for row in after_rows}
    before_keys = {key(row) for row in before_rows}
    removed = [row for row in before_rows if key(row) not in after_keys]
    remaining = [row for row in after_rows if key(row) in before_keys or row["id"]]
    patchable = [row for row in before_rows if row["fixed_versions"]]
    could_not_patch = [row for row in patchable if key(row) in after_keys]
    before_by_key = {key(row): row for row in before_rows}
    after_by_key = {key(row): row for row in after_rows}
    vulnerability_results = []
    for row_key in list(dict.fromkeys([*before_by_key, *after_by_key])):
        before_row = before_by_key.get(row_key)
        after_row = after_by_key.get(row_key)
        if before_row and not after_row:
            result = "Remediated"
        elif not before_row and after_row:
            result = "New after patch"
        elif not before_row or not after_row:
            continue
        elif not before_row["fixed_versions"]:
            result = "No fix available"
        elif before_row["installed_version"] == after_row["installed_version"]:
            result = "Patch failed"
        else:
            result = "Still detected"
        source = after_row or before_row
        fixed_versions = (before_row or {}).get("fixed_versions") or (after_row or {}).get("fixed_versions") or []
        vulnerability_results.append({
            "id": source["id"],
            "severity": source["severity"],
            "package": source["package"],
            "before_version": before_row["installed_version"] if before_row else None,
            "after_version": after_row["installed_version"] if after_row else None,
            "result": result,
            "fixed_versions": fixed_versions,
        })
    unresolved_count = sum(1 for row_key in before_keys & after_keys)
    new_after_count = sum(1 for row_key in after_keys if row_key not in before_keys)
    remediated_count = len(removed)
    unresolved_count = len(before_keys & after_keys)
    if not before_rows:
        patch_status = "NO_APPLICABLE_FIXES"
        patch_reason = "No fixable vulnerabilities were detected"
    elif remediated_count and not after_rows:
        patch_status = "PATCHED"
        patch_reason = "Applicable vulnerabilities were remediated"
    elif remediated_count:
        patch_status = "PARTIALLY_PATCHED"
        patch_reason = "Fixable vulnerabilities remain after patching"
    else:
        patch_status = "NO_APPLICABLE_FIXES"
        patch_reason = "Copa reported no applicable package updates"
    return {
        "vulnerabilities_before": len(before_rows),
        "vulnerabilities_after": len(after_rows),
        "vulnerabilities_removed": len(removed),
        "vulnerabilities_remaining": len(remaining),
        "could_not_be_patched": len(could_not_patch),
        "vulnerabilities_unresolved": unresolved_count,
        "vulnerabilities_new_after": new_after_count,
        "removed": removed,
        "remaining": remaining,
        "could_not_patch": could_not_patch,
        "vulnerability_results": vulnerability_results,
        "remediated": remediated_count,
        "unresolved": unresolved_count,
        "patch_status": patch_status,
        "reason": patch_reason,
    }


def _safe_marker(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "-", str(value or "cats"))[:80] or "cats"


def certificate_trust_script(manager: str, marker: str = "cats-trusted-ca") -> str:
    """Install bootstrap trust while preserving every source trust artifact."""
    marker = _safe_marker(marker)
    state = f"/tmp/{marker}-state"
    anchor = f"{marker}.crt"
    if manager == "apk":
        return (
            "set -eu; "
            # apk fetches indexes before ca-certificates can be installed.
            # Seed the trust path first so private/intercepting roots work for
            # that bootstrap request as well.
            f"state={state}; mkdir -p \"$state\" /etc/ssl/certs /usr/local/share/ca-certificates; "
            "if [ -e /etc/ssl/certs/ca-certificates.crt ]; then cp -p /etc/ssl/certs/ca-certificates.crt \"$state/original-bundle\"; else : > \"$state/no-bundle\"; fi; "
            "if [ -e /etc/ssl/cert.pem ]; then cp -a /etc/ssl/cert.pem \"$state/original-cert-pem\"; else : > \"$state/no-cert-pem\"; fi; "
            f"if [ -e /usr/local/share/ca-certificates/{anchor} ]; then cp -p /usr/local/share/ca-certificates/{anchor} \"$state/original-anchor\"; else : > \"$state/no-anchor\"; fi; "
            "cp /tmp/cats-patch-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt; "
            "rm -f /etc/ssl/cert.pem; ln -s /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; "
            "apk add --no-cache ca-certificates; "
            f"if [ -s /tmp/cats-custom-ca.pem ]; then cp /tmp/cats-custom-ca.pem /usr/local/share/ca-certificates/{anchor}; fi; "
            "update-ca-certificates"
        )
    if manager == "apt":
        return (
            "set -eu; "
            # apt must trust its first HTTPS index request before it can
            # install/update the ca-certificates package.
            f"state={state}; mkdir -p \"$state\" /etc/ssl/certs /usr/local/share/ca-certificates; "
            "if [ -e /etc/ssl/certs/ca-certificates.crt ]; then cp -p /etc/ssl/certs/ca-certificates.crt \"$state/original-bundle\"; else : > \"$state/no-bundle\"; fi; "
            f"if [ -e /usr/local/share/ca-certificates/{anchor} ]; then cp -p /usr/local/share/ca-certificates/{anchor} \"$state/original-anchor\"; else : > \"$state/no-anchor\"; fi; "
            "cp /tmp/cats-patch-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt; "
            "apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates; "
            f"if [ -s /tmp/cats-custom-ca.pem ]; then cp /tmp/cats-custom-ca.pem /usr/local/share/ca-certificates/{anchor}; fi; "
            "update-ca-certificates"
        )
    if manager == "dnf":
        return (
            "set -eu; "
            # dnf/microdnf/yum also need a usable bundle to install the CA
            # package itself.  Seed their conventional bundle locations first.
            f"state={state}; mkdir -p \"$state\" /etc/pki/tls/certs /etc/ssl/certs /etc/pki/ca-trust/source/anchors; "
            "if [ -e /etc/pki/tls/certs/ca-bundle.crt ]; then cp -p /etc/pki/tls/certs/ca-bundle.crt \"$state/original-pki-bundle\"; else : > \"$state/no-pki-bundle\"; fi; "
            "if [ -e /etc/ssl/certs/ca-bundle.crt ]; then cp -p /etc/ssl/certs/ca-bundle.crt \"$state/original-ssl-bundle\"; else : > \"$state/no-ssl-bundle\"; fi; "
            f"if [ -e /etc/pki/ca-trust/source/anchors/{anchor} ]; then cp -p /etc/pki/ca-trust/source/anchors/{anchor} \"$state/original-anchor\"; else : > \"$state/no-anchor\"; fi; "
            "cp /tmp/cats-patch-ca-bundle.pem /etc/pki/tls/certs/ca-bundle.crt; "
            "cp /tmp/cats-patch-ca-bundle.pem /etc/ssl/certs/ca-bundle.crt; "
            "if command -v microdnf >/dev/null 2>&1; then microdnf install -y ca-certificates; "
            "elif command -v dnf >/dev/null 2>&1; then dnf install -y ca-certificates; "
            "elif command -v yum >/dev/null 2>&1; then yum install -y ca-certificates; fi; "
            f"if [ -s /tmp/cats-custom-ca.pem ]; then cp /tmp/cats-custom-ca.pem /etc/pki/ca-trust/source/anchors/{anchor}; fi; "
            "if command -v update-ca-trust >/dev/null 2>&1; then update-ca-trust extract; "
            "elif command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates; "
            "elif command -v trust >/dev/null 2>&1; then trust extract-compat; fi"
        )
    raise ValueError(f"Unsupported package manager: {manager or 'unknown'}")


def certificate_cleanup_script(manager: str, marker: str = "cats-trusted-ca") -> str:
    """Remove only CATS-created material and restore source trust artifacts."""
    marker = _safe_marker(marker)
    state = f"/tmp/{marker}-state"
    anchor = f"{marker}.crt"
    if manager == "apk" or manager == "apt":
        restore_cert_pem = "if [ -f \"$state/original-cert-pem\" ]; then rm -f /etc/ssl/cert.pem; cp -a \"$state/original-cert-pem\" /etc/ssl/cert.pem; elif [ -f \"$state/no-cert-pem\" ]; then rm -f /etc/ssl/cert.pem; fi; " if manager == "apk" else ""
        return (
            f"set -eu; state={state}; "
            f"if [ -f \"$state/original-anchor\" ]; then cp -p \"$state/original-anchor\" /usr/local/share/ca-certificates/{anchor}; elif [ -f \"$state/no-anchor\" ]; then rm -f /usr/local/share/ca-certificates/{anchor}; fi; "
            f"rm -f /tmp/cats-patch-ca-bundle.pem /tmp/cats-custom-ca.pem; update-ca-certificates; "
            "if [ -f \"$state/original-bundle\" ]; then cat /etc/ssl/certs/ca-certificates.crt \"$state/original-bundle\" > \"$state/merged-bundle\"; mv \"$state/merged-bundle\" /etc/ssl/certs/ca-certificates.crt; elif [ -f \"$state/no-bundle\" ]; then rm -f /etc/ssl/certs/ca-certificates.crt; fi; "
            + restore_cert_pem + f"rm -rf \"$state\""
        )
    if manager == "dnf":
        return (
            f"set -eu; state={state}; "
            f"if [ -f \"$state/original-anchor\" ]; then cp -p \"$state/original-anchor\" /etc/pki/ca-trust/source/anchors/{anchor}; elif [ -f \"$state/no-anchor\" ]; then rm -f /etc/pki/ca-trust/source/anchors/{anchor}; fi; "
            "rm -f /tmp/cats-patch-ca-bundle.pem /tmp/cats-custom-ca.pem; "
            "if command -v update-ca-trust >/dev/null 2>&1; then update-ca-trust extract; "
            "elif command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates; "
            "elif command -v trust >/dev/null 2>&1; then trust extract-compat; fi; "
            "if [ -f \"$state/original-pki-bundle\" ]; then cat /etc/pki/tls/certs/ca-bundle.crt \"$state/original-pki-bundle\" > \"$state/merged-pki\"; mv \"$state/merged-pki\" /etc/pki/tls/certs/ca-bundle.crt; fi; "
            "if [ -f \"$state/original-ssl-bundle\" ]; then cat /etc/ssl/certs/ca-bundle.crt \"$state/original-ssl-bundle\" > \"$state/merged-ssl\"; mv \"$state/merged-ssl\" /etc/ssl/certs/ca-bundle.crt; fi; "
            f"rm -rf \"$state\""
        )
    raise ValueError(f"Unsupported package manager: {manager or 'unknown'}")


def copa_command(image: str, report: Path, patched_tag: str, timeout: str = "30m") -> list[str]:
    return [
        "copa", "patch", "--image", image, "--report", str(report),
        "--scanner", "native", "--tag", patched_tag, "--loader", "docker",
        "--timeout", timeout,
    ]


def repository_overlay_script(manager: str, verify_tls: bool = True, verify_packages: bool = True, marker: str = "cats") -> str:
    """Return the in-image script used to make a configured mirror authoritative.

    Copa executes package-manager commands inside the target image.  Passing a
    repository file through the host environment is therefore insufficient;
    the file must be present in the temporary image that Copa patches.  The
    script preserves the image's original repository files under a private
    marker directory so they can be restored after patching.
    """
    marker = _safe_marker(marker)
    apt_state = f"/etc/{marker}-original-apt"
    dnf_state = f"/etc/{marker}-original-dnf"
    apk_state = f"/etc/{marker}-original-apk"
    if manager == "apt":
        tls = ""
        if not verify_tls:
            tls = "mkdir -p /etc/apt/apt.conf.d; printf '%s\\n' 'Acquire::https::Verify-Peer \"false\";' 'Acquire::https::Verify-Host \"false\";' > /etc/apt/apt.conf.d/99-cats-repository-tls; "
        return (
            f"set -eu; mkdir -p {apt_state}/sources.list.d; "
            f"if [ -f /etc/apt/sources.list ]; then mv /etc/apt/sources.list {apt_state}/sources.list; fi; "
            f"for f in /etc/apt/sources.list.d/*; do if [ -f \"$f\" ]; then mv \"$f\" {apt_state}/sources.list.d/; fi; done; "
            "cp /tmp/cats-repository /etc/apt/sources.list; " + tls
        )
    if manager == "dnf":
        return (
            f"set -eu; mkdir -p {dnf_state}; "
            f"for f in /etc/yum.repos.d/*.repo; do if [ -f \"$f\" ]; then mv \"$f\" {dnf_state}/; fi; done; "
            "cp /tmp/cats-repository /etc/yum.repos.d/99-cats.repo"
        )
    if manager == "apk":
        insecure_wrapper = ""
        if not verify_tls or not verify_packages:
            flags = ""
            if not verify_tls: flags += " --no-check-certificate"
            if not verify_packages: flags += " --allow-untrusted"
            insecure_wrapper = (
                f"apk_bin=\"$(command -v apk)\"; mv \"$apk_bin\" \"$apk_bin.cats-original\"; "
                f"printf '%s\\n' '#!/bin/sh' 'exec \"$0.cats-original\"{flags} \"$@\"' > \"$apk_bin\"; chmod 0755 \"$apk_bin\"; "
                f"printf '%s\\n' \"$apk_bin\" > /tmp/{marker}-apk-path; "
            )
        return (
            f"set -eu; mkdir -p {apk_state}; "
            f"if [ -f /etc/apk/repositories ]; then mv /etc/apk/repositories {apk_state}/repositories; fi; "
            "cp /tmp/cats-repository /etc/apk/repositories; " + insecure_wrapper
        )
    raise ValueError(f"Unsupported package manager: {manager or 'unknown'}")


def repository_cleanup_script(manager: str, verify_tls: bool = True, verify_packages: bool = True, marker: str = "cats") -> str:
    """Return the script restoring repository files after Copa completes."""
    marker = _safe_marker(marker)
    apt_state = f"/etc/{marker}-original-apt"
    dnf_state = f"/etc/{marker}-original-dnf"
    apk_state = f"/etc/{marker}-original-apk"
    if manager == "apt":
        return (
            "set -eu; rm -f /etc/apt/sources.list /etc/apt/apt.conf.d/99-cats-repository-tls; "
            f"if [ -f {apt_state}/sources.list ]; then mv {apt_state}/sources.list /etc/apt/sources.list; fi; "
            "mkdir -p /etc/apt/sources.list.d; "
            f"for f in {apt_state}/sources.list.d/*; do if [ -f \"$f\" ]; then mv \"$f\" /etc/apt/sources.list.d/; fi; done; "
            f"rm -rf {apt_state}"
        )
    if manager == "dnf":
        return (
            "set -eu; rm -f /etc/yum.repos.d/99-cats.repo; "
            f"for f in {dnf_state}/*.repo; do [ -f \"$f\" ] && mv \"$f\" /etc/yum.repos.d/; done; "
            f"rm -rf {dnf_state}"
        )
    if manager == "apk":
        return (
            "set -eu; rm -f /etc/apk/repositories; "
            f"if [ -f {apk_state}/repositories ]; then mv {apk_state}/repositories /etc/apk/repositories; fi; "
            f"rm -rf {apk_state}; "
            f"if [ -f /tmp/{_safe_marker(marker)}-apk-path ]; then apk_bin=\"$(cat /tmp/{_safe_marker(marker)}-apk-path)\"; rm -f \"$apk_bin\"; mv \"$apk_bin.cats-original\" \"$apk_bin\"; rm -f /tmp/{_safe_marker(marker)}-apk-path; fi"
        )
    raise ValueError(f"Unsupported package manager: {manager or 'unknown'}")


def run_command(
    command: list[str], *, env: dict[str, str], log: Callable[[str], None],
    timeout: int, stdin: str | None = None, stdout_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(command[0], path=env.get("PATH"))
    if not executable:
        raise RuntimeError(f"Required patch tool is unavailable: {command[0]}")
    safe_command = ["[REDACTED]" if any(marker in part.lower() for marker in ("password=", "token=")) else part for part in command]
    log(f"$ {' '.join(safe_command)}")
    if stdout_path:
        with stdout_path.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(command, env=env, input=stdin, text=True, stdout=stream,
                                       stderr=subprocess.PIPE, timeout=timeout, check=False)
    else:
        completed = subprocess.run(command, env=env, input=stdin, text=True, capture_output=True,
                                   timeout=timeout, check=False)
    output = (completed.stderr or "") if stdout_path else "\n".join(filter(None, (completed.stdout, completed.stderr)))
    if output.strip():
        log(output.strip())
    if completed.returncode:
        detail = output[-3000:]
        lowered = output.lower()
        if any(marker in lowered for marker in ("certificate not trusted", "certificate signed by unknown authority", "certificate verify failed", "tls: failed to verify")):
            category = "Repository TLS trust failure"
        elif any(marker in lowered for marker in ("gpg", "signature", "public key", "no_pubkey", "untrusted package", "package is not signed")):
            category = "Package signature verification failure"
        elif any(marker in lowered for marker in ("no such package", "unable to locate package", "no match for argument")):
            category = "Package resolution failure"
        else:
            category = "Patch command failure"
        raise RuntimeError(f"{category}: {command[0]} exited with code {completed.returncode}: {detail}")
    return completed
