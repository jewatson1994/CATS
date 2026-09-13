from __future__ import annotations

import json
import os
import re
import shutil
import signal
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .admin_config import OS_DEFINITIONS, resolve_policy, write_repository_config
from .signing import SECRET_ENV, clean_environment, sign_and_verify
from .patching import (
    PATCH_PHASES,
    archive_sha256, certificate_cleanup_script, certificate_trust_script, compare_reports, copa_command, copa_native_report, grype_archive_source, grype_records, normalize_package_manager, package_ecosystem, package_manager_probe_script, patched_reference,
    redact, registry_host, repository_cleanup_script, repository_overlay_script,
    run_command, validate_image_archive, initial_patch_stages, advance_patch_stages,
)


class PatchCancelled(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: python -m app.patch_worker CONFIG OUTPUT")
    config_path, output = Path(sys.argv[1]), Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    signing_credentials = {name: os.environ.pop(name, "") for name in SECRET_ENV}
    secrets = tuple(filter(None, (
        os.getenv("CATS_PATCH_SOURCE_PASSWORD", ""), os.getenv("CATS_PATCH_DEST_PASSWORD", ""),
    )))
    log_path = output / "patch.log"
    stages = initial_patch_stages(config.get("output_mode", "download"))
    if not config.get("signing_enabled"):
        stages["signing_image"] = {"status": "skipped", "reason": "not_configured"}
    current_phase = "queued"

    def log(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(redact(message, secrets) + "\n")

    def state(status: str, phase: str, **values) -> None:
        nonlocal stages, current_phase
        if phase in PATCH_PHASES:
            current_phase = phase
        stages = advance_patch_stages(stages, phase, status, config.get("output_mode", "download"))
        payload = {"status": status, "phase": phase, "stages": stages, "updated_at": now(), **values}
        if status == "failed":
            payload["failed_stage"] = phase
        temp = output / "patch-state.json.tmp"
        temp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temp.replace(output / "patch-state.json")
        # Keep a nonsensitive transition history for troubleshooting and UI
        # timelines. This contains phases and public image references only;
        # registry credentials are supplied exclusively through the process
        # environment and can never enter this file.
        with (output / "patch-events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, separators=(",", ":")) + "\n")

    workspace = Path(tempfile.mkdtemp(prefix="cats-patch-", dir=output))
    docker_config = workspace / "docker-config"
    docker_config.mkdir(mode=0o700)
    env = clean_environment(dict(os.environ))
    env["DOCKER_CONFIG"] = str(docker_config)
    # Administrative trust and repository settings are copied into this
    # isolated workspace only.  They are never written to durable job
    # metadata and are removed with the workspace in finally.
    trusted_bundle = workspace / "ca-bundle.pem"
    custom_bundle = workspace / "custom-ca.pem"
    repository_root = workspace / "repository-config"
    configured_certificates = config.get("trusted_ca_certificates") or []
    system_candidates = [Path("/etc/ssl/certs/ca-certificates.crt")]
    try:
        import certifi
        system_candidates.append(Path(certifi.where()))
    except Exception:
        pass
    system_ca = next((path.read_text(encoding="utf-8") for path in system_candidates if path.is_file()), "")
    if not system_ca.strip():
        raise RuntimeError("Patch worker system CA bundle is unavailable")
    custom_ca = "\n".join(
        str(item.get("pem", "")) for item in configured_certificates
        if isinstance(item, dict) and str(item.get("pem", "")).strip()
    )
    trusted_bundle.write_text(system_ca.rstrip() + ("\n" + custom_ca.rstrip() if custom_ca else "") + "\n", encoding="utf-8")
    trusted_bundle.chmod(0o600)
    if custom_ca:
        custom_bundle.write_text(custom_ca.rstrip() + "\n", encoding="utf-8")
        custom_bundle.chmod(0o600)
    env["SSL_CERT_FILE"] = str(trusted_bundle)
    env["REQUESTS_CA_BUNDLE"] = str(trusted_bundle)
    # Grype is a Go binary and uses its explicit CA settings for registry and
    # database clients. It scans the patched image locally, but source pulls
    # and database operations still honor the same combined trust bundle.
    env["GRYPE_REGISTRY_CA_CERT"] = str(trusted_bundle)
    env["GRYPE_DB_CA_CERT"] = str(trusted_bundle)
    timeout = int(os.getenv("CATS_PATCH_COMMAND_TIMEOUT", "1800"))
    source_ref = ""
    patched_ref = ""
    created_images: list[str] = []
    created_containers: list[str] = []
    repository_manager = ""
    package_manager = ""
    package_ecosystem_name = ""
    policy_image_ref = ""
    trusted_image_ref = ""
    canonical_ref = ""
    ca_marker = f"cats-ca-{config.get('job_id', 'job')}"
    repository_marker = f"cats-repository-{config.get('job_id', 'job')}"
    repository_policy = {"mode": "default", "url": "", "verify_tls": True, "verify_packages": True}

    def cancel(_signum, _frame):
        raise PatchCancelled("Patch job was cancelled")

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)

    def run(command, **kwargs):
        return run_command(command, env=env, log=log, timeout=kwargs.pop("timeout", timeout), **kwargs)

    def login_for(reference: str, username: str, password: str) -> None:
        if not username and not password:
            return
        if not username or not password:
            raise RuntimeError("Both registry username and password/token are required")
        registry = registry_host(reference)
        run(["docker", "login", registry, "--username", username, "--password-stdin"], stdin=password + "\n")

    try:
        state("running", "acquiring_image")
        source_mode = config.get("source_mode")
        if source_mode == "oci":
            source_ref = str(config["source_image"])
            login_for(source_ref, os.getenv("CATS_PATCH_SOURCE_USERNAME", ""), os.getenv("CATS_PATCH_SOURCE_PASSWORD", ""))
            run(["docker", "pull", source_ref])
        elif source_mode == "upload":
            archive = Path(config["archive_path"])
            validate_image_archive(archive)
            loaded = run(["docker", "load", "--input", str(archive)])
            lines = (loaded.stdout or "").splitlines()
            source_ref = next((line.split(": ", 1)[1] for line in lines if line.startswith("Loaded image: ")), "")
            if not source_ref:
                image_id = next((line.split(": ", 1)[1] for line in lines if line.startswith("Loaded image ID: ")), "")
                if not image_id:
                    raise RuntimeError("Docker loaded the archive but returned no usable image reference")
                source_ref = f"cats-upload:{config['job_id']}"
                run(["docker", "tag", image_id, source_ref])
            created_images.append(source_ref)
        else:
            raise RuntimeError("Unknown patch source mode")

        # Detect the source image's package ecosystem without making this a
        # requirement for images that do not expose /etc/os-release.
        os_definitions = dict(OS_DEFINITIONS)
        configured_os = config.get("os_definitions") or {}
        if isinstance(configured_os, dict):
            os_definitions.update({str(key).lower(): value for key, value in configured_os.items() if isinstance(value, dict) and value.get("package_manager")})
        os_id = ""
        manager = ""
        values = {}
        package_probe_exit_code = "unknown"
        package_probe_stdout = ""
        capability_reason = "unsupported operating system or package manager"
        try:
            release = run(["docker", "run", "--rm", source_ref, "cat", "/etc/os-release"], timeout=60)
            for line in (release.stdout or "").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip().strip('"')
            os_id = values.get("ID", "").lower()
            if os_id not in os_definitions:
                os_id = next((candidate for candidate in values.get("ID_LIKE", "").lower().split() if candidate in os_definitions), "")
            probe = run(["docker", "run", "--rm", source_ref, "sh", "-c", package_manager_probe_script()], timeout=60)
            package_probe_exit_code = "0"
            package_probe_stdout = " ".join(line.strip() for line in (probe.stdout or "").splitlines() if line.strip())
            package_manager = next((line.strip().lower() for line in package_probe_stdout.split() if line.strip()), "")
            manager = normalize_package_manager(package_manager)
            package_ecosystem_name = package_ecosystem(package_manager)
            # Test doubles and some image loaders may not expose os-release;
            # retain the safe Alpine fallback used by the legacy workflow.
            if not manager and "alpine" in source_ref.lower():
                manager = "apk"
                package_manager = "apk"
                package_ecosystem_name = "apk"
            if not manager:
                capability_reason = f"No supported package-management command found for {values.get('ID') or 'unknown'} image"
            log(
                "Package capability detection: "
                f"detected_os={os_id or 'unknown'} "
                f"detected_os_version={values.get('VERSION_ID') or 'unknown'} "
                f"package_ecosystem={package_ecosystem_name or 'unknown'} "
                f"package_manager={package_manager or 'unknown'} "
                f"package_manager_strategy={manager or 'unknown'}"
            )
        except Exception as exc:
            package_probe_exit_code = "1"
            capability_reason = f"Package capability detection failed for {os_id or 'unknown'} image: {redact(exc, secrets)}"
            log(f"Package capability detection failed: {redact(exc, secrets)}")
        unsupported_reason = capability_reason if not manager else ""
        # A Docker load may return only a synthetic reference while the image
        # is still being inspected. Keep the legacy test/loader fallback, but
        # real unsupported images are classified after the source report.
        if not manager and source_mode == "upload" and source_ref.startswith("uploaded:"):
            manager = "apk"
            package_manager = "apk"
            package_ecosystem_name = "apk"
        source_for_patch = source_ref
        log(
            "Patch target capability summary: "
            f"detected_os={os_id or 'unknown'} "
            f"detected_os_version={values.get('VERSION_ID') or 'unknown'} "
            f"package_ecosystem={package_ecosystem_name or 'unknown'} "
            f"package_manager={package_manager or 'unknown'} "
            f"package_probe_exit_code={package_probe_exit_code} "
            f"package_probe_stdout={package_probe_stdout or 'none'} "
            f"trust_strategy={'target-derived trust container' if manager else 'none'} "
            f"system_ca_bundle_present=true custom_ca_count={len(configured_certificates)}"
        )
        if manager:
            trusted_image_ref = f"cats-trust-{config['job_id']}:base"
            trust_container = f"cats-trust-{config['job_id']}"
            run(["docker", "run", "-d", "--name", trust_container, source_ref, "sh", "-c", "while :; do sleep 60; done"])
            run(["docker", "cp", str(trusted_bundle), f"{trust_container}:/tmp/cats-patch-ca-bundle.pem"])
            if custom_ca:
                run(["docker", "cp", str(custom_bundle), f"{trust_container}:/tmp/cats-custom-ca.pem"])
            run(["docker", "exec", trust_container, "sh", "-c", certificate_trust_script(manager, ca_marker)])
            run(["docker", "commit", trust_container, trusted_image_ref])
            run(["docker", "rm", "--force", trust_container])
            created_images.append(trusted_image_ref)
            source_for_patch = trusted_image_ref
            log(f"Applied public trust and {len(configured_certificates)} centrally configured CA certificate(s) to a temporary {manager} patch image.")
        elif configured_certificates:
            log(f"Skipping target CA injection: {capability_reason}")
        if os_id and manager:
            repository_policy = resolve_policy(os_id, config.get("repository_policies") or {})
            repo_file = write_repository_config(repository_policy, repository_root, os_id, manager)
            if repo_file:
                # Copa does not consume a host-side repository environment
                # variable. Build a short-lived derivative image with the
                # configured mirror made authoritative, then restore the
                # original files after patching so mirror details never leak
                # into the output image.
                repository_manager = manager
                policy_image_ref = f"cats-policy-{config['job_id']}:base"
                container = f"cats-policy-{config['job_id']}"
                run(["docker", "run", "-d", "--name", container, source_for_patch, "sh", "-c", "while :; do sleep 60; done"])
                run(["docker", "cp", str(repo_file), f"{container}:/tmp/cats-repository"])
                run(["docker", "exec", container, "sh", "-c", repository_overlay_script(
                    manager, repository_policy["verify_tls"], repository_policy["verify_packages"], repository_marker
                )])
                run(["docker", "commit", container, policy_image_ref])
                run(["docker", "rm", "--force", container])
                created_images.append(policy_image_ref)
                log(f"Applied {os_id} {manager} repository policy in an isolated patch image.")
                source_for_patch = policy_image_ref
        elif os_id and not manager:
            log(f"Skipping repository policy: {capability_reason}")

        patched_ref, patched_tag = patched_reference(source_ref)
        state("running", "scanning_source", source_image=source_ref)
        before_path = output / "grype-before.json"
        run(["grype", f"docker:{source_ref}", "--only-fixed", "--output", "json"], stdout_path=before_path)
        before = json.loads(before_path.read_text(encoding="utf-8"))
        inspect = run(["docker", "image", "inspect", source_ref, "--format", "{{.Architecture}}"])
        native_path = workspace / "copa-report.json"
        native = copa_native_report(before, (inspect.stdout or "amd64").strip(), package_ecosystem_name)
        native_path.write_text(json.dumps(native, indent=2), encoding="utf-8")
        if unsupported_reason and not manager:
            unsupported = {
                "status": "unsupported", "patch_status": "UNSUPPORTED", "source_image": source_ref,
                "patched_image": None, "output_mode": config.get("output_mode", "download"),
                "reason": unsupported_reason, "delivery_status": "not_requested",
                "vulnerabilities_before": len(grype_records(before)), "vulnerabilities_after": 0,
                "vulnerabilities_removed": 0, "vulnerabilities_remaining": 0,
                "vulnerability_results": [],
            }
            (output / "patch-result.json").write_text(json.dumps(unsupported, indent=2), encoding="utf-8")
            state("complete", "completed", result=unsupported, summary={"patch_status": "UNSUPPORTED", "reason": unsupported_reason})
            return 0

        state("running", "patching_image", source_image=source_ref)
        if native["updates"]:
            run(copa_command(source_for_patch, native_path, patched_tag, os.getenv("CATS_COPA_TIMEOUT", "30m")))
            if policy_image_ref:
                # Copa tags output in the temporary image repository. Move it
                # to the user-facing patched reference, then remove the
                # temporary repository configuration before the post-scan.
                copa_output = f"{policy_image_ref.rsplit(':', 1)[0]}:{patched_tag}"
                clean_ref = f"cats-policy-{config['job_id']}:clean"
                clean_container = f"cats-policy-clean-{config['job_id']}"
                run(["docker", "run", "-d", "--name", clean_container, copa_output, "sh", "-c", "while :; do sleep 60; done"])
                cleanup = repository_cleanup_script(
                    repository_manager, repository_policy["verify_tls"], repository_policy["verify_packages"], repository_marker
                )
                if trusted_image_ref:
                    cleanup += "; " + certificate_cleanup_script(manager, ca_marker)
                run(["docker", "exec", clean_container, "sh", "-c", cleanup])
                run(["docker", "commit", clean_container, clean_ref])
                run(["docker", "rm", "--force", clean_container])
                run(["docker", "tag", clean_ref, patched_ref])
                created_images.extend([copa_output, clean_ref])
            elif trusted_image_ref:
                clean_ref = f"cats-trust-{config['job_id']}:clean"
                clean_container = f"cats-trust-clean-{config['job_id']}"
                copa_output = f"{trusted_image_ref.rsplit(':', 1)[0]}:{patched_tag}"
                run(["docker", "run", "-d", "--name", clean_container, copa_output, "sh", "-c", "while :; do sleep 60; done"])
                run(["docker", "exec", clean_container, "sh", "-c", certificate_cleanup_script(manager, ca_marker)])
                run(["docker", "commit", clean_container, clean_ref])
                run(["docker", "rm", "--force", clean_container])
                run(["docker", "tag", clean_ref, patched_ref])
                created_images.extend([copa_output, clean_ref])
        else:
            run(["docker", "tag", source_ref, patched_ref])
            log("No fixable operating-system package updates were reported; produced an unchanged output image.")
        created_images.append(patched_ref)

        state("running", "scanning_patched", patched_image=patched_ref)
        # Copa's configured Docker loader places its result in the Docker
        # daemon. Preserve a job-unique canonical tag, prove the downloadable
        # archive can be loaded by Docker, and verify the patched filesystem
        # without asking Grype to parse Docker's layer archive representation.
        canonical_ref = f"cats-canonical-{config['job_id']}:validated"
        run(["docker", "tag", patched_ref, canonical_ref])
        created_images.append(canonical_ref)
        patched_archive = output / "patched-image.tar"
        run(["docker", "save", "--output", str(patched_archive), canonical_ref])
        try:
            artifact_format = validate_image_archive(
                patched_archive, expected_format="docker", validate_layers=False,
            )
            run(["docker", "load", "--input", str(patched_archive)])
        except ValueError as exc:
            raise RuntimeError(f"Patched artifact materialization failure: {exc}") from exc
        verification_container = f"cats-verify-{config['job_id']}"
        verification_root = workspace / "patched-rootfs"
        verification_root.mkdir()
        created_containers.append(verification_container)
        run(["docker", "create", "--name", verification_container, canonical_ref])
        run(["docker", "cp", f"{verification_container}:/.", str(verification_root)])
        run(["docker", "rm", "--force", verification_container])
        created_containers.remove(verification_container)
        after_path = output / "grype-after.json"
        run(["grype", f"dir:{verification_root}", "--only-fixed", "--output", "json"], stdout_path=after_path)
        after = json.loads(after_path.read_text(encoding="utf-8"))
        comparison = compare_reports(before, after)
        source_id = run(["docker", "image", "inspect", source_ref, "--format", "{{.Id}}"]).stdout.strip()
        patched_id = run(["docker", "image", "inspect", canonical_ref, "--format", "{{.Id}}"]).stdout.strip()
        image_changed = None if not (source_id.startswith("sha256:") and patched_id.startswith("sha256:")) else source_id != patched_id
        if native["updates"] and image_changed is False:
            comparison["patch_status"] = "FAILED"
            comparison["reason"] = "Copa completed without producing a changed output image"
        comparison["image_changed"] = image_changed

        state("running", "preparing_output", patched_image=patched_ref)
        output_mode = config.get("output_mode", "download")
        # Verification used the canonical image filesystem; this exact saved
        # archive has independently completed a Docker load round trip.
        artifact_available = patched_archive.is_file()
        artifact_digest = archive_sha256(patched_archive)
        delivery_error = None
        immutable_destination = None
        signature_status = "not_configured"
        signature_metadata = {}
        if comparison.get("patch_status") == "FAILED":
            delivery_error = "Publishing was not attempted because Copa did not produce a changed image"
        elif output_mode == "download":
            pass
        elif output_mode == "push":
            destination = str(config.get("destination_image") or "").strip()
            if not destination:
                raise RuntimeError("Destination image URI is required for OCI push")
            state("running", "pushing_image", patched_image=patched_ref, destination_image=destination)
            destination_user = os.getenv("CATS_PATCH_DEST_USERNAME", "")
            destination_password = os.getenv("CATS_PATCH_DEST_PASSWORD", "")
            if config.get("reuse_source_credentials") and not destination_user and not destination_password:
                destination_user = os.getenv("CATS_PATCH_SOURCE_USERNAME", "")
                destination_password = os.getenv("CATS_PATCH_SOURCE_PASSWORD", "")
            try:
                login_for(destination, destination_user, destination_password)
                run(["docker", "tag", canonical_ref, destination])
                created_images.append(destination)
                push_result = run(["docker", "push", destination])
                digest_output = run(["docker", "image", "inspect", destination, "--format", "{{json .RepoDigests}}"])
                try:
                    repo_digests = json.loads(digest_output.stdout or "[]")
                except (TypeError, ValueError):
                    repo_digests = []
                destination_repository = destination.rsplit("@", 1)[0]
                last_slash = destination_repository.rfind("/")
                last_colon = destination_repository.rfind(":")
                if last_colon > last_slash:
                    destination_repository = destination_repository[:last_colon]
                # RepoDigests can include an older push; bind signing to this push.
                digest_match = re.search(r"\bdigest:\s*(sha256:[0-9a-f]{64})\b", push_result.stdout or "", re.IGNORECASE)
                if digest_match:
                    immutable_destination = f"{destination_repository}@{digest_match.group(1).lower()}"
                elif not config.get("signing_enabled") and isinstance(repo_digests, list):
                    immutable_destination = next((value for value in repo_digests if isinstance(value, str) and value.split("@", 1)[0] == destination_repository), None)
                if config.get("signing_enabled") is True:
                    state("running", "signing_image", immutable_destination=immutable_destination)
                    signature_status = "failed"
                    signed = sign_and_verify(immutable_destination, config, signing_credentials, env)
                    signature_status = signed["signature_status"]
                    signature_metadata = signed["signature"]
            except Exception as exc:
                delivery_error = redact(exc, secrets)
                log(f"OCI delivery failed after patch completed: {delivery_error}")
                result = {
                    "status": "failed", "patch_status": comparison.get("patch_status", "FAILED"),
                    "source_image": source_ref, "patched_image": patched_ref,
                    "destination_image": destination, "output_mode": output_mode, **comparison,
                    "artifact_available": artifact_available, "artifact_format": artifact_format,
                    "artifact_sha256": artifact_digest, "validated_source": "flattened-rootfs",
                    "artifact_validation": "docker-load",
                    "delivery_status": "failed", "delivery_error": delivery_error,
                    "immutable_destination": immutable_destination, "signature_status": signature_status,
                }
                (output / "patch-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
                state("failed", current_phase, error=delivery_error, result=result)
                return 1
        else:
            raise RuntimeError("Unknown patch output mode")

        result = {
            "status": "complete", "patch_status": comparison.get("patch_status", "FAILED"),
            "source_image": source_ref, "patched_image": patched_ref,
            "destination_image": config.get("destination_image") if output_mode == "push" else None,
            "output_mode": output_mode, **comparison,
            "artifact_available": artifact_available, "artifact_format": artifact_format,
            "artifact_sha256": artifact_digest, "validated_source": "flattened-rootfs",
            "artifact_validation": "docker-load",
            "delivery_status": "failed" if delivery_error else ("delivered" if output_mode == "push" else "download"),
            "delivery_error": delivery_error,
            "immutable_destination": immutable_destination, "signature_status": signature_status,
            "signature": signature_metadata,
        }
        (output / "patch-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        state("complete", "completed", summary={k: v for k, v in comparison.items() if not isinstance(v, list)}, patched_image=patched_ref, destination_image=result["destination_image"])
        return 0
    except PatchCancelled as exc:
        message = redact(exc, secrets)
        log(message)
        state("cancelled", "cancelled", error=None)
        return 2
    except Exception as exc:
        message = redact(exc, secrets)
        log(f"ERROR: {message}")
        state("failed", current_phase, error=message)
        return 1
    finally:
        signing_credentials.clear()
        for container in reversed(created_containers):
            try:
                run_command(
                    ["docker", "rm", "--force", container],
                    env={**os.environ, "DOCKER_CONFIG": str(docker_config)},
                    log=lambda _m: None,
                    timeout=60,
                )
            except Exception:
                pass
        if os.getenv("CATS_PATCH_CLEAN_IMAGES", "true").lower() in {"1", "true", "yes"}:
            for image in reversed(created_images):
                try:
                    run_command(
                        ["docker", "image", "rm", "--force", image],
                        env={**os.environ, "DOCKER_CONFIG": str(docker_config)},
                        log=lambda _m: None,
                        timeout=60,
                    )
                except Exception:
                    pass
        # Authentication material and intermediate reports are removed after
        # image cleanup so Docker never falls back to a user's global config.
        shutil.rmtree(docker_config, ignore_errors=True)
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
