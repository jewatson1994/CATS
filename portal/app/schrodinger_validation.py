"""Artifact adapters for one independently executed Kind validation pipeline."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import os
import re
import tempfile
import shutil
from urllib.parse import urlsplit

from .deployment_validation import ValidationArtifact, ValidationConfig, KindDeploymentValidator, _default_runner, _command_environment
from .helm_archives import extract_chart
from .validator_protocol import REQUEST_SCHEMA_VERSION, validate_request, source_digest


class SchrodingerValidator:
    def __init__(self, config=None, runner=None, *, trusted_ca_certificates=(), oci_registry_config=None, allowed_registries=None, oci_ca_file=None):
        self.config = config or ValidationConfig.from_env()
        self.runner = runner or _default_runner
        self.trusted_ca_certificates = trusted_ca_certificates
        self.oci_registry_config = oci_registry_config or os.getenv("CATS_VALIDATOR_OCI_REGISTRY_CONFIG", "")
        self.oci_ca_file = oci_ca_file or os.getenv("CATS_VALIDATOR_OCI_CA_FILE") or os.getenv("SSL_CERT_FILE", "")
        self.allowed_registries = set(allowed_registries if allowed_registries is not None else os.getenv("CATS_VALIDATOR_OCI_ALLOWED_REGISTRIES", "").split(","))

    def validate(self, request, *, artifact_path=None, source_files=None, values_files=(), declared_resources=(), job_id="job", progress_callback=None):
        validate_request(request)
        kind = request["validation_type"]
        if self.config.workspace_root:
            Path(self.config.workspace_root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=f"cats-schrodinger-{job_id}-", dir=self.config.workspace_root or None) as temporary:
            root = Path(temporary)
            dependencies_verified = None
            artifact = ValidationArtifact(source_files=source_files or {}, values_files=values_files,
                declared_resources=declared_resources, job_id=job_id, reference=request["artifact"]["reference"],
                trusted_ca_certificates=self.trusted_ca_certificates, require_helm_lifecycle=True, namespace=request["deployment"].get("namespace"))
            try:
                if kind == "helm-chart":
                    if artifact_path is not None:
                        from .deployment_bundle import prepare_helm_archive
                        prepared = prepare_helm_archive(Path(artifact_path), root / "helm", expected_digest=request["artifact"]["digest"])
                        if prepared["manifest"]["service"] != request["service"]:
                            raise ValueError("Helm service/version differs from request")
                        artifact = replace(artifact, prepared_directory=str(prepared["root_directory"]), chart_path=Path(prepared["chart_directory"]).relative_to(prepared["root_directory"]).as_posix(), values_files=[Path(value).relative_to(prepared["root_directory"]).as_posix() if Path(value).is_absolute() else value for value in prepared["values_files"]])
                    elif source_files is None or source_digest(source_files) != request["artifact"]["digest"]:
                        raise ValueError("Helm source digest does not match the validation request")
                elif kind == "oci":
                    chart_root = self._resolve_oci(request, root)
                    artifact = replace(artifact, prepared_directory=str(chart_root))
                else:
                    from .deployment_bundle import validate_bundle
                    if artifact_path is None:
                        raise ValueError("Bundle validation requires a streamed artifact file")
                    bundle_root = root / "bundle"
                    manifest = validate_bundle(Path(artifact_path), destination=bundle_root, expected_digest=request["artifact"]["digest"], expected_type=kind)
                    if manifest["service"] != request["service"]:
                        raise ValueError("Bundle service/version differs from request")
                    bundle_namespace = manifest["deployment"].get("namespace")
                    requested_namespace = request["deployment"].get("namespace")
                    if requested_namespace is not None and bundle_namespace is not None and requested_namespace != bundle_namespace:
                        raise ValueError("Bundle namespace differs from request")
                    artifact = replace(artifact, namespace=requested_namespace or bundle_namespace)
                    chart_path = manifest["deployment"]["chartPath"]
                    chart_root = root / "deployment"
                    target_chart = chart_root / chart_path
                    target_chart.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(bundle_root / chart_path, target_chart)
                    for value in manifest["deployment"].get("valuesFiles", ()):
                        target = chart_root / value
                        if not target.exists():
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(bundle_root / value, target)
                    artifact = replace(artifact, prepared_directory=str(chart_root),
                        chart_path=chart_path,
                        values_files=manifest["deployment"].get("valuesFiles", ()),
                        image_archives={item["reference"]: str(bundle_root / item["file"]) for item in manifest.get("images", ())},
                        offline=kind == "offline-bundle", expected_images=manifest.get("requiredImages", ()))
                    dependencies_verified = all(item.get("vendored") is True for item in manifest["helmDependencies"])
                config = replace(self.config, strict_sandbox_policy=True, allow_network_egress=False, require_local_images=True) if artifact.offline else self.config
                evidence = KindDeploymentValidator(config, self.runner).validate_artifact(artifact, progress_callback)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                evidence = {"status": "COULD_NOT_VALIDATE", "reason_category": "ARTIFACT_INTEGRITY_FAILURE", "reason": str(exc), "cleanup_status": "NOT_REQUIRED", "helm_result": {"install": "NOT_ATTEMPTED"}}
            return self._result(request, evidence, dependencies_verified)

    def _resolve_oci(self, request, root):
        reference = request["artifact"]["reference"]
        parsed = urlsplit(reference)
        if parsed.netloc not in self.allowed_registries or parsed.username or parsed.password or parsed.query or parsed.fragment or not re.fullmatch(r"/[A-Za-z0-9._/@:-]+", parsed.path):
            raise ValueError("OCI registry is not an explicitly configured trusted destination")
        env = _command_environment()
        if self.oci_registry_config:
            if not Path(self.oci_registry_config).is_file():
                raise ValueError("Configured OCI credentials are unavailable")
            env["HELM_REGISTRY_CONFIG"] = self.oci_registry_config
        from .trusted_ca import additional_pem
        configured_pem = additional_pem(self.trusted_ca_certificates)
        ca = Path(self.oci_ca_file)
        if configured_pem:
            ca = root / "oci-ca.pem"
            ca.write_text(configured_pem, encoding="utf-8")
        if not ca.is_file() or ca.is_symlink():
            raise ValueError("OCI resolution requires an explicitly configured registry CA bundle")
        command = [self.config.helm_binary, "pull", reference, "--destination", str(root)]
        command.extend(["--ca-file", str(ca)])
        env["SSL_CERT_FILE"] = str(ca)
        completed = self.runner(command, timeout=self.config.install_timeout_seconds, env=env)
        if completed.returncode:
            raise ValueError("Immutable OCI chart resolution failed (registry authentication, trust or availability)")
        reported = re.search(r"(?im)^Digest:\s*(sha256:[0-9a-f]{64})\s*$", completed.stdout + "\n" + completed.stderr)
        if not reported or reported.group(1) != request["artifact"]["digest"]:
            raise ValueError("OCI resolver did not confirm the requested immutable digest")
        archives = list(root.glob("*.tgz"))
        if len(archives) != 1:
            raise ValueError("OCI resolution did not produce exactly one chart")
        charts = root / "charts"
        with archives[0].open("rb") as source:
            extract_chart(source, archives[0].name, charts)
        return charts

    @staticmethod
    def _result(request, evidence, dependencies_verified):
        helm = evidence.get("helm_result", {})
        offline = evidence.get("offline", {})
        verified = evidence.get("status") == "VERIFIED"
        result = dict(evidence)
        if verified and (helm.get("install") != "PASS" or helm.get("release_status") != "DEPLOYED" or helm.get("execution_mode") == "PREFLIGHTED_MANIFEST_APPLY"):
            verified = False
            result["status"] = result["classification"] = "NOT_VERIFIED"
            result["reason"] = "An actual successful Helm release lifecycle is required."
        result.update(schema_version=REQUEST_SCHEMA_VERSION, request_id=request["request_id"], artifact_reference=request["artifact"]["reference"], validator="CATSchrodinger", environment="kind",
            validation_type=request["validation_type"], service=request["service"], artifact=request["artifact"],
            deployment={"type": "helm", "status": helm.get("install", "NOT_ATTEMPTED")},
            helm={"status": helm.get("install", "NOT_ATTEMPTED"), "dependencies_vendored": dependencies_verified},
            artifact_digest=request["artifact"]["digest"],
            network={"isolated": offline.get("network_isolated"), "external_chart_fetches": offline.get("external_chart_fetches"), "external_image_pulls": offline.get("external_image_pulls")},
            offlineVerified=False)
        if request["validation_type"] == "offline-bundle":
            result["images"] = {"required": offline.get("required_images"), "provided": offline.get("provided_images"), "loaded": offline.get("loaded_images")}
            complete = (verified and dependencies_verified is True and helm.get("install") == "PASS"
                and offline.get("network_isolated") is True and offline.get("external_chart_fetches") == 0
                and offline.get("external_image_pulls") == 0 and offline.get("required_images") is not None
                and set(offline.get("required_images", ())) == set(offline.get("loaded_images", ())))
            result["offlineVerified"] = complete
            if verified and not complete:
                result["status"] = result["classification"] = "PARTIALLY_VERIFIED"
                result["reason"] = "Runtime passed, but offline inventory, image loading, network isolation or retrieval checks did not all pass."
        return result
