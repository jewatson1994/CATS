import copy
import pytest

from app.validator_protocol import REQUEST_SCHEMA_VERSION, validate_request, source_digest
from app.schrodinger_validation import SchrodingerValidator
from app.deployment_validation import ValidationConfig


def request(kind="helm-chart"):
    digest = "sha256:" + "a" * 64
    return {"schema_version": REQUEST_SCHEMA_VERSION, "request_id": "1" * 32, "validation_type": kind,
        "service": {"id": "test-service", "version": "1.2.3"},
        "artifact": {"reference": "oci://registry.test/chart@" + digest if kind == "oci" else "candidate.zip", "digest": digest},
        "deployment": {"type": "helm"}}


@pytest.mark.parametrize("kind", ["helm-chart", "oci", "standard-bundle", "offline-bundle"])
def test_explicit_request_types(kind):
    assert validate_request(request(kind))["validation_type"] == kind


@pytest.mark.parametrize("mutation", [lambda r: r.update(validation_type="zip"), lambda r: r["artifact"].update(digest="bad"), lambda r: r["service"].update(version=""), lambda r: r["deployment"].update(type="shell")])
def test_request_rejects_ambiguous_identity(mutation):
    value = request()
    mutation(value)
    with pytest.raises(ValueError):
        validate_request(value)


def test_source_identity_is_stable_and_failure_never_executes_runtime():
    assert source_digest({"b": "2", "a": "1"}) == source_digest({"a": "1", "b": "2"})
    def forbidden(*args, **kwargs):
        pytest.fail("Digest mismatch must never reach runtime")
    result = SchrodingerValidator(runner=forbidden).validate(request(), source_files={"Chart.yaml": "name: test"})
    assert result["status"] == "COULD_NOT_VALIDATE"
    assert result["artifact_digest"] == request()["artifact"]["digest"]


def test_prepared_helm_service_version_mismatch_never_executes_runtime(tmp_path):
    from app.deployment_bundle import build_helm_archive, file_digest
    archive = tmp_path / "prepared.zip"
    build_helm_archive(archive, {"Chart.yaml": "apiVersion: v2\nname: local\nversion: 1.0.0\n"},
        service={"id": "test-service", "version": "previous-version"})
    declaration = request()
    declaration["artifact"]["digest"] = file_digest(archive)
    def forbidden(*args, **kwargs):
        pytest.fail("Service/version mismatch must not reach runtime")
    result = SchrodingerValidator(runner=forbidden).validate(declaration, artifact_path=archive)
    assert result["status"] == "COULD_NOT_VALIDATE"
    assert "service/version" in result["reason"]


def test_offline_verified_requires_every_measured_check():
    evidence = {"status": "VERIFIED", "helm_result": {"install": "PASS", "release_status": "DEPLOYED"}, "offline": {
        "network_isolated": True, "external_chart_fetches": 0, "external_image_pulls": 0,
        "required_images": ["local/app:1"], "loaded_images": ["local/app:1"]}}
    assert SchrodingerValidator._result(request("offline-bundle"), evidence, True)["offlineVerified"] is True
    for field in ("network_isolated", "external_chart_fetches", "external_image_pulls", "loaded_images"):
        changed = copy.deepcopy(evidence)
        changed["offline"][field] = None if field != "loaded_images" else []
        result = SchrodingerValidator._result(request("offline-bundle"), changed, True)
        assert result["offlineVerified"] is False
        assert result["status"] == "PARTIALLY_VERIFIED"
    changed = copy.deepcopy(evidence)
    changed["offline"]["external_image_pulls"] = 1
    assert SchrodingerValidator._result(request("offline-bundle"), changed, True)["offlineVerified"] is False


def test_oci_trust_and_destination_fail_closed(tmp_path):
    validator = SchrodingerValidator(allowed_registries=["registry.test"])
    result = validator.validate(request("oci"))
    assert result["status"] == "COULD_NOT_VALIDATE"
    assert "configured registry CA" in result["reason"]
    validator = SchrodingerValidator(allowed_registries=[])
    assert "trusted destination" in validator.validate(request("oci"))["reason"]

@pytest.mark.parametrize("field,value", [("request_id", None), ("request_id", "bad"), ("schema_version", "cats.validation/v1")])
def test_request_requires_versioned_unique_identity(field, value):
    declaration = request()
    declaration[field] = value
    with pytest.raises(ValueError):
        validate_request(declaration)


def test_mutable_oci_reference_is_rejected():
    declaration = request("oci")
    declaration["artifact"]["reference"] = "oci://registry.test/chart:latest"
    with pytest.raises(ValueError):
        validate_request(declaration)


@pytest.mark.parametrize("kind", ["helm-chart", "standard-bundle", "offline-bundle"])
def test_adapters_preserve_values_namespace_and_dispatch_common_runtime(tmp_path, monkeypatch, kind):
    from pathlib import Path
    from app.deployment_bundle import build_bundle, file_digest
    import app.schrodinger_validation as core
    archive = tmp_path / "prepared.zip"
    build_bundle(archive, bundle_type=kind, service=request()["service"],
        source_files={"chart/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\n", "first.yaml": "value: first", "second.yaml": "value: second"},
        chart_path="chart", values_files=["first.yaml", "second.yaml"], rendered_manifests="", namespace="acceptance")
    declaration = request(kind)
    declaration["artifact"]["digest"] = file_digest(archive)
    declaration["deployment"]["namespace"] = "acceptance"
    seen = []
    def runtime(self, artifact, callback):
        seen.append(artifact)
        assert artifact.require_helm_lifecycle is True
        assert artifact.namespace == "acceptance"
        assert list(artifact.values_files) == ["first.yaml", "second.yaml"]
        assert (Path(artifact.prepared_directory) / "second.yaml").read_text() == "value: second"
        return {"status": "VERIFIED", "helm_result": {"install": "PASS", "release_status": "DEPLOYED"}, "cleanup_status": "COMPLETE"}
    monkeypatch.setattr(core.KindDeploymentValidator, "validate_artifact", runtime)
    result = core.SchrodingerValidator().validate(declaration, artifact_path=archive)
    assert len(seen) == 1
    assert result["request_id"] == declaration["request_id"]
    assert result["artifact"] == declaration["artifact"]
    assert not Path(seen[0].prepared_directory).exists()
    assert result["offlineVerified"] is False


@pytest.mark.parametrize("helm", [{"install": "FAIL"}, {"install": "PASS", "release_status": "UNKNOWN"}, {"install": "PASS", "release_status": "DEPLOYED", "execution_mode": "PREFLIGHTED_MANIFEST_APPLY"}])
def test_verified_requires_actual_successful_helm_release(helm):
    result = SchrodingerValidator._result(request(), {"status": "VERIFIED", "helm_result": helm}, None)
    assert result["status"] == "NOT_VERIFIED"
    assert result["network"]["isolated"] is None
    assert result["offlineVerified"] is False
