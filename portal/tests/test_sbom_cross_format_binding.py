"""Cross-format comparisons preserve identity without promoting scanner labels."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from app.container_intelligence import observation_identities
from app.sbom_components import _assess


DIGEST = "sha256:" + "a" * 64
DOCUMENT = "sha256:" + "b" * 64
CPE = "cpe:2.3:a:libssl3:libssl3:3.0.2-0ubuntu1.26:*:*:*:*:*:*:*"


def records(package_type="deb", scanner_type=None, retained_type="dpkg-db-entry",
            scanner_name="ubuntu", distro_id="ubuntu", version="22.04",
            display_name="Ubuntu", display_version="22.04.5 LTS (Jammy Jellyfish)"):
    purl = f"pkg:{package_type}/{scanner_name}/libssl3@3.0.2-0ubuntu1.26?arch=amd64&distro={distro_id}-{version}&upstream=openssl"
    artifact = {"id": "component-one", "name": "libssl3", "version": "3.0.2-0ubuntu1.26",
        "type": package_type, "purl": purl,
        "metadataType": retained_type, "foundBy": retained_type.replace("-entry", "-cataloger"),
        "locations": [{"path": "/var/lib/dpkg/status", "annotations": {"evidence": "primary"}}],
        "metadata": {"package": "libssl3", "name": "libssl3", "version": "3.0.2-0ubuntu1.26",
            "architecture": "amd64", "source": "openssl", "sourceVersion": "", "epoch": None,
            "sourceRpm": "openssl.src.rpm", "release": "1", "vendor": "vendor", "modularityLabel": ""},
        "cpes": [{"cpe": CPE, "source": "syft-generated"}]}
    scanner = deepcopy(artifact)
    scanner["cpes"] = [CPE]
    if scanner_type:
        scanner["metadataType"] = scanner_type
    else:
        scanner.pop("metadataType")
    distro = {"id": distro_id, "name": display_name, "versionID": version, "version": display_version}
    observation = SimpleNamespace(execution_id=1, image="registry.example/app:1", image_digest=DIGEST,
        package=artifact["name"], installed_version=artifact["version"], evidence={
            "component_id": artifact["id"], "sbom_digest": DOCUMENT, "image_platform": "linux/amd64",
            "scanner_artifact": scanner, "scanner_distro": {"name": scanner_name, "version": version}})
    component = {"component_id": artifact["id"], "name": artifact["name"], "version": artifact["version"],
        "purl": artifact["purl"], "image": observation.image, "image_manifest_digest": DIGEST,
        "image_platform": "linux/amd64", "sbom_digest": DOCUMENT,
        "sbom_artifact": json.dumps(artifact), "sbom_distro": json.dumps(distro)}
    return observation, component


def assess(observation, component):
    return _assess(observation, [(10, component)], "component-one", "component_id")


@pytest.mark.parametrize("changes", [
    {},
    {"scanner_name": "debian", "distro_id": "debian", "version": "12",
        "display_name": "Debian GNU/Linux", "display_version": "12 (bookworm)"},
    {"package_type": "apk", "scanner_type": "ApkMetadata", "retained_type": "apk-db-entry",
        "scanner_name": "alpine", "distro_id": "alpine", "version": "3.20.0", "display_name": "Alpine Linux"},
    {"package_type": "rpm", "scanner_type": "RpmMetadata", "retained_type": "rpm-db-entry",
        "scanner_name": "redhat", "distro_id": "rhel", "version": "9.6",
        "display_name": "Red Hat Enterprise Linux", "display_version": "9.6 (Plow)"},
    {"package_type": "rpm", "scanner_type": "RpmMetadata", "retained_type": "rpm-db-entry",
        "scanner_name": "sles", "distro_id": "sles", "version": "15.6",
        "display_name": "SLES", "display_version": "15-SP6"},
    {"package_type": "go-module", "scanner_type": "GolangBinMetadata",
        "retained_type": "go-module-buildinfo-entry"},
])
def test_real_scanner_representation_differences_preserve_originals(changes):
    observation, component = records(**changes)
    before = deepcopy(observation.evidence)
    result = assess(observation, component)
    assert result["status"] == "matched"
    assert result["evidence"]["sbom_artifact"] == json.loads(component["sbom_artifact"])
    assert result["evidence"]["sbom_distro"] == json.loads(component["sbom_distro"])
    assert observation.evidence == before


@pytest.mark.parametrize("field", ["id", "name", "version", "purl", "type", "foundBy"])
def test_cross_format_package_identity_and_authority_conflicts_fail_closed(field):
    observation, component = records()
    observation.evidence["scanner_artifact"][field] = "contradiction"
    assert assess(observation, component)["status"] == "conflict"


@pytest.mark.parametrize("field,value", [
    ("package", "other"), ("name", "other"), ("version", "other"), ("architecture", "arm64"),
    ("source", "other"), ("source", ""), ("source", None), ("sourceVersion", "other"),
    ("sourceRpm", "other.src.rpm"), ("epoch", 1), ("release", "other"),
    ("vendor", "other"), ("modularityLabel", "other"),
])
@pytest.mark.parametrize("original_field", ["scanner_artifact", "sbom_artifact"])
def test_metadata_conflicts_include_explicit_empty_and_null_claims(original_field, field, value):
    observation, component = records()
    observation.evidence[original_field] = json.loads(component["sbom_artifact"])
    observation.evidence[original_field]["metadata"][field] = value
    result = assess(observation, component)
    assert result["status"] == "conflict" and result["reasons"] == ["sbom_scanner_metadata_conflict"]


@pytest.mark.parametrize("field", ["id", "versionID", "versionCodename", "cpeName", "variantID"])
def test_stable_distro_claims_cannot_disagree(field):
    observation, component = records()
    distro = json.loads(component["sbom_distro"])
    distro[field] = "retained-value"
    component["sbom_distro"] = json.dumps(distro)
    observation.evidence["scanner_distro"][field] = "different-value"
    assert assess(observation, component)["status"] == "conflict"


@pytest.mark.parametrize("scanner_name,retained_id", [
    ("alpine", "wolfi"), ("sles", "rhel"), ("debian", "ubuntu"),
    ("Ubuntu", "ubuntu"), ("rhel", "redhat"), ("redhat", "fedora"),
])
def test_scanner_namespaces_do_not_gain_unverified_distro_aliases(scanner_name, retained_id):
    observation, component = records(scanner_name=scanner_name, distro_id=retained_id)
    assert assess(observation, component)["status"] == "conflict"


def test_explicit_scanner_distro_id_takes_precedence_over_display_name():
    observation, component = records()
    observation.evidence["scanner_distro"] = {'id': 'ubuntu', 'name': 'Ubuntu', 'versionID': '22.04'}
    assert assess(observation, component)["status"] == "matched"


def test_scanner_release_and_codename_aliases_are_compared_exactly():
    observation, component = records()
    observation.evidence["scanner_distro"]["version"] = "24.04"
    assert assess(observation, component)["status"] == "conflict"
    observation.evidence["scanner_distro"] = {"codename": "noble"}
    distro = json.loads(component["sbom_distro"])
    distro["versionCodename"] = "jammy"
    component["sbom_distro"] = json.dumps(distro)
    assert assess(observation, component)["status"] == "conflict"


@pytest.mark.parametrize("evidence_field,field,value", [
    ("scanner_artifact", "metadataType", "unverified-type"),
    ("scanner_artifact", "metadataType", {"type": "rpm-db-entry"}),
    ("scanner_artifact", "metadataType", ["rpm-db-entry"]),
    ("scanner_artifact", "metadata", "invalid-metadata"),
    ("scanner_artifact", "cpes", ["different-cpe"]),
    ("sbom_artifact", "cpes", [CPE]),
    ("sbom_distro", "name", "different display name"),
])
def test_unknown_authority_or_same_source_changes_still_conflict(evidence_field, field, value):
    observation, component = records()
    if evidence_field.startswith("sbom_"):
        observation.evidence[evidence_field] = json.loads(component[evidence_field])
    observation.evidence[evidence_field][field] = value
    assert assess(observation, component)["status"] == "conflict"


@pytest.mark.parametrize("location", ["metadata", "target"])
@pytest.mark.parametrize("field,value", [("os", "windows"), ("architecture", "arm64"), ("variant", "v8")])
def test_present_scanner_source_platform_claims_must_match(location, field, value):
    observation, component = records()
    observation.evidence["scanner_source"] = {location: {"manifestDigest": DIGEST, field: value}}
    assert assess(observation, component)["reasons"] == ["sbom_platform_conflict"]


def test_adapter_does_not_replace_nested_empty_or_null_evidence(monkeypatch):
    from app import sbom_components
    observation, component = records()
    observation.evidence["sbom_artifact"] = {"metadata": {"source": "", "sourceVersion": None, "epoch": None}}
    original = deepcopy(observation.evidence)
    # Even if a lookup implementation returns a conflicting projection, the
    # adapter may add absent keys but cannot rewrite an existing raw claim.
    monkeypatch.setattr(sbom_components, "recover_identities", lambda db, rows: [{
        "status": "matched", "reasons": [], "component_id": 10,
        "evidence": {"purl": component["purl"], "sbom_artifact": {
            "metadata": {"source": "openssl", "sourceVersion": "3", "epoch": 1, "architecture": "amd64"}}}}])
    identity = observation_identities(None, [observation])[0]
    assert identity["sbom_artifact"]["metadata"] == {
        "source": "", "sourceVersion": None, "epoch": None, "architecture": "amd64"}
    assert identity["scanner_identity"]["sbom_artifact"] == original["sbom_artifact"]
    assert observation.evidence == original
