"""The real-registry helper must retain every signed attachment before discovery."""
import copy

import pytest

from app import cyber_release_publication as publication, release_oci
from nginx_replica_acceptance import copy_receipt


def receipt():
    def item(name, value):
        digest = "sha256:" + value * 64
        return {"reference": "publisher.test:5000/approved/" + name + "@" + digest,
                "digest": digest, "tag": "cats-release-1"}
    image = item("nginx", "a")
    image["signature"] = {"digest": "sha256:" + "b" * 64,
                          "retention_tag": "cats-signature-" + "b" * 64}
    image["attestation"] = {"digest": "sha256:" + "c" * 64,
                            "retention_tag": "cats-attestation-" + "c" * 64}
    return {"status": "published", "verification_status": "verified",
            "signature_status": "verified", "artifacts": [image],
            "release": item("releases", "d"), "manifest": {"portable": {}}}


def test_attachment_graphs_and_retention_precede_discovery(tmp_path, monkeypatch):
    events = []

    class Transport:
        def __init__(self, *args):
            pass

        def graph(self, source, digest, target):
            events.append(("graph", digest))
            return {"digest": digest}

        def tag(self, target, descriptor, tag):
            events.append(("tag", descriptor["digest"], tag))

    monkeypatch.setattr(publication, "_Transport", Transport)
    monkeypatch.setattr(release_oci, "_Client", lambda *args: object())
    value = receipt()
    copy_receipt(value, tmp_path, {}, "publisher.test:5000", "replica.test:5000")
    for kind in ("signature", "attestation"):
        attachment = value["artifacts"][0][kind]
        assert ("graph", attachment["digest"]) in events
        assert ("tag", attachment["digest"], attachment["retention_tag"]) in events
    assert events[-1] == ("tag", value["release"]["digest"], "cats-release-1")


@pytest.mark.parametrize("attachment", [None, {}, {"digest": "sha256:invalid"},
    {"digest": "sha256:" + "c" * 64, "retention_tag": "../../invalid"}])
def test_malformed_attestation_rejected_before_any_registry_write(tmp_path, monkeypatch, attachment):
    value = copy.deepcopy(receipt())
    value["artifacts"][0]["attestation"] = attachment
    monkeypatch.setattr(publication, "_Transport", lambda *args: pytest.fail("Unexpected registry write"))
    with pytest.raises(ValueError):
        copy_receipt(value, tmp_path, {}, "publisher.test:5000", "replica.test:5000")
