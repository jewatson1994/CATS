"""Check operator-facing repositories against the bytes and tags written by the worker."""
import json

import pytest

from app import cyber_release_publication as publication, release_oci, signing
from test_cyber_release_publication import environment, publish


def freeze_snapshot(env):
    env.approval.snapshot_digest = release_oci._digest(publication.canonical(env.approval.snapshot))


def content_tags(env, artifact):
    host, repository, digest = release_oci._reference(artifact["reference"])
    manifests = env.stores[host, repository]["manifests"]
    assert release_oci._digest(manifests[digest]) == digest == artifact["digest"]
    return {key for key, content in manifests.items() if key != digest and content == manifests[digest]}


@pytest.mark.parametrize("namespace", ["", "cyber-approved"])
def test_named_repositories_and_release_tags(environment, namespace):
    env = environment
    env.destination["namespace"] = namespace
    snapshot = env.approval.snapshot
    image, chart = snapshot["artifacts"]
    images = []
    for name in ("node", "redis"):
        env.stores["source.example", "library/" + name] = env.source.data
        images.append({**image, "reference": f"source.example/library/{name}@{image['digest']}"})
    snapshot["artifacts"] = [*images, chart]
    freeze_snapshot(env)

    receipt = publish(env, [])
    prefix = "approved.example/cyber-approved/demo/"
    artifacts = receipt["artifacts"]
    for artifact, name in zip(artifacts, ("node", "redis", "charts/sample"), strict=True):
        assert artifact["reference"] == prefix + name + "@" + artifact["digest"]
    release = receipt["release"]
    assert release["reference"] == f"{prefix}releases/{env.approval.release_key}@{release['digest']}"
    assert all(artifact["digest"] == image["digest"] for artifact in artifacts[:2])
    node_tags, redis_tags = (content_tags(env, artifact) for artifact in artifacts[:2])
    assert node_tags and redis_tags and node_tags.isdisjoint(redis_tags)
    assert artifacts[0]["tag"] in node_tags and artifacts[1]["tag"] in redis_tags


def test_same_image_name_from_different_sources_keeps_both_approved_digests(environment):
    env = environment
    env.destination["namespace"] = "cyber-approved"
    original = env.approval.snapshot["artifacts"][0]
    other_source = env.Registry("mirror.example", "another/app")
    other_source.data["blobs"].update(env.source.data["blobs"])
    source_manifest = json.loads(env.source.data["manifests"][original["digest"]])
    source_manifest["annotations"] = {"org.opencontainers.image.version": "other"}
    content = publication.canonical(source_manifest)
    digest = release_oci._digest(content)
    other_source.data["manifests"][digest] = content
    other = {"kind": "image", "digest": digest, "reference": "mirror.example/another/app@" + digest}
    env.approval.snapshot["artifacts"] = [original, other]
    freeze_snapshot(env)

    first, second = publish(env, [])["artifacts"]
    repo = "approved.example/cyber-approved/demo/app@"
    assert first["reference"] == repo + original["digest"]
    assert second["reference"] == repo + digest
    assert first["tag"] in content_tags(env, first)
    assert second["tag"] in content_tags(env, second)
    assert first["tag"] != second["tag"]


def test_registry_chart_without_display_name_uses_its_source_repository(environment):
    env = environment
    image = env.approval.snapshot["artifacts"][0]
    env.stores["source.example", "helm/sample"] = env.source.data
    env.approval.snapshot["artifacts"] = [{"kind": "chart", "digest": image["digest"],
        "reference": "source.example/helm/sample@" + image["digest"]}]
    freeze_snapshot(env)

    artifact, = publish(env, [])["artifacts"]
    assert artifact["reference"] == "approved.example/team/demo/charts/sample@" + image["digest"]


def test_unsafe_service_id_uses_one_distinct_registry_segment(environment):
    env = environment
    env.destination["namespace"] = "cyber-approved"
    env.approval.snapshot["artifacts"] = env.approval.snapshot["artifacts"][:1]

    def segment(service_key, service_id):
        env.approval.id = env.approval.service_id = service_id
        env.approval.release_key = f"approval-{service_id}"
        env.approval.snapshot.update(service_key=service_key, service_id=service_id)
        freeze_snapshot(env)
        artifact, = publish(env, [])["artifacts"]
        _, repo, _ = release_oci._reference(artifact["reference"])
        project, service, image = repo.split("/")
        assert (project, image) == ("cyber-approved", "app")
        return service

    unsafe = segment("Demo/../Blue", 12)
    assert unsafe != segment("demo-blue", 13)
    assert unsafe != segment(unsafe, 14)


def test_two_approvals_retain_their_tags_and_signatures_for_one_digest(environment, monkeypatch):
    env = environment
    env.destination["namespace"] = "cyber-approved"
    env.approval.snapshot["artifacts"] = env.approval.snapshot["artifacts"][:1]
    freeze_snapshot(env)

    # Cosign 2 appends a signature layer to the existing per-digest manifest.
    # The shared fixture creates a real signed layer but models only one signer.
    sign = signing.sign_and_verify

    def append_signature(reference, config, credentials, environ):
        host, repo, digest = release_oci._reference(reference)
        client = env.Registry(host, repo)
        tag = "sha256-" + digest[7:] + ".sig"
        previous = client.data["manifests"].get(tag)
        result = sign(reference, config, credentials, environ)
        if previous:
            signature = json.loads(client.data["manifests"][tag])
            signature["layers"] = json.loads(previous)["layers"] + signature["layers"]
            client.request("PUT", client.api + "/manifests/" + tag, body=publication.canonical(signature))
        return result

    monkeypatch.setattr(signing, "sign_and_verify", append_signature)
    first_key = env.approval.release_key
    first, = publish(env, [])["artifacts"]
    first_tags = content_tags(env, first)
    assert first_tags
    env.approval.id += 1
    env.approval.release_key = "second-approval"
    second, = publish(env, [])["artifacts"]
    assert first["reference"] == second["reference"]
    assert first_tags < content_tags(env, second)
    host, repo, _ = release_oci._reference(first["reference"])
    registry = env.stores[host, repo]
    layers = json.loads(registry["manifests"][second["signature"]["tag"]])["layers"]
    releases = {json.loads(registry["blobs"][layer["digest"]])["optional"]["io.cats.approval.release"]
                for layer in layers}
    assert releases == {first_key, env.approval.release_key}
