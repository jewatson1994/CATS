"""Packaging and worker-admission contracts for CI artifact uploads."""
import io
import hashlib
import json
import tarfile
from zipfile import ZipFile
import uuid

from fastapi import HTTPException
import pytest

from app import main, scan_coordination, scan_artifacts
from app.models import Service
from app.pipeline_scan_dispatch import prepare_scan
from test_scan_worker_coordination import database


def bundle(entries, extension):
    output = io.BytesIO()
    if extension == "zip":
        with ZipFile(output, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)
    else:
        with tarfile.open(fileobj=output, mode="w:gz" if extension == "tgz" else "w") as archive:
            for name, value in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


CHART = {"mychart/Chart.yaml": b"apiVersion: v2\nname: mychart\nversion: 1.0.0\n",
         "mychart/values.yaml": b"replicas: 1\n"}
DOCKER = {"manifest.json": json.dumps([{"Config": "config.json", "RepoTags": ["test/app:v1"], "Layers": ["layer.tar"]}]).encode(),
          "layer.tar": b"data", "config.json": b"{}"}
DIGEST = "a" * 64
COMPOSE = b"services:\n  web:\n    image: test/app:v1\n"


def oci_layout():
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}'}
    def blob(media_type, content):
        digest = hashlib.sha256(content).hexdigest()
        files["blobs/sha256/" + digest] = content
        return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(content)}
    config = blob("application/vnd.oci.image.config.v1+json", b'{"architecture":"amd64","os":"linux"}')
    image = blob("application/vnd.oci.image.manifest.v1+json", json.dumps({
        "schemaVersion": 2, "config": config, "layers": []}).encode())
    image["annotations"] = {"org.opencontainers.image.ref.name": "test/app:v1"}
    files["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [image]}).encode()
    return files


@pytest.fixture
def dispatch(tmp_path, database, monkeypatch):
    root = tmp_path / "jobs"
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", root)
    def send(*, content=None, filename=None, **options):
        identity = uuid.uuid4().hex
        directory = root / identity
        directory.mkdir(parents=True)
        if content is not None:
            (directory / "submission-input").write_bytes(content)
        with database() as db:
            service = db.get(Service, 1)
            job = prepare_scan(db, service, identity, directory, filename=filename, **options)
            db.commit()
        return directory, job
    return send


@pytest.mark.parametrize(("binary", "filename", "expected", "member"), [
    (bundle(CHART, "tgz"), "anything.tgz", "helm-chart", "mychart/Chart.yaml"),
    (bundle(CHART, "zip"), "chart.zip", "helm-chart", "mychart/Chart.yaml"),
    (bundle(DOCKER, "tar"), "images.tar", "docker-archive", "image-archives/images.tar"),
    (bundle(oci_layout(), "tgz"), "images.tar.gz", "docker-archive", "image-archives/images.tar.gz"),
    (COMPOSE, "manifest.yaml", "compose", ".cats-compose/compose.yaml"),
    (bundle({"stack/compose.yaml": COMPOSE}, "zip"), "stack.zip", "compose", ".cats-compose/stack/compose.yaml"),
], ids=["chart-tgz", "chart-zip", "docker-save", "oci-image-layout", "compose-yaml", "compose-zip"])
def test_uploads_become_verified_worker_inputs(dispatch, binary, filename, expected, member, tmp_path):
    directory, job = dispatch(content=binary, filename=filename)
    assert job.payload["pipeline_input_kind"] == expected and job.status == "queued"
    assert job.input_digest == scan_artifacts.digest(directory / "input.tar.gz")
    unpacked = tmp_path / "worker-input"
    archive = scan_artifacts.unpack(directory / "input.tar.gz", unpacked, {"job_id": job.id})
    assert any(name.endswith(member) for name in archive["files"])
    assert not (directory / "submission-input").exists()
    claim = scan_coordination.claim("worker")
    assert claim["service_key"] == "service" and claim["input_digest"] == job.input_digest
    assert claim["job"]["credential_policy"] == "public" and not job.anonymous


@pytest.mark.parametrize(("binary", "filename", "kind"), [
    (b"replicaCount: 1\n", "values.yaml", "auto"),
    (b"apiVersion: v1\nkind: Service\n", "k8s.yaml", "compose"),
    (bundle(CHART, "tgz"), "chart.tgz", "docker-archive"),
    (bundle({"manifest.json": DOCKER["manifest.json"]}, "tar"), "images.tar", "auto"),
    (bundle({"../escape": b"x"}, "tar"), "images.tar", "auto"),
    (bundle({"index.json": b"{}", "oci-layout": b"{}"}, "tar"), "images.tar", "auto"),
    (bundle({"no-chart.yaml": b"{}"}, "zip"), "chart.zip", "helm-chart"),
    (bundle({**CHART, "compose.yaml": COMPOSE}, "tgz"), "repo.tgz", "auto"),
    (bundle({**CHART, **DOCKER}, "zip"), "repo.zip", "auto"),
], ids=["standalone-values", "kubernetes-yaml", "kind-mismatch", "missing-layer", "escape", "untagged-oci",
        "missing-chart", "mixed-compose-chart", "mixed-image-chart"])
def test_invalid_inputs_rejected_before_admission(dispatch, database, binary, filename, kind):
    with pytest.raises(HTTPException):
        dispatch(content=binary, filename=filename, kind=kind)
    assert scan_coordination.claim("worker") is None


@pytest.mark.parametrize("ref", ["https://user:secret@registry/chart", "oci://user:secret@registry/chart",
                                 "test/app@token:value", "repo:tag?token=secret", "../other", "oci://reg/a@sha256:" + DIGEST])
def test_unsafe_and_unsupported_references_are_rejected(dispatch, ref):
    with pytest.raises(HTTPException) as caught:
        dispatch(reference=ref)
    assert caught.value.status_code == 422 and "secret" not in str(caught.value)


def test_reference_kind_version_and_service_fenced_before_claim(dispatch, database):
    _, job = dispatch(reference="oci://registry.example/org/chart:1.2.3", version="v2")
    assert job.payload["pipeline_input_kind"] == "helm-chart"
    assert job.payload["chart_url"] == "oci://registry.example/org/chart:1.2.3"
    assert job.service_version == "v2"
    with database() as db:
        source = db.get(Service, 1)
        source.service_key = "renamed"
        db.commit()
    assert scan_coordination.claim("worker") is None
    assert scan_coordination.DurableJobs()[job.id]["status"] == "error"
