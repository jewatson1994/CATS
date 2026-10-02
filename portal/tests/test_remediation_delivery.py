import hashlib
import io
import json
from contextlib import contextmanager
from types import SimpleNamespace
from zipfile import ZipFile, ZipInfo
import pytest
import yaml
from app import remediation_delivery as delivery


def retained(tmp_path, entries=None):
    folder = tmp_path / "r1"
    folder.mkdir(exist_ok=True)
    path = folder / "candidate.zip"
    with ZipFile(path, "w") as archive:
        for name, content in (entries or {"manifest.json": "{}"}).items():
            archive.writestr(name, content)
    return SimpleNamespace(job_key="r1", artifact_path=str(path),
        artifact_digest="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest())


def test_retained_candidate_requires_original_integrity_and_directory(tmp_path):
    record = retained(tmp_path)
    assert delivery.retained_candidate(record, tmp_path).name == "candidate.zip"
    record.artifact_digest = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="integrity"):
        delivery.retained_candidate(record, tmp_path)
    record.job_key = "../r1"
    with pytest.raises(ValueError, match="unavailable"):
        delivery.retained_candidate(record, tmp_path)


@pytest.mark.parametrize("names", [["../escape"], ["/escape"], ["a\\escape"], ["C:escape"],
    ["a", "a"], ["a/b", "a//b"], ["a./escape"], ["a /escape"]])
def test_archive_entries_reject_escape_and_aliases(names):
    stream = io.BytesIO()
    with ZipFile(stream, "w") as archive:
        for name in names:
            entry = ZipInfo(name)
            entry.filename = name  # Preserve hostile separators on Windows too.
            archive.writestr(entry, "x")
    with ZipFile(stream) as archive, pytest.raises(ValueError, match="Unsafe"):
        delivery.checked_inventory(archive)


def test_archive_symlink_rejected():
    stream = io.BytesIO()
    with ZipFile(stream, "w") as archive:
        entry = ZipInfo("candidate/link")
        entry.external_attr = 0o120777 << 16
        archive.writestr(entry, "../../escape")
    with ZipFile(stream) as archive, pytest.raises(ValueError):
        delivery.checked_inventory(archive)


def test_materialization_changes_image_fields_not_policy_text():
    source = "old/api:patched"
    dest = "registry/team/api@sha256:" + "a" * 64
    content = yaml.safe_dump({"spec": {"containers": [{"image": source}]},
        "annotation": source, "description": "see " + source, "image": source + "-other"})
    result = yaml.safe_load(delivery.materialize({"manifest.yaml": content}, {source: dest})["manifest.yaml"])
    assert result["spec"]["containers"][0]["image"] == dest
    assert result["annotation"] == source
    assert result["description"] == "see " + source
    assert result["image"] == source + "-other"
    template = '{{ if .Values.enabled }}\nimage: "' + source + '" # image\nannotation: "' + source + '"\n{{ end }}'
    result = delivery.materialize({"templates/pod.yaml": template}, {source: dest})["templates/pod.yaml"]
    assert 'image: "' + dest + '"' in result
    assert 'annotation: "' + source + '"' in result


def test_recursive_yaml_rejected():
    with pytest.raises(ValueError, match="Recursive"):
        delivery.materialize({"values.yaml": "loop: &loop [*loop]"}, {})


@pytest.mark.parametrize("values", [["../override.yaml"], ["/override.yaml"], ["C:/override.yaml"],
    ["a\\override.yaml"], ["a//override.yaml"], ["a/./override.yaml"], ["missing.yaml"],
    ["override.yaml", "override.yaml"], "override.yaml", [None]])
def test_values_overrides_are_confined_to_retained_files(values):
    with pytest.raises(ValueError):
        delivery.checked_values_files(values, {"override.yaml", "a/override.yaml"})


def test_delivery_preserves_ordered_custom_values(tmp_path, monkeypatch):
    from pathlib import Path
    overrides = ["overrides/base.yaml", "overrides/service.yaml"]
    record = retained(tmp_path, {"manifest.json": json.dumps({"values_files": overrides}),
        "candidate/api/Chart.yaml": "apiVersion: v2\nname: api\nversion: 1.0.0\n",
        "candidate/overrides/base.yaml": "replicas: 2\n",
        "candidate/overrides/service.yaml": "replicas: 3\n"})
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1] in {"lint", "template"}:
            paths = [args[index + 1] for index, value in enumerate(args) if value == "--values"]
            assert [Path(path).relative_to(Path(path).parents[1]).as_posix() for path in paths] == overrides
            assert [yaml.safe_load(Path(path).read_text())["replicas"] for path in paths] == [2, 3]
        if args[1] == "package":
            (Path(args[args.index("--destination") + 1]) / "api-1.0.0.tgz").write_bytes(b"package")
        return SimpleNamespace(returncode=0, stdout="", stderr="Digest: sha256:" + "a" * 64 if args[1] == "push" else "")
    monkeypatch.setattr(delivery.subprocess, "run", run)
    result, path = delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 1, tmp_path)
    assert result["values_files"] == overrides
    assert [args[1] for args in calls] == ["lint", "template", "package", "push"]
    with ZipFile(path) as output:
        assert json.loads(output.read("lineage.json"))["values_files"] == overrides


@pytest.mark.parametrize('image,source',[
    ({'registry':'old.example:5443','repository':'team/api','tag':'patched'},'old.example:5443/team/api:patched'),
    ({'repository':'old.example/team/api','tag':'patched'},'old.example/team/api:patched'),
    ({'registry':'old.example','repository':'team/api','digest':'sha256:'+'b'*64,'tag':'ignored'},'old.example/team/api@sha256:'+'b'*64),
])
def test_materialization_split_images_require_exact_complete_identity(image,source):
    destination = 'new.example:5443/team/image-one@sha256:'+'a'*64
    content = yaml.safe_dump({'image':{**image,'pullPolicy':'Always'},'unmatched':{'registry':'old.example','repository':'team/api','tag':'original'},'annotation':source})
    result = yaml.safe_load(delivery.materialize({'values.yaml':content},{source:destination})['values.yaml'])
    assert result['image']['digest'] == 'sha256:'+'a'*64
    assert result['image']['tag'] == ''
    if 'registry' in image:
        assert result['image']['registry'] == 'new.example:5443'
        assert result['image']['repository'] == 'team/image-one'
    else:
        assert result['image']['repository'] == 'new.example:5443/team/image-one'
    assert result['image']['pullPolicy'] == 'Always'
    assert result['unmatched']['tag'] == 'original' and result['annotation'] == source


def test_split_materialization_does_not_guess_defaults_or_change_partial_matches():
    data = {'image':{'registry':'old.example','repository':'api'},'other':{'repository':'old.example/api','tag':'other'}}
    result = yaml.safe_load(delivery.materialize({'values.yaml':yaml.safe_dump(data)},
        {'old.example/api:patched':'new.example/api@sha256:'+'a'*64})['values.yaml'])
    assert result == data


@pytest.mark.parametrize("registry_changed", [False, True])
@pytest.mark.parametrize("signing_outcome", [None, "verified", "failed"])
def test_delivery_uses_archive_hash_then_registry_manifest_and_preserves_r1(tmp_path, monkeypatch, registry_changed, signing_outcome):
    archive_name = "images/" + "a" * 32 + ".tar"
    image_content = b"retained-image-archive"
    tar_digest = "sha256:" + hashlib.sha256(image_content).hexdigest()
    manifest_digest = "sha256:" + "b" * 64
    record = retained(tmp_path, {"manifest.json": json.dumps({"images": [{
        "archive_path": archive_name, "artifact_sha256": tar_digest, "remediated": "local/api:validated"}]}),
        archive_name: image_content, "candidate/manifest.yaml": "image: local/api:validated\n"})
    original_digest = record.artifact_digest
    calls = []
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    def run(args, **kwargs):
        calls.append(args)
        assert kwargs.get("shell") is None
        if args[1] == "copy":
            from pathlib import Path
            Path(args[args.index("--digestfile") + 1]).write_text(manifest_digest)
        observed = "sha256:" + "c" * 64 if registry_changed else manifest_digest
        return SimpleNamespace(returncode=0, stdout=observed if args[1] == "inspect" else "", stderr="")
    monkeypatch.setattr(delivery.subprocess, "run", run)
    from app import signing
    def sign(reference, config, credentials, env):
        assert reference.endswith("@" + manifest_digest)
        assert "DOCKER_CONFIG" in env
        if signing_outcome == "failed":
            raise RuntimeError("private-key-secret")
        return {"signature_status": "verified", "signature": {"image": reference}}
    monkeypatch.setattr(signing, "sign_and_verify", sign)
    if registry_changed:
        with pytest.raises(ValueError, match="identity differs"):
            delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example:5443", "namespace": "team"}, 1, tmp_path)
        assert delivery.retained_candidate(record, tmp_path).exists()
        return
    result, path = delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example:5443", "namespace": "team"}, 1, tmp_path,
        signing_material=({}, {}) if signing_outcome else None)
    assert result["signing_status"] == (signing_outcome or "not_requested")
    assert "private-key-secret" not in json.dumps(result)
    identity = result["artifact_identities"][0]
    assert identity["digest"] == manifest_digest
    assert identity["digest"] != tar_digest
    assert identity["reference"].startswith("registry.example:5443/team/")
    assert identity["reference"].endswith("@" + manifest_digest)
    assert record.artifact_digest == original_digest
    assert [args[1] for args in calls] == ["copy", "inspect"]
    with ZipFile(path) as output:
        assert manifest_digest in output.read("candidate/manifest.yaml").decode()
    assert delivery.retained_candidate(record, tmp_path).exists()


def test_delivery_failure_retains_candidate_and_sanitizes_error(tmp_path, monkeypatch):
    name = "images/" + "a" * 32 + ".tar"
    record = retained(tmp_path, {"manifest.json": json.dumps({"images": [{"archive_path": name,
        "artifact_sha256": hashlib.sha256(b"archive").hexdigest(), "remediated": "local:tag"}]}), name: b"archive"})
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    monkeypatch.setattr(delivery.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="secret-password"))
    with pytest.raises(ValueError) as error:
        delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 1, tmp_path)
    assert "secret-password" not in str(error.value)
    assert delivery.retained_candidate(record, tmp_path).exists()


def test_helm_ignoring_rewritten_digest_is_not_published(tmp_path, monkeypatch):
    name = "images/" + "a" * 32 + ".tar"
    digest = "sha256:" + "b" * 64
    record = retained(tmp_path, {
        "manifest.json": json.dumps({"images": [{"archive_path": name,
            "artifact_sha256": hashlib.sha256(b"archive").hexdigest(), "remediated": "local:tag"}]}),
        name: b"archive", "candidate/Chart.yaml": "apiVersion: v2\nname: example\nversion: 1.0.0\n",
        "candidate/values.yaml": "image: local:tag\n"})
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "copy":
            from pathlib import Path
            Path(args[args.index("--digestfile") + 1]).write_text(digest)
        output = digest if args[1] == "inspect" else ""
        if args[1] == "template":
            output = "spec:\n  containers:\n  - image: local:tag\n"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(delivery.subprocess, "run", run)
    with pytest.raises(ValueError, match="Rendered Helm images"):
        delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 1, tmp_path)
    assert not any(args[1] in {"package", "push"} for args in calls)
    assert delivery.retained_candidate(record, tmp_path).exists()
