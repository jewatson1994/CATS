import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cats_setup_bundle", ROOT / "scripts/package-cats-setup.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode()


def write_archive(path, members):
    with tarfile.open(path, "w") as archive:
        for name, data in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def saved_image(reference="cats:test", oci=True, architecture="amd64"):
    """A Docker save fixture, including containerd's dual Docker/OCI metadata."""
    members = {}

    def blob(data, media_type):
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        members["blobs/sha256/" + digest.split(":")[1]] = data
        return {"mediaType": media_type, "digest": digest, "size": len(data)}

    layer = b"fixture layer for " + reference.encode()
    config = json_bytes({"os": "linux", "architecture": architecture,
                         "config": {"Env": ["FIXTURE=" + reference]},
                         "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
    config_id = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest_id = None
    if oci:
        config_descriptor = blob(config, "application/vnd.oci.image.config.v1+json")
        layer_descriptor = blob(layer, "application/vnd.oci.image.layer.v1.tar")
        manifest = blob(json_bytes({"schemaVersion": 2,
                                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "config": config_descriptor, "layers": [layer_descriptor]}),
                        "application/vnd.oci.image.manifest.v1+json")
        manifest_id = manifest["digest"]
        manifest["platform"] = {"os": "linux", "architecture": architecture}
        source = blob(json_bytes({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                                  "manifests": [manifest,
                                                {"mediaType": manifest["mediaType"], "size": 100,
                                                 "digest": "sha256:" + "f" * 64,
                                                 "platform": {"os": "linux", "architecture": "arm64"}}]}),
                      "application/vnd.oci.image.index.v1+json")
        source["annotations"] = {"io.containerd.image.name": "docker.io/" + reference}
        members["index.json"] = json_bytes({"schemaVersion": 2, "manifests": [source]})
        members["oci-layout"] = json_bytes({"imageLayoutVersion": "1.0.0"})
        source_id = source["digest"]
        config_name = "blobs/sha256/" + config_id.split(":")[1]
        layer_name = "blobs/sha256/" + layer_descriptor["digest"].split(":")[1]
    else:
        source_id = config_id
        config_name = config_id.split(":")[1] + ".json"
        layer_name = hashlib.sha256(layer).hexdigest() + "/layer.tar"
        members[config_name] = config
        members[layer_name] = layer
    members["manifest.json"] = json_bytes([{"Config": config_name, "RepoTags": [reference], "Layers": [layer_name]}])
    item = {"role": "cats", "source_reference": reference, "archive_reference": reference, "image_id": source_id}
    return members, item, config_id, manifest_id


@pytest.fixture
def source_tree(tmp_path):
    root = tmp_path / "source"
    for name in set(bundle.source_files("main") + bundle.source_files("replica")):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name.startswith("templates/compose."):
            path.write_bytes((ROOT / name).read_bytes())
        elif name == "deploy/discovery-mirror/manifest.json":
            path.write_text('{"version":1,"artifacts":[]}\n', encoding="utf-8")
        else:
            path.write_text("source file " + name, encoding="utf-8")
    # Real deployments can coexist with the source files. None is an export input.
    for name in (".env", "scan-registry-auth/config.json", "backups/postgres/db.sql",
                 "cats-scanner/grype-db/vulnerability.db", "certs/tls.key",
                 "deploy/discovery-mirror/private-chart.tgz"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("private sentinel", encoding="utf-8")
    return root


@pytest.mark.parametrize("mode,postgres", [("main", "postgres:16-alpine"), ("replica", "postgres:16")])
def test_files_only_uses_exact_mode_allowlist_and_never_docker(tmp_path, source_tree, monkeypatch, mode, postgres):
    def no_docker(*args, **kwargs):
        raise AssertionError("Files-only packaging must not run Docker")
    monkeypatch.setattr(bundle.subprocess, "run", no_docker)
    output = tmp_path / "bundle"
    manifest = bundle.export_bundle(output, mode, "cats:release", files_only=True, root=source_tree)
    actual = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    assert actual == set(bundle.source_files(mode)) | {"manifest.json", "INGRESS.txt"}
    assert set(manifest["files"]) == actual - {"manifest.json"}
    assert manifest["mode"] == mode and manifest["schema_version"] == 1
    assert manifest["files_only"] and manifest["platform"] is None
    assert [item["role"] for item in manifest["images"]] == ["cats", "postgres", "nginx"]
    assert manifest["images"][0]["source_reference"] == "cats:release"
    assert manifest["images"][1]["source_reference"] == postgres
    assert all(item["image_id"] is None and item["archive_reference"] == item["source_reference"]
               for item in manifest["images"])
    for name, checksum in manifest["files"].items():
        data = (output / name).read_bytes()
        assert checksum == hashlib.sha256(data).hexdigest()
        assert b"private sentinel" not in data
    assert "FILES ONLY" in (output / "INGRESS.txt").read_text()
    assert all("deploy/" not in name for name in actual) if mode == "replica" else "deploy/discovery-seccomp.json" in actual
    assert json.loads((output / "manifest.json").read_text()) == manifest


@pytest.mark.parametrize("mode", ["main", "replica"])
@pytest.mark.parametrize("options", [[], ["--files-only"], ["--image", "cats:target-suggestion"]])
def test_cli_defaults_to_files_only_without_docker_or_a_required_image(tmp_path, source_tree, monkeypatch, mode, options):
    monkeypatch.setattr(bundle, "ROOT", source_tree)
    monkeypatch.setattr(bundle.subprocess, "run", lambda *args, **kwargs: pytest.fail("Installer-only export must not invoke Docker"))
    output = tmp_path / "bundle"
    assert bundle.main(["--mode", mode, "--output", str(output), *options]) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["files_only"] and manifest["platform"] is None
    assert not (output / "images.tar").exists()
    assert "images.tar" not in manifest["files"]
    cats = next(item for item in manifest["images"] if item["role"] == "cats")
    expected = "cats:target-suggestion" if "--image" in options else None
    assert cats == {"role": "cats", "source_reference": expected, "archive_reference": expected, "image_id": None}
    inventory = (output / "INGRESS.txt").read_text()
    assert "None" not in inventory
    if expected is None:
        assert "select CATS_IMAGE on the target host" in inventory
    else:
        assert "cats:target-suggestion (suggested; existing target settings take precedence)" in inventory


@pytest.mark.parametrize("options", [["--include-images"], ["--include-images", "--files-only", "--image", "cats:release"]])
def test_cli_requires_image_selection_and_exclusive_export_flags(tmp_path, monkeypatch, options):
    monkeypatch.setattr(bundle, "export_bundle", lambda *args, **kwargs: pytest.fail("Invalid options must not begin an export"))
    with pytest.raises(SystemExit) as stopped:
        bundle.main(["--mode", "replica", "--output", str(tmp_path / "bundle"), *options])
    assert stopped.value.code == 2


def test_image_export_api_requires_selected_image_before_using_docker(tmp_path, source_tree, monkeypatch):
    monkeypatch.setattr(bundle.subprocess, "run", lambda *args, **kwargs: pytest.fail("No image was selected"))
    output = tmp_path / "bundle"
    with pytest.raises(ValueError, match="Select a CATS image"):
        bundle.export_bundle(output, "replica", files_only=False, root=source_tree)
    assert not output.exists()


def test_existing_output_is_never_overwritten(tmp_path, source_tree, monkeypatch):
    monkeypatch.setattr(bundle.subprocess, "run", lambda *args, **kwargs: pytest.fail("Unexpected Docker call"))
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep").write_text("unchanged")
    with pytest.raises(FileExistsError):
        bundle.export_bundle(output, "main", "cats:release", root=source_tree)
    assert (output / "keep").read_text() == "unchanged"


@pytest.mark.parametrize("mode,postgres", [("main", "postgres:16-alpine"), ("replica", "postgres:16")])
def test_include_images_cli_inspects_and_saves_all_three_images_once(tmp_path, source_tree, monkeypatch, mode, postgres):
    calls = []
    images = bundle.template_images((source_tree / f"templates/compose.{mode}.yaml").read_text(), "cats:release")
    fixtures = {item["source_reference"]: saved_image(item["source_reference"], oci=False) for item in images}
    identities = {reference: fixture[1]["image_id"] for reference, fixture in fixtures.items()}

    def run(command, **kwargs):
        calls.append(command)
        if command[1:3] == ["image", "inspect"]:
            identity = identities[command[-1]]
            if "--format" in command:
                return SimpleNamespace(stdout=identity + "\n")
            return SimpleNamespace(stdout=json.dumps([{"Id": identity, "Os": "linux", "Architecture": "amd64"}]))
        if command[1] == "save":
            members, rows = {}, []
            for reference, fixture in zip(command[4:], fixtures.values()):
                members.update(fixture[0])
                row = json.loads(fixture[0]["manifest.json"])[0]
                row["RepoTags"] = [reference]
                rows.append(row)
            members["manifest.json"] = json_bytes(rows)
            write_archive(Path(command[3]), members)
        return SimpleNamespace()

    monkeypatch.setattr(bundle.subprocess, "run", run)
    monkeypatch.setattr(bundle, "ROOT", source_tree)
    output = tmp_path / "bundle"
    assert bundle.main(["--mode", mode, "--image", "cats:release", "--include-images", "--output", str(output)]) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["platform"] == "linux/amd64"
    assert not manifest["files_only"]
    save, = [command for command in calls if command[1] == "save"]
    cats_id, _, nginx_id = identities.values()
    assert save[4:] == ["cats-setup/cats:" + cats_id.split(":")[1], postgres, "cats-setup/nginx:" + nginx_id.split(":")[1]]
    assert [command[2:] for command in calls if command[1] == "tag"] == [
        [cats_id, "cats-setup/cats:" + cats_id.split(":")[1]],
        [nginx_id, "cats-setup/nginx:" + nginx_id.split(":")[1]],
    ]
    assert all(item["image_config_id"] == item["image_id"] and item["image_manifest_id"] is None
               for item in manifest["images"])
    assert manifest["files"]["images.tar"] == hashlib.sha256((output / "images.tar").read_bytes()).hexdigest()
    assert not any("pull" in command or "build" in command for command in calls)


@pytest.mark.parametrize("mode", ["main", "replica"])
def test_shared_full_image_requires_amd64_before_creating_bundle(tmp_path, source_tree, monkeypatch, mode):
    monkeypatch.setattr(bundle.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        stdout=json.dumps([{"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "arm64"}])))
    output = tmp_path / "bundle"
    with pytest.raises(ValueError, match="linux/amd64"):
        bundle.export_bundle(output, mode, "cats:release", root=source_tree)
    assert not output.exists()


@pytest.mark.parametrize("oci", [False, True])
def test_archive_records_only_linked_config_and_platform_identities(tmp_path, oci):
    members, item, config_id, manifest_id = saved_image(oci=oci)
    original_id = item["image_id"]
    path = tmp_path / "images.tar"
    write_archive(path, members)
    assert bundle.inspect_archive_images(path, [item], "linux/amd64") == [item]
    assert item["image_id"] == original_id
    assert item["image_config_id"] == config_id
    assert item["image_manifest_id"] == manifest_id


@pytest.mark.parametrize("source_kind", ["config", "manifest"])
def test_oci_archive_also_supports_config_and_direct_manifest_source_ids(tmp_path, source_kind):
    members, item, config_id, manifest_id = saved_image()
    if source_kind == "config":
        item["image_id"] = config_id
    else:
        source = json.loads(members["blobs/sha256/" + item["image_id"].split(":")[1]])["manifests"][0]
        members["index.json"] = json_bytes({"schemaVersion": 2, "manifests": [source]})
        item["image_id"] = manifest_id
    path = tmp_path / "images.tar"
    write_archive(path, members)
    bundle.inspect_archive_images(path, [item], "linux/amd64")
    assert item["image_config_id"] == config_id
    assert item["image_manifest_id"] == manifest_id


@pytest.mark.parametrize("damage", ["wrong_identity", "unrelated_config", "missing_config", "missing_layer",
                                    "tampered_config", "tampered_index", "tampered_manifest", "layer_size",
                                    "wrong_platform", "wrong_layers", "duplicate_tag", "bad_rootfs"])
def test_oci_archive_rejects_unlinked_or_damaged_metadata(tmp_path, damage):
    members, item, config_id, manifest_id = saved_image()
    row = json.loads(members["manifest.json"])[0]
    if damage == "wrong_identity":
        item["image_id"] = "sha256:" + "a" * 64
    elif damage == "unrelated_config":
        other, _, _, _ = saved_image("cats:unrelated")
        other_row = json.loads(other["manifest.json"])[0]
        members[other_row["Config"]] = other[other_row["Config"]]
        row["Config"] = other_row["Config"]
    elif damage in ("missing_config", "missing_layer"):
        del members[row["Config"] if damage == "missing_config" else row["Layers"][0]]
    elif damage.startswith("tampered_"):
        identity = {"tampered_config": config_id, "tampered_index": item["image_id"],
                    "tampered_manifest": manifest_id}[damage]
        name = "blobs/sha256/" + identity.split(":")[1]
        # Keep JSON valid and descriptor sizes unchanged: reject by digest.
        before, after = ((b"cats:test", b"cats:evil") if damage == "tampered_config"
                         else (b'"schemaVersion":2', b'"schemaVersion":3'))
        members[name] = members[name].replace(before, after)
    elif damage == "layer_size":
        members[row["Layers"][0]] += b"changed"
    elif damage == "wrong_platform":
        members, item, _, _ = saved_image(architecture="arm64")
        row = json.loads(members["manifest.json"])[0]
    elif damage == "wrong_layers":
        row["Layers"] = [row["Config"]]
    elif damage == "bad_rootfs":
        config = json.loads(members[row["Config"]])
        config["rootfs"]["diff_ids"] = []
        members[row["Config"]] = json_bytes(config)
    members["manifest.json"] = json_bytes([row, row] if damage == "duplicate_tag" else [row])
    path = tmp_path / "images.tar"
    write_archive(path, members)
    with pytest.raises(ValueError):
        bundle.inspect_archive_images(path, [item], "linux/amd64")
    assert "image_config_id" not in item and "image_manifest_id" not in item


@pytest.mark.parametrize("damage", ["wrong_identity", "tampered_config", "missing_layer"])
def test_legacy_archive_rejects_wrong_config_identity_or_missing_layers(tmp_path, damage):
    members, item, _, _ = saved_image(oci=False)
    row = json.loads(members["manifest.json"])[0]
    if damage == "wrong_identity":
        item["image_id"] = "sha256:" + "a" * 64
    elif damage == "tampered_config":
        members[row["Config"]] += b" "
    else:
        del members[row["Layers"][0]]
    path = tmp_path / "images.tar"
    write_archive(path, members)
    with pytest.raises(ValueError):
        bundle.inspect_archive_images(path, [item], "linux/amd64")


@pytest.mark.parametrize("damage", ["duplicate_member", "linked_layer"])
def test_archive_rejects_ambiguous_members_and_nonregular_layers(tmp_path, damage):
    members, item, _, _ = saved_image()
    path = tmp_path / "images.tar"
    layer = json.loads(members["manifest.json"])[0]["Layers"][0]
    if damage == "linked_layer":
        del members[layer]
    write_archive(path, members)
    with tarfile.open(path, "a") as archive:
        extra = tarfile.TarInfo(layer)
        if damage == "linked_layer":
            extra.type = tarfile.SYMTYPE
            extra.linkname = "manifest.json"
        archive.addfile(extra)
    with pytest.raises(ValueError):
        bundle.inspect_archive_images(path, [item], "linux/amd64")


@pytest.mark.parametrize("invalid", ["missing", "windows", "mixed_architecture"])
def test_bad_images_fail_before_creating_output(tmp_path, source_tree, monkeypatch, invalid):
    def run(command, **kwargs):
        if invalid == "missing":
            raise bundle.subprocess.CalledProcessError(1, command, stderr="No such image")
        return SimpleNamespace(stdout=json.dumps([{
            "Id": "sha256:" + "a" * 64,
            "Os": "windows" if invalid == "windows" else "linux",
            "Architecture": "arm64" if "postgres:16" == command[-1] else "amd64",
        }]))
    monkeypatch.setattr(bundle.subprocess, "run", run)
    output = tmp_path / "bundle"
    with pytest.raises((ValueError, bundle.subprocess.CalledProcessError)):
        bundle.export_bundle(output, "replica", "cats:release", root=source_tree)
    assert not output.exists()


def test_changed_postgres_tag_leaves_no_success_manifest(tmp_path, source_tree, monkeypatch):
    def run(command, **kwargs):
        if "--format" in command:
            return SimpleNamespace(stdout="sha256:" + "b" * 64)
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(stdout=json.dumps([{"Id": "sha256:" + "a" * 64,
                                                       "Os": "linux", "Architecture": "amd64"}]))
        assert command[1] != "save"
        return SimpleNamespace()
    monkeypatch.setattr(bundle.subprocess, "run", run)
    output = tmp_path / "bundle"
    with pytest.raises(ValueError, match="tag changed"):
        bundle.export_bundle(output, "main", "cats:release", root=source_tree)
    assert not (output / "manifest.json").exists()


def test_custom_mirror_is_not_silently_exported(tmp_path, source_tree):
    (source_tree / "deploy/discovery-mirror/manifest.json").write_text(
        json.dumps({"version": 1, "artifacts": [{"url": "https://private.example/chart"}]}))
    with pytest.raises(ValueError, match="empty default discovery mirror"):
        bundle.export_bundle(tmp_path / "bundle", "main", "cats:release", files_only=True, root=source_tree)


@pytest.mark.parametrize("mode", ["main", "replica"])
def test_runtime_inventory_covers_actual_template_bind_mounts(mode):
    yaml = pytest.importorskip("yaml")
    template = (ROOT / f"templates/compose.{mode}.yaml").read_text(encoding="utf-8-sig")
    expected = set()
    for service in yaml.safe_load(template)["services"].values():
        for mount in service.get("volumes", []):
            if isinstance(mount, dict) and mount.get("type") == "bind":
                expected.add((mount["source"], mount["target"]))
            elif isinstance(mount, str) and mount.startswith(("/", "./", "../", "${")):
                # Split at the actual mount separator rather than the default in ${...:-...}.
                source, target = mount.rsplit(":/", 1)
                expected.add((source, "/" + target.split(":", 1)[0]))
    actual = {(item["source"], item["target"]) for item in bundle.runtime_bind_inventory(template)}
    assert actual == expected
    assert len(actual) == (8 if mode == "main" else 2)


def test_main_ingress_reports_public_node_setting_and_exact_template_default():
    template = (ROOT / "templates/compose.main.yaml").read_text(encoding="utf-8-sig")
    example = (ROOT / "templates/main.env.example").read_text(encoding="utf-8-sig")
    node = next(line.split("=", 1)[1] for line in example.splitlines() if line.startswith("CATS_KIND_NODE_IMAGE="))
    ingress = bundle.ingress_requirements("main", template)
    instruction, = [item for item in ingress["optional_feature_inputs"] if item.startswith("Deployment Validation only:")]
    assert "CATS_KIND_NODE_IMAGE" in instruction
    assert "template default: " + node in instruction
    assert any("/opt/cats/certs/portal" in item for item in ingress["operator_provided"])
    assert any("/opt/cats/certs/oci-proxy" in item for item in ingress["operator_provided"])


def test_unrecognized_image_and_unpinned_nginx_fail_closed():
    template = (ROOT / "templates/compose.replica.yaml").read_text()
    with pytest.raises(ValueError, match="Unrecognized template image"):
        bundle.template_images(template + "\n    image: redis:7\n", "cats:release")
    with pytest.raises(ValueError, match="digest-pinned"):
        bundle.template_images(template.replace("nginx:stable-alpine@sha256:" + "0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949", "nginx:latest"), "cats:release")
