#!/usr/bin/env python3
"""List the tagged images in an uploaded image archive without a Docker daemon.

Supports `docker save` archives (manifest.json) and OCI image-layout archives
(index.json), plain or gzip-compressed. An uncompressed docker-save archive
that holds one image is used in place.
Otherwise each tagged image is written to its own docker-save archive, so
Syft, Trivy and Dockle each read exactly the image that was named.

Output: one line per tagged image, `IMAGE<TAB>docker-archive<TAB>PATH`. Untagged images are
reported on stderr and skipped, matching `docker load` behaviour.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import posixpath
import sys
import tarfile
from pathlib import Path

_REF_NAME = "org.opencontainers.image.ref.name"
_IMAGE_NAME = "io.containerd.image.name"


def _safe_member(name: str) -> str:
    normalized = posixpath.normpath(name.lstrip("./") or ".")
    if normalized.startswith("../") or normalized == ".." or posixpath.isabs(name):
        raise ValueError(f"unsafe archive member: {name}")
    return normalized


def _members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members = {}
    for member in archive.getmembers():
        if member.isfile():
            members[_safe_member(member.name)] = member
    return members


def _read_json(archive: tarfile.TarFile, members: dict, name: str):
    member = members.get(name)
    if member is None:
        return None
    handle = archive.extractfile(member)
    return json.loads(handle.read().decode("utf-8")) if handle else None


def _write(output: Path, files: list[tuple[str, bytes | None, tarfile.TarInfo | None]], source: tarfile.TarFile) -> None:
    # Some archive readers require explicit directory entries, so emit each
    # parent directory once before its files.
    directories = sorted({posixpath.dirname(name) for name, _data, _member in files} - {""})
    directories = sorted({"/".join(d.split("/")[:i]) for d in directories for i in range(1, d.count("/") + 2)})
    with tarfile.open(output, "w") as target:
        for directory in directories:
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            target.addfile(info)
        for name, data, member in files:
            info = tarfile.TarInfo(name)
            if data is not None:
                info.size = len(data)
                target.addfile(info, io.BytesIO(data))
            else:
                info.size = member.size
                target.addfile(info, source.extractfile(member))


def _label(archive: Path, tag: str) -> str:
    # Distinct per archive, so the same tag in two uploads never collides.
    return hashlib.sha256(f"{archive.resolve()}\0{tag}".encode("utf-8")).hexdigest()[:20]


def docker_archive(path: Path, archive, members, manifest, output_dir: Path) -> list[tuple[str, str, str]]:
    tagged = [(entry, tag) for entry in manifest if isinstance(entry, dict)
              for tag in (entry.get("RepoTags") or []) if isinstance(tag, str) and tag]
    for entry in manifest:
        if isinstance(entry, dict) and not entry.get("RepoTags"):
            print(f"WARNING: untagged image in {path.name} is not scanned; tag it before saving", file=sys.stderr)
    with path.open("rb") as handle:
        compressed = handle.read(2) == b"\x1f\x8b"
    if len(manifest) == 1 and not compressed:
        return [(tag, "docker-archive", str(path.resolve())) for _entry, tag in tagged]
    rows = []
    for entry, tag in tagged:
        names = [entry.get("Config"), *(entry.get("Layers") or [])]
        files = [("manifest.json", json.dumps([{**entry, "RepoTags": [tag]}]).encode("utf-8"), None)]
        for name in names:
            name = _safe_member(str(name or ""))
            if name not in members:
                raise ValueError(f"{path.name}: {tag} references missing member {name}")
            files.append((name, None, members[name]))
        target = output_dir / f"{_label(path, tag)}.tar"
        _write(target, files, archive)
        rows.append((tag, "docker-archive", str(target.resolve())))
    return rows


def _blob(archive, members, digest: str) -> tuple[str, tarfile.TarInfo]:
    algorithm, _, value = str(digest).partition(":")
    name = _safe_member(f"blobs/{algorithm}/{value}")
    if not value or name not in members:
        raise ValueError(f"missing blob {digest}")
    return name, members[name]


def _image_manifest(archive, members, descriptor: dict) -> dict:
    """Follow an index to one image manifest, preferring linux/amd64."""
    for _depth in range(4):
        name, _member = _blob(archive, members, descriptor.get("digest"))
        document = _read_json(archive, members, name)
        if not isinstance(document, dict):
            raise ValueError(f"unreadable manifest {descriptor.get('digest')}")
        if "layers" in document and "config" in document:
            return document
        children = [item for item in document.get("manifests") or [] if isinstance(item, dict)]
        if not children:
            raise ValueError(f"manifest {descriptor.get('digest')} has no image")
        descriptor = next((item for item in children
                           if (item.get("platform") or {}).get("os") == "linux"
                           and (item.get("platform") or {}).get("architecture") == "amd64"), children[0])
    raise ValueError("image index nesting is too deep")


def oci_archive(path: Path, archive, members, index, output_dir: Path) -> list[tuple[str, str, str]]:
    """Rewrite each tagged OCI image as a docker-save archive.

    Syft, Trivy and Dockle all read docker-save tars, while their support for
    OCI layout tars differs. The output keeps the original blobs and lists
    them in manifest.json, as Docker 25+ does when it saves an image.
    """
    tagged = []
    for item in (index.get("manifests") or []):
        if not isinstance(item, dict):
            continue
        annotations = item.get("annotations") or {}
        tag = annotations.get(_IMAGE_NAME) or annotations.get(_REF_NAME)
        if tag and ("/" in tag or ":" in tag):
            tagged.append((item, tag))
        else:
            print(f"WARNING: untagged image in {path.name} is not scanned; tag it before saving", file=sys.stderr)
    rows = []
    for item, tag in tagged:
        manifest = _image_manifest(archive, members, item)
        config_name, config_member = _blob(archive, members, (manifest.get("config") or {}).get("digest"))
        layers = [_blob(archive, members, layer.get("digest")) for layer in manifest.get("layers") or []]
        entry = {"Config": config_name, "RepoTags": [tag], "Layers": [name for name, _member in layers]}
        files = [("manifest.json", json.dumps([entry]).encode("utf-8"), None),
                 (config_name, None, config_member),
                 *[(name, None, member) for name, member in dict(layers).items()]]
        target = output_dir / f"{_label(path, tag)}.tar"
        _write(target, files, archive)
        rows.append((tag, "docker-archive", str(target.resolve())))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(args.archive, "r:*") as archive:
            members = _members(archive)
            manifest = _read_json(archive, members, "manifest.json")
            if isinstance(manifest, list) and manifest:
                rows = docker_archive(args.archive, archive, members, manifest, args.output_dir)
            else:
                index = _read_json(archive, members, "index.json")
                if not isinstance(index, dict):
                    print(f"ERROR: {args.archive.name} is not a docker-save or OCI image archive", file=sys.stderr)
                    return 2
                rows = oci_archive(args.archive, archive, members, index, args.output_dir)
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(f"ERROR: unable to read image archive {args.archive.name}: {exc}", file=sys.stderr)
        return 2
    for row in rows:
        print("\t".join(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
