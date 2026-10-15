"""Publish a frozen approval and retain a genuinely self-contained offline release.

Only the worker invokes this module. Checkpoints are durable progress receipts;
the final published checkpoint is emitted only after registry and bundle checks.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy import select
import yaml

from . import release_oci, release_signing, signing
from .deployment_bundle import file_digest
from .models import PortalSetting
from .release_documentation import canonical, registry_environment
from .remediation_jobs import check_worker
from .remediation_bundles import configured_material


class PublicationError(ValueError):
    """Public, sanitized failure with a durable partial-operation receipt."""

    def __init__(self, receipt):
        self.receipt = receipt
        super().__init__(receipt["error"])


def _public_snapshot(value):
    """The private snapshot hash stays authoritative; local storage paths stay private."""
    if isinstance(value, dict):
        return {key: _public_snapshot(item) for key, item in value.items()
                if not (isinstance(item, str) and (Path(item).is_absolute() or PureWindowsPath(item).is_absolute()))}
    if isinstance(value, list):
        return [_public_snapshot(item) for item in value]
    if isinstance(value, str) and (Path(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        return "[retained local file]"
    return value


@contextmanager
def _source_environments(settings):
    """Saved source credentials and CA trust are scoped to the matching host."""
    with configured_material(settings) as material, tempfile.TemporaryDirectory(prefix="cats-release-sources-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        auth = root / "config.json"
        shutil.copyfile(material["image_auth_file"], auth)
        auth.chmod(0o600)
        base = signing.clean_environment(dict(os.environ))
        for key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            base.pop(key, None)
        base["DOCKER_CONFIG"] = str(root)
        environments = {}
        if material.get("helm_ca_file"):
            base["SSL_CERT_FILE"] = material["helm_ca_file"]
        for row in material.get("image_registries", []):
            host = row["endpoint"].removeprefix("https://").rstrip("/")
            if host in environments:
                raise ValueError("Source registry configuration is ambiguous")
            env = dict(base)
            if row.get("ca_file"):
                env["SSL_CERT_FILE"] = row["ca_file"]
            environments[host] = env
        yield base, environments


def _checked_file(value):
    path = Path(value["path"])
    if (not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents))
            or not path.is_file() or file_digest(path) != value["digest"]):
        raise ValueError("Frozen release evidence is missing or changed")
    return path


def _descriptor(item):
    if (not isinstance(item, dict) or not release_oci._DIGEST.fullmatch(item.get("digest", ""))
            or not isinstance(item.get("size"), int) or item["size"] < 0
            or not isinstance(item.get("mediaType"), str)):
        raise ValueError("Invalid OCI descriptor")
    return item


class _Transport:
    """Exact-byte OCI graph copy with a shared content-addressed offline layout."""

    def __init__(self, root, env):
        self.root, self.env = Path(root), env
        self.blobs = self.root / "blobs" / "sha256"
        self.blobs.mkdir(parents=True)
        self.entries = []
        self.total = 0
        self.limit = int(env.get("CATS_CYBER_RELEASE_MAX_BYTES", str(20 * 1024**3)))
        self.blob_limit = int(env.get("CATS_CYBER_RELEASE_BLOB_MAX_BYTES", str(1024**3)))
        if self.limit <= 0 or self.blob_limit <= 0:
            raise ValueError("Release transport limits must be positive")

    def retain(self, descriptor, content):
        _descriptor(descriptor)
        if len(content) != descriptor["size"] or release_oci._digest(content) != descriptor["digest"]:
            raise ValueError("OCI content digest or size mismatch")
        path = self.blobs / descriptor["digest"][7:]
        if not path.exists():
            self.total += len(content)
            if self.total > self.limit:
                raise ValueError("Offline release exceeds transport size limit")
            path.write_bytes(content)
        return path

    def graph(self, source, digest, target=None, depth=0, seen=None):
        check_worker()
        if depth > 32:
            raise ValueError("OCI graph nesting exceeds limit")
        seen = set() if seen is None else seen
        if digest in seen:
            raise ValueError("Cyclic OCI graph")
        seen = seen | {digest}
        if not release_oci._DIGEST.fullmatch(digest):
            raise ValueError("Invalid OCI manifest digest")
        _, headers, data = source.request("GET", source.api + "/manifests/" + digest)
        document = json.loads(data)
        descriptor = {"digest": digest, "size": len(data),
                      "mediaType": document.get("mediaType") or headers.get_content_type()}
        self.retain(descriptor, data)
        children = document.get("manifests", [])
        if not isinstance(children, list) or len(children) > 256:
            raise ValueError("Invalid OCI index")
        for child in children:
            _descriptor(child)
            actual = self.graph(source, child["digest"], target, depth + 1, seen)
            if any(actual[k] != child[k] for k in ("digest", "size", "mediaType")):
                raise ValueError("OCI child descriptor mismatch")
        blobs = ([document["config"]] if "config" in document else []) + document.get("layers", [])
        if not children and not blobs:
            raise ValueError("Empty OCI artifact graph")
        if len(blobs) > 4096:
            raise ValueError("OCI layer count exceeds limit")
        for item in blobs:
            check_worker()
            _descriptor(item)
            if item["size"] > self.blob_limit:
                raise ValueError("OCI layer exceeds configured transport size limit")
            _, _, content = source.request("GET", source.api + "/blobs/" + item["digest"], limit=item["size"])
            self.retain(item, content)
            if target is not None:
                target.upload(content, item["mediaType"])
                _, _, retrieved = target.request("GET", target.api + "/blobs/" + item["digest"], limit=item["size"])
                if retrieved != content:
                    raise ValueError("Destination OCI blob verification failed")
        if target is not None:
            status, _, _ = target.request("PUT", target.api + "/manifests/" + digest,
                                         body=data, media_type=descriptor["mediaType"])
            if status != 201:
                raise ValueError("Destination did not accept immutable manifest")
            _, _, retrieved = target.request("GET", target.api + "/manifests/" + digest)
            if retrieved != data:
                raise ValueError("Destination OCI manifest verification failed")
        return descriptor

    def entry(self, descriptor, name):
        self.entries.append({**descriptor, "annotations": {"org.opencontainers.image.ref.name": name}})
        (self.root / "oci-layout").write_bytes(canonical({"imageLayoutVersion": "1.0.0"}))
        (self.root / "index.json").write_bytes(canonical({"schemaVersion": 2, "manifests": self.entries}))


def _signature(transport, client, reference, config, credentials, env, layout_name):
    result = signing.sign_and_verify(reference, config, credentials, env)
    if result.get("signature_status") != "verified":
        raise ValueError("Artifact signature verification failed")
    # The portal pins Cosign 2.x, which uses this interoperable signature tag.
    # A tool/version writing elsewhere fails closed rather than dropping signatures.
    tag = "sha256-" + reference.rsplit("@sha256:", 1)[1] + ".sig"
    _, _, data = client.request("GET", client.api + "/manifests/" + tag)
    digest = release_oci._digest(data)
    descriptor = transport.graph(client, digest)
    transport.entry(descriptor, layout_name)
    return {"tag": tag, "digest": digest, "layout_name": layout_name, **result}


def _publish_files(client, files):
    layers = []
    for name, path in files.items():
        descriptor = client.upload(path.read_bytes(), release_oci._media_type(name))
        descriptor["annotations"] = {"org.opencontainers.image.title": name}
        layers.append(descriptor)
    config = client.upload(b"{}", "application/vnd.oci.empty.v1+json")
    content = canonical({"schemaVersion": 2, "mediaType": release_oci.MANIFEST_TYPE,
                         "config": config, "layers": layers,
                         "annotations": {"io.cats.release.type": "cyber-approved-v1"}})
    digest = release_oci._digest(content)
    status, _, _ = client.request("PUT", client.api + "/manifests/" + digest,
                                 body=content, media_type=release_oci.MANIFEST_TYPE)
    if status != 201:
        raise ValueError("Release document publication failed")
    return digest


def image_source(reference):
    """Validate/normalize a container reference, allowing a tag when scan identity is absent."""
    from .overview import parse_image_reference
    if not isinstance(reference, str) or not reference or any(c.isspace() for c in reference) or '://' in reference or reference.count('@') > 1 or '//' in reference or reference.startswith('/') or reference.endswith(('/', ':')):
        raise ValueError('Invalid retained image reference')
    parsed = parse_image_reference(reference)
    repository = '/'.join(part for part in (parsed['repository'], parsed['artifact']) if part != '—')
    identity = parsed['digest'] if '@' in reference else parsed['version']
    if '@' in reference:
        release_oci._reference(parsed['registry'] + '/' + repository + '@' + identity)
    else:
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', identity):
            raise ValueError('Invalid retained image tag')
        release_oci._reference(parsed['registry'] + '/' + repository + '@sha256:' + '0' * 64)
    return parsed['registry'], repository, identity


def _publish_image_archive(client, item, env, work, index):
    """Reuse the existing Skopeo Docker-archive delivery format, then verify the OCI graph."""
    path = _checked_file(item)
    skopeo = shutil.which('skopeo')
    if not skopeo:
        raise ValueError('Skopeo is required to publish a retained remediation image archive')
    digestfile = work / f'image-{index}.digest'
    certdir = work / 'image-certs'
    certdir.mkdir(exist_ok=True)
    if env.get('SSL_CERT_FILE'):
        shutil.copyfile(env['SSL_CERT_FILE'], certdir / 'ca.crt')
    # Credentials/trust come from the same scoped destination environment used by OCI signing.
    destination = client.api.removeprefix('https://').replace('/v2/', '/', 1) + ':retained'
    subprocess.run([skopeo, 'copy', '--authfile', str(Path(env['DOCKER_CONFIG']) / 'config.json'),
        '--dest-cert-dir', str(certdir), '--digestfile', str(digestfile),
        'docker-archive:' + str(path), 'docker://' + destination],
        env=env, capture_output=True, check=True, timeout=600)
    digest = digestfile.read_text().strip()
    if not release_oci._DIGEST.fullmatch(digest):
        raise ValueError('Image archive publication did not return an OCI digest')
    return digest


def _publish_chart(client, item):
    """Retain the approved chart bytes as the Helm OCI content layer."""
    path = _checked_file(item)
    content = path.read_bytes()
    with tarfile.open(path, "r:gz") as archive:
        metadata = [member for member in archive.getmembers()
                    if member.name.count("/") == 1 and member.name.endswith("/Chart.yaml")]
        if len(metadata) != 1 or not metadata[0].isfile() or metadata[0].size > 1024 * 1024:
            raise ValueError("Retained Helm chart metadata is invalid")
        chart = yaml.safe_load(archive.extractfile(metadata[0]).read())
        if not isinstance(chart, dict) or not all(chart.get(key) for key in ("apiVersion", "name", "version")):
            raise ValueError("Retained Helm chart metadata is incomplete")
    if release_oci._digest(content) != item["digest"]:
        raise ValueError("Frozen Helm chart changed during publication")
    config = client.upload(canonical(chart), "application/vnd.cncf.helm.config.v1+json")
    layer = client.upload(content, "application/vnd.cncf.helm.chart.content.v1.tar+gzip")
    encoded = canonical({"schemaVersion": 2, "mediaType": release_oci.MANIFEST_TYPE,
                         "config": config, "layers": [layer]})
    digest = release_oci._digest(encoded)
    status, _, _ = client.request("PUT", client.api + "/manifests/" + digest,
                                 body=encoded, media_type=release_oci.MANIFEST_TYPE)
    if status != 201:
        raise ValueError("Approved Helm chart publication failed")
    return digest


def publish(db, approval, destination, checkpoint):
    """Publish exactly approval.snapshot, never reconstructing live evidence.

    snapshot = {artifacts: [{kind, reference, digest}], evidence: {path, digest},
                candidate?: {path, digest}, ...frozen policy/provenance...}
    approval.snapshot_digest is SHA-256 of canonical(snapshot); release_key is
    a safe identifier. Destination is an already-authorized saved destination.
    """
    receipt = {"status": "publishing", "artifacts": [], "destination_id": str(destination["id"]),
               "approval_id": approval.id, "release_key": approval.release_key,
               "resolved_images": dict((getattr(approval, "publication", None) or {}).get("resolved_images", {}))}

    def save():
        checkpoint(deepcopy(receipt))

    try:
        snapshot = deepcopy(approval.snapshot)
        if release_oci._digest(canonical(snapshot)) != approval.snapshot_digest:
            raise ValueError("Approval snapshot integrity mismatch")
        if (approval.status != "approved" or not approval.decided_by_id or not approval.decided_at
                or not approval.decision_rationale or approval.revoked_at):
            raise ValueError("A current recorded Cyber approval decision is required")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", approval.release_key):
            raise ValueError("Invalid release identifier")
        evidence = _checked_file(snapshot["evidence"])
        candidate = _checked_file(snapshot["candidate"]) if snapshot.get("candidate") else None
        artifacts = snapshot.get("artifacts")
        if not artifacts or len(artifacts) > 512:
            raise ValueError("Frozen deployable inventory unavailable")
        for item in artifacts:
            if item.get("path") and (item.get("kind") == "chart" or (item.get("kind") == "image" and item.get("format") == "docker-archive")):
                _checked_file(item)
                continue
            if item.get('kind') == 'image' and item.get('resolve_at_publication') and item.get('digest') is None:
                image_source(item['reference'])
                continue
            _, _, digest = image_source(item["reference"])
            if not release_oci._DIGEST.fullmatch(digest) or item.get("digest") != digest or item.get("kind") not in {"chart", "image"}:
                raise ValueError("Frozen deployable identity mismatch")
        settings = {row.key: row.value for row in db.scalars(select(PortalSetting))}
        config, credentials = signing.job_material(settings, "push")
        if config.get("signing_enabled") is not True or not shutil.which("cosign"):
            raise ValueError("Cyber-approved releases require configured Cosign signing")
        if config["signing_fingerprint"] != snapshot.get("signing_fingerprint"):
            raise ValueError("Signing identity changed after approval request")
        if any(snapshot.get("destination", {}).get(key) != destination.get(key) for key in ("id", "endpoint", "namespace")):
            raise ValueError("Publication destination differs from approved snapshot")
        save()
        output = evidence.parent / "publications" / hashlib.sha256(str(destination["id"]).encode()).hexdigest()[:24]
        output.mkdir(parents=True, exist_ok=True)
        if any(p.is_symlink() for p in (output, *output.parents)):
            raise ValueError("Unsafe publication output path")
        with tempfile.TemporaryDirectory(prefix=".publication-", dir=output) as temporary:
            root = Path(temporary)
            evidence_copy = root / "evidence.zip"
            shutil.copyfile(evidence, evidence_copy)
            if file_digest(evidence_copy) != snapshot["evidence"]["digest"]:
                raise ValueError("Frozen evidence changed during copy")
            if candidate:
                shutil.copyfile(candidate, root / "candidate.zip")
                if file_digest(root / "candidate.zip") != snapshot["candidate"]["digest"]:
                    raise ValueError("Frozen candidate changed during copy")
            documents = {"evidence.zip": evidence_copy}
            archive_signature = release_signing.sign_release_archive(evidence_copy, root, (config, credentials))
            if archive_signature.get("signature_status") != "verified":
                raise ValueError("Evidence signing failed")
            (root / "documentation.zip.sig").rename(root / "evidence.zip.sig")
            documents["evidence.zip.sig"] = root / "evidence.zip.sig"
            documents["release-public-key.pem"] = root / "release-public-key.pem"
            with registry_environment(destination) as environment, _source_environments(settings) as (source_env, source_envs):
                env = signing.clean_environment(environment)
                transport = _Transport(root / "oci", env)
                host = destination["endpoint"].removeprefix("https://").rstrip("/")
                prefix = "/".join(filter(None, (destination.get("namespace", ""), "cyber-approved", approval.release_key.lower())))
                for index, item in enumerate(artifacts):
                    check_worker()
                    repository = f"{prefix}/{item['kind']}-{index}"
                    target = release_oci._Client(host, repository, env)
                    if item.get("path"):
                        digest = (_publish_image_archive(target, item, env, root, index)
                            if item.get('format') == 'docker-archive' else _publish_chart(target, item))
                        descriptor = transport.graph(target, digest)
                    else:
                        source_host, source_repository, digest = image_source(item["reference"])
                        retrieval_env = env if source_host == host else source_envs.get(source_host, source_env)
                        source = release_oci._Client(source_host, source_repository, retrieval_env)
                        if item.get('resolve_at_publication'):
                            retained = receipt['resolved_images'].get(str(index))
                            if retained:
                                if not release_oci._DIGEST.fullmatch(retained):
                                    raise ValueError('Invalid retained publication image identity')
                                digest = retained
                            else:
                                _, _, content = source.request('GET', source.api + '/manifests/' + digest,
                                    limit=release_oci.MAX_MANIFEST_BYTES)
                                digest = release_oci._digest(content)
                                receipt['resolved_images'][str(index)] = digest
                                save()  # Retries must not resolve a moved tag again.
                        descriptor = transport.graph(source, digest, target)
                    name = f"artifact-{index}"
                    transport.entry(descriptor, name)
                    reference = f"{host}/{repository}@{digest}"
                    artifact = {"kind": item["kind"], "source_reference": item.get("reference"),
                                "source_references": item.get("source_references", [item["reference"]] if item.get("reference") else []),
                                "name": item.get("name"), "version": item.get("version"),
                                "source_digest": item["digest"] or digest,
                                "scan_identity_retained": not bool(item.get('resolve_at_publication')),
                                "identity_resolution": 'publication' if item.get('resolve_at_publication') else 'retained-evidence',
                                "reference": reference, "digest": digest, "layout_name": name,
                                "repository_suffix": f"{item['kind']}-{index}", "verification_status": "verified"}
                    receipt["artifacts"].append(artifact)
                    save()
                    artifact["signature"] = _signature(transport, target, reference, config, credentials, env, name + "-signature")
                    save()
                manifest = {"format": "cats-cyber-approved-release-v1", "release_key": approval.release_key,
                            "approval_id": approval.id, "snapshot_digest": approval.snapshot_digest,
                            "approval": {"id": approval.id, "status": approval.status,
                                         "decided_by_id": approval.decided_by_id,
                                         "decided_at": approval.decided_at.isoformat(),
                                         "decision_rationale": approval.decision_rationale},
                            "destination": deepcopy(snapshot["destination"]),
                            "snapshot": _public_snapshot(snapshot),
                            "snapshot_paths_redacted": True,
                            "evidence": {"path": "evidence.zip", "digest": snapshot["evidence"]["digest"]},
                            "artifacts": receipt["artifacts"], "signing_fingerprint": config["signing_fingerprint"]}
                if candidate:
                    manifest["candidate"] = {"path": "candidate.zip", "digest": snapshot["candidate"]["digest"]}
                manifest_path = root / "release-manifest.json"
                manifest_path.write_bytes(canonical(manifest))
                signed = release_signing.sign_release_manifest(manifest_path, root, (config, credentials))
                if signed.get("signature_status") != "verified":
                    raise ValueError("Release manifest signing failed")
                documents.update({name: root / name for name in ("release-manifest.json", "release-manifest.sig")})
                client = release_oci._Client(host, prefix + "/release", env)
                digest = _publish_files(client, documents)
                descriptor = transport.graph(client, digest)
                transport.entry(descriptor, "release")
                reference = f"{host}/{prefix}/release@{digest}"
                receipt["release"] = {"reference": reference, "digest": digest, "layout_name": "release", "repository_suffix": "release"}
                receipt["release"]["signature"] = _signature(transport, client, reference, config, credentials, env, "release-signature")
                save()
                (root / "transport.json").write_bytes(canonical({"format": "cats-cyber-transport-v1", "artifacts": receipt["artifacts"] + [receipt["release"]]}))
                # Bind the transport inventory (including release/signature identities)
                # in a separate detached signature to avoid a self-referential manifest.
                transport_sign = release_signing._sign_release_blob(root / "transport.json", root, (config, credentials),
                                                                   "transport.sig", "transport_sha256", "transport.json")
                if transport_sign.get("signature_status") != "verified":
                    raise ValueError("Transport inventory signing failed")
                (root / "verify-import.py").write_text(OFFLINE_SCRIPT, encoding="utf-8")
                (root / "README.txt").write_text(
                    "Extract into an empty directory. Requires Python 3 and Cosign 2.x.\n"
                    "Obtain the signing key fingerprint independently from your Cyber approver.\n"
                    "Verify without registry/network access:\n"
                    "  python verify-import.py --fingerprint sha256:<trusted-key-fingerprint>\n"
                    "Import requires ORAS 1.2+ and prior oras/cosign registry login and trusted CA configuration:\n"
                    "  python verify-import.py --fingerprint sha256:<trusted-key-fingerprint> --destination registry.example/team/release\n"
                    "Every OCI manifest and layer, signature, signed evidence and release manifest is included.\n"
                    "release-manifest.json maps every source image/chart to its approved digest reference; imports print the new mapping.\n"
                    "Apply environment-specific chart/image overrides before deployment; retained charts are never rewritten after approval.\n"
                    "Operators must configure registry access controls, immutability and retention, and deployment signature/admission policies.\n"
                    "Publication alone does not restrict repository access or enforce approved-only deployment.\n",
                    encoding="utf-8")
                verify_local(root, config["signing_fingerprint"])
                archive = root / "offline-bundle.zip"
                with ZipFile(archive, "w", ZIP_DEFLATED, allowZip64=True) as bundle:
                    for path in sorted(root.rglob("*")):
                        if path.is_file() and path != archive:
                            bundle.write(path, path.relative_to(root).as_posix())
                with ZipFile(archive) as bundle:
                    if bundle.testzip() is not None:
                        raise ValueError("Offline archive verification failed")
                bundle_digest = file_digest(archive)
                target = output / (bundle_digest[7:] + ".zip")
                os.replace(archive, target)
                receipt.update(status="published", verification_status="verified", signature_status="verified",
                               manifest=manifest, bundle_path=str(target), bundle_digest=bundle_digest,
                               bundle_bytes=target.stat().st_size, signing_fingerprint=config["signing_fingerprint"])
                save()
        return receipt
    except Exception as exc:
        receipt.update(status="failed", error="Cyber release publication did not complete. Verify retained evidence, signing keys, registry access and worker tools before retrying.")
        save()
        raise PublicationError(receipt) from exc


def verify_local(root, fingerprint):
    """Execute exactly the offline verifier delivered to the recipient."""
    namespace = {"__name__": "cats_offline_verifier", "__file__": str(Path(root) / "verify-import.py")}
    exec(compile(OFFLINE_SCRIPT, namespace["__file__"], "exec"), namespace)
    namespace["verify"](Path(root), fingerprint)


OFFLINE_SCRIPT = r'''#!/usr/bin/env python3
"""Verify and optionally import a CATS Cyber-approved release. No portal needed."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def digest(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


def run(args):
    result = subprocess.run(args, check=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=600)
    return result.stdout


def blob(root, descriptor):
    value = descriptor["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("Invalid content digest")
    content = (root / "oci" / "blobs" / "sha256" / value[7:]).read_bytes()
    if digest(content) != value or len(content) != descriptor["size"]:
        raise ValueError("OCI content verification failed")
    return content


def graph(root, descriptor, depth=0):
    if depth > 32:
        raise ValueError("OCI graph too deep")
    value = json.loads(blob(root, descriptor))
    for item in value.get("manifests", []):
        graph(root, item, depth + 1)
    for item in ([value["config"]] if "config" in value else []) + value.get("layers", []):
        blob(root, item)
    return value


def verify_remote(root, target, descriptor, depth=0):
    if depth > 32:
        raise ValueError("Imported OCI graph too deep")
    encoded = run(["oras", "manifest", "fetch", target + "@" + descriptor["digest"]])
    if encoded != blob(root, descriptor):
        raise ValueError("Imported manifest digest changed")
    value = json.loads(encoded)
    for item in value.get("manifests", []):
        verify_remote(root, target, item, depth + 1)
    for item in ([value["config"]] if "config" in value else []) + value.get("layers", []):
        retrieved = run(["oras", "blob", "fetch", "--output", "-", target + "@" + item["digest"]])
        if len(retrieved) != item["size"] or digest(retrieved) != item["digest"]:
            raise ValueError("Imported OCI layer digest changed")


def verify(root, fingerprint):
    public = root / "release-public-key.pem"
    pem = public.read_text()
    der = base64.b64decode("".join(line for line in pem.splitlines() if not line.startswith("---")), validate=True)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint) or digest(der) != fingerprint:
        raise ValueError("Signing key does not match independently trusted fingerprint")
    for name, signature in (("release-manifest.json", "release-manifest.sig"),
                            ("evidence.zip", "evidence.zip.sig"), ("transport.json", "transport.sig")):
        run(["cosign", "verify-blob", "--key", str(public), "--signature", str(root / signature),
             "--insecure-ignore-tlog=true", "--offline", str(root / name)])
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    if manifest["signing_fingerprint"] != fingerprint:
        raise ValueError("Release signing identity mismatch")
    for name in ("evidence", "candidate"):
        if name in manifest:
            file = "evidence.zip" if name == "evidence" else "candidate.zip"
            if digest((root / file).read_bytes()) != manifest[name]["digest"]:
                raise ValueError("Retained evidence digest mismatch")
    entries = json.loads((root / "oci" / "index.json").read_bytes())["manifests"]
    index = {item["annotations"]["org.opencontainers.image.ref.name"]: item for item in entries}
    if len(index) != len(entries):
        raise ValueError("Duplicate OCI layout reference")
    transport = json.loads((root / "transport.json").read_bytes())
    if transport["artifacts"][:-1] != manifest["artifacts"]:
        raise ValueError("Transport inventory differs from signed approval manifest")
    for artifact in transport["artifacts"]:
        entry = index[artifact["layout_name"]]
        if entry["digest"] != artifact["digest"]:
            raise ValueError("Transport artifact identity mismatch")
        graph(root, entry)
        signature = artifact["signature"]
        signed_entry = index[signature["layout_name"]]
        if signed_entry["digest"] != signature["digest"]:
            raise ValueError("Transport signature identity mismatch")
        signed = graph(root, signed_entry)
        verified = False
        # A registry signature tag may also contain other trusted identities.
        for layer in signed.get("layers", []):
            value = layer.get("annotations", {}).get("dev.cosignproject.cosign/signature")
            if not value:
                continue
            payload = blob(root, layer)
            if json.loads(payload).get("critical", {}).get("image", {}).get("docker-manifest-digest") != artifact["digest"]:
                raise ValueError("Cosign payload binds a different artifact")
            with tempfile.TemporaryDirectory(prefix="cats-offline-verify-") as folder:
                payload_path, signature_path = Path(folder) / "payload", Path(folder) / "signature"
                payload_path.write_bytes(payload)
                signature_path.write_text(value)
                try:
                    run(["cosign", "verify-blob", "--key", str(public), "--signature", str(signature_path),
                         "--insecure-ignore-tlog=true", "--offline", str(payload_path)])
                    verified = True
                except subprocess.CalledProcessError:
                    continue
        if not verified:
            raise ValueError("No verified offline signature for artifact")
    return transport


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprint", required=True, help="Independently trusted SHA-256 public-key fingerprint")
    parser.add_argument("--destination", help="Target registry/namespace/release, without scheme or tag")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    inventory = verify(root, args.fingerprint)
    print("Offline release, evidence, all OCI layers and artifact signatures verified.")
    if args.destination:
        prefix = args.destination
        if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+", prefix) or ".." in prefix:
            raise ValueError("Destination must be a credential-free registry/repository")
        entries = json.loads((root / "oci" / "index.json").read_bytes())["manifests"]
        index = {item["annotations"]["org.opencontainers.image.ref.name"]: item for item in entries}
        for artifact in inventory["artifacts"]:
            suffix = artifact["repository_suffix"]
            if not re.fullmatch(r"(?:image-[0-9]+|chart-[0-9]+|release)", suffix):
                raise ValueError("Invalid destination suffix")
            target = prefix + "/" + suffix
            source = str(root / "oci") + ":" + artifact["layout_name"]
            run(["oras", "cp", "--from-oci-layout", source, target + ":approved"])
            verify_remote(root, target, index[artifact["layout_name"]])
            signature = artifact["signature"]
            tag = "sha256-" + artifact["digest"][7:] + ".sig"
            if signature["tag"] != tag:
                raise ValueError("Invalid signature destination tag")
            run(["oras", "cp", "--from-oci-layout", str(root / "oci") + ":" + signature["layout_name"], target + ":" + tag])
            if digest(run(["oras", "manifest", "fetch", target + ":" + tag])) != signature["digest"]:
                raise ValueError("Imported signature digest changed")
            verify_remote(root, target, index[signature["layout_name"]])
            reference = target + "@" + artifact["digest"]
            run(["cosign", "verify", "--key", str(root / "release-public-key.pem"), "--insecure-ignore-tlog=true", "--offline", reference])
            print(json.dumps({"sources": artifact.get("source_references", []), "name": artifact.get("name"),
                              "version": artifact.get("version"), "published_reference": artifact["reference"],
                              "imported_reference": reference}, sort_keys=True))


if __name__ == "__main__":
    main()
'''
