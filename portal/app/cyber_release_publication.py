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
import ssl
from urllib.error import URLError
import subprocess
import tarfile
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy import select
import yaml

from . import release_oci, release_signing, signing
from .delivery_execution import delivery_lock
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


class PublicationValidationError(ValueError):
    """Only fixed, credential-free validation messages from this module."""


def failure_diagnostic(exc, stage):
    """Keep validated origins and fixed diagnostics. Omit URL paths, queries and tool output."""
    detail = {"stage": stage, "cause": "Unexpected publication error; inspect the worker using the correlation ID."}
    reason = exc.reason if isinstance(exc, URLError) else exc
    if isinstance(exc, PublicationValidationError):
        detail["cause"] = str(exc)
    elif isinstance(exc, release_oci._RedirectError):
        detail.update(http_status=int(exc.status), cause=exc.cause, redirect_reason=exc.reason)
        for key in ("operation", "registry_origin", "redirect_from_origin", "redirect_origin"):
            value = getattr(exc, key)
            if value:
                detail[key] = value
    elif isinstance(exc, release_oci._RegistryError):
        detail["http_status"] = int(exc.status)
        detail["cause"] = {
            401: "Registry authentication was rejected. Check the saved registry credentials.",
            403: "Registry access was denied. Check repository pull/push permissions.",
            404: "The registry image, manifest or repository was not found.",
            429: "The registry rate limit was exceeded. Retry later.",
        }.get(exc.status, "The registry rejected the request.")
        if exc.status in (301, 302, 303, 307, 308):
            detail["cause"] = "The registry returned a redirect that could not be followed. Check registry and storage redirect configuration."
    elif isinstance(reason, ssl.SSLError):
        detail["cause"] = "TLS verification or negotiation failed. Check the registry certificate and trusted CA."
    elif isinstance(exc, PermissionError):
        detail["cause"] = "The worker cannot access a required file or directory. Check mount ownership and permissions."
    elif isinstance(exc, FileNotFoundError):
        detail["cause"] = "A required worker file or executable was not found."
    elif isinstance(exc, (subprocess.TimeoutExpired, TimeoutError)):
        detail["cause"] = "The publication operation timed out."
    elif isinstance(exc, subprocess.CalledProcessError):
        detail["exit_code"] = int(exc.returncode)
        detail["cause"] = "A publication tool exited unsuccessfully."
    elif isinstance(exc, (URLError, ConnectionError)):
        detail["cause"] = "The worker could not connect to the registry or authentication service. Check network access and DNS."
    elif isinstance(exc, OSError):
        detail["cause"] = "A worker filesystem or operating system operation failed."
        if isinstance(exc.errno, int):
            detail["os_error"] = exc.errno
    return detail


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
                raise PublicationValidationError("Source registry configuration is ambiguous")
            env = dict(base)
            if row.get("ca_file"):
                env["SSL_CERT_FILE"] = row["ca_file"]
            environments[host] = env
        yield base, environments


def _checked_file(value):
    path = Path(value["path"])
    if (not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents))
            or not path.is_file() or file_digest(path) != value["digest"]):
        raise PublicationValidationError("Frozen release evidence is missing or changed")
    return path


def _descriptor(item):
    if (not isinstance(item, dict) or not release_oci._DIGEST.fullmatch(item.get("digest", ""))
            or not isinstance(item.get("size"), int) or item["size"] < 0
            or not isinstance(item.get("mediaType"), str)):
        raise PublicationValidationError("Invalid OCI descriptor")
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
            raise PublicationValidationError("Release transport limits must be positive")

    def retain(self, descriptor, content):
        _descriptor(descriptor)
        if len(content) != descriptor["size"] or release_oci._digest(content) != descriptor["digest"]:
            raise PublicationValidationError("OCI content digest or size mismatch")
        path = self.blobs / descriptor["digest"][7:]
        if not path.exists():
            self.total += len(content)
            if self.total > self.limit:
                raise PublicationValidationError("Offline release exceeds transport size limit")
            path.write_bytes(content)
        return path

    def graph(self, source, digest, target=None, depth=0, seen=None):
        check_worker()
        if depth > 32:
            raise PublicationValidationError("OCI graph nesting exceeds limit")
        seen = set() if seen is None else seen
        if digest in seen:
            raise PublicationValidationError("Cyclic OCI graph")
        seen = seen | {digest}
        if not release_oci._DIGEST.fullmatch(digest):
            raise PublicationValidationError("Invalid OCI manifest digest")
        _, headers, data = source.request("GET", source.api + "/manifests/" + digest)
        document = json.loads(data)
        descriptor = {"digest": digest, "size": len(data),
                      "mediaType": document.get("mediaType") or headers.get_content_type()}
        self.retain(descriptor, data)
        children = document.get("manifests", [])
        if not isinstance(children, list):
            raise PublicationValidationError("Invalid OCI index")
        for child in children:
            _descriptor(child)
            actual = self.graph(source, child["digest"], target, depth + 1, seen)
            if any(actual[k] != child[k] for k in ("digest", "size", "mediaType")):
                raise PublicationValidationError("OCI child descriptor mismatch")
        blobs = ([document["config"]] if "config" in document else []) + document.get("layers", [])
        if not children and not blobs:
            raise PublicationValidationError("Empty OCI artifact graph")
        for item in blobs:
            check_worker()
            _descriptor(item)
            if item["size"] > self.blob_limit:
                raise PublicationValidationError("OCI layer exceeds configured transport size limit")
            _, _, content = source.request("GET", source.api + "/blobs/" + item["digest"], limit=item["size"])
            self.retain(item, content)
            if target is not None:
                target.upload(content, item["mediaType"])
                _, _, retrieved = target.request("GET", target.api + "/blobs/" + item["digest"], limit=item["size"])
                if retrieved != content:
                    raise PublicationValidationError("Destination OCI blob verification failed")
        if target is not None:
            status, _, _ = target.request("PUT", target.api + "/manifests/" + digest,
                                         body=data, media_type=descriptor["mediaType"])
            if status != 201:
                raise PublicationValidationError("Destination did not accept immutable manifest")
            _, _, retrieved = target.request("GET", target.api + "/manifests/" + digest)
            if retrieved != data:
                raise PublicationValidationError("Destination OCI manifest verification failed")
        return descriptor

    def entry(self, descriptor, name):
        self.entries.append({**descriptor, "annotations": {"org.opencontainers.image.ref.name": name}})
        (self.root / "oci-layout").write_bytes(canonical({"imageLayoutVersion": "1.0.0"}))
        (self.root / "index.json").write_bytes(canonical({"schemaVersion": 2, "manifests": self.entries}))

    def tag(self, client, descriptor, tag):
        url = client.api + "/manifests/" + tag
        try:
            _, _, existing = client.request("GET", url)
        except release_oci._RegistryError as exc:
            if exc.status != 404:
                raise
        else:
            if release_oci._digest(existing) == descriptor["digest"]:
                return
            raise PublicationValidationError("The release tag already identifies different content")
        content = (self.blobs / descriptor["digest"][7:]).read_bytes()
        status, _, _ = client.request("PUT", url, body=content, media_type=descriptor["mediaType"])
        if status != 201:
            raise PublicationValidationError("Destination did not accept the release tag")
        _, _, retrieved = client.request("GET", url)
        if release_oci._digest(retrieved) != descriptor["digest"]:
            raise PublicationValidationError("Release tag verification failed")


def _signature(transport, client, reference, config, credentials, env, layout_name):
    result = signing.sign_and_verify(reference, config, credentials, env)
    if result.get("signature_status") != "verified":
        raise PublicationValidationError("Artifact signature verification failed")
    # The portal pins Cosign 2.x, which uses this interoperable signature tag.
    # A tool/version writing elsewhere fails closed rather than dropping signatures.
    tag = "sha256-" + reference.rsplit("@sha256:", 1)[1] + ".sig"
    _, _, data = client.request("GET", client.api + "/manifests/" + tag)
    digest = release_oci._digest(data)
    descriptor = transport.graph(client, digest)
    transport.entry(descriptor, layout_name)
    retention_tag = 'cats-signature-' + digest[7:]
    transport.tag(client, descriptor, retention_tag)
    return {"tag": tag, "digest": digest, "layout_name": layout_name,
            "retention_tag": retention_tag, **result}


def _attestations(transport, client, reference, evidence, config, credentials, env, layout_name):
    """Publish and pin only this approval's verified native Cosign envelopes.

    Cosign appends to a mutable per-subject tag. Rebuild an inert manifest from
    the exact new predicate so prior approvals or key rotations cannot change
    the immutable inventory retained by this release.
    """
    from .oci_attestations import ATTESTATION_TYPE, attest_and_verify, verify_envelope, AttestationError
    receipt = attest_and_verify(reference, 'cyber-approval', evidence, (config, credentials), env)
    subject = reference.rsplit('@', 1)[1]
    tag = subject.replace(':', '-', 1) + '.att'
    _, _, raw = client.request('GET', client.api + '/manifests/' + tag)
    document = json.loads(raw)
    layers = document.get('layers')
    if not isinstance(layers, list) or not 1 <= len(layers) <= 64:
        raise PublicationValidationError('Published attestation manifest is invalid')
    retained = []
    for layer in layers:
        _descriptor(layer)
        if layer['mediaType'] != ATTESTATION_TYPE or layer['size'] > 1024 * 1024:
            continue
        _, _, payload = client.request('GET', client.api + '/blobs/' + layer['digest'], limit=layer['size'])
        if len(payload) != layer['size'] or release_oci._digest(payload) != layer['digest']:
            raise PublicationValidationError('Published attestation content changed')
        try:
            verify_envelope(payload, subject, config['signing_public_key'].encode(),
                            config['signing_fingerprint'], receipt)
        except (AttestationError, ValueError):
            continue
        retained.append(layer)
    if not retained:
        raise PublicationValidationError('Published attestation does not bind the approved evidence')
    empty = client.upload(b'{}', 'application/vnd.oci.empty.v1+json')
    raw = canonical({'schemaVersion': 2, 'mediaType': release_oci.MANIFEST_TYPE,
                     'config': empty, 'layers': retained})
    digest = release_oci._digest(raw)
    status, _, _ = client.request('PUT', client.api + '/manifests/' + tag,
                                body=raw, media_type=release_oci.MANIFEST_TYPE)
    if status != 201:
        raise PublicationValidationError('Attestation publication failed')
    descriptor = transport.graph(client, digest)
    transport.entry(descriptor, layout_name)
    retention_tag = 'cats-attestation-' + digest[7:]
    transport.tag(client, descriptor, retention_tag)
    return {**descriptor, 'tag': tag, 'layout_name': layout_name, 'retention_tag': retention_tag, 'receipts': [receipt],
            'blobs': sorted({empty['digest'], *(layer['digest'] for layer in retained)})}


def _publish_files(client, files, *, portable=False):
    layers = []
    for name, path in files.items():
        descriptor = client.upload(path.read_bytes(), release_oci._media_type(name))
        descriptor["annotations"] = {"org.opencontainers.image.title": name}
        layers.append(descriptor)
    config = client.upload(b"{}", "application/vnd.oci.empty.v1+json")
    content = canonical({"schemaVersion": 2, "mediaType": release_oci.MANIFEST_TYPE,
                         **({'artifactType': 'application/vnd.cats.approved-release.v1'} if portable else {}),
                         "config": config, "layers": layers,
                         "annotations": {"io.cats.release.type": "cyber-approved-v1"}})
    digest = release_oci._digest(content)
    status, _, _ = client.request("PUT", client.api + "/manifests/" + digest,
                                 body=content, media_type=release_oci.MANIFEST_TYPE)
    if status != 201:
        raise PublicationValidationError("Release document publication failed")
    return digest


def image_source(reference):
    """Validate/normalize a container reference, allowing a tag when scan identity is absent."""
    from .overview import parse_image_reference
    if not isinstance(reference, str) or not reference or any(c.isspace() for c in reference) or '://' in reference or reference.count('@') > 1 or '//' in reference or reference.startswith('/') or reference.endswith(('/', ':')):
        raise PublicationValidationError('Invalid retained image reference')
    parsed = parse_image_reference(reference)
    repository = '/'.join(part for part in (parsed['repository'], parsed['artifact']) if part != '—')
    identity = parsed['digest'] if '@' in reference else parsed['version']
    if '@' in reference:
        release_oci._reference(parsed['registry'] + '/' + repository + '@' + identity)
    else:
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', identity):
            raise PublicationValidationError('Invalid retained image tag')
        release_oci._reference(parsed['registry'] + '/' + repository + '@sha256:' + '0' * 64)
    return parsed['registry'], repository, identity


def _repository_component(value):
    """Preserve ordinary Service IDs and chart names without aliasing unsafe names."""
    if not isinstance(value, str) or not value:
        raise PublicationValidationError("Approved repository name is missing")
    if "/" not in value and release_oci._REPOSITORY.fullmatch(value) and not value.startswith("cats-id-"):
        return value
    return "cats-id-" + hashlib.sha256(value.encode()).hexdigest()


def _publish_image_archive(client, item, env, work, index):
    """Reuse the existing Skopeo Docker-archive delivery format, then verify the OCI graph."""
    path = _checked_file(item)
    skopeo = shutil.which('skopeo')
    if not skopeo:
        raise PublicationValidationError('Skopeo is required to publish a retained remediation image archive')
    digestfile = work / f'image-{index}.digest'
    certdir = work / 'image-certs'
    certdir.mkdir(exist_ok=True)
    if env.get('SSL_CERT_FILE'):
        shutil.copyfile(env['SSL_CERT_FILE'], certdir / 'ca.crt')
    # Credentials/trust come from the same scoped destination environment used by OCI signing.
    destination = client.api.removeprefix('https://').replace('/v2/', '/', 1) + ':retained-' + item['digest'][7:]
    subprocess.run([skopeo, 'copy', '--authfile', str(Path(env['DOCKER_CONFIG']) / 'config.json'),
        '--dest-tls-verify=true', '--dest-cert-dir', str(certdir), '--digestfile', str(digestfile),
        'docker-archive:' + str(path), 'docker://' + destination],
        env=env, capture_output=True, check=True, timeout=600)
    digest = digestfile.read_text().strip()
    if not release_oci._DIGEST.fullmatch(digest):
        raise PublicationValidationError('Image archive publication did not return an OCI digest')
    return digest


def _publish_chart(client, item):
    """Retain the approved chart bytes as the Helm OCI content layer."""
    path = _checked_file(item)
    content = path.read_bytes()
    with tarfile.open(path, "r:gz") as archive:
        metadata = [member for member in archive.getmembers()
                    if member.name.count("/") == 1 and member.name.endswith("/Chart.yaml")]
        if len(metadata) != 1 or not metadata[0].isfile() or metadata[0].size > 1024 * 1024:
            raise PublicationValidationError("Retained Helm chart metadata is invalid")
        chart = yaml.safe_load(archive.extractfile(metadata[0]).read())
        if not isinstance(chart, dict) or not all(chart.get(key) for key in ("apiVersion", "name", "version")):
            raise PublicationValidationError("Retained Helm chart metadata is incomplete")
    if release_oci._digest(content) != item["digest"]:
        raise PublicationValidationError("Frozen Helm chart changed during publication")
    config = client.upload(canonical(chart), "application/vnd.cncf.helm.config.v1+json")
    layer = client.upload(content, "application/vnd.cncf.helm.chart.content.v1.tar+gzip")
    encoded = canonical({"schemaVersion": 2, "mediaType": release_oci.MANIFEST_TYPE,
                         "config": config, "layers": [layer]})
    digest = release_oci._digest(encoded)
    status, _, _ = client.request("PUT", client.api + "/manifests/" + digest,
                                 body=encoded, media_type=release_oci.MANIFEST_TYPE)
    if status != 201:
        raise PublicationValidationError("Approved Helm chart publication failed")
    return digest


def publish(db, approval, destination, checkpoint):
    """Publish exactly approval.snapshot, never reconstructing live evidence.

    snapshot = {artifacts: [{kind, reference, digest}], evidence: {path, digest},
                candidate?: {path, digest}, ...frozen policy/provenance...}
    approval.snapshot_digest is SHA-256 of canonical(snapshot); release_key is
    a safe identifier. Destination is an already-authorized saved destination.
    """
    from . import release_validity
    receipt = {"status": "publishing", "artifacts": [], "destination_id": str(destination["id"]),
               "approval_id": approval.id, "release_key": approval.release_key,
               "resolved_images": dict((getattr(approval, "publication", None) or {}).get("resolved_images", {}))}

    def save():
        if receipt['status'] != 'failed':
            release_validity.require_current(approval)
        checkpoint(deepcopy(receipt))

    stage = "Checking retained evidence"
    try:
        snapshot = deepcopy(approval.snapshot)
        if release_oci._digest(canonical(snapshot)) != approval.snapshot_digest:
            raise PublicationValidationError("Approval snapshot integrity mismatch")
        if (approval.status != "approved" or not approval.decided_by_id or not approval.decided_at
                or not approval.decision_rationale or approval.revoked_at):
            raise PublicationValidationError("A current recorded Cyber approval decision is required")
        release_validity.require_current(approval)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", approval.release_key):
            raise PublicationValidationError("Invalid release identifier")
        evidence = _checked_file(snapshot["evidence"])
        from .portable_release import evidence_capture, validate_metadata, release_tag
        try:
            portable = validate_metadata(snapshot.get('portable_release'))
            captured = evidence_capture(evidence.read_bytes())
        except ValueError as exc:
            raise PublicationValidationError(str(exc)) from None
        if captured['service_key'] != portable['service_uuid']:
            raise PublicationValidationError('Frozen service capture differs from the approved portable identity')
        candidate = _checked_file(snapshot["candidate"]) if snapshot.get("candidate") else None
        artifacts = snapshot.get("artifacts")
        if not artifacts:
            raise PublicationValidationError("Frozen deployable inventory unavailable")
        for item in artifacts:
            if item.get("path") and (item.get("kind") == "chart" or (item.get("kind") == "image" and item.get("format") == "docker-archive")):
                _checked_file(item)
                continue
            if item.get('kind') == 'image' and item.get('resolve_at_publication') and item.get('digest') is None:
                image_source(item['reference'])
                continue
            _, _, digest = image_source(item["reference"])
            if not release_oci._DIGEST.fullmatch(digest) or item.get("digest") != digest or item.get("kind") not in {"chart", "image"}:
                raise PublicationValidationError("Frozen deployable identity mismatch")
        stage = "Checking signing configuration"
        settings = {row.key: row.value for row in db.scalars(select(PortalSetting))}
        config, credentials = signing.job_material(settings, "push")
        config = {**config, 'approval_annotations': release_validity.annotations(approval.release_key, snapshot['approval_validity'])}
        if config.get("signing_enabled") is not True or not shutil.which("cosign"):
            raise PublicationValidationError("Cyber-approved releases require configured Cosign signing")
        if config["signing_fingerprint"] != snapshot.get("signing_fingerprint"):
            raise PublicationValidationError("Signing identity changed after approval request")
        from .release_key_rotation import manifest_identity
        publisher_identity = manifest_identity(settings, portable['service_uuid'], portable['release_sequence'])
        if any(snapshot.get("destination", {}).get(key) != destination.get(key) for key in ("id", "endpoint", "namespace")):
            raise PublicationValidationError("Publication destination differs from approved snapshot")
        save()
        stage = "Preparing publication files"
        output = evidence.parent / "publications" / hashlib.sha256(str(destination["id"]).encode()).hexdigest()[:24]
        output.mkdir(parents=True, exist_ok=True)
        if any(p.is_symlink() for p in (output, *output.parents)):
            raise PublicationValidationError("Unsafe publication output path")
        with tempfile.TemporaryDirectory(prefix=".publication-", dir=output) as temporary:
            root = Path(temporary)
            evidence_copy = root / "evidence.zip"
            shutil.copyfile(evidence, evidence_copy)
            if file_digest(evidence_copy) != snapshot["evidence"]["digest"]:
                raise PublicationValidationError("Frozen evidence changed during copy")
            if candidate:
                shutil.copyfile(candidate, root / "candidate.zip")
                if file_digest(root / "candidate.zip") != snapshot["candidate"]["digest"]:
                    raise PublicationValidationError("Frozen candidate changed during copy")
            documents = {"evidence.zip": evidence_copy}
            if candidate:
                documents['candidate.zip'] = root / 'candidate.zip'
            stage = "Signing retained evidence"
            archive_signature = release_signing.sign_release_archive(evidence_copy, root, (config, credentials))
            if archive_signature.get("signature_status") != "verified":
                raise PublicationValidationError("Evidence signing failed")
            (root / "documentation.zip.sig").rename(root / "evidence.zip.sig")
            documents["evidence.zip.sig"] = root / "evidence.zip.sig"
            documents["release-public-key.pem"] = root / "release-public-key.pem"
            stage = "Preparing registry authentication"
            # Resolve current portal-managed trust in the executing worker, not
            # from its startup environment or the frozen approval snapshot.
            certificates = settings.get("trusted_ca_certificates", "[]")
            if isinstance(certificates, str):
                certificates = json.loads(certificates)
            with registry_environment(destination, certificates or []) as environment, _source_environments(settings) as (source_env, source_envs):
                env = signing.clean_environment(environment)
                retained_receipt = output / 'portable-publication.json'
                if retained_receipt.exists():
                    from .portable_release import fetch_release
                    previous = json.loads(retained_receipt.read_bytes())
                    verified = fetch_release(previous['release']['reference'], env,
                                             [publisher_identity.get('publisher_root', config['signing_fingerprint'])])
                    bundle_path = Path(previous['bundle_path'])
                    if (verified['manifest'].get('snapshot_digest') != approval.snapshot_digest
                            or verified['manifest'] != previous['manifest']
                            or not bundle_path.resolve().is_relative_to(output.resolve())
                            or file_digest(bundle_path) != previous['bundle_digest']):
                        raise PublicationValidationError('Retained publication integrity mismatch')
                    with ZipFile(bundle_path) as bundle:
                        if bundle.read('release-manifest.json') != verified['files']['release-manifest.json']:
                            raise PublicationValidationError('Retained bundle belongs to a different release')
                    receipt = previous
                    # A worker can stop after retaining the complete package but
                    # before exposing its discovery tag. Reuse its exact signed
                    # bytes rather than generating a different signature graph.
                    cached_host, cached_repository, cached_digest = release_oci._reference(previous['release']['reference'])
                    cached_client = release_oci._Client(cached_host, cached_repository, env)
                    cached_transport = _Transport(root / 'cached-oci', env)
                    cached_descriptor = cached_transport.graph(cached_client, cached_digest)
                    cached_transport.tag(cached_client, cached_descriptor, release_tag(portable))
                    if snapshot.get('release_revision') is not None and not receipt.get('revision_signature'):
                        from .release_revisions import publish_manifest
                        stage = 'Signing immutable release revision'
                        receipt['revision_signature'] = publish_manifest(db, approval, (config, credentials))
                        _retain_receipt(retained_receipt, receipt)
                    save()
                    return receipt
                transport = _Transport(root / "oci", env)
                host = destination["endpoint"].removeprefix("https://").rstrip("/")
                namespace = destination.get("namespace") or "cyber-approved"
                prefix = namespace + "/" + _repository_component(snapshot["service_key"])
                for index, item in enumerate(artifacts):
                    check_worker()
                    stage = f"Transferring and verifying artifact {index + 1} of {len(artifacts)}"
                    if item["kind"] == "image":
                        _, source_name, _ = image_source(item["reference"])
                        repository = prefix + "/" + source_name.rsplit("/", 1)[-1]
                    else:
                        chart_name = item.get("name") or image_source(item["reference"])[1].rsplit("/", 1)[-1]
                        repository = prefix + "/charts/" + _repository_component(chart_name)
                    target = release_oci._Client(host, repository, env)
                    if item.get("path"):
                        digest = (_publish_image_archive(target, item, env, root, index)
                            if item.get('format') == 'docker-archive' else _publish_chart(target, item))
                        descriptor = transport.graph(target, digest)
                    else:
                        source_host, source_repository, digest = image_source(item["reference"])
                        retrieval_env = env if source_host == host else source_envs.get(source_host, source_env)
                        source = release_oci._Client(source_host, source_repository, retrieval_env, pull_only=True)
                        if item.get('resolve_at_publication'):
                            retained = receipt['resolved_images'].get(str(index))
                            if retained:
                                if not release_oci._DIGEST.fullmatch(retained):
                                    raise PublicationValidationError('Invalid retained publication image identity')
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
                    tag = f"approval-{approval.id}-{index + 1}"
                    transport.tag(target, descriptor, tag)
                    reference = f"{host}/{repository}@{digest}"
                    artifact = {"kind": item["kind"], "source_reference": item.get("reference"),
                                "source_references": item.get("source_references", [item["reference"]] if item.get("reference") else []),
                                "name": item.get("name"), "version": item.get("version"),
                                "source_digest": item["digest"] or digest,
                                "scan_identity_retained": not bool(item.get('resolve_at_publication')),
                                "identity_resolution": 'publication' if item.get('resolve_at_publication') else 'retained-evidence',
                                "reference": reference, "digest": digest, "layout_name": name, "tag": tag,
                                "repository_suffix": f"{item['kind']}-{index}", "verification_status": "verified"}
                    receipt["artifacts"].append(artifact)
                    save()
                    stage = f"Signing and verifying artifact {index + 1} of {len(artifacts)}"
                    # Cosign appends approval annotations to a shared per-digest signature tag.
                    with delivery_lock(evidence.parent.parent / ".signatures", snapshot["service_id"], wait=True) as owned:
                        if not owned:
                            raise PublicationValidationError("Another release is signing this service. Retry publication.")
                        check_worker()
                        artifact["signature"] = _signature(transport, target, reference, config, credentials, env, name + "-signature")
                        artifact['attestation'] = _attestations(transport, target, reference,
                            {'approval-snapshot': approval.snapshot_digest, 'evidence.zip': snapshot['evidence']['digest']},
                            config, credentials, env, name + '-attestation')
                    save()
                manifest = {"format": "cats-cyber-approved-release-v1", "release_key": approval.release_key,
                            "portable": portable, **publisher_identity,
                            "approval_id": approval.id, "snapshot_digest": approval.snapshot_digest,
                            "approval": {"id": approval.id, "status": approval.status,
                                         **snapshot['approval_validity'],
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
                stage = "Signing release manifest"
                signed = release_signing.sign_release_manifest(manifest_path, root, (config, credentials))
                if signed.get("signature_status") != "verified":
                    raise PublicationValidationError("Release manifest signing failed")
                documents.update({name: root / name for name in ("release-manifest.json", "release-manifest.sig")})
                release_repository = prefix + "/releases"
                client = release_oci._Client(host, release_repository, env)
                stage = "Publishing release documents"
                digest = _publish_files(client, documents, portable=True)
                descriptor = transport.graph(client, digest)
                transport.entry(descriptor, "release")
                reference = f"{host}/{release_repository}@{digest}"
                receipt["release"] = {"reference": reference, "digest": digest, "tag": release_tag(portable), "layout_name": "release", "repository_suffix": "release"}
                stage = "Signing published release"
                receipt["release"]["signature"] = _signature(transport, client, reference, config, credentials, env, "release-signature")
                save()
                (root / "transport.json").write_bytes(canonical({"format": "cats-cyber-transport-v1", "artifacts": receipt["artifacts"] + [receipt["release"]]}))
                # Bind the transport inventory (including release/signature identities)
                # in a separate detached signature to avoid a self-referential manifest.
                stage = "Signing transport inventory"
                transport_sign = release_signing._sign_release_blob(root / "transport.json", root, (config, credentials),
                                                                   "transport.sig", "transport_sha256", "transport.json")
                if transport_sign.get("signature_status") != "verified":
                    raise PublicationValidationError("Transport inventory signing failed")
                (root / "verify-import.py").write_text(OFFLINE_SCRIPT, encoding="utf-8")
                (root / "README.txt").write_text(
                    "Extract into an empty directory. Requires Python 3 and Cosign 2.x.\n"
                    "Obtain the original publisher trust fingerprint independently from your Cyber approver.\n"
                    "Verify without registry/network access:\n"
                    "  python verify-import.py --fingerprint sha256:<trusted-key-fingerprint>\n"
                    "Import requires ORAS 1.2+ and prior oras/cosign registry login and trusted CA configuration:\n"
                    "  python verify-import.py --fingerprint sha256:<trusted-key-fingerprint> --destination registry.example/team/release\n"
                    "Every OCI manifest and layer, signature, signed evidence and release manifest is included.\n"
                    "Verification/import rejects expired approvals; registry transfers never extend their validity.\n"
                    "Use a trusted UTC clock. Generic cosign verify checks authenticity, not approval expiry.\n"
                    "release-manifest.json maps every source image/chart to its approved digest reference; imports print the new mapping.\n"
                    "Apply environment-specific chart/image overrides before deployment; retained charts are never rewritten after approval.\n"
                    "Operators must configure registry access controls, immutability and retention, and deployment signature/admission policies.\n"
                    "Publication alone does not restrict repository access or enforce approved-only deployment.\n",
                    encoding="utf-8")
                stage = "Verifying offline bundle"
                verify_local(root, publisher_identity.get("publisher_root", config["signing_fingerprint"]))
                stage = "Packaging offline bundle"
                archive = root / "offline-bundle.zip"
                with ZipFile(archive, "w", ZIP_DEFLATED, allowZip64=True) as bundle:
                    for path in sorted(root.rglob("*")):
                        if path.is_file() and path != archive:
                            bundle.write(path, path.relative_to(root).as_posix())
                with ZipFile(archive) as bundle:
                    if bundle.testzip() is not None:
                        raise PublicationValidationError("Offline archive verification failed")
                bundle_digest = file_digest(archive)
                target = output / (bundle_digest[7:] + ".zip")
                os.replace(archive, target)
                receipt.update(status="published", verification_status="verified", signature_status="verified",
                               manifest=manifest, bundle_path=str(target), bundle_digest=bundle_digest,
                               bundle_bytes=target.stat().st_size, signing_fingerprint=config["signing_fingerprint"])
                # Retain exact signatures before exposing discovery, so an
                # interrupted attempt resumes the same immutable package.
                _retain_receipt(retained_receipt, receipt)
                stage = 'Publishing complete release discovery tag'
                transport.tag(client, descriptor, release_tag(portable))
                save()
        if snapshot.get('release_revision') is not None:
            from .release_revisions import publish_manifest
            stage = "Signing immutable release revision"
            receipt['revision_signature'] = publish_manifest(db, approval, (config, credentials))
            _retain_receipt(retained_receipt, receipt)
            save()
        return receipt
    except Exception as exc:
        diagnostic = failure_diagnostic(exc, stage)
        receipt.update(status="failed", diagnostic=diagnostic, error=f"{stage}: {diagnostic['cause']}")
        save()
        raise PublicationError(receipt) from exc


def _retain_receipt(path, receipt):
    pending = path.with_suffix('.pending')
    pending.write_bytes(canonical(receipt))
    os.replace(pending, path)


def publish_revocation(db, approval, destination, metadata, checkpoint):
    """Publish a standalone signed event through the existing release repository.

    The sequence was reserved in the revocation transaction. No live evidence is
    rebuilt and the original approval snapshot and publication stay immutable.
    """
    from .portable_release import validate_metadata, release_tag, fetch_release
    from . import release_validity
    receipt = {'status': 'publishing', 'kind': 'revocation', 'approval_id': approval.id,
               'portable': metadata}
    stage = 'Checking signed revocation authorization'
    try:
        validate_metadata(metadata)
        if (metadata.get('kind') != 'revocation' or not approval.revoked_at
                or metadata.get('target_release_uuid') != str(approval.id)
                or metadata.get('revoked_at') != release_validity.utc(approval.revoked_at).isoformat()
                or metadata.get('reason') != approval.revocation_reason):
            raise PublicationValidationError('Revocation differs from the recorded Cyber decision')
        settings = {row.key: row.value for row in db.scalars(select(PortalSetting))}
        config, credentials = signing.job_material(settings, 'push')
        from .release_key_rotation import authorized_successor, manifest_identity
        if config.get('signing_enabled') is not True or not authorized_successor(settings, approval.snapshot.get('signing_fingerprint')):
            raise PublicationValidationError('An authenticated successor of the original publisher key is required to publish this revocation')
        publisher_identity = manifest_identity(settings, metadata['service_uuid'], metadata['release_sequence'])
        if any(approval.snapshot.get('destination', {}).get(key) != destination.get(key) for key in ('id', 'endpoint', 'namespace')):
            raise PublicationValidationError('Revocation destination differs from the approved release')
        checkpoint(deepcopy(receipt))
        output = Path(approval.snapshot['evidence']['path']).parent / ('revocation-' + str(metadata['release_sequence']))
        if any(path.is_symlink() for path in (output, *output.parents)):
            raise PublicationValidationError('Unsafe revocation output path')
        output.mkdir(parents=True, exist_ok=True)
        manifest = {'format': 'cats-cyber-release-v1', 'portable': metadata, **publisher_identity,
                    'release_key': approval.release_key, 'snapshot_digest': approval.snapshot_digest,
                    'approval': {'id': approval.id, 'status': 'approved',
                                 **approval.snapshot['approval_validity'],
                                 'decided_by_id': approval.decided_by_id,
                                 'decided_at': release_validity.utc(approval.decided_at).isoformat()},
                    'signing_fingerprint': config['signing_fingerprint'], 'artifacts': []}
        content = canonical(manifest)
        path = output / 'release-manifest.json'
        if path.exists() and path.read_bytes() != content:
            raise PublicationValidationError('Retained revocation event changed')
        path.write_bytes(content)
        stage = 'Signing revocation event'
        signed = release_signing.sign_release_manifest(path, output, (config, credentials))
        if signed.get('signature_status') != 'verified':
            raise PublicationValidationError('Revocation signing failed')
        certificates = settings.get('trusted_ca_certificates', '[]')
        if isinstance(certificates, str):
            certificates = json.loads(certificates)
        with registry_environment(destination, certificates or []) as environment:
            env = signing.clean_environment(environment)
            host = destination['endpoint'].removeprefix('https://').rstrip('/')
            repository = destination['namespace'].strip('/') + '/' + _repository_component(approval.snapshot['service_key']) + '/releases'
            client = release_oci._Client(host, repository, env)
            stage = 'Publishing revocation event'
            digest = _publish_files(client, {name: output / name for name in
                ('release-manifest.json', 'release-manifest.sig', 'release-public-key.pem')}, portable=True)
            reference = host + '/' + repository + '@' + digest
            verified = fetch_release(reference, env,
                                     [publisher_identity.get('publisher_root', config['signing_fingerprint'])])
            if verified['manifest'] != manifest:
                raise PublicationValidationError('Published revocation verification failed')
            with tempfile.TemporaryDirectory(prefix='.transport-', dir=output) as temporary:
                transport = _Transport(Path(temporary) / 'oci', env)
                descriptor = transport.graph(client, digest)
                checkpoint(deepcopy(receipt))
                transport.tag(client, descriptor, release_tag(metadata))
        receipt.update(status='published', signature_status='verified', verification_status='verified',
                       manifest=manifest, release={'reference': reference, 'digest': digest, 'tag': release_tag(metadata)},
                       signing_fingerprint=config['signing_fingerprint'])
        checkpoint(deepcopy(receipt))
        return receipt
    except Exception as exc:
        diagnostic = failure_diagnostic(exc, stage)
        receipt.update(status='failed', diagnostic=diagnostic, error=f"{stage}: {diagnostic['cause']}")
        checkpoint(deepcopy(receipt))
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
from datetime import datetime, timedelta, timezone
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


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate attestation JSON key')
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def public_fingerprint(pem):
    if not isinstance(pem, str) or len(pem) > 32768:
        raise ValueError('Invalid publisher public key')
    lines = pem.splitlines()
    if len(lines) < 3 or lines[0] != '-----BEGIN PUBLIC KEY-----' or lines[-1] != '-----END PUBLIC KEY-----':
        raise ValueError('Invalid publisher public key')
    der = base64.b64decode(''.join(lines[1:-1]), validate=True)
    encoded = base64.b64encode(der).decode()
    normalized = '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + '\n-----END PUBLIC KEY-----\n'
    if normalized != pem:
        raise ValueError('Noncanonical publisher public key')
    return digest(der)


def verify_publisher(manifest, pem, fingerprint):
    signer = public_fingerprint(pem)
    if not isinstance(fingerprint, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', fingerprint):
        raise ValueError('Invalid independently trusted publisher fingerprint')
    if manifest.get('signing_fingerprint') != signer:
        raise ValueError('Release signing identity mismatch')
    chain = manifest.get('signing_key_chain', [])
    if not chain:
        if chain != [] or manifest.get('publisher_root', signer) != signer or fingerprint != signer:
            raise ValueError('Signing key does not match independently trusted fingerprint')
        return
    if not isinstance(chain, list) or len(chain) > 32 or len(canonical(chain)) > 4 * 1024 * 1024:
        raise ValueError('Invalid publisher key transition chain size')
    fields = {'format', 'publisher_root', 'generation', 'previous_digest', 'from_fingerprint',
              'to_fingerprint', 'from_public_key', 'to_public_key', 'service_cutovers'}
    previous, keys, prior_cutovers = None, [fingerprint], {}
    with tempfile.TemporaryDirectory(prefix='cats-offline-key-transition-') as temporary:
        certificate_path, signature_path, public_path = (Path(temporary) / name for name in ('certificate', 'signature', 'public.pem'))
        for generation, entry in enumerate(chain, 1):
            if not isinstance(entry, dict) or set(entry) != {'certificate', 'from_signature', 'to_signature'}:
                raise ValueError('Malformed publisher key transition')
            certificate = entry['certificate']
            if not isinstance(certificate, dict) or set(certificate) != fields:
                raise ValueError('Malformed publisher key transition certificate')
            if (certificate['format'] != 'cats-publisher-key-transition-v1'
                    or type(certificate['generation']) is not int or certificate['generation'] != generation
                    or certificate['previous_digest'] != previous or certificate['publisher_root'] != fingerprint
                    or certificate['from_fingerprint'] != keys[-1] or certificate['to_fingerprint'] in keys):
                raise ValueError('Publisher key transition order or identity mismatch')
            for field in ('publisher_root', 'from_fingerprint', 'to_fingerprint'):
                if not isinstance(certificate[field], str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', certificate[field]):
                    raise ValueError('Invalid publisher key fingerprint')
            cutovers = certificate['service_cutovers']
            if (not isinstance(cutovers, dict) or len(cutovers) > 10000
                    or any(not isinstance(service, str) or not 1 <= len(service) <= 120
                           or type(sequence) is not int or not 1 <= sequence <= 2147483647
                           for service, sequence in cutovers.items())
                    or any(service not in cutovers or cutovers[service] < sequence for service, sequence in prior_cutovers.items())):
                raise ValueError('Invalid or regressing service sequence cutover')
            certificate_path.write_bytes(canonical(certificate))
            for prefix in ('from', 'to'):
                public = certificate[prefix + '_public_key']
                signature = entry[prefix + '_signature']
                if (public_fingerprint(public) != certificate[prefix + '_fingerprint']
                        or not isinstance(signature, str) or not 1 <= len(signature) <= 16384):
                    raise ValueError('Invalid publisher key transition proof')
                public_path.write_text(public, encoding='utf-8')
                signature_path.write_text(signature, encoding='utf-8')
                run(['cosign', 'verify-blob', '--key', str(public_path), '--signature', str(signature_path),
                     '--insecure-ignore-tlog=true', '--offline', str(certificate_path)])
            keys.append(certificate['to_fingerprint'])
            previous, prior_cutovers = digest(canonical(entry)), cutovers
    metadata = manifest.get('portable', {})
    sequence, service = metadata.get('release_sequence'), metadata.get('service_uuid')
    if (manifest.get('publisher_root') != fingerprint or signer != keys[-1]
            or type(sequence) is not int or not isinstance(service, str)
            or sequence < prior_cutovers.get(service, 1)):
        raise ValueError('Release is outside its certified signing key interval')


def retention_tag(kind, inventory):
    expected = 'cats-' + kind + '-' + inventory['digest'][7:]
    if inventory.get('retention_tag', expected) != expected:
        raise ValueError('Invalid immutable ' + kind + ' retention tag')
    return expected


def verify_attestations(root, artifact, index, public):
    inventory = artifact.get('attestation')
    if 'attestation' not in artifact:
        return
    if (not isinstance(inventory, dict) or not isinstance(inventory.get('receipts'), list)
            or not 1 <= len(inventory['receipts']) <= 64
            or inventory.get('tag') != artifact['digest'].replace(':', '-', 1) + '.att'):
        raise ValueError('Invalid attestation inventory')
    entry = index[inventory['layout_name']]
    if any(entry.get(key) != inventory.get(key) for key in ('digest', 'size', 'mediaType')):
        raise ValueError('Attestation transport identity mismatch')
    attested = graph(root, entry)
    layers = attested.get('layers')
    if (attested.get('schemaVersion') != 2 or 'manifests' in attested
            or entry['mediaType'] not in ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
            or ('subject' in attested and (not isinstance(attested['subject'], dict)
                or attested['subject'].get('digest') != artifact['digest']))
            or not isinstance(layers, list) or not 1 <= len(layers) <= 64
            or sorted({attested['config']['digest'], *(layer['digest'] for layer in layers)}) != inventory['blobs']):
        raise ValueError('Attestation graph differs from signed inventory')
    config = attested['config']
    if (config['size'] > 1024 * 1024 or config.get('mediaType') not in (
            'application/vnd.oci.empty.v1+json', 'application/vnd.oci.image.config.v1+json',
            'application/vnd.docker.container.image.v1+json')):
        raise ValueError('Invalid attestation configuration')
    value = json.loads(blob(root, config), object_pairs_hook=unique_object)
    zero = '0001-01-01T00:00:00Z'
    if (not isinstance(value, dict) or (value and (
            config['mediaType'] == 'application/vnd.oci.empty.v1+json'
            or set(value) - {'architecture', 'os', 'config', 'rootfs', 'created', 'history'}
            or value.get('architecture', '') not in ('', 'unknown') or value.get('os', '') not in ('', 'unknown')
            or value.get('config', {}) != {} or ('created' in value and value['created'] != zero)
            or ('history' in value and value['history'] != [{'created': zero} for _ in layers])
            or value.get('rootfs') != {'type': 'layers', 'diff_ids': [layer['digest'] for layer in layers]}))):
        raise ValueError('Attestation configuration is not inert metadata')
    matched = set()
    for layer in layers:
        if layer.get('mediaType') != 'application/vnd.dsse.envelope.v1+json' or layer['size'] > 1024 * 1024:
            raise ValueError('Invalid attestation layer')
        envelope = json.loads(blob(root, layer), object_pairs_hook=unique_object)
        if envelope.get('payloadType') != 'application/vnd.in-toto+json':
            raise ValueError('Invalid attestation payload type')
        payload = base64.b64decode(envelope['payload'], validate=True)
        statement = json.loads(payload, object_pairs_hook=unique_object)
        if (statement.get('_type') not in ('https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1')
                or len(statement.get('subject', [])) != 1
                or statement['subject'][0].get('digest') != {'sha256': artifact['digest'][7:]}):
            raise ValueError('Attestation subject mismatch')
        matches = []
        for number, receipt in enumerate(inventory['receipts']):
            purpose, evidence = receipt['purpose'], receipt['evidence']
            if (purpose not in ('scan', 'patch', 'deployment-validation', 'cyber-approval', 'release')
                    or receipt['predicate_type'] != 'https://cats.security/attestations/' + purpose + '/v1'
                    or not isinstance(evidence, dict) or not 1 <= len(evidence) <= 64
                    or any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', key)
                           or not re.fullmatch(r'sha256:[0-9a-f]{64}', value) for key, value in evidence.items())):
                raise ValueError('Invalid typed attestation evidence')
            predicate = dict(schemaVersion=1, subject=receipt['subject'], purpose=receipt['purpose'], evidence=receipt['evidence'])
            if (receipt['subject'] == artifact['reference'] and statement.get('predicate') == predicate
                    and statement.get('predicateType') == receipt['predicate_type']):
                matches.append(number)
        if len(matches) != 1:
            raise ValueError('Attestation predicate differs from signed inventory')
        payload_type = envelope['payloadType'].encode()
        pae = b'DSSEv1 ' + str(len(payload_type)).encode() + b' ' + payload_type + b' ' + str(len(payload)).encode() + b' ' + payload
        signatures = envelope.get('signatures')
        if not isinstance(signatures, list) or not 1 <= len(signatures) <= 64:
            raise ValueError('Invalid attestation signature list')
        verified = False
        with tempfile.TemporaryDirectory(prefix='cats-attestation-offline-') as temporary:
            payload_path, signature_path = Path(temporary) / 'pae', Path(temporary) / 'signature'
            payload_path.write_bytes(pae)
            for signature in signatures:
                base64.b64decode(signature['sig'], validate=True)
                signature_path.write_text(signature['sig'])
                try:
                    run(['cosign', 'verify-blob', '--key', str(public), '--signature', str(signature_path),
                         '--insecure-ignore-tlog=true', '--offline', str(payload_path)])
                    verified = True
                    break
                except subprocess.CalledProcessError:
                    pass
        if not verified:
            raise ValueError('Attestation signature verification failed')
        matched.add(matches[0])
    if matched != set(range(len(inventory['receipts']))):
        raise ValueError('Incomplete attestation inventory')


def approval_window(manifest, now=None):
    try:
        approval = manifest['approval']
        start = datetime.fromisoformat(approval['approved_at'])
        end = datetime.fromisoformat(approval['expires_at'])
        days = approval['validity_days']
        validity = {key: approval[key] for key in ('approved_at', 'expires_at', 'validity_days')}
        if 'owning_group_id' in approval:
            group_id = approval['owning_group_id']
            if type(group_id) is not int or group_id <= 0:
                raise ValueError()
            validity['owning_group_id'] = group_id
        decision = datetime.fromisoformat(approval['decided_at'])
        # Retained database dates may be naive UTC; signed validity dates must carry a zone.
        if decision.tzinfo is None:
            decision = decision.replace(tzinfo=timezone.utc)
        if (start.utcoffset() is None or end.utcoffset() is None or type(days) is not int
                or not 1 <= days <= 3650 or end - start != timedelta(days=days)
                or start != decision or approval['status'] != 'approved'
                or manifest['snapshot']['approval_validity'] != validity):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError('Missing or invalid signed approval expiry. Request Cyber approval again.') from None
    now = now or datetime.now(timezone.utc)
    if now < start:
        raise ValueError('Cyber approval is not yet valid. Check the system clock.')
    if now >= end:
        raise ValueError('Cyber approval has expired. Request Cyber approval again.')
    return {'io.cats.approval.type': 'cyber-approved-v1',
            'io.cats.approval.release': manifest['release_key'],
            'io.cats.approval.approved-at': approval['approved_at'],
            'io.cats.approval.expires-at': approval['expires_at']}


def verify(root, fingerprint):
    public = root / "release-public-key.pem"
    pem = public.read_text()
    for name, signature in (("release-manifest.json", "release-manifest.sig"),
                            ("evidence.zip", "evidence.zip.sig"), ("transport.json", "transport.sig")):
        run(["cosign", "verify-blob", "--key", str(public), "--signature", str(root / signature),
             "--insecure-ignore-tlog=true", "--offline", str(root / name)])
    manifest = json.loads((root / "release-manifest.json").read_bytes(), object_pairs_hook=unique_object)
    verify_publisher(manifest, pem, fingerprint)
    expected_annotations = approval_window(manifest)
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
        for kind in ('signature', 'attestation'):
            if kind in artifact:
                retention_tag(kind, artifact[kind])
        entry = index[artifact["layout_name"]]
        if entry["digest"] != artifact["digest"]:
            raise ValueError("Transport artifact identity mismatch")
        graph(root, entry)
        verify_attestations(root, artifact, index, public)
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
            annotations = json.loads(payload).get('optional') or {}
            if any(annotations.get(key) != value for key, value in expected_annotations.items()):
                continue
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
    approval_window(manifest)
    return transport


def copy_attachment(root, target, inventory, index, kind):
    # Preserve each approved graph when a later import moves the native tag.
    source = str(root / 'oci') + ':' + inventory['layout_name']
    for tag in (inventory['tag'], retention_tag(kind, inventory)):
        run(['oras', 'cp', '--from-oci-layout', source, target + ':' + tag])
        if digest(run(['oras', 'manifest', 'fetch', target + ':' + tag])) != inventory['digest']:
            raise ValueError('Imported ' + kind + ' digest changed')
    verify_remote(root, target, index[inventory['layout_name']])


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
            approval_window(json.loads((root / 'release-manifest.json').read_bytes()))
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
            copy_attachment(root, target, signature, index, 'signature')
            attestation = artifact.get('attestation')
            if attestation is not None:
                tag = 'sha256-' + artifact['digest'][7:] + '.att'
                if attestation['tag'] != tag:
                    raise ValueError('Invalid attestation destination tag')
                copy_attachment(root, target, attestation, index, 'attestation')
            reference = target + "@" + artifact["digest"]
            expected = approval_window(json.loads((root / 'release-manifest.json').read_bytes()))
            annotation_args = [arg for key, value in sorted(expected.items()) for arg in ('-a', key + '=' + value)]
            run(["cosign", "verify", "--key", str(root / "release-public-key.pem"), "--insecure-ignore-tlog=true", "--offline", *annotation_args, reference])
            print(json.dumps({"sources": artifact.get("source_references", []), "name": artifact.get("name"),
                              "version": artifact.get("version"), "published_reference": artifact["reference"],
                              "imported_reference": reference}, sort_keys=True))
        approval_window(json.loads((root / 'release-manifest.json').read_bytes()))


if __name__ == "__main__":
    main()
'''
