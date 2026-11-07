"""Explicit acceptance helpers for actual scanned and patched nginx approvals.

This module creates no fixture evidence, starts no services, changes no database
rows directly, and never stops a registry. The caller supplies actual publication
receipts, authenticated requests.Session objects and disposable deployment URLs.
Keep machine secrets in the session's auth property, not in report JSON.

Registry copy, run inside an application image with the app package available::

    SSL_CERT_FILE=/verification/tls/registry.crt python \
        /workspace/portal/tests/nginx_replica_acceptance.py copy \
        --receipt-file /verification/receipt.json --root /verification/copy \
        --source-host publisher.test:5000 --target-host replica.test:5000

The receipt file may hold one published receipt or a list of published receipts.
HTTP helpers are imported by the full acceptance runner; they do not log in or
provision users, since those steps belong to the normal application workflow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import quote, urlsplit
import uuid
import zipfile


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z")
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError("Expected an exact SHA-256 digest")
    return value


def _base(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise ValueError("Use an explicit HTTP(S) base URL without credentials or query")
    return value.rstrip("/")


def _repository(value):
    if not isinstance(value, str) or not REPOSITORY.fullmatch(value):
        raise ValueError("Expected an explicit OCI repository path")
    return value


def copy_receipt(receipt, root, env, source_host, target_host):
    """Copy every receipt graph and attachment, then publish discovery last.

    Uses the exact-byte production transport, preserving repository paths and
    signed digests. Trust verification still happens through the replica's
    independently configured publisher pin during normal synchronization.
    """
    from app import cyber_release_publication as publication, release_oci

    if not isinstance(receipt, dict) or receipt.get("status") != "published":
        raise ValueError("Supply an actual completed publication receipt")
    if any(receipt.get(key) != "verified" for key in ("verification_status", "signature_status")):
        raise ValueError("Publication must have completed signature and content verification")
    if source_host == target_host:
        raise ValueError("Source and target registries must be different")
    for host in (source_host, target_host):
        release_oci._reference(host + "/validation/reference@sha256:" + "0" * 64)
    artifacts = receipt.get("artifacts", [])
    release = receipt.get("release")
    if not isinstance(artifacts, list) or not isinstance(release, dict):
        raise ValueError("Receipt must include its immutable release document")
    if not artifacts and receipt.get("kind") != "revocation":
        raise ValueError("An approved image release must contain actual artifacts")
    manifest = receipt.get("manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("portable"), dict):
        raise ValueError("Receipt must contain the actual portable signed manifest")

    # Validate the whole supplied inventory before making any target writes.
    inventory = []
    for item in [*artifacts, release]:
        if not isinstance(item, dict):
            raise ValueError("Invalid receipt artifact")
        host, repository, digest = release_oci._reference(item.get("reference"))
        if host != source_host or item.get("digest") != digest:
            raise ValueError("Receipt reference must match the explicit source host and digest")
        if not isinstance(item.get("tag"), str) or not re.fullmatch(r"[\w][\w.-]{0,127}", item["tag"], re.ASCII):
            raise ValueError("Receipt must contain a valid publication tag")
        if item.get("signature") is None and item is not release:
            raise ValueError("Every approved artifact must have an immutable signature descriptor")
        for kind in ("signature", "attestation"):
            if kind not in item:
                continue
            attachment = item[kind]
            if not isinstance(attachment, dict):
                raise ValueError("Invalid immutable " + kind + " descriptor")
            _digest(attachment.get("digest"))
            retention = attachment.get("retention_tag")
            if retention is not None and (not isinstance(retention, str)
                    or not re.fullmatch(r"[\w][\w.-]{0,127}", retention, re.ASCII)):
                raise ValueError("Invalid immutable attachment retention tag")
        inventory.append((item, repository, digest))

    # Production transport intentionally requires a new layout. A fresh child
    # makes a repeated acceptance invocation safe without deleting evidence.
    transport = publication._Transport(Path(root) / ("receipt-" + uuid.uuid4().hex), dict(env))
    copied = []
    for item, repository, digest in inventory:
        source = release_oci._Client(source_host, repository, env)
        target = release_oci._Client(target_host, repository, env)
        descriptor = transport.graph(source, digest, target)
        attachment_digests = {}
        for kind in ("signature", "attestation"):
            if item.get(kind):
                attachment = item[kind]
                attachment_digests[kind] = attachment["digest"]
                retained = transport.graph(source, attachment["digest"], target)
                if attachment.get("retention_tag"):
                    transport.tag(target, retained, attachment["retention_tag"])
        # The release document is last in inventory, so its discovery tag is
        # exposed only after all artifact, signature and attestation graphs exist.
        transport.tag(target, descriptor, item["tag"])
        copied.append({"source_reference": item["reference"],
                       "target_reference": target_host + "/" + repository + "@" + digest,
                       "digest": digest, "tag": item["tag"],
                       "signature_digest": attachment_digests.get("signature"),
                       "attestation_digest": attachment_digests.get("attestation")})
    return {"approval_id": receipt.get("approval_id"), "copied": copied,
            "artifact_count": len(artifacts), "discovery_tag_copied_last": True}


def pull_graph(session, proxy_base, repository, digest, auth=None, *, timeout=120,
               max_bytes=20 * 1024**3, max_objects=20000, max_depth=32):
    """Download and hash every manifest/config/layer through the real OCI proxy.

    No client content cache is used. Blobs stream through SHA-256 rather than
    accumulating in memory; only manifest JSON is retained while traversing.
    Limits fail the acceptance run explicitly, never truncate a graph.
    """
    root_digest = _digest(digest)
    endpoint = _base(proxy_base) + "/v2/" + _repository(repository)
    if any(type(value) is not int or value < 1 for value in (max_bytes, max_objects, max_depth)):
        raise ValueError("Graph limits must be positive integers")
    manifests, blobs = {}, {}
    total = 0

    def fetch(kind, identity, expected_size=None):
        nonlocal total
        _digest(identity)
        _require(len(manifests) + len(blobs) < max_objects, "OCI graph object limit exceeded")
        response = session.get(endpoint + "/" + kind + "/" + identity, auth=auth,
                               headers={"Accept": ACCEPT, "Accept-Encoding": "identity"},
                               timeout=timeout, allow_redirects=False, stream=True)
        try:
            _require(response.status_code == 200,
                     f"OCI {kind} {identity} returned HTTP {response.status_code}")
            _require(response.headers.get("Content-Encoding", "identity") == "identity",
                     "OCI response unexpectedly applied content encoding")
            declared_digest = response.headers.get("Docker-Content-Digest")
            _require(declared_digest == identity, "OCI response digest header differs from requested digest")
            length = response.headers.get("Content-Length")
            _require(isinstance(length, str) and length.isdigit(), "OCI response requires exact Content-Length")
            declared_size = int(length)
            if expected_size is not None:
                _require(declared_size == expected_size, "OCI descriptor and Content-Length differ")
            _require(total + declared_size <= max_bytes, "OCI graph byte limit exceeded")
            if kind == "manifests":
                _require(declared_size <= 4 * 1024**2, "OCI manifest exceeds 4 MiB")
            checksum, size, content = hashlib.sha256(), 0, bytearray()
            for part in response.iter_content(chunk_size=1024 * 1024):
                size += len(part)
                _require(size <= declared_size, "OCI response exceeds declared length")
                checksum.update(part)
                if kind == "manifests":
                    content.extend(part)
            _require(size == declared_size, "OCI response was truncated")
            _require("sha256:" + checksum.hexdigest() == identity, "Downloaded OCI object digest mismatch")
            total += size
            return bytes(content), {"digest": identity, "size": size,
                                    "mediaType": response.headers.get("Content-Type", "").split(";", 1)[0]}
        finally:
            response.close()

    def descriptor(item):
        if not isinstance(item, dict):
            raise AssertionError("OCI graph contains an invalid descriptor")
        _digest(item.get("digest"))
        _require(type(item.get("size")) is int and item["size"] >= 0, "Invalid OCI descriptor size")
        _require(isinstance(item.get("mediaType"), str) and item["mediaType"], "Missing OCI descriptor media type")

    def visit(identity, expected=None, ancestors=frozenset()):
        _require(identity not in ancestors, "Cyclic OCI graph")
        _require(len(ancestors) <= max_depth, "OCI graph nesting limit exceeded")
        if identity not in manifests:
            raw, actual = fetch("manifests", identity, expected["size"] if expected else None)
            document = json.loads(raw)
            _require(isinstance(document, dict) and document.get("schemaVersion") == 2,
                     "Expected OCI/Docker schema version 2")
            if document.get("mediaType"):
                _require(document["mediaType"] == actual["mediaType"], "Manifest media type header mismatch")
            manifests[identity] = actual
            children = document.get("manifests", [])
            layers = document.get("layers", [])
            _require(isinstance(children, list) and isinstance(layers, list), "Invalid OCI graph inventory")
            members = ([document["config"]] if "config" in document else []) + layers
            _require(children or members, "Empty OCI graph")
            for child in children:
                descriptor(child)
                visit(child["digest"], child, ancestors | {identity})
            for blob in members:
                descriptor(blob)
                if blob["digest"] not in blobs:
                    _, metadata = fetch("blobs", blob["digest"], blob["size"])
                    blobs[blob["digest"]] = {"digest": metadata["digest"], "size": metadata["size"]}
                _require(blobs[blob["digest"]]["size"] == blob["size"], "Repeated blob descriptor size differs")
        if expected:
            _require(all(manifests[identity][key] == expected[key] for key in ("digest", "size", "mediaType")),
                     "Downloaded child does not match its parent descriptor")

    visit(root_digest)
    return {"repository": repository, "root_digest": root_digest, "verified_bytes": total,
            "manifests": list(manifests.values()), "blobs": list(blobs.values()),
            "manifest_count": len(manifests), "blob_count": len(blobs), "complete": True}


def assert_root_denied(session, proxy_base, repository, digest, auth=None, *, reason="release_superseded"):
    response = session.get(_base(proxy_base) + "/v2/" + _repository(repository)
                           + "/manifests/" + _digest(digest), auth=auth,
                           headers={"Accept": ACCEPT}, timeout=30, allow_redirects=False)
    try:
        _require(response.status_code == 403, f"Expected pull denial, got HTTP {response.status_code}")
        errors = response.json().get("errors", [])
        _require(len(errors) == 1 and errors[0].get("code") == "DENIED", "Expected OCI authorization denial")
        _require(errors[0].get("message") == reason, "Pull was denied for a different reason")
        if reason == "Artifact does not belong to this verified replica repository":
            # Repository membership is rejected before release-policy evaluation;
            # this boundary intentionally has no policy-detail payload.
            return {"requested_artifact_digest": digest, "allowed": False,
                    "denial_stage": "replica_repository_membership", "message": reason}
        detail = errors[0].get("detail", {})
        _require(detail.get("artifact_digest") == digest and detail.get("allowed") is False,
                 "Denial does not identify the requested artifact")
        return detail
    finally:
        response.close()


def verify_manifest_binding(context, release_id, expected_receipt):
    """Bind the full signed context to the independently retained source receipt.

    Approval DTOs recursively redact ``path`` from their manifest projection.
    Hash the full imported document, and compare every remaining field exactly.
    The immutable OCI root also binds the omitted paths: replica import verifies
    that root's signed manifest before exposing this read-only context.
    """
    expected_manifest = expected_receipt.get("manifest")
    _require(isinstance(expected_manifest, dict), "Supply the actual source publication receipt")
    actual_manifest = context.get("manifest")
    _require(isinstance(actual_manifest, dict), "Imported signed manifest is missing")

    def public_projection(value):
        if isinstance(value, dict):
            return {key: public_projection(item) for key, item in value.items() if key != "path"}
        if isinstance(value, list):
            return [public_projection(item) for item in value]
        return value

    _require(context.get("read_only") is True, "Imported evidence context must be read-only")
    _require(public_projection(actual_manifest) == expected_manifest,
             "Imported manifest differs from the actual publication receipt projection")
    canonical = json.dumps(actual_manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode()
    manifest_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    release = context.get("release", {})
    _require(release.get("id") == release_id and release.get("manifest_digest") == manifest_digest,
             "Imported release does not identify the exact full signed manifest")
    _require(release.get("publisher") == expected_manifest.get("signing_fingerprint")
             and release.get("source_release_id") == expected_manifest.get("portable", {}).get("release_uuid"),
             "Imported release publisher or portable identity differs from the source receipt")

    def immutable_reference(value):
        _require(isinstance(value, str) and value.count("@") == 1,
                 "Expected an immutable release OCI reference")
        location, digest = value.split("@")
        host, separator, repository = location.partition("/")
        _require(separator and host, "Release OCI reference must identify its registry and repository")
        _base("https://" + host)
        return _repository(repository), _digest(digest)

    published = expected_receipt.get("release", {})
    expected_reference = immutable_reference(published.get("reference"))
    _require(expected_reference[1] == published.get("digest"),
             "Publication release reference differs from its immutable digest")
    _require(immutable_reference(release.get("source_reference")) == expected_reference,
             "Imported release OCI root differs from the independently retained source receipt")
    return manifest_digest


def verify_evidence(session, base_url, release_id, expected_receipt, *,
                    max_bytes=2 * 1024**3, max_state_bytes=256 * 1024**2):
    """Bind downloaded evidence and immutable context to the source receipt.

    The expected receipt comes from the actual publisher API, independently of
    the replica response. No archive members are extracted.
    """
    if type(release_id) is not int or release_id < 1:
        raise ValueError("Use the replica's local integer release ID")
    if not isinstance(expected_receipt, dict):
        raise ValueError("Supply the actual source publication receipt")
    expected_manifest = expected_receipt.get("manifest", {})
    evidence_digest = _digest(expected_manifest.get("evidence", {}).get("digest"))
    endpoint = _base(base_url) + f"/api/replica/releases/{release_id}"
    response = session.get(endpoint + "/context", timeout=120, allow_redirects=False)
    try:
        _require(response.status_code == 200, f"Evidence context returned HTTP {response.status_code}")
        context = response.json()
    finally:
        response.close()
    manifest_digest = verify_manifest_binding(context, release_id, expected_receipt)
    checksum, size = hashlib.sha256(), 0
    response = session.get(endpoint + "/evidence", headers={"Accept-Encoding": "identity"},
                           timeout=120, allow_redirects=False, stream=True)
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024**2, mode="w+b") as archive:
        try:
            _require(response.status_code == 200, f"Evidence archive returned HTTP {response.status_code}")
            length = response.headers.get("Content-Length", "")
            _require(length.isdigit() and 0 < int(length) <= max_bytes, "Evidence archive has invalid length")
            for part in response.iter_content(chunk_size=1024 * 1024):
                size += len(part)
                _require(size <= int(length), "Evidence archive exceeds declared length")
                checksum.update(part)
                archive.write(part)
            _require(size == int(length), "Evidence archive was truncated")
            _require("sha256:" + checksum.hexdigest() == evidence_digest,
                     "Evidence archive bytes differ from the signed manifest digest")
        finally:
            response.close()
        archive.seek(0)
        with zipfile.ZipFile(archive) as bundle:
            members = [item for item in bundle.infolist() if item.filename == "replica-service.json"]
            _require(len(members) == 1 and 0 < members[0].file_size <= max_state_bytes,
                     "Evidence archive must contain exactly one bounded replica service state")
            original = json.loads(bundle.read(members[0]))
            _require(original == context.get("original_evidence"),
                     "Read-only context differs from the signed archive's original evidence")
            entries = len(bundle.infolist())
    return {"release_id": release_id, "manifest_digest": manifest_digest,
            "evidence_digest": evidence_digest, "evidence_bytes": size, "archive_entries": entries,
            "record_counts": {key: len(value) for key, value in original.get("records", {}).items()},
            "read_only": True, "original_evidence_equal": True}


def exact_override_payload(release_id, digest, *, mission_impact, justification, risk_acceptance,
                           denial_condition="superseded", expires_at=None):
    if type(release_id) is not int or release_id < 1:
        raise ValueError("Use the replica's local integer release ID")
    if denial_condition not in {"superseded", "expired"}:
        raise ValueError("This acceptance helper is for superseded or expired approvals")
    if any(not isinstance(text, str) or not text.strip() for text in (mission_impact, justification, risk_acceptance)):
        raise ValueError("Supply explicit impact, justification and risk acceptance")
    return {"release_id": release_id, "digest": _digest(digest), "denial_condition": denial_condition,
            "mission_impact": mission_impact, "justification": justification,
            "risk_acceptance": risk_acceptance, "expires_at": expires_at}


def _override_url(base_url, service_key):
    if not isinstance(service_key, str) or not service_key:
        raise ValueError("A service key is required")
    return _base(base_url) + "/api/services/" + quote(service_key, safe="") + "/local-overrides"


def _post(session, url, csrf, payload, expected_status):
    if not csrf:
        raise ValueError("Supply the signed-in user's actual CSRF token")
    response = session.post(url, json=payload, headers={"X-CSRF-Token": csrf},
                            timeout=30, allow_redirects=False)
    try:
        _require(response.status_code == expected_status,
                 f"Expected HTTP {expected_status}, got HTTP {response.status_code}")
        return response.json()
    finally:
        response.close()


def assert_override_admin_denied(session, base_url, csrf, service_key, payload):
    """Use an Administrator-only session and valid CSRF; reject for role scope."""
    result = _post(session, _override_url(base_url, service_key), csrf, payload, 403)
    _require(result.get("detail") == "Local Cyber permission denied", "Denial did not establish Local Cyber separation")
    return {"administrator_override_denied": True}


def create_exact_override(session, base_url, csrf, service_key, payload):
    _digest(payload.get("digest"))
    result = _post(session, _override_url(base_url, service_key), csrf, payload, 200)
    _require(result.get("release_id") == payload["release_id"]
             and result.get("digests") == [payload["digest"]]
             and result.get("denial_condition") == payload["denial_condition"]
             and result.get("status") == "active", "Override did not preserve the exact requested scope")
    return result


def revoke_override(session, base_url, csrf, service_key, override_id, reason):
    result = _post(session, _override_url(base_url, service_key) + f"/{int(override_id)}/revoke",
                   csrf, {"reason": reason}, 200)
    _require(result.get("id") == override_id and result.get("status") == "revoked",
             "Override was not revoked")
    _require((result.get("revocation") or {}).get("reason") == reason, "Revocation reason was not retained")
    return result


def assert_override_uses(session, base_url, service_key, override_id, *, release_id, digest, principal_id):
    response = session.get(_override_url(base_url, service_key) + f"/{int(override_id)}/uses",
                           timeout=30, allow_redirects=False)
    try:
        _require(response.status_code == 200, f"Override audit returned HTTP {response.status_code}")
        uses = response.json().get("uses", [])
        matching = [item for item in uses if item.get("override_id") == override_id
                    and item.get("release_id") == release_id and item.get("digest") == digest
                    and item.get("principal_id") == principal_id
                    and item.get("authorization_source") == "local_override"]
        _require(matching, "No audited exact-digest use by the expected machine principal")
        return {"override_id": override_id, "matching_uses": matching}
    finally:
        response.close()


def assert_disconnected(session, urls, *, timeout=5):
    """Require connection failure, not a 401/403/TLS error masquerading as isolation."""
    from requests.exceptions import ConnectionError, SSLError, Timeout

    if not urls:
        raise ValueError("Supply explicit publisher health/registry URLs to probe")
    results = []
    for url in urls:
        _base(url)
        try:
            response = session.get(url, timeout=timeout, allow_redirects=False)
        except SSLError:
            raise AssertionError("TLS failure does not establish publisher disconnection") from None
        except (ConnectionError, Timeout):
            results.append({"url": url, "unavailable": True})
        else:
            response.close()
            raise AssertionError(f"Publisher still responded with HTTP {response.status_code}")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="phase", required=True)
    copy = commands.add_parser("copy", help="Copy actual completed publication receipts between explicit registries")
    copy.add_argument("--receipt-file", type=Path, required=True)
    copy.add_argument("--root", type=Path, required=True)
    copy.add_argument("--source-host", required=True)
    copy.add_argument("--target-host", required=True)
    args = parser.parse_args()
    supplied = json.loads(args.receipt_file.read_text(encoding="utf-8-sig"))
    receipts = supplied if isinstance(supplied, list) else [supplied]
    if not receipts:
        parser.error("The receipt file contains no completed publications")
    results = [copy_receipt(receipt, args.root / str(index), os.environ,
                            args.source_host, args.target_host) for index, receipt in enumerate(receipts)]
    print(json.dumps({"phase": "actual-receipts-copied", "receipts": results}, sort_keys=True))


if __name__ == "__main__":
    main()
