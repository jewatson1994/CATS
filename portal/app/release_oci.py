"""Publish release documents beside an approved immutable deployment artifact.

The caller owns destination authorization and passes the Docker authentication
and additive CA environment produced by destination_trust. No global Docker
configuration, subprocess, credential helper, or insecure TLS mode is used.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import ssl
from typing import Mapping
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


ARTIFACT_TYPE = "application/vnd.cats.release.documentation.v1"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
SUBJECT_ANNOTATION = "io.cats.release.subject"
REVISION_ANNOTATION = "org.opencontainers.image.revision"
MAX_BYTES = 256 * 1024 * 1024
METADATA_ALLOWANCE = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _size_limit(env):
    limit = int(env.get("CATS_RELEASE_DOC_MAX_BYTES", str(MAX_BYTES)))
    if limit < 1:
        raise ValueError("Documentation size limit must be positive")
    return limit + METADATA_ALLOWANCE


def _reference(value):
    if not isinstance(value, str) or value.count("@") != 1:
        raise ValueError("Documentation requires an immutable OCI SHA-256 reference")
    repository, digest = value.split("@")
    host, slash, name = repository.partition("/")
    parsed = urlsplit("https://" + host)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid OCI registry reference") from None
    if (not slash or not _DIGEST.fullmatch(digest) or not _REPOSITORY.fullmatch(name)
            or not parsed.hostname or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host)
            or (port is not None and port == 0)):
        raise ValueError("Invalid immutable OCI registry reference")
    return host, name, digest


def _origin(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("Registry URLs must use credential-free HTTPS")
    return parts.scheme, parts.hostname.lower(), parts.port or 443


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class _RegistryError(ValueError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Registry rejected documentation operation (HTTP {status})")


class _Client:
    def __init__(self, host, repository, env):
        self.max_bytes = _size_limit(env)
        self.base = "https://" + host
        self.repository = repository
        self.api = self.base + "/v2/" + repository
        context = ssl.create_default_context()
        ca = env.get("SSL_CERT_FILE") or env.get("REQUESTS_CA_BUNDLE")
        if ca:
            context.load_verify_locations(cafile=ca)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
        self.basic = ""
        self.token = ""
        self.auth_origins = {_origin(self.base)}
        # Delegated token services must be explicitly approved by the operator.
        for realm in env.get("CATS_OCI_TOKEN_REALMS", "").split(","):
            if realm.strip():
                self.auth_origins.add(_origin(realm.strip()))
        config_dir = env.get("DOCKER_CONFIG")
        if config_dir:
            config = json.loads((Path(config_dir) / "config.json").read_text(encoding="utf-8"))
            auths = config.get("auths", {})
            for key in (host, self.base, self.base + "/v1/"):
                entry = auths.get(key, {})
                if entry.get("auth"):
                    credential = entry["auth"]
                    decoded = base64.b64decode(credential, validate=True)
                    if b":" not in decoded or b"\n" in decoded or b"\r" in decoded:
                        raise ValueError("Invalid destination Docker authentication")
                    self.basic = "Basic " + credential
                    break

    def _open(self, request, limit):
        with self.opener.open(request, timeout=45) as response:
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("Registry response exceeds documentation size limit")
            return response.status, response.headers, data

    def _authenticate(self, challenge):
        scheme, _, parameters = challenge.partition(" ")
        if scheme.lower() != "bearer":
            raise ValueError("Registry authentication failed")
        fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(parameters))
        realm = fields.get("realm", "")
        if _origin(realm) not in self.auth_origins:
            raise ValueError("Registry token service is outside approved authentication origins")
        parts = urlsplit(realm)
        # Derive scope locally; never grant a server-requested unrelated scope.
        query = [(key, value) for key, value in parse_qsl(parts.query)
                 if key not in ("scope", "service", "account")]
        query.append(("scope", f"repository:{self.repository}:pull,push"))
        if fields.get("service"):
            query.append(("service", fields["service"]))
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
        headers = {"Authorization": self.basic} if self.basic else {}
        try:
            _, _, data = self._open(urllib.request.Request(url, headers=headers), 1024 * 1024)
        except urllib.error.HTTPError as exc:
            raise _RegistryError(exc.code) from None
        document = json.loads(data)
        token = document.get("token") or document.get("access_token")
        if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
            raise ValueError("Registry token service did not return a valid token")
        self.token = "Bearer " + token

    def request(self, method, url, *, body=None, media_type=None, limit=MAX_MANIFEST_BYTES):
        if _origin(url) != _origin(self.base):
            raise ValueError("Registry operation attempted to leave the approved destination")
        headers = {"Accept": ", ".join((MANIFEST_TYPE, INDEX_TYPE,
                   "application/vnd.docker.distribution.manifest.v2+json",
                   "application/vnd.docker.distribution.manifest.list.v2+json"))}
        if media_type:
            headers["Content-Type"] = media_type
        for attempt in range(2):
            authorization = self.token or self.basic
            if authorization:
                headers["Authorization"] = authorization
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                return self._open(request, limit)
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and not attempt:
                    self._authenticate(exc.headers.get("WWW-Authenticate", ""))
                    continue
                raise _RegistryError(exc.code) from None
        raise ValueError("Registry authentication failed")

    def manifest(self, digest):
        _, headers, data = self.request("GET", self.api + "/manifests/" + digest)
        if _digest(data) != digest:
            raise ValueError("Registry manifest digest verification failed")
        document = json.loads(data)
        media_type = document.get("mediaType") or headers.get_content_type()
        return document, {"mediaType": media_type, "digest": digest, "size": len(data)}

    def upload(self, data, media_type):
        digest = _digest(data)
        descriptor = {"mediaType": media_type, "digest": digest, "size": len(data)}
        try:
            self.request("HEAD", self.api + "/blobs/" + digest)
            return descriptor
        except _RegistryError as exc:
            if exc.status != 404:
                raise
        status, headers, _ = self.request("POST", self.api + "/blobs/uploads/", body=b"")
        if status != 202 or not headers.get("Location"):
            raise ValueError("Registry did not start a documentation blob upload")
        location = urljoin(self.api + "/blobs/uploads/", headers["Location"])
        parts = urlsplit(location)
        query = [(key, value) for key, value in parse_qsl(parts.query) if key != "digest"]
        query.append(("digest", digest))
        location = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
        status, _, _ = self.request("PUT", location, body=data, media_type="application/octet-stream")
        if status != 201:
            raise ValueError("Registry did not complete a documentation blob upload")
        return descriptor


def _media_type(name):
    if name.endswith(".zip"):
        return "application/zip"
    if name.endswith(".json"):
        return "application/json"
    return "application/octet-stream"


def _revision(layers):
    inventory = [{"name": item["annotations"]["org.opencontainers.image.title"],
                  "digest": item["digest"], "size": item["size"]} for item in layers]
    return _digest(_json(sorted(inventory, key=lambda item: item["name"])))


def _verify(client, reference, subject):
    _, _, digest = _reference(reference)
    document, _ = client.manifest(digest)
    annotations = document.get("annotations", {})
    if annotations.get(SUBJECT_ANNOTATION) != subject:
        raise ValueError("Documentation subject does not match the deployment artifact")
    if document.get("subject") and document["subject"].get("digest") != subject.split("@", 1)[1]:
        raise ValueError("Documentation OCI subject does not match the deployment artifact")
    if document.get("artifactType", document.get("config", {}).get("mediaType")) != ARTIFACT_TYPE:
        raise ValueError("Registry artifact is not a CATS release documentation artifact")
    layers = document.get("layers", [])
    if not layers or len(layers) > 64:
        raise ValueError("Invalid documentation artifact inventory")
    total, names = 0, set()
    for item in [document["config"], *layers]:
        size, blob_digest = item.get("size"), item.get("digest", "")
        if not isinstance(size, int) or size < 0 or not _DIGEST.fullmatch(blob_digest):
            raise ValueError("Invalid documentation blob descriptor")
        total += size
        if total > client.max_bytes:
            raise ValueError("Documentation artifact exceeds size limit")
        _, _, data = client.request("GET", client.api + "/blobs/" + blob_digest, limit=size)
        if len(data) != size or _digest(data) != blob_digest:
            raise ValueError("Registry documentation blob digest verification failed")
    for item in layers:
        name = item.get("annotations", {}).get("org.opencontainers.image.title", "")
        if not _safe_name(name) or name in names:
            raise ValueError("Invalid documentation file name")
        names.add(name)
    if not {"documentation.zip", "release-manifest.json"}.issubset(names):
        raise ValueError("Documentation archive or release manifest is missing")
    revision = _revision(layers)
    if annotations.get(REVISION_ANNOTATION) != revision:
        raise ValueError("Documentation revision verification failed")
    return {"reference": reference, "digest": digest, "subject": subject,
            "revision": revision, "files": layers, "verification_status": "verified"}


def _safe_name(name):
    return (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", name)
            and not name.endswith((".", ".key")))


def verify_documentation(reference: str, subject: str, env: Mapping[str, str]) -> dict:
    """Fetch a manifest and every blob by digest; never rely on a mutable tag.

    Verification here proves content integrity and subject association. Detached
    signature authenticity is checked separately with the configured public key.
    """
    result = {"status": "failed", "verification_status": "failed", "reference": reference, "subject": subject}
    try:
        host, repository, _ = _reference(subject)
        if _reference(reference)[:2] != (host, repository):
            raise ValueError("Documentation must use the deployment artifact repository")
        client = _Client(host, repository, env)
        result.update(_verify(client, reference, subject), status="verified")
    except Exception:
        result["error"] = "Documentation retrieval verification failed; check digest, subject, registry access and destination trust."
    return result


def publish_documentation(files: Mapping[str, Path], subject: str, env: Mapping[str, str]) -> dict:
    """Publish files into the subject's repository, then retrieve and hash them.

    A content-derived compatibility tag is always written, so deployments on
    registries without the Referrers API still retain an explicit immutable
    documentation reference. Results preserve publication identity when later
    verification fails. Caller may safely persist the returned sanitized result.
    """
    result = {"status": "failed", "publication_status": "failed", "verification_status": "not_verified", "subject": subject}
    try:
        host, repository, subject_digest = _reference(subject)
        max_bytes = _size_limit(env)
        if (not files or len(files) > 64 or not {"documentation.zip", "release-manifest.json"}.issubset(files)
                or not all(_safe_name(name) for name in files)):
            raise ValueError("Documentation files must include the archive and release manifest with safe file names")
        contents, total = {}, 2
        for name, path in sorted(files.items()):
            path = Path(path)
            if not path.is_file() or path.is_symlink():
                raise ValueError("Documentation file is unavailable")
            if total + path.stat().st_size > max_bytes:
                raise ValueError("Documentation files exceed publication size limit")
            with path.open("rb") as stream:
                data = stream.read(max_bytes - total + 1)
            total += len(data)
            if total > max_bytes or re.search(rb"-----BEGIN (?:ENCRYPTED |EC |RSA |ENCRYPTED COSIGN |ENCRYPTED SIGSTORE )?PRIVATE KEY-----", data[:65536]):
                raise ValueError("Documentation input is too large or contains private key material")
            contents[name] = data
        client = _Client(host, repository, env)
        _, subject_descriptor = client.manifest(subject_digest)
        config = client.upload(b"{}", "application/vnd.oci.empty.v1+json")
        layers = []
        for name, data in contents.items():
            descriptor = client.upload(data, _media_type(name))
            descriptor["annotations"] = {"org.opencontainers.image.title": name}
            layers.append(descriptor)
        revision = _revision(layers)
        tag = "sha256-" + subject_digest[7:] + ".docs-" + revision[7:23]
        manifest = {"schemaVersion": 2, "mediaType": MANIFEST_TYPE, "artifactType": ARTIFACT_TYPE,
                    "config": config, "layers": layers, "subject": subject_descriptor,
                    "annotations": {SUBJECT_ANNOTATION: subject, REVISION_ANNOTATION: revision}}
        result.update(revision=revision, compatibility_reference=f"{host}/{repository}:{tag}")
        encoded = _json(manifest)
        try:
            status, _, _ = client.request("PUT", client.api + "/manifests/" + tag, body=encoded, media_type=MANIFEST_TYPE)
        except _RegistryError as exc:
            if exc.status not in (400, 415, 422):
                raise
            # Older OCI 1.0 registries may reject the new subject/artifactType
            # fields. Their association remains explicit in the annotations.
            manifest.pop("subject")
            manifest.pop("artifactType")
            manifest["config"] = {**config, "mediaType": ARTIFACT_TYPE}
            encoded = _json(manifest)
            status, _, _ = client.request("PUT", client.api + "/manifests/" + tag, body=encoded, media_type=MANIFEST_TYPE)
        if status != 201:
            raise ValueError("Registry did not accept the documentation manifest")
        digest = _digest(encoded)
        reference = f"{host}/{repository}@{digest}"
        result.update(reference=reference, digest=digest, publication_status="published",
                      verification_status="failed", association_mode="compatibility_tag")
        result.update(_verify(client, reference, subject))
        if "subject" in manifest:
            try:
                _, _, data = client.request("GET", client.api + "/referrers/" + subject_digest
                                           + "?" + urlencode({"artifactType": ARTIFACT_TYPE}))
                index = json.loads(data)
                if any(item.get("digest") == digest for item in index.get("manifests", [])):
                    result["association_mode"] = "oci_referrers"
            except Exception:
                # Publication was verified by digest; unavailable discovery
                # cannot invalidate it. The deterministic tag remains usable.
                pass
        result["status"] = "published"
    except Exception:
        result["error"] = ("Documentation publication or verification failed; check registry access, "
                           "destination trust, immutable subject and documentation files.")
    return result
