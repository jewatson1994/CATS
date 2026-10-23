"""Bounded Helm retrieval using administrator-approved sources only.

The worker owns the network feature gate. This transport never invokes Helm,
uses ambient proxies, or learns source permissions from uploaded documents.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
import time
import tempfile
from urllib import request, error
from urllib.parse import urlsplit, urljoin, urlencode, unquote
from http.client import HTTPException

import yaml

from .discovery_artifacts import ArtifactResolutionError, ResolvedArtifact, _identity
from .trusted_ca import additional_pem

from .discovery_limits import limit as discovery_limit

MAX_BYTES = discovery_limit("UPLOAD_BYTES")
MAX_METADATA = 16 * 1024 * 1024
CHART_LAYER = 'application/vnd.cncf.helm.chart.content.v1.tar+gzip'


def _url(value):
    try:
        p = urlsplit(value)
        if (p.scheme not in ('https', 'oci') or not p.hostname or p.username is not None
                or p.password is not None or p.query or p.fragment or '%' in p.netloc
                or '\\' in value or any(ord(c) <= 32 for c in value)
                or re.search(r'%(?![0-9a-fA-F]{2})', p.path)):
            raise ValueError()
        # GitLab project identifiers legitimately contain encoded slashes. Keep
        # those slashes encoded for scope matching, but validate the decoded path
        # too so server-side decoding cannot introduce traversal or controls.
        decoded = unquote(p.path, errors='strict')
        if (any(part in ('.', '..') for part in decoded.split('/'))
                or any(c in decoded for c in ('%', '\\', '?', '#'))
                or any(ord(c) <= 32 or ord(c) == 127 for c in decoded)):
            raise ValueError()
        if p.port is not None and not 1 <= p.port <= 65535:
            raise ValueError()
        return p._replace(path=re.sub(r'%[0-9a-fA-F]{2}', lambda m: m[0].upper(), p.path))
    except (ValueError, TypeError, UnicodeError):
        raise ArtifactResolutionError('Invalid Helm source URL.') from None


def _origin(value):
    p = _url(value)
    return ('https', p.hostname.lower(), p.port or 443)


def _origin_label(value):
    """Expose only the validated destination origin, never paths or tokens."""
    p = _url(value)
    host = p.hostname.lower()
    if ':' in host:
        host = '[' + host + ']'
    return 'https://' + host + (':' + str(p.port) if p.port not in (None, 443) else '')


def _under(value, prefix):
    target, approved = _url(value), _url(prefix)
    if target.scheme != approved.scheme or _origin(value) != _origin(prefix):
        return False
    # Literal slash boundaries only: encoded slashes never expand permission
    # from an approved namespace to a differently interpreted repository.
    return target.path == approved.path or target.path.startswith(approved.path.rstrip('/') + '/')


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class HelmNetworkResolver:
    def __init__(self, *, allowed_sources=(), oci_registries=(),
                 trusted_ca_certificates=(), allowed_redirect_origins=(),
                 allowed_token_origins=(), ca_file=None, timeout=20):
        self.sources = []
        self.credentials = []
        for source in allowed_sources:
            _url(source)
            self.sources.append(source.rstrip('/'))
        for row in oci_registries:
            endpoint = str(row.get('endpoint') or '').rstrip('/')
            if '://' not in endpoint:
                endpoint = 'https://' + endpoint
            p = _url(endpoint)
            if p.scheme != 'https' or p.path:
                raise ArtifactResolutionError('Configured OCI registry must be an HTTPS origin.')
            namespace = str(row.get('namespace') or '').strip('/')
            source = 'oci://' + p.netloc + ('/' + namespace if namespace else '')
            _url(source)
            self.sources.append(source)
            if row.get('auth_mode') == 'credentials':
                from .secrets import decrypt_secret
                username = str(row.get('username') or '')
                password = decrypt_secret(str(row.get('password') or ''))
                self.credentials.append((source, 'Basic ' + base64.b64encode(
                    (username + ':' + password).encode()).decode()))
        self.redirect_origins = {_origin(v) for v in allowed_redirect_origins}
        self.token_origins = {_origin(v) for v in allowed_token_origins}
        self.timeout = min(max(float(timeout), 1), 45)
        context = ssl.create_default_context()
        if ca_file:
            context.load_verify_locations(cafile=str(ca_file))
        pem = additional_pem(trusted_ca_certificates)
        if pem:
            context.load_verify_locations(cadata=pem)
        self.opener = request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=context), _NoRedirect())

    def _get(self, url, *, limit=MAX_BYTES, headers=None, origins=(), query=False, file_backed=False):
        # Queries are generated only by the token client or returned by approved redirects.
        initial = urlsplit(url)
        clean = initial._replace(query='').geturl() if query else url
        if _url(clean).scheme != 'https' or _origin(clean) not in origins:
            raise ArtifactResolutionError('Helm download origin is not administrator-approved: ' + _origin_label(clean))
        headers = dict(headers or {})
        deadline = time.monotonic() + self.timeout
        for hop in range(6):
            try:
                with self.opener.open(request.Request(url, headers=headers), timeout=self.timeout) as response:
                    spool, size = tempfile.TemporaryFile(), 0
                    try:
                        while True:
                            if time.monotonic() > deadline:
                                raise ArtifactResolutionError('Helm download timed out; retry or check the source.')
                            chunk = response.read(min(65536, limit + 1 - size) if limit else 65536)
                            if not chunk:
                                spool.seek(0)
                                if file_backed:
                                    result, spool = spool, None
                                    return result, response.headers
                                return spool.read(), response.headers
                            spool.write(chunk)
                            size += len(chunk)
                            if limit and size > limit:
                                raise ArtifactResolutionError('Helm download exceeds the configured size limit.')
                    finally:
                        if spool is not None:
                            spool.close()
            except error.HTTPError as exc:
                if exc.code not in (301, 302, 303, 307, 308):
                    raise
                target = urljoin(url, exc.headers.get('Location', ''))
                p = urlsplit(target)
                clean = p._replace(query='').geturl()
                if (_url(clean).scheme != 'https' or _origin(clean) not in origins
                        or hop == 5 or time.monotonic() > deadline):
                    raise ArtifactResolutionError('Helm redirect is not approved or exceeds limits: ' + _origin_label(clean)) from None
                if _origin(clean) != _origin(urlsplit(url)._replace(query='').geturl()):
                    headers.pop('Authorization', None)
                url = target
                exc.close()
        raise ArtifactResolutionError('Helm redirect limit exceeded.')

    def _oci(self, reference, version):
        p = _url(reference)
        repository = p.path.strip('/')
        if not re.fullmatch(r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*', repository):
            raise ArtifactResolutionError('Invalid OCI chart repository.')
        base = 'https://' + p.netloc
        origins = {_origin(base)} | self.redirect_origins
        matches = sorted((pair for pair in self.credentials if _under(reference, pair[0])), key=lambda x: len(x[0]), reverse=True)
        basic = matches[0][1] if matches else ''
        authorization = basic
        def fetch(url, limit, file_backed=False):
            nonlocal authorization
            for attempt in range(2):
                headers = {'Accept': 'application/vnd.oci.image.manifest.v1+json'}
                if authorization:
                    headers['Authorization'] = authorization
                try:
                    return self._get(url, limit=limit, headers=headers, origins=origins, file_backed=file_backed)
                except error.HTTPError as exc:
                    if exc.code != 401 or attempt:
                        raise
                    scheme, _, params = exc.headers.get('WWW-Authenticate', '').partition(' ')
                    exc.close()
                    fields = request.parse_keqv_list(request.parse_http_list(params))
                    realm = fields.get('realm', '')
                    if scheme.lower() != 'bearer' or _origin(realm) not in self.token_origins:
                        raise ArtifactResolutionError('Approve the OCI token service origin before retrieving this chart: ' + _origin_label(realm))
                    query = urlencode({'scope': 'repository:' + repository + ':pull', 'service': fields.get('service', '')})
                    data, _ = self._get(realm + '?' + query, limit=1024 * 1024,
                        headers={'Authorization': basic} if basic else {}, origins=self.token_origins, query=True)
                    document = json.loads(data)
                    token = document.get('token') or document.get('access_token')
                    if not isinstance(token, str) or not token or any(ord(c) < 33 for c in token):
                        raise ArtifactResolutionError('OCI token service returned an invalid token.')
                    authorization = 'Bearer ' + token
        tag = version.replace('+', '_')
        data, headers = fetch(base + '/v2/' + repository + '/manifests/' + tag, MAX_METADATA)
        expected = version if version.startswith('sha256:') else headers.get('Docker-Content-Digest')
        if expected and expected != 'sha256:' + hashlib.sha256(data).hexdigest():
            raise ArtifactResolutionError('OCI manifest checksum verification failed.')
        manifest = json.loads(data)
        layers = [row for row in manifest.get('layers', []) if row.get('mediaType') == CHART_LAYER]
        if len(layers) != 1:
            raise ArtifactResolutionError('OCI manifest must contain exactly one Helm chart layer.')
        layer = layers[0]
        digest = layer.get('digest', '')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest) or type(layer.get('size')) is not int or (layer['size'] < 0 or (MAX_BYTES and layer['size'] > MAX_BYTES)):
            raise ArtifactResolutionError('Invalid or oversized OCI chart layer.')
        archive, _ = fetch(base + '/v2/' + repository + '/blobs/' + digest, MAX_BYTES, file_backed=True)
        actual_size = len(archive) if isinstance(archive, bytes) else archive.seek(0, 2)
        if not isinstance(archive, bytes):
            archive.seek(0)
        if actual_size != layer['size']:
            if not isinstance(archive, bytes):
                archive.close()
            raise ArtifactResolutionError('OCI chart layer size verification failed.')
        return archive, digest[7:]

    def resolve(self, kind, reference, version):
        key = _identity(kind, reference, version)
        if kind != 'helm' or not any(_under(reference, source) for source in self.sources):
            raise ArtifactResolutionError('Helm source is not administrator-approved.')
        p = _url(reference)
        if not re.fullmatch(r'(?:v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?|sha256:[0-9a-f]{64})', version):
            raise ArtifactResolutionError('Helm network retrieval requires an exact chart version or OCI SHA-256 digest.')
        try:
            if p.scheme == 'oci':
                data, expected = self._oci(reference, version)
            else:
                repository, _, chart = reference.rpartition('/')
                origins = {_origin(repository)} | self.redirect_origins
                index, _ = self._get(repository + '/index.yaml', limit=MAX_METADATA, origins=origins)
                document = yaml.safe_load(index)
                rows = document.get('entries', {}).get(chart, [])
                entries = [row for row in rows if str(row.get('version')) == version]
                if len(entries) != 1:
                    raise ArtifactResolutionError('Exact Helm chart version was not uniquely found in the approved repository.')
                entry = entries[0]
                expected = str(entry.get('digest', '')).removeprefix('sha256:').lower()
                if not re.fullmatch('[0-9a-f]{64}', expected):
                    raise ArtifactResolutionError('Helm repository index must provide a SHA-256 chart checksum.')
                urls = entry.get('urls', [])
                if not urls or not isinstance(urls[0], str):
                    raise ArtifactResolutionError('Helm repository index has no chart download URL.')
                data, _ = self._get(urljoin(repository + '/', urls[0]), origins=origins, file_backed=True)
            digest = hashlib.sha256(data).hexdigest() if isinstance(data, bytes) else hashlib.file_digest(data, 'sha256').hexdigest()
            if not isinstance(data, bytes):
                data.seek(0)
            if digest != expected:
                if not isinstance(data, bytes):
                    data.close()
                raise ArtifactResolutionError('Helm chart checksum verification failed.')
            return ResolvedArtifact(data, 'chart.tgz', digest, kind,
                hashlib.sha256(json.dumps(key, separators=(',', ':')).encode()).hexdigest(), 'admin-approved-helm-network')
        except ArtifactResolutionError:
            raise
        except error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise ArtifactResolutionError(f'Helm source returned HTTP {code}; check the version and configured registry access.') from None
        except (OSError, HTTPException, ValueError, TypeError, KeyError, AttributeError, RecursionError, yaml.YAMLError):
            raise ArtifactResolutionError('Helm retrieval failed; check repository metadata, connectivity, and trusted certificates.') from None
