"""Retrieve an immutable source archive from an operator-approved GitLab instance."""
from contextlib import closing
from http.client import HTTPException
import hashlib
import json
import os
import re
import ssl
import time
from urllib import error, request
from urllib.parse import quote, urlencode, urlsplit

from .discovery_limits import limit
from .trusted_ca import additional_pem

REF_PAGE_SIZE = 50


class GitLabSourceError(ValueError):
    def __init__(self, message, status_code=502):
        super().__init__(message)
        self.status_code = status_code


def _location(value, *, allow_origin=False):
    invalid = 'Enter an HTTPS GitLab project URL without credentials, a query, or a fragment.'
    if (not isinstance(value, str) or len(value) > 4096 or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or any(c in value for c in '?%#\\')):
        raise GitLabSourceError(invalid, 422)
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if (parsed.scheme != 'https' or parsed.username is not None or not host or port == 0
                or not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9.\-]*|\[[0-9a-fA-F:.]+\])(?::[0-9]+)?', parsed.netloc)):
            raise ValueError()
    except ValueError:
        raise GitLabSourceError(invalid, 422) from None
    origin = 'https://' + (f'[{host}]' if ':' in host else host)
    if port not in (None, 443):
        origin += f':{port}'
    path = parsed.path.removesuffix('/')
    if allow_origin and not path:
        return origin
    parts = path.removeprefix('/').removesuffix('.git').split('/')
    if (len(parts) < 2 or parts[-1].endswith('.git')
            or any(not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9._-]*', part) for part in parts)):
        raise GitLabSourceError(invalid, 422)
    return origin + '/' + '/'.join(parts)


def validate_gitlab_project(url):
    """Return a canonical project identity only if current process policy permits it."""
    project = _location(url)
    raw = os.getenv('CATS_DISCOVERY_GITLAB_SOURCES', '').strip()
    try:
        rows = json.loads(raw) if raw.startswith('[') else [row for row in re.split(r'[,\s]+', raw) if row]
        allowed = {_location(row, allow_origin=True) for row in rows}
    except (ValueError, RecursionError):
        raise GitLabSourceError('The GitLab Discovery source configuration is invalid.', 503) from None
    origin = 'https://' + urlsplit(project).netloc
    if project not in allowed and origin not in allowed:
        raise GitLabSourceError('This GitLab project is not approved for Discovery.', 403)
    return project


def validate_gitlab_ref(ref):
    if ref is None or ref == '':
        return ''
    if (not isinstance(ref, str) or len(ref) > 1024 or not ref.isprintable()
            or any(c in ref for c in ' ~^:?*[\\') or '..' in ref or '@{' in ref
            or ref == '@' or ref.endswith('.') or ref.startswith('-')
            or any(not part or part.startswith('.') or part.endswith('.lock') for part in ref.split('/'))):
        raise GitLabSourceError('Enter a valid GitLab branch, tag, or commit.', 422)
    return ref


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def _chunks(opener, url, token, maximum, *, metadata, check, deadline):
    headers = {'Accept-Encoding': 'identity'}
    req = request.Request(url, headers=headers)
    if token:
        req.add_unredirected_header('PRIVATE-TOKEN', token)
    too_large = (GitLabSourceError('GitLab returned oversized repository metadata.') if metadata else
                 GitLabSourceError('The GitLab archive exceeds the configured upload size limit.', 413))
    size = 0
    try:
        check()
        with opener.open(req, timeout=15) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise GitLabSourceError('GitLab returned an unsupported response.')
            length = response.headers.get('Content-Length')
            if length is not None:
                if not re.fullmatch(r'[0-9]{1,20}', length):
                    raise GitLabSourceError('GitLab returned an invalid content length.')
                length = int(length)
                if maximum and length > maximum:
                    raise too_large
            while True:
                check()
                chunk = response.read1(65536)
                if time.monotonic() > deadline:
                    raise GitLabSourceError('GitLab repository retrieval timed out.', 504)
                if not chunk:
                    break
                size += len(chunk)
                if maximum and size > maximum:
                    raise too_large
                yield chunk
            if length is not None and size != length:
                raise GitLabSourceError('GitLab returned an incomplete response.')
    except error.HTTPError as exc:
        exc.close()
        if exc.code in {401, 403}:
            raise GitLabSourceError('GitLab denied access. Check the token and project permissions.', 403) from None
        if exc.code == 404:
            raise GitLabSourceError('GitLab could not find the project or revision with the supplied access.', 404) from None
        if 300 <= exc.code < 400:
            raise GitLabSourceError('GitLab redirects are not permitted. Use the current project URL.') from None
        if exc.code == 429:
            raise GitLabSourceError('GitLab rate-limited the request. Try again later.', 503) from None
        raise GitLabSourceError('GitLab could not serve the repository request.') from None
    except (OSError, HTTPException):
        raise GitLabSourceError('GitLab repository retrieval failed. Check connectivity and HTTPS trust.') from None


def _repository_client(url, token, trusted_ca_certificates):
    project = urlsplit(validate_gitlab_project(url))
    if token is not None and (not isinstance(token, str) or len(token) > 4096
                              or any(not 33 <= ord(c) <= 126 for c in token)):
        raise GitLabSourceError('Invalid GitLab access token.', 422)
    try:
        tls = ssl.create_default_context()
        ca_file = os.getenv('CATS_DISCOVERY_GITLAB_CA_FILE')
        if ca_file:
            tls.load_verify_locations(cafile=ca_file)
        pem = additional_pem(trusted_ca_certificates)
        if pem:
            tls.load_verify_locations(cadata=pem)
    except (OSError, ValueError, TypeError, AttributeError):
        raise GitLabSourceError('The GitLab HTTPS trust configuration is invalid.', 503) from None
    opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=tls), _NoRedirect())
    api = f'https://{project.netloc}/api/v4/projects/{quote(project.path[1:], safe="")}/repository'
    return opener, api


def _metadata(opener, url, token, deadline, check=lambda: None):
    with closing(_chunks(opener, url, token, 1024 * 1024, metadata=True, check=check, deadline=deadline)) as chunks:
        raw = b''.join(chunks)
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise GitLabSourceError('GitLab returned invalid repository metadata.') from None


def list_gitlab_refs(url, *, token=None, trusted_ca_certificates=(), search=''):
    """Return one bounded page each of branch and tag names matching the search."""
    if not isinstance(search, str) or len(search) > 128 or (search and not search.isprintable()):
        raise GitLabSourceError('Enter a GitLab revision search of up to 128 printable characters.', 422)
    opener, api = _repository_client(url, token, trusted_ca_certificates)
    params = {'per_page': REF_PAGE_SIZE + 1}
    if search:
        params['search'] = search
    query = urlencode(params)
    result = {'truncated': False}
    deadline = time.monotonic() + 30
    for kind in ('branches', 'tags'):
        rows = _metadata(opener, f'{api}/{kind}?{query}', token, deadline)
        if not isinstance(rows, list):
            raise GitLabSourceError('GitLab returned invalid branch or tag metadata.')
        names = []
        for row in rows[:REF_PAGE_SIZE]:
            try:
                name = validate_gitlab_ref(row['name'])
                if not name:
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise GitLabSourceError('GitLab returned an invalid branch or tag name.') from None
            names.append(name)
        result[kind] = names
        if len(rows) > REF_PAGE_SIZE:
            result['truncated'] = True
    return result


def fetch_gitlab_archive(url, ref, destination, *, token=None, trusted_ca_certificates=(), ref_kind='', check=lambda: None):
    """Stream the ZIP to a binary writer and return (full commit SHA, archive SHA-256)."""
    ref = validate_gitlab_ref(ref)
    if ref_kind not in ('', 'branch', 'tag') or (ref_kind and not ref):
        raise GitLabSourceError('Select a named GitLab branch or tag.', 422)
    opener, api = _repository_client(url, token, trusted_ca_certificates)
    if ref_kind:
        collection = 'branches' if ref_kind == 'branch' else 'tags'
        commit_url = f'{api}/{collection}/{quote(ref, safe="")}'
    elif ref:
        commit_url = api + '/commits/' + quote(ref, safe='') + '?stats=false'
    else:
        commit_url = api + '/commits?per_page=1'
    deadline = time.monotonic() + 300
    metadata = _metadata(opener, commit_url, token, deadline, check)
    if not ref and metadata == []:
        raise GitLabSourceError('The GitLab repository has no commits.', 404)
    try:
        if not ref:
            metadata = metadata[0]
        commit = metadata['commit'] if ref_kind else metadata
        sha = commit['id']
        if not isinstance(sha, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', sha):
            raise KeyError()
        if not ref_kind and re.fullmatch(r'(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', ref) and ref.lower() != sha:
            raise KeyError()
    except (IndexError, KeyError, TypeError):
        raise GitLabSourceError('GitLab returned invalid commit metadata.') from None

    archive_url = api + '/archive.zip?sha=' + sha
    prefix = bytearray()
    digest = hashlib.sha256()
    with closing(_chunks(opener, archive_url, token, limit('UPLOAD_BYTES'), metadata=False,
                         check=check, deadline=deadline)) as chunks:
        for chunk in chunks:
            if len(prefix) < 4:
                prefix.extend(chunk[:4 - len(prefix)])
                if len(prefix) == 4 and prefix not in (b'PK\x03\x04', b'PK\x05\x06'):
                    raise GitLabSourceError('GitLab did not return a ZIP archive.')
            destination.write(chunk)
            digest.update(chunk)
    if len(prefix) < 4:
        raise GitLabSourceError('GitLab returned an incomplete ZIP archive.')
    return sha, digest.hexdigest()
