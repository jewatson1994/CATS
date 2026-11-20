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


def _approved_locations():
    raw = os.getenv('CATS_DISCOVERY_GITLAB_SOURCES', '').strip()
    try:
        rows = json.loads(raw) if raw.startswith('[') else [row for row in re.split(r'[,\s]+', raw) if row]
        return {_location(row, allow_origin=True) for row in rows}
    except (ValueError, RecursionError):
        raise GitLabSourceError('The GitLab Discovery source configuration is invalid.', 503) from None


def validate_gitlab_project(url):
    """Return a canonical project identity only if current process policy permits it."""
    project = _location(url)
    allowed = _approved_locations()
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


def _chunks(opener, url, token, maximum, *, metadata, check, deadline, pagination=None):
    headers = {'Accept-Encoding': 'identity'}
    req = request.Request(url, headers=headers)
    if token:
        req.add_unredirected_header('PRIVATE-TOKEN', token)
    too_large = (GitLabSourceError('GitLab returned oversized repository metadata.') if metadata else
                 GitLabSourceError('The GitLab archive exceeds the configured upload size limit.', 413))
    size = 0
    try:
        check()
        next_check = time.monotonic() + 1
        with opener.open(req, timeout=15) as response:
            if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise GitLabSourceError('GitLab returned an unsupported response.')
            if pagination is not None:
                pagination['next_page'] = response.headers.get('X-Next-Page')
                # Only use the relation; every subsequent URL is rebuilt from
                # the approved origin, namespace and a local integer cursor.
                pagination['more'] = bool(re.search(r'(?:^|;)\s*rel\s*=\s*"?next"?(?=[,;\s]|$)',
                                                     response.headers.get('Link', ''), re.I))
            length = response.headers.get('Content-Length')
            if length is not None:
                if not re.fullmatch(r'[0-9]{1,20}', length):
                    raise GitLabSourceError('GitLab returned an invalid content length.')
                length = int(length)
                if maximum and length > maximum:
                    raise too_large
            while True:
                chunk = response.read1(65536)
                current = time.monotonic()
                if current > deadline:
                    raise GitLabSourceError('GitLab repository retrieval timed out.', 504)
                if not chunk:
                    break
                if current >= next_check:
                    check()
                    next_check = current + 1
                size += len(chunk)
                if maximum and size > maximum:
                    raise too_large
                yield chunk
            if length is not None and size != length:
                raise GitLabSourceError('GitLab returned an incomplete response.')
        check()
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


def _opener(token, trusted_ca_certificates):
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
    return request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=tls), _NoRedirect())


def _repository_client(url, token, trusted_ca_certificates):
    project = urlsplit(validate_gitlab_project(url))
    opener = _opener(token, trusted_ca_certificates)
    api = f'https://{project.netloc}/api/v4/projects/{quote(project.path[1:], safe="")}/repository'
    return opener, api


def _metadata(opener, url, token, deadline, check=lambda: None, *, pagination=None):
    with closing(_chunks(opener, url, token, 1024 * 1024, metadata=True, check=check, deadline=deadline,
                         pagination=pagination)) as chunks:
        raw = b''.join(chunks)
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise GitLabSourceError('GitLab returned invalid repository metadata.') from None


def validate_topic_scope(origin, namespace, topic):
    origin = _location(origin, allow_origin=True)
    if urlsplit(origin).path:
        raise GitLabSourceError('Enter the HTTPS GitLab origin without a project path.', 422)
    if origin not in _approved_locations():
        raise GitLabSourceError('GitLab topic polling requires an approved GitLab origin.', 403)
    if (not isinstance(namespace, str) or len(namespace) > 255 or
            not all(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9._-]*', part) for part in namespace.split('/'))):
        raise GitLabSourceError('Enter a GitLab group or subgroup path.', 422)
    if (not isinstance(topic, str) or not 1 <= len(topic) <= 128 or topic != topic.strip()
            or not topic.isprintable() or ',' in topic):
        raise GitLabSourceError('Enter one GitLab topic of up to 128 characters.', 422)
    return origin, namespace, topic


def gitlab_api_client(origin, namespace, topic, token=None, trusted_ca_certificates=()):
    origin, _, _ = validate_topic_scope(origin, namespace, topic)
    return _opener(token, trusted_ca_certificates), origin + '/api/v4'


def topic_project(row, origin, namespace, topic):
    """Recheck explicit opt-in and ownership even when the API filters its list."""
    if not isinstance(row, dict):
        raise GitLabSourceError('GitLab returned invalid project metadata.')
    topics = row.get('topics')
    if not isinstance(topics, list) or not all(isinstance(value, str) for value in topics):
        raise GitLabSourceError('GitLab returned invalid project topics.')
    if topic not in topics:
        return None
    if type(row.get('archived')) is not bool or 'default_branch' not in row:
        raise GitLabSourceError('GitLab returned incomplete project status metadata.')
    if row['archived'] or not row['default_branch']:
        return None
    path = row.get('path_with_namespace')
    if not isinstance(path, str):
        raise GitLabSourceError('GitLab returned an invalid project path.')
    if not path.startswith(namespace + '/'):
        return None
    if len(path) > 1024:
        raise GitLabSourceError('GitLab returned a project path that is too long.')
    project_id = row.get('id')
    if type(project_id) is not int or not 0 < project_id <= 2**63 - 1:
        raise GitLabSourceError('GitLab returned an invalid project ID.')
    canonical = _location(origin + '/' + path)
    if canonical != origin + '/' + path or row.get('web_url') != canonical:
        raise GitLabSourceError('GitLab returned an inconsistent project URL.')
    branch = validate_gitlab_ref(row['default_branch'])
    return dict(project_id=project_id, path_with_namespace=path, web_url=canonical, default_branch=branch)


def iter_topic_projects(origin, namespace, topic, *, token=None, trusted_ca_certificates=(), check=lambda: None,
                        on_project_error=None):
    """Yield immutable branch tips from an approved namespace, paginating by stable ID order."""
    opener, api = gitlab_api_client(origin, namespace, topic, token, trusted_ca_certificates)
    origin = api.removesuffix('/api/v4')
    endpoint = api + '/groups/' + quote(namespace, safe='') + '/projects'
    previous, page = 0, 1
    while True:
        query = urlencode(dict(topic=topic, include_subgroups='true', with_shared='false', archived='false',
                               order_by='id', sort='asc', per_page=REF_PAGE_SIZE, page=page))
        pagination = {}
        rows = _metadata(opener, endpoint + '?' + query, token, time.monotonic() + 45, check,
                         pagination=pagination)
        if not isinstance(rows, list) or len(rows) > REF_PAGE_SIZE:
            raise GitLabSourceError('GitLab returned an invalid project page.')
        for row in rows:
            project_id = row.get('id') if isinstance(row, dict) else None
            if type(project_id) is not int or not previous < project_id <= 2**63 - 1:
                raise GitLabSourceError('GitLab project pagination did not advance in ID order.')
            previous = project_id
            try:
                project = topic_project(row, origin, namespace, topic)
                if project is None:
                    continue
                branch = quote(project['default_branch'], safe='')
                url = f'{api}/projects/{project_id}/repository/branches/{branch}'
                head = _metadata(opener, url, token, time.monotonic() + 45, check)
                commit = head.get('commit') if isinstance(head, dict) else None
                sha = commit.get('id') if isinstance(commit, dict) else None
                if (not isinstance(sha, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', sha)
                        or head.get('name') != project['default_branch']):
                    raise GitLabSourceError('GitLab returned an invalid default branch revision.')
            except GitLabSourceError as exc:
                if on_project_error is None or exc.status_code == 503:
                    raise
                on_project_error(project_id, str(exc))
                continue
            yield {**project, 'commit_sha': sha}
        next_page = pagination.get('next_page')
        more = pagination.get('more', False)
        if next_page not in (None, '', str(page + 1)) or (not rows and (next_page or more)) or (next_page == '' and more):
            raise GitLabSourceError('GitLab returned inconsistent pagination metadata.')
        if not rows or next_page == '' or (next_page is None and not more and len(rows) < REF_PAGE_SIZE):
            return
        page += 1


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
