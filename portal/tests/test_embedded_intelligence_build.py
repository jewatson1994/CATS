"""Builder-only synthetic caches; no fixture intelligence or signing keys ship."""
import base64
import gzip
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
from urllib.request import Request

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/build-embedded-intelligence.py'
DATE = '2026-10-18T00:00:00+00:00'

@pytest.fixture
def builder(monkeypatch):
    monkeypatch.setattr(sys, 'path', list(sys.path))
    spec = importlib.util.spec_from_file_location('embedded_builder_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def forbidden(*args, **kwargs):
        pytest.fail('Replay must not open a network connection')
    monkeypatch.setattr(module, 'build_opener', forbidden)
    monkeypatch.setattr(module, 'source_adapters', lambda: [])
    return module


def archive(path, mode, entries):
    with tarfile.open(path, mode) as tar:
        for name, value in entries:
            raw = json.dumps(value).encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))

@pytest.fixture
def cached(tmp_path, builder, monkeypatch):
    cache = tmp_path / 'cache'; cache.mkdir()
    vex = {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'https://example.test/test-only', 'version': 1,
           'timestamp': DATE, 'statements': [{'vulnerability': {'name': 'CVE-2026-1234'},
           'products': [{'@id': 'pkg:deb/ubuntu/test@1'}], 'status': 'affected'}]}
    archive(cache/'ubuntu-vex.tar.xz', 'w:xz', [('vex/cve/CVE-2026-1234.json', vex), ('vex/usn/USN.json', dict(vex, statements=[dict(vex['statements'][0], vulnerability={'name':'USN-1-1'})]))])
    archive(cache/'ghsa.tar.gz', 'w:gz', [('advisory-database-main/advisories/github-reviewed/2026/GHSA-test.json',
        {'id': 'GHSA-test-only', 'aliases': ['CVE-2026-5678'], 'summary': 'Synthetic test only'})])
    (cache/'alpine-index.html').write_text('<a href="v3.1/">old</a><a href="v3.2/">latest</a>')
    (cache/'kev.json').write_text(json.dumps({'vulnerabilities': [{'cveID': 'CVE-2026-1234', 'vendorProject': 'Test', 'product': 'Fixture'}]}))
    for component in ('main', 'community'):
        (cache/f'alpine-{component}.json').write_text(json.dumps({'packages': [{'pkg': {'name': 'fixture-'+component, 'secfixes': {'1.2': ['CVE-2026-5678']}}}]}))
    urls = {'alpine-index.html': 'https://secdb.alpinelinux.org/',
        'ubuntu-vex.tar.xz': 'https://security-metadata.canonical.com/vex/vex-all.tar.xz',
        'kev.json': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'alpine-main.json': 'https://secdb.alpinelinux.org/v3.2/main.json',
        'alpine-community.json': 'https://secdb.alpinelinux.org/v3.2/community.json',
        'ghsa.tar.gz': 'https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main',
        'LICENSE-ubuntu.txt': 'https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/LICENSE',
        'LICENSE-kev.txt': 'https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE',
        'LICENSE-alpine.txt': 'https://secdb.alpinelinux.org/license.txt',
        'LICENSE-ghsa.txt': 'https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md'}
    for name in urls:
        if name.startswith('LICENSE-'):
            (cache/name).write_text('Synthetic test-only license fixture')
    monkeypatch.setattr(builder, 'LICENSE_SHA256', {name: builder.sha(cache/name) for name in urls if name.startswith('LICENSE-')})
    lock = {'schema': 'cats-acquisition-lock/v1', 'built_at': DATE, 'inputs': {
        name: {'url': url, 'sha256': builder.sha(cache/name), 'bytes': (cache/name).stat().st_size,
               'acquired_at': DATE, 'tls_verified': True} for name, url in urls.items()}}
    (cache/'acquisition-lock.json').write_bytes(builder.canonical(lock))
    key = Ed25519PrivateKey.generate()
    keypath = tmp_path/'private.pem'
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cache, keypath, key, vex


def run(builder, cached, output, monkeypatch, private_key=None):
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--cache', str(cached[0]), '--private-key', str(private_key or cached[1]),
        '--output', str(output), '--sequence', '1', '--version', 'test-only'])
    builder.main()


def test_canonical_order_unicode_and_nonfinite_rejection(builder):
    assert builder.canonical({'z': 'é', 'a': 1}) == builder.canonical({'a': 1, 'z': 'é'})
    assert builder.canonical({'z': 'é'}) == '{"z":"é"}'.encode()
    with pytest.raises(ValueError):
        builder.canonical({'bad': float('nan')})

@pytest.mark.parametrize('url', ['http://publisher.test/feed', 'https://other.test/feed', 'https://user@publisher.test/feed', 'https://publisher.test:444/feed'])
def test_redirect_scope_rejected_before_parent_can_follow(builder, monkeypatch, url):
    monkeypatch.setattr(builder.HTTPRedirectHandler, 'redirect_request', lambda *args: pytest.fail('Unsafe redirect reached follow handler'))
    with pytest.raises(ValueError, match='publisher scope'):
        builder.ScopedRedirect().redirect_request(Request('https://publisher.test/start'), None, 302, 'Found', {}, url)


def test_cached_full_source_replay_is_deterministic_signed_and_preserves_whole_vex(builder, cached, tmp_path, monkeypatch):
    one, two = tmp_path/'one', tmp_path/'two'
    run(builder, cached, one, monkeypatch)
    run(builder, cached, two, monkeypatch)
    for name in ('manifest.json', 'manifest.sig', 'intelligence.jsonl.gz', 'acquisition-lock.json', 'release-key.pem'):
        assert (one/name).read_bytes() == (two/name).read_bytes()
    manifest = json.loads((one/'manifest.json').read_bytes())
    cached[2].public_key().verify(base64.b64decode((one/'manifest.sig').read_bytes()), (one/'manifest.json').read_bytes())
    assert builder.sha(one/'intelligence.jsonl.gz') == manifest['payload_sha256']
    raw = gzip.decompress((one/'intelligence.jsonl.gz').read_bytes())
    assert len(raw) == manifest['uncompressed_bytes']
    records = [json.loads(line) for line in raw.splitlines()]
    assert len(records) == 5
    assert {row['source'] for row in records} == {'ubuntu-vex', 'cisa-kev', 'alpine-secdb', 'ghsa-reviewed'}
    assert next(row for row in records if row['kind'] == 'vex')['raw'] == cached[3]
    assert manifest['sources'][0]['selection']['excluded']['ubuntu_invalid_alias_or_identifier'] == 1
    assert 'PRIVATE KEY' not in ''.join(path.read_text(errors='ignore') for path in one.iterdir() if path.suffix != '.gz')

@pytest.mark.parametrize('corruption', ['bytes', 'tls'])
def test_replay_rejects_unverified_or_modified_cached_input(builder, cached, tmp_path, monkeypatch, corruption):
    cache = cached[0]
    if corruption == 'bytes':
        with (cache/'kev.json').open('ab') as stream:
            stream.write(b' ')
    else:
        lock = json.loads((cache/'acquisition-lock.json').read_text())
        lock['inputs']['kev.json']['tls_verified'] = False
        (cache/'acquisition-lock.json').write_bytes(builder.canonical(lock))
    output = tmp_path/'rejected'
    with pytest.raises(ValueError):
        run(builder, cached, output, monkeypatch)
    assert not (output/'manifest.json').exists()


def test_private_key_in_repository_is_rejected_before_reading(builder, cached, tmp_path, monkeypatch):
    with pytest.raises(ValueError, match='outside repository'):
        run(builder, cached, tmp_path/'rejected', monkeypatch, private_key=SCRIPT.parent/'never-created-private.pem')
    assert not (SCRIPT.parent/'never-created-private.pem').exists()

def test_signing_key_rotation_requires_explicit_action_and_preserves_existing_release(builder, cached, tmp_path, monkeypatch):
    output = tmp_path/'release'
    run(builder, cached, output, monkeypatch)
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    other = Ed25519PrivateKey.generate()
    otherpath = tmp_path/'other-private.pem'
    otherpath.write_bytes(other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(ValueError, match='release pin'):
        run(builder, cached, output, monkeypatch, private_key=otherpath)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_cache_lock_url_cannot_substitute_a_different_publisher(builder, cached, tmp_path, monkeypatch):
    lockpath = cached[0]/'acquisition-lock.json'
    lock = json.loads(lockpath.read_text())
    lock['inputs']['kev.json']['url'] = 'https://unrelated.test/kev'
    lockpath.write_bytes(builder.canonical(lock))
    with pytest.raises(ValueError, match='integrity mismatch'):
        run(builder, cached, tmp_path/'rejected', monkeypatch)


def test_changed_license_is_rejected_even_with_matching_acquisition_hash(builder, cached, tmp_path, monkeypatch):
    cache = cached[0]
    license_path = cache/'LICENSE-ubuntu.txt'
    license_path.write_text('Changed synthetic license terms')
    lockpath = cache/'acquisition-lock.json'
    lock = json.loads(lockpath.read_text())
    lock['inputs'][license_path.name]['sha256'] = builder.sha(license_path)
    lock['inputs'][license_path.name]['bytes'] = license_path.stat().st_size
    lockpath.write_bytes(builder.canonical(lock))
    output = tmp_path/'rejected'
    with pytest.raises(ValueError, match='Upstream license changed; review required'):
        run(builder, cached, output, monkeypatch)
    assert not (output/'manifest.json').exists()


@pytest.mark.parametrize('kind', ['exploitation', 'vex'])
def test_duplicate_content_only_preserves_conflicting_identity(builder, cached, tmp_path, monkeypatch, kind):
    import copy
    cache = cached[0]
    if kind == 'exploitation':
        name = 'kev.json'
        first = {'cveID': 'CVE-2026-1234', 'vendorProject': 'Test', 'product': 'Fixture', 'notes': 'Original evidence'}
        conflict = dict(first, notes='Conflicting evidence')
        (cache/name).write_text(json.dumps({'vulnerabilities': [first, first, conflict]}))
    else:
        name = 'ubuntu-vex.tar.xz'
        first = cached[3]
        conflict = copy.deepcopy(first)
        conflict['statements'][0]['status'] = 'fixed'
        member = 'vex/cve/CVE-2026-1234.json'
        archive(cache/name, 'w:xz', [(member, first), (member, first), (member, conflict)])
    lockpath = cache/'acquisition-lock.json'
    lock = json.loads(lockpath.read_bytes())
    lock['inputs'][name].update(sha256=builder.sha(cache/name), bytes=(cache/name).stat().st_size)
    lockpath.write_bytes(builder.canonical(lock))
    output = tmp_path/'conflicting-content'
    run(builder, cached, output, monkeypatch)
    records = [json.loads(line) for line in gzip.decompress((output/'intelligence.jsonl.gz').read_bytes()).splitlines()]
    selected = [r for r in records if r['kind'] == kind]
    assert len(selected) == 2
    assert len({builder.canonical(r) for r in selected}) == 2
    manifest = json.loads((output/'manifest.json').read_bytes())
    source = next(source for source in manifest['sources'] if source['id'] == ('ubuntu-vex' if kind == 'vex' else 'cisa-kev'))
    assert source['counts'][kind] == 2
    assert manifest['exclusions'][0]['counts'][source['id']+'_duplicate_records'] == 1
    if kind == 'vex':
        selection = source['selection']
        assert selection['normalized_statements'] == 2
        assert selection['versioned_purl_statements'] == 2
        assert selection['documents_with_versioned_purls'] == 2
        assert selection['document_kinds'] == {'cve_documents': 2, 'cve_statements': 2}
        assert selection['status_counts'] == {'affected': 1, 'fixed': 1}
        assert selection['excluded']['ubuntu-vex_duplicate_records'] == 1
        assert selection['archive_documents'] == 3
