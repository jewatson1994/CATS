"""Builder decoders reject ambiguous raw objects before canonicalization."""
import gzip
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest
from test_embedded_intelligence_build import builder, cached, run


@pytest.fixture
def supplemental():
    path = Path(__file__).resolve().parents[2] / 'scripts/embedded_supplemental.py'
    spec = importlib.util.spec_from_file_location('strict_supplemental_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('raw', [
    b'{"status":"affected","status":"fixed"}',
    b'{"nested":{"status":"affected","statu\\u0073":"fixed"}}',
    b'{"score":NaN}', b'{"score":Infinity}', b'{"score":-Infinity}',
])
def test_decoders_reject_duplicate_keys_and_nonfinite_values(builder, supplemental, raw):
    with pytest.raises(ValueError):
        builder.strict_json(raw)
    with pytest.raises(ValueError):
        supplemental._json(io.BytesIO(raw), 4096)


def raw_archive(path, mode, name, raw):
    with tarfile.open(path, mode) as archive:
        member = tarfile.TarInfo(name)
        member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))


def update_lock(builder, cache, name):
    path = cache / 'acquisition-lock.json'
    lock = json.loads(path.read_bytes())
    lock['inputs'][name].update(sha256=builder.sha(cache/name), bytes=(cache/name).stat().st_size)
    path.write_bytes(builder.canonical(lock))


@pytest.mark.parametrize('source', ['ubuntu', 'kev', 'alpine', 'ghsa'])
def test_build_never_signs_silently_collapsed_duplicate_keys(builder, cached, tmp_path, monkeypatch, source):
    cache = cached[0]
    if source == 'ubuntu':
        name = 'ubuntu-vex.tar.xz'
        raw = json.dumps(cached[3]).encode().replace(b'"status": "affected"', b'"status":"affected","status":"fixed"')
        raw_archive(cache/name, 'w:xz', 'vex/cve/CVE-2026-1234.json', raw)
    elif source == 'ghsa':
        name = 'ghsa.tar.gz'
        raw_archive(cache/name, 'w:gz', 'repo/advisories/github-reviewed/2026/GHSA-test.json',
            b'{"id":"GHSA-original","id":"GHSA-collapsed","aliases":["CVE-2026-1234"]}')
    elif source == 'kev':
        name = 'kev.json'
        (cache/name).write_bytes(b'{"vulnerabilities":[{"cveID":"CVE-2026-1234","cveID":"CVE-2026-9999","vendorProject":"Test","product":"Fixture"}]}')
    else:
        name = 'alpine-main.json'
        (cache/name).write_bytes(b'{"packages":[{"pkg":{"name":"original","name":"collapsed","secfixes":{"1.2":["CVE-2026-1234"]}}}]}')
    update_lock(builder, cache, name)
    output = tmp_path/'strict-release'
    if source != 'ubuntu':
        with pytest.raises(ValueError, match='Duplicate JSON key'):
            run(builder, cached, output, monkeypatch)
        assert not (output/'manifest.json').exists()
        return
    run(builder, cached, output, monkeypatch)
    records = [json.loads(line) for line in gzip.decompress((output/'intelligence.jsonl.gz').read_bytes()).splitlines()]
    assert all(row['source'] != 'ubuntu-vex' for row in records)
    manifest = json.loads((output/'manifest.json').read_bytes())
    assert manifest['sources'][0]['selection']['excluded']['ubuntu_malformed_json'] == 1


def test_ubuntu_nonregular_headers_count_toward_archive_limit(builder, cached, tmp_path, monkeypatch):
    cache = cached[0]
    with tarfile.open(cache/'ubuntu-vex.tar.xz', 'w:xz') as archive:
        for name in ('first/', 'second/', 'third/'):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
    update_lock(builder, cache, 'ubuntu-vex.tar.xz')
    monkeypatch.setattr(builder, 'MAX_UBUNTU_MEMBERS', 2)
    output = tmp_path/'bounded-release'
    with pytest.raises(ValueError, match='Ubuntu archive exceeds aggregate bounds'):
        run(builder, cached, output, monkeypatch)
    assert not (output/'manifest.json').exists()
