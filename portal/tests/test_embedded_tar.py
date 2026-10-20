"""Tar metadata bounds apply before hidden extension payloads are allocated."""
import collections
import gzip
import io
import json
import lzma
from pathlib import Path
import sys
import tarfile

import pytest
from test_embedded_intelligence_build import builder, cached, run

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import embedded_tar


def extension(kind, body=b'x\0', size=None):
    header = tarfile.TarInfo('metadata')
    header.type = kind
    header.size = len(body) if size is None else size
    return header.tobuf(format=tarfile.GNU_FORMAT) + (body + b'\0' * (-len(body) % 512) if size is None else b'')


def member(name='source.json', body=b'{}'):
    header = tarfile.TarInfo(name)
    header.size = len(body)
    return header.tobuf() + body + b'\0' * (-len(body) % 512)


def read_members(raw):
    with embedded_tar.bounded_tar_open(fileobj=io.BytesIO(raw + b'\0' * 1024)) as archive:
        return [(m.name, m.linkname, m.pax_headers.copy(), archive.extractfile(m).read() if m.isfile() else None)
                for m in archive]


@pytest.mark.parametrize('kind', sorted(embedded_tar.EXTENSIONS))
def test_oversized_extension_rejected_from_header_without_body(kind):
    # A declaration of a huge body is enough: no allocation/read of that body
    # should occur, including the otherwise invisible GNU/PAX header types.
    raw = extension(kind, size=2 * 1024 * 1024 * 1024)
    with pytest.raises(ValueError, match='extension exceeds byte bound'):
        read_members(raw)


def test_small_pax_paths_and_global_metadata_preserved():
    payload = io.BytesIO()
    path = 'publisher/' + 'long-name-' * 20 + 'café.json'
    with tarfile.open(fileobj=payload, mode='w', format=tarfile.PAX_FORMAT,
                      pax_headers={'comment': 'publisher archive'}) as archive:
        info = tarfile.TarInfo(path)
        info.size = 2
        info.pax_headers = {'mtime': '1.25'}
        archive.addfile(info, io.BytesIO(b'{}'))
    rows = read_members(payload.getvalue())
    assert rows[0][0] == path
    assert rows[0][2]['comment'] == 'publisher archive'
    assert rows[0][2]['mtime'] == '1.25'
    assert rows[0][3] == b'{}'


def test_small_gnu_long_names_and_links_preserved():
    payload = io.BytesIO()
    name, target = 'n' * 150, 't' * 160
    with tarfile.open(fileobj=payload, mode='w', format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo(name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        archive.addfile(info)
    assert read_members(payload.getvalue()) == [(name, target, {}, None)]


def test_extension_chain_depth_rejected_before_python_recursion_limit(monkeypatch):
    monkeypatch.setattr(embedded_tar, 'MAX_EXTENSION_DEPTH', 2)
    raw = extension(tarfile.GNUTYPE_LONGNAME) * 3 + member()
    with pytest.raises(ValueError, match='extension depth bound'):
        read_members(raw)


def test_extension_depth_resets_between_members(monkeypatch):
    monkeypatch.setattr(embedded_tar, 'MAX_EXTENSION_DEPTH', 1)
    raw = (extension(tarfile.GNUTYPE_LONGNAME, b'name.json\0') + member()) * 3
    assert [row[0] for row in read_members(raw)] == ['name.json'] * 3


def test_padded_metadata_and_hidden_headers_count_toward_aggregate(monkeypatch):
    monkeypatch.setattr(embedded_tar, 'MAX_METADATA_BYTES', 1024)
    raw = (extension(tarfile.GNUTYPE_LONGNAME) + member()) * 2
    with pytest.raises(ValueError, match='aggregate byte bound'):
        read_members(raw)


def test_global_pax_dictionary_cannot_grow_across_members(monkeypatch):
    monkeypatch.setattr(embedded_tar, 'MAX_PAX_FIELDS', 2)
    first = tarfile.TarInfo.create_pax_global_header({'first': '1', 'second': '2'})
    second = tarfile.TarInfo.create_pax_global_header({'third': '3'})
    with pytest.raises(ValueError, match='PAX metadata exceeds field bound'):
        read_members(first + member() + second + member())


@pytest.mark.parametrize('pax', [
    {'GNU.sparse.map': '0,2'}, {'GNU.sparse.size': '2'},
    {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'},
])
def test_pax_sparse_variants_cannot_read_unbounded_maps(pax):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w', format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo('source.json')
        info.size = 2
        info.pax_headers = pax
        archive.addfile(info, io.BytesIO(b'{}'))
    with pytest.raises(ValueError, match='Sparse tar members are unsupported'):
        read_members(payload.getvalue())


def test_legacy_sparse_extension_rejected():
    with pytest.raises(ValueError, match='Sparse tar members are unsupported'):
        read_members(extension(tarfile.GNUTYPE_SPARSE, size=0))


@pytest.mark.parametrize('name, compressor', [('ubuntu-vex.tar.xz', lzma.compress), ('ghsa.tar.gz', gzip.compress)])
def test_release_builder_rejects_hidden_metadata_before_signing(builder, cached, tmp_path, monkeypatch, name, compressor):
    cache = cached[0]
    (cache/name).write_bytes(compressor(extension(tarfile.XHDTYPE, size=embedded_tar.MAX_EXTENSION_BYTES + 1)))
    lockpath = cache/'acquisition-lock.json'
    lock = json.loads(lockpath.read_bytes())
    lock['inputs'][name].update(sha256=builder.sha(cache/name), bytes=(cache/name).stat().st_size)
    lockpath.write_bytes(builder.canonical(lock))
    output = tmp_path/'release'
    with pytest.raises(ValueError, match='extension exceeds byte bound'):
        run(builder, cached, output, monkeypatch)
    assert not (output/'manifest.json').exists()


def test_vulnrichment_uses_metadata_guard(tmp_path):
    import embedded_supplemental
    path = tmp_path/'vulnrichment.tar.gz'
    path.write_bytes(gzip.compress(extension(tarfile.XHDTYPE, size=embedded_tar.MAX_EXTENSION_BYTES + 1)))
    with pytest.raises(ValueError, match='extension exceeds byte bound'):
        embedded_supplemental.emit_vulnrichment(path, lambda _: pytest.fail('Unsafe input emitted'), collections.Counter())


def test_redhat_uses_metadata_guard(tmp_path):
    zstandard = pytest.importorskip('zstandard')
    import embedded_redhat
    path = tmp_path/'redhat.tar.zst'
    path.write_bytes(zstandard.ZstdCompressor().compress(extension(tarfile.GNUTYPE_LONGNAME, size=embedded_tar.MAX_EXTENSION_BYTES + 1)))
    with pytest.raises(ValueError, match='extension exceeds byte bound'):
        embedded_redhat.emit_records({'archive': path, 'max_canonical_bytes': 262144},
            lambda _: pytest.fail('Unsafe input emitted'), lambda _: pytest.fail('Unsafe input parsed'), collections.Counter())
