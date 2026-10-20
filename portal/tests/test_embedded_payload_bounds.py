"""Compressed files stay within signed byte budgets while they are consumed."""
import base64
import gzip
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import embedded_intelligence as loader
from app.embedded_payload import PayloadReader, payload_paths


class TrackedFile:
    """Expose virtual padding without allocating the advertised hostile size."""
    def __init__(self, prefix, padding=0):
        self.prefix, self.padding, self.position = prefix, padding, 0
        self.requests, self.returned, self.closed = [], 0, False

    def read(self, count):
        assert count >= 0
        self.requests.append(count)
        end = min(self.position + count, len(self.prefix) + self.padding)
        block = self.prefix[self.position:min(end, len(self.prefix))]
        block += b'\0' * max(0, end - max(self.position, len(self.prefix)))
        self.position = end
        self.returned += len(block)
        return block

    def close(self):
        self.closed = True


class MemoryPath:
    def __init__(self, content):
        self.content, self.opened = content, []

    def stat(self):
        return SimpleNamespace(st_size=len(self.content))

    def open(self, mode):
        assert mode == 'rb'
        result = TrackedFile(self.content)
        self.opened.append(result)
        return result


def signed_package(tmp_path, sharded=False, signed_padding=0):
    raw = b'{"test":"bounded signed compressed payload"}\n'
    compressed = gzip.compress(raw, mtime=0) + b'\0' * signed_padding
    blocks = [compressed[:9], compressed[9:]] if sharded else [compressed]
    manifest = dict(schema='cats-embedded-intelligence/v1', version='bounded-test', sequence=1,
                    built_at='2026-10-18T00:00:00+00:00', sources=[],
                    payload_bytes=len(compressed), uncompressed_bytes=len(raw),
                    payload_sha256=hashlib.sha256(compressed).hexdigest())
    paths = []
    for index, block in enumerate(blocks):
        name = f'intelligence.jsonl.gz.part{index:04d}' if sharded else 'intelligence.jsonl.gz'
        path = tmp_path / name
        path.write_bytes(block)
        paths.append(path)
    if sharded:
        manifest['payload_parts'] = [dict(name=path.name, bytes=len(block),
            sha256=hashlib.sha256(block).hexdigest()) for path, block in zip(paths, blocks)]
    key = Ed25519PrivateKey.generate()
    pin = tmp_path / 'release-key.pem'
    pin.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    encoded = loader.canonical(manifest)
    (tmp_path / 'manifest.json').write_bytes(encoded)
    (tmp_path / 'manifest.sig').write_bytes(base64.b64encode(key.sign(encoded)))
    return manifest, pin, paths, blocks, raw


def consume(stage, directory, manifest, pin):
    if stage == 'preflight':
        assert loader._manifest(directory, pin) == manifest
    else:
        with loader._authenticated_payload(directory, manifest) as payload:
            return payload.read()


@pytest.mark.parametrize('sharded', [False, True])
@pytest.mark.parametrize('signed_padding', [0, 11])
def test_exact_signed_payload_accepts_legacy_shards_and_bounded_padding(tmp_path, sharded, signed_padding):
    manifest, pin, paths, blocks, raw = signed_package(tmp_path, sharded, signed_padding)
    assert loader._manifest(tmp_path, pin) == manifest
    assert consume('import', tmp_path, manifest, pin) == raw


@pytest.mark.parametrize('stage', ['preflight', 'import'])
@pytest.mark.parametrize('sharded', [False, True])
@pytest.mark.parametrize('change', ['growth', 'short', 'replacement'])
def test_changed_file_after_stat_is_bounded_and_rejected(tmp_path, monkeypatch, stage, sharded, change):
    manifest, pin, paths, blocks, raw = signed_package(tmp_path, sharded)
    # Complete initial authentication before presenting different file contents.
    assert loader._manifest(tmp_path, pin) == manifest
    target, original = paths[0], blocks[0]
    replacement = original
    padding = 0
    if change == 'growth':
        padding = 10 ** 12
    elif change == 'short':
        replacement = original[:-1]
    else:
        # Change gzip's mtime only: the replacement remains valid gzip, has the
        # same size, and produces the same data, but was never authenticated.
        replacement = original[:4] + bytes([original[4] ^ 1]) + original[5:]
    opened = []
    actual_open = Path.open

    def raced_open(path, *args, **kwargs):
        if path == target:
            stream = TrackedFile(replacement, padding)
            opened.append(stream)
            return stream
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', raced_open)
    with pytest.raises(ValueError, match='Payload (changed|digest mismatch)'):
        consume(stage, tmp_path, manifest, pin)
    assert len(opened) == 1
    assert opened[0].returned <= len(original) + 1
    assert opened[0].closed
    if change == 'growth':
        assert opened[0].returned == len(original) + 1
        assert opened[0].requests[-1] == 1


def test_per_shard_budget_cannot_be_borrowed_from_next_shard(tmp_path, monkeypatch):
    manifest, pin, paths, blocks, raw = signed_package(tmp_path, True)
    first = TrackedFile(blocks[0] + blocks[1][:1])
    second = TrackedFile(blocks[1][1:])
    actual_open = Path.open
    opened = []

    def raced_open(path, *args, **kwargs):
        if path in paths:
            opened.append(path)
            return first if path == paths[0] else second
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', raced_open)
    with pytest.raises(ValueError, match='part exceeds signed size'):
        loader._manifest(tmp_path, pin)
    assert opened == [paths[0]]
    assert first.returned == len(blocks[0]) + 1
    assert second.returned == 0


def test_reader_exact_boundaries_hashes_every_shard_and_preserves_compatibility():
    paths = [MemoryPath(b'a'), MemoryPath(b'bc'), MemoryPath(b'def')]
    manifest = dict(payload_bytes=6, payload_parts=[dict(bytes=len(path.content),
        sha256=hashlib.sha256(path.content).hexdigest()) for path in paths])
    with PayloadReader(paths, manifest) as reader:
        assert reader.read(0) == b''
        assert reader.read(1) == b'a'
        assert reader.read(2) == b'bc'
        assert reader.read(10 ** 12) == b'def'
        assert reader.read(1) == b''
        with pytest.raises(ValueError, match='Unbounded'):
            reader.read(-1)
    assert [path.opened[0].requests for path in paths] == [[1, 1], [2, 1], [3, 1]]
    assert all(path.opened[0].closed for path in paths)
    with PayloadReader(paths) as reader:
        assert reader.read(6) == b'abcdef'
        assert reader.read(1) == b''


def test_reader_rejects_wrong_shard_digest_even_with_correct_aggregate_bytes():
    paths = [MemoryPath(b'ab'), MemoryPath(b'cd')]
    manifest = dict(payload_bytes=4, payload_parts=[dict(bytes=2, sha256='0' * 64),
        dict(bytes=2, sha256=hashlib.sha256(b'cd').hexdigest())])
    with PayloadReader(paths, manifest) as reader:
        with pytest.raises(ValueError, match='part digest mismatch'):
            reader.read(4)
    assert paths[1].opened == []


@pytest.mark.parametrize('content', [b'abc', b'abcd'])
def test_hashing_reader_enforces_aggregate_bound_and_authenticates_only_signed_bytes(content):
    stream = TrackedFile(content)
    reader = loader._HashingReader(stream, 3)
    assert reader.read(10 ** 12) == b'abc'
    assert reader.size == 3
    assert reader.digest.hexdigest() == hashlib.sha256(b'abc').hexdigest()
    if len(content) == 3:
        assert reader.read(1) == b''
        assert reader.read(1) == b''
    else:
        with pytest.raises(ValueError, match='exceeds signed size'):
            reader.read(10 ** 12)
    assert stream.requests == [3, 1]
    assert stream.returned <= 4
    assert reader.size == 3


def test_hashing_reader_rejects_short_and_unbounded_reads():
    reader = loader._HashingReader(io.BytesIO(b'ab'), 3)
    assert reader.read(3) == b'ab'
    with pytest.raises(ValueError, match='shorter than signed size'):
        reader.read(3)
    with pytest.raises(ValueError, match='Unbounded'):
        reader.read()


@pytest.mark.parametrize('sharded', [False, True])
def test_import_requires_full_authenticated_consumption(tmp_path, sharded):
    manifest, pin, paths, blocks, raw = signed_package(tmp_path, sharded)
    with pytest.raises(ValueError, match='Payload changed during import'):
        with loader._authenticated_payload(tmp_path, manifest):
            pass
