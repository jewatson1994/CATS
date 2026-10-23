"""Regression coverage for streaming repositories beyond historical ceilings."""
import hashlib
import tracemalloc
import zipfile
from pathlib import Path
import pytest
from app.discovery_engine import run_discovery

POD = 'apiVersion: v1\nkind: Pod\nmetadata: {name: web}\nspec:\n  containers: [{name: web, image: nginx:1.27}]\n'


def test_large_repository_is_streamed(tmp_path, monkeypatch):
    archive = tmp_path / 'repository.zip'
    block = b'x' * (1024 * 1024)
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as output:
        with output.open('large.bin', 'w') as member:
            for _ in range(129):
                member.write(block)
        output.writestr('pod.yaml', POD)
    assert archive.stat().st_size > 128 * 1024 * 1024
    def forbidden(*args, **kwargs):
        raise AssertionError('Repository must not use whole-file read_bytes')
    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    tracemalloc.start()
    try:
        result = run_discovery(archive)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result['images'][0]['reference'] == 'nginx:1.27'
    assert result['metrics']['files'] == 2
    assert peak < 32 * 1024 * 1024


def test_repository_more_than_ten_thousand_entries(tmp_path):
    archive = tmp_path / 'many.zip'
    with zipfile.ZipFile(archive, 'w') as output:
        for index in range(10001):
            output.writestr(f'docs/{index}.txt', '')
        output.writestr('pod.yaml', POD)
    result = run_discovery(archive)
    assert result['metrics']['files'] == 10002
    assert result['images'][0]['reference'] == 'nginx:1.27'


def test_document_larger_than_four_mib(tmp_path):
    (tmp_path / 'pod.yaml').write_text('#' + 'x' * (4 * 1024 * 1024) + '\n' + POD)
    result = run_discovery(tmp_path)
    assert result['images'][0]['reference'] == 'nginx:1.27'


def test_cancellation_cleans_repository_scratch(tmp_path, monkeypatch):
    import app.discovery_engine as engine
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'large.bin').write_bytes(b'x' * (3 * 1024 * 1024))
    monkeypatch.setattr(engine.tempfile, 'tempdir', str(scratch))
    class Cancelled(Exception):
        pass
    calls = 0
    def check():
        nonlocal calls
        calls += 1
        if calls == 3:
            raise Cancelled()
    with pytest.raises(Cancelled):
        run_discovery(source, check_cancelled=check)
    assert not list(scratch.iterdir())


def test_large_encrypted_source_has_no_128_mib_clamp(tmp_path, monkeypatch):
    import base64
    from app.discovery_sources import encrypted_writer, decrypted_source
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.b64encode(b'k' * 32).decode())
    monkeypatch.setenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', str(256 * 1024 * 1024))
    encrypted = tmp_path / 'encrypted.zip'
    chunk = b'x' * (1024 * 1024)
    digest = hashlib.sha256()
    with encrypted_writer(encrypted, 'a' * 32) as stream:
        for _ in range(129):
            stream.write(chunk)
            digest.update(chunk)
    with decrypted_source(encrypted, 'a' * 32, digest.hexdigest()) as plaintext:
        assert plaintext.stat().st_size == 129 * 1024 * 1024
    assert not plaintext.exists()


def test_large_compose_document_uses_discovery_limits(tmp_path):
    (tmp_path / 'compose.yaml').write_text('#' + 'x' * (4 * 1024 * 1024) + '\nservices:\n  web:\n    image: nginx:1.27\n')
    result = run_discovery(tmp_path)
    assert result['images'][0]['reference'] == 'nginx:1.27'
