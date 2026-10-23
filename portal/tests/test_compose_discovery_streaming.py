from io import BytesIO
import tarfile
import zipfile

import pytest

from app.compose_ingestion import MAX_FILE, ComposeInputError, stage_uploads


class ChunkedInput(BytesIO):
    def read(self, size=-1):
        assert 0 < size <= 1024 * 1024, 'Whole-upload read attempted'
        return super().read(size)


@pytest.mark.parametrize('limit', [None, 0])
@pytest.mark.parametrize('kind', ['raw', 'zip', 'tar.gz'])
def test_streaming_unlimited_large_file(tmp_path, limit, kind):
    payload = b'x' * (MAX_FILE + 1)
    source = BytesIO()
    if kind == 'zip':
        with zipfile.ZipFile(source, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('nested/large.txt', payload)
    elif kind == 'tar.gz':
        with tarfile.open(fileobj=source, mode='w:gz') as archive:
            member = tarfile.TarInfo('nested/large.txt')
            member.size = len(payload)
            archive.addfile(member, BytesIO(payload))
    else:
        source.write(payload)
    stream = ChunkedInput(source.getvalue())
    result = stage_uploads(tmp_path, [(stream, 'nested/large.txt' if kind == 'raw' else 'bundle.' + kind)],
                           max_files=limit, max_total=limit, max_file=limit)
    assert (result['root'] / 'nested/large.txt').read_bytes() == payload
    assert not stream.closed
    assert not list(tmp_path.glob('.cats-stage-*'))


def test_unlimited_entry_count_and_default_compose_limit(tmp_path):
    source = BytesIO()
    with zipfile.ZipFile(source, 'w') as archive:
        for index in range(501):
            archive.writestr(str(index), b'x')
    with pytest.raises(ComposeInputError, match='500 entries'):
        stage_uploads(tmp_path, [(source.getvalue(), 'bundle.zip')])
    assert not list(tmp_path.iterdir())
    result = stage_uploads(tmp_path, [(ChunkedInput(source.getvalue()), 'bundle.zip')],
                           max_files=None, max_total=None, max_file=None)
    assert len(result['files']) == 501


@pytest.mark.parametrize('kwargs, message', [({}, 'Archive file exceeds'),
                                            ({'max_file': None, 'max_total': 2}, 'Expanded archive exceeds')])
def test_limits_leave_no_partial_files(tmp_path, kwargs, message):
    with pytest.raises(ComposeInputError, match=message):
        stage_uploads(tmp_path, [(b'ok', 'first'), (b'x' * (MAX_FILE + 1), 'second')], **kwargs)
    assert not list(tmp_path.iterdir())


def test_cancellation_during_publication_rolls_back(tmp_path):
    class Cancelled(RuntimeError):
        pass

    def cancel():
        if (tmp_path / '.cats-compose' / 'nested' / 'first').exists():
            raise Cancelled('cancel')

    with pytest.raises(Cancelled):
        stage_uploads(tmp_path, [(b'ok', 'nested/first'), (b'ok', 'second')], check_cancelled=cancel)
    assert not list(tmp_path.iterdir())


def test_collision_preserves_existing_destination(tmp_path):
    destination = tmp_path / '.cats-compose'
    destination.mkdir()
    (destination / 'existing').write_bytes(b'original')
    with pytest.raises(ComposeInputError):
        stage_uploads(tmp_path, [(b'new', 'new'), (b'replacement', 'existing')])
    assert list(destination.iterdir()) == [destination / 'existing']
    assert (destination / 'existing').read_bytes() == b'original'


def test_corrupt_zip_cleans_staging(tmp_path):
    source = BytesIO()
    with zipfile.ZipFile(source, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('first', b'original-content')
    damaged = source.getvalue().replace(b'original-content', b'changed!-content')
    with pytest.raises(ComposeInputError):
        stage_uploads(tmp_path, [(damaged, 'bundle.zip')], max_files=None, max_total=None, max_file=None)
    assert not list(tmp_path.iterdir())


def test_disk_exhaustion_is_actionable_and_cleans_staging(tmp_path, monkeypatch):
    import errno
    from pathlib import Path
    original = Path.open

    def fail(path, *args, **kwargs):
        if path.name == '0' and path.parent.name.startswith('.cats-stage-'):
            raise OSError(errno.ENOSPC, 'sensitive-device-path')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', fail)
    with pytest.raises(ComposeInputError, match='Insufficient disk space') as error:
        stage_uploads(tmp_path, [(b'content', 'first')])
    assert 'sensitive' not in str(error.value)
    assert not list(tmp_path.iterdir())


def test_discover_optional_limits_preserve_compose_defaults(tmp_path):
    from app.compose_ingestion import discover
    source = tmp_path / 'compose.yaml'
    source.write_text('services: {web: {image: nginx:1.27}}\n#' + 'x' * MAX_FILE)
    bounded = discover(tmp_path, ['compose.yaml'])
    assert bounded['complete'] is False
    unlimited = discover(tmp_path, ['compose.yaml'], max_file=None, max_files=None, max_total=None)
    assert unlimited['images'] == ['nginx:1.27']



def test_archive_upload_and_expansion_limits_are_independent(tmp_path):
    source = BytesIO()
    with zipfile.ZipFile(source, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('tiny', b'x')
    assert len(source.getvalue()) > 1
    staged = stage_uploads(tmp_path, [(source.getvalue(), 'bundle.zip')],
                           max_total=1, max_archive_bytes=None)
    assert (staged['root'] / 'tiny').read_bytes() == b'x'


def test_compose_file_selection_limit_can_be_disabled(tmp_path):
    from app.compose_ingestion import discover
    files = []
    for index in range(51):
        name = f'{index}.yaml'
        (tmp_path / name).write_text('services: {web: {image: nginx:1.27}}')
        files.append(name)
    assert discover(tmp_path, files)['complete'] is False
    assert discover(tmp_path, files, max_selected_files=0)['images'] == ['nginx:1.27']
