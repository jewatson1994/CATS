"""Archive selection inspects content without creating a scan or retaining files."""
import io
import json
import tarfile
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import main


def bundle(suffix, entries):
    stream = io.BytesIO()
    if suffix == 'zip':
        with zipfile.ZipFile(stream, 'w') as output:
            for name, body in entries.items():
                output.writestr(name, body)
    else:
        compression = {'tar': '', 'tgz': 'gz', 'tar.gz': 'gz',
                       'tar.bz2': 'bz2', 'tbz2': 'bz2', 'tar.xz': 'xz', 'txz': 'xz'}[suffix]
        with tarfile.open(fileobj=stream, mode='w:' + compression) as output:
            for name, body in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(body)
                output.addfile(member, io.BytesIO(body))
    return stream.getvalue()


@pytest.mark.parametrize('suffix', ['zip', 'tar', 'tgz', 'tar.gz', 'tar.bz2', 'tbz2', 'tar.xz', 'txz'])
def test_inspection_lists_content_detected_documents_and_cleans_up(tmp_path, monkeypatch, suffix):
    monkeypatch.setattr(main.tempfile, 'tempdir', str(tmp_path))
    def no_scan(*args, **kwargs):
        pytest.fail('Inspection must not start a scan')
    monkeypatch.setattr(main, '_start_public_scan', no_scan)
    content = bundle(suffix, {
        'app/Compose.txt': b'services: {web: {image: "nginx:1", environment: {TOKEN: secret-sentinel}}}',
        'app/compose.main.yaml(2)': b'services: {web: {image: "nginx:2"}}',
        'other/deployment': b'services: {db: {image: "postgres:16"}}',
        'app/.env': b'TOKEN=secret-sentinel',
        'app/settings.yaml': b'logging: {level: debug}',
        'app/logo.bin': b'\xff\x00',
        'not-compose/compose.yaml': b'just a text document',
    })
    response = TestClient(main.app).post('/api/public/compose/files', files=[
        ('compose_uploads', ('bundle.' + suffix, content, 'application/octet-stream')),
    ])
    assert response.status_code == 200, response.text
    assert response.json() == {'files': ['app/Compose.txt', 'app/compose.main.yaml(2)', 'other/deployment'],
                               'default_files': [], 'missing_variables': []}
    assert response.headers['cache-control'] == 'no-store'
    assert 'secret-sentinel' not in response.text
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('entries, expected', [
    ({'Compose.txt': b'services: {}'}, ['Compose.txt']),
    ({'a/compose.override.yaml': b'services: {}', 'a/compose.yaml': b'services: {}'},
     ['a/compose.yaml', 'a/compose.override.yaml']),
    ({'notes.txt': b'not compose'}, []),
    ({'resources.txt': b'networks: {default: {external: true}}'}, ['resources.txt']),
])
def test_inspection_defaults_only_unambiguous_selection(entries, expected):
    response = TestClient(main.app).post('/api/public/compose/files', files=[
        ('compose_uploads', (name, content)) for name, content in entries.items()
    ])
    assert response.status_code == 200
    assert response.json()['default_files'] == expected


@pytest.mark.parametrize('content', [b'not a zip', bundle('zip', {'../escape.yaml': b'services: {}'})])
def test_inspection_rejects_bad_archives_and_removes_temporary_files(tmp_path, monkeypatch, content):
    monkeypatch.setattr(main.tempfile, 'tempdir', str(tmp_path))
    response = TestClient(main.app).post('/api/public/compose/files', files=[
        ('compose_uploads', ('bundle.zip', content)),
    ])
    assert response.status_code == 422
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('profiles, variables, expected', [
    ('', {}, [dict(name='TOKEN', required=True, sources=['compose.yaml'], services=['web'])]),
    ('data,unused\nmetrics', {}, [
        dict(name='DB_TAG', required=False, sources=['compose.yaml'], services=['db']),
        dict(name='TOKEN', required=True, sources=['compose.yaml'], services=['web']),
    ]),
    ('data', {'TOKEN': 'entered-runtime-secret', 'DB_TAG': '16', 'TAG': 'entered-image-tag'}, []),
])
def test_inspection_reports_only_selected_active_missing_variables(
        tmp_path, monkeypatch, profiles, variables, expected):
    monkeypatch.setattr(main.tempfile, 'tempdir', str(tmp_path))
    monkeypatch.setattr(main, '_start_public_scan', lambda *a, **k: pytest.fail('Inspection must not start a scan'))
    response = TestClient(main.app).post('/api/public/compose/files', data={
        'compose_files': 'compose.yaml', 'compose_profiles': profiles,
        'compose_variables': json.dumps(variables),
    }, files=[
        ('compose_uploads', ('compose.yaml', b'''services:
  web:
    image: example/app:${TAG}
    environment:
      TOKEN: ${TOKEN:?private-required-message}
      OPTIONAL: ${OPTIONAL:-private-default-value}
  db:
    image: postgres:${DB_TAG}
    profiles: [data]
''')),
        ('compose_uploads', ('.env', b'TAG=dot-env-image-tag\n')),
        ('compose_uploads', ('other.yaml', b'services: {other: {image: "app:${UNSELECTED}"}}')),
    ])
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['files'] == ['compose.yaml', 'other.yaml']
    assert sorted(result['missing_variables'], key=lambda item: item['name']) == expected
    assert response.headers['cache-control'] == 'no-store'
    for private in ('private-required-message', 'private-default-value', 'dot-env-image-tag',
                    'entered-runtime-secret', 'entered-image-tag', 'UNSELECTED'):
        assert private not in response.text
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('selection, expected', [
    (None, [dict(name='TAG', required=False, sources=['compose.yaml'], services=['web'])]),
    ('', []),
])
def test_inspection_distinguishes_omitted_selection_from_explicit_empty(selection, expected):
    data = {} if selection is None else {'compose_files': selection}
    response = TestClient(main.app).post('/api/public/compose/files', data=data, files=[
        ('compose_uploads', ('compose.yaml', b'services: {web: {image: "app:${TAG}"}}')),
    ])
    assert response.status_code == 200, response.text
    assert response.json()['default_files'] == ['compose.yaml']
    assert response.json()['missing_variables'] == expected


@pytest.mark.parametrize('raw', [
    '{"TOKEN":"invalid-variable-secret"',
    '"invalid-variable-secret"',
    'null',
    '["invalid-variable-secret"]',
    '{"TOKEN":null}',
    '{"TOKEN":5}',
    '{"TOKEN":true}',
    '{"TOKEN":["invalid-variable-secret"]}',
    '{"bad name":"invalid-variable-secret"}',
    json.dumps({'A' * 129: 'invalid-variable-secret'}),
    json.dumps({'TOKEN': 'invalid-variable-secret\x00'}),
    json.dumps({'TOKEN': 'invalid-variable-secret' + 'x' * 8192}),
    json.dumps({f'VARIABLE_{index}': 'invalid-variable-secret' for index in range(201)}),
    json.dumps({f'VARIABLE_{index}': 'invalid-variable-secret' + 'x' * 8000 for index in range(9)}),
], ids=['malformed', 'string', 'null', 'array', 'null-value', 'number-value', 'boolean-value',
        'array-value', 'invalid-name', 'long-name', 'nul-value', 'long-value', 'entry-limit', 'total-limit'])
def test_inspection_rejects_invalid_variable_values_without_echo_or_retention(tmp_path, monkeypatch, raw):
    monkeypatch.setattr(main.tempfile, 'tempdir', str(tmp_path))
    monkeypatch.setattr(main, '_start_public_scan', lambda *a, **k: pytest.fail('Inspection must not start a scan'))
    response = TestClient(main.app).post('/api/public/compose/files', data={
        'compose_variables': raw,
    }, files=[('compose_uploads', ('compose.yaml', b'services: {}'))])
    assert response.status_code == 422
    assert isinstance(response.json()['detail'], str)
    assert 'invalid-variable-secret' not in response.text
    assert len(response.text) < 500
    assert list(tmp_path.iterdir()) == []
