import base64
from app.discovery_render_cache import RenderCache

def test_cache_reuses_and_invalidates_all_visible_files(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x'*32).decode())
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'values.yaml').write_text('a: 1')
    calls = []
    def runner(*args):
        calls.append(args)
        return {'stdout': 'secret-manifest', 'version': 'v1'}
    cache = RenderCache(runner, tmp_path / 'cache', 'group-source', lambda tool: 'v1')
    args = ['template', str(source)]
    assert cache('helm', args, source) == cache('helm', args, source)
    assert len(calls) == 1
    assert b'secret-manifest' not in next((tmp_path/'cache').glob('*.cache')).read_bytes()
    (source / 'dependency.yaml').write_text('changed')
    cache('helm', args, source)
    assert len(calls) == 2
    cache.scope = 'other-group'
    cache('helm', args, source)
    assert len(calls) == 3
    cache.version = lambda tool: 'v2'
    cache('helm', args, source)
    assert len(calls) == 4

def test_corrupt_cache_renders_again(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x'*32).decode())
    source = tmp_path/'source'
    source.mkdir()
    calls = []
    cache = RenderCache(lambda *args: calls.append(1) or {'stdout':'ok'}, tmp_path/'cache', 'source', lambda tool:'v1')
    cache('helm', [], source)
    next((tmp_path/'cache').glob('*.cache')).write_bytes(b'corrupt')
    cache('helm', [], source)
    assert len(calls) == 2
