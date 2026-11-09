import base64
import pytest
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

def test_helm_dependency_scope_excludes_unrelated_and_tracks_values(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x'*32).decode())
    source=tmp_path/'repo'; source.mkdir()
    chart=source/'chart-a'; chart.mkdir()
    (chart/'Chart.yaml').write_text('apiVersion: v2\nname: a\nversion: 1.0.0')
    (chart/'values.yaml').write_text('image: one')
    values=source/'selected.yaml'; values.write_text('image: override')
    other=source/'unrelated.yaml'; other.write_text('one')
    calls=[]
    def runner(tool,args,cwd):
        from pathlib import Path
        root=Path(cwd)
        assert not (root/'unrelated.yaml').exists()
        assert Path(args[2]).is_dir() and Path(args[4]).is_file()
        calls.append(args)
        return {'stdout':'ok'}
    cache=RenderCache(runner,tmp_path/'cache','scope',lambda _: 'v1')
    args=['template','release',str(chart),'-f',str(values)]
    cache('helm',args,source)
    other.write_text('two')
    cache('helm',args,source)
    assert len(calls)==1 and cache.hits==1
    values.write_text('image: different')
    cache('helm',args,source)
    assert len(calls)==2
    (chart/'values.yaml').write_text('image: changed')
    cache('helm',args,source)
    assert len(calls)==3 and cache.scoped_renders==4

def test_generated_values_paths_do_not_invalidate_same_content(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x'*32).decode())
    chart=tmp_path/'chart'; chart.mkdir()
    (chart/'Chart.yaml').write_text('name: a')
    calls=[]
    cache=RenderCache(lambda *args: calls.append(1) or {'stdout':'ok'},tmp_path/'cache','scope',lambda _: 'v1')
    for name in ['random-first.yaml','random-second.yaml']:
        values=tmp_path/name; values.write_text('image: same')
        cache('helm',['template','release',str(chart),'-f',str(values)],tmp_path)
        values.unlink()
    assert len(calls)==1

def test_kustomize_scope_tracks_shared_base_not_other_root(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x'*32).decode())
    source=tmp_path/'repo'; source.mkdir()
    base=source/'base'; base.mkdir()
    overlay=source/'overlay'; overlay.mkdir()
    (base/'kustomization.yaml').write_text('resources: [pod.yaml]')
    pod=base/'pod.yaml'; pod.write_text('kind: Pod')
    (overlay/'kustomization.yaml').write_text('resources: [../base]')
    unrelated=source/'unrelated.yaml'; unrelated.write_text('one')
    calls=[]
    def runner(tool,args,cwd):
        from pathlib import Path
        root=Path(args[1]); assert (root/'../base/pod.yaml').is_file()
        assert not (Path(cwd)/'unrelated.yaml').exists()
        calls.append(1)
        return {'stdout':'ok'}
    cache=RenderCache(runner,tmp_path/'cache','scope',lambda _: 'v1')
    args=['build',str(overlay)]
    cache('kustomize',args,source)
    unrelated.write_text('two')
    cache('kustomize',args,source)
    assert len(calls)==1
    pod.write_text('kind: Deployment')
    cache('kustomize',args,source)
    assert len(calls)==2


def test_failed_render_is_retried_then_success_survives_cache_recreation(tmp_path, monkeypatch):
    from app.rendering import RendererError
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    calls = []
    def runner(*args):
        calls.append(1)
        if len(calls) == 1:
            raise RendererError('Transient renderer failure')
        return {'stdout': 'recovered'}
    cache = RenderCache(runner, tmp_path / 'cache', 'source', lambda _: 'v1')
    with pytest.raises(RendererError):
        cache('helm', [], source)
    assert cache('helm', [], source)['stdout'] == 'recovered'
    reopened = RenderCache(runner, tmp_path / 'cache', 'source', lambda _: 'v1')
    assert reopened('helm', [], source)['stdout'] == 'recovered'
    assert len(calls) == 2 and reopened.hits == 1


def test_nonzero_result_does_not_poison_cache(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    calls = []
    cache = RenderCache(lambda *args: calls.append(1) or {'stdout': '', 'returncode': 1},
                        tmp_path / 'cache', 'source', lambda _: 'v1')
    cache('helm', [], source)
    cache('helm', [], source)
    assert len(calls) == 2 and cache.hits == 0


def test_unparseable_native_success_can_be_invalidated(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    calls = []
    cache = RenderCache(lambda *args: calls.append(1) or {'stdout': 'bad: ['},
                        tmp_path / 'cache', 'source', lambda _: 'v1')
    cache('helm', [], source)
    cache.invalidate_last()
    cache('helm', [], source)
    assert len(calls) == 2 and cache.hits == 0


def test_cache_write_failure_does_not_repeat_successful_renderer(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    cache_path = tmp_path / 'cache'; cache_path.write_text('not a directory')
    calls = []
    cache = RenderCache(lambda *args: calls.append(1) or {'stdout': 'success'}, cache_path, 'source', lambda _: 'v1')
    assert cache('helm', [], source)['stdout'] == 'success'
    assert len(calls) == 1


def test_native_io_failure_is_not_invoked_twice(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    calls = []
    def runner(*args):
        calls.append(1)
        raise OSError('native tool unavailable')
    cache = RenderCache(runner, tmp_path / 'cache', 'source', lambda _: 'v1')
    with pytest.raises(OSError, match='native tool unavailable'):
        cache('helm', [], source)
    assert len(calls) == 1


def test_component_override_only_invalidates_affected_render(tmp_path, monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    charts = []
    for name in ('one', 'two'):
        chart = source / name; chart.mkdir()
        (chart / 'Chart.yaml').write_text('name: ' + name)
        charts.append(chart)
    override = source / 'override.yaml'; override.write_text('replicas: 1')
    calls = []
    cache = RenderCache(lambda tool, args, cwd: calls.append(args[1]) or {'stdout': args[1]},
                        tmp_path / 'cache', 'source', lambda _: 'v1')
    for _ in range(2):
        cache('helm', ['template', 'one', str(charts[0]), '-f', str(override)], source)
        cache('helm', ['template', 'two', str(charts[1])], source)
        override.write_text('replicas: 2')
    assert calls == ['one', 'two', 'one'] and cache.hits == 1


def test_source_cache_cleanup_preserves_other_sources_and_removes_pending_files(tmp_path, monkeypatch):
    from app.discovery_render_cache import remove_source_cache
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'; source.mkdir()
    directory = tmp_path / 'cache'
    monkeypatch.setenv('CATS_DISCOVERY_RENDER_CACHE_DIR', str(directory))
    for token in ('a' * 32, 'b' * 32):
        cache = RenderCache(lambda *args: {'stdout': 'secret-manifest'}, directory, token,
                            lambda _: 'v1', source_id=token)
        cache('helm', [], source)
    pending = directory / ('a' * 32 + '-interrupted.pending'); pending.write_bytes(b'encrypted')
    unrelated = directory / 'keep.txt'; unrelated.write_text('keep')
    remove_source_cache('../outside')
    assert len(list(directory.glob('*.cache'))) == 2
    remove_source_cache('a' * 32)
    assert not pending.exists() and unrelated.exists()
    remaining = list(directory.glob('*.cache'))
    assert len(remaining) == 1 and remaining[0].name.startswith('b' * 32 + '-')
    assert b'secret-manifest' not in remaining[0].read_bytes()


def test_source_cache_cleanup_reports_unreadable_directory(tmp_path, monkeypatch):
    from app import discovery_render_cache
    directory = tmp_path / 'cache'; directory.mkdir()
    monkeypatch.setenv('CATS_DISCOVERY_RENDER_CACHE_DIR', str(directory))
    def denied(directory):
        raise PermissionError('cache cannot be read')
    monkeypatch.setattr(discovery_render_cache.os, 'scandir', denied)
    with pytest.raises(PermissionError):
        discovery_render_cache.remove_source_cache('a' * 32)
