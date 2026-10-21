"""Native Compose semantics override limitations of the fallback parser."""
import json
from app.discovery_engine import run_discovery


def test_native_extends_resolves_inherited_image(tmp_path):
    (tmp_path / 'compose.yaml').write_text('services: {web: {extends: {file: base.yaml, service: base}}}')
    (tmp_path / 'base.yaml').write_text('services: {base: {image: nginx:1.27}}')
    result = run_discovery(tmp_path, runner=lambda *args: json.dumps({'services': {'web': {'image': 'nginx:1.27'}}}))
    assert [i['reference'] for i in result['images']] == ['nginx:1.27']
    assert result['completeness'] == 'complete'


def test_native_include_is_not_blocked_by_fallback(tmp_path):
    (tmp_path / 'compose.yaml').write_text('include: [child.yaml]')
    (tmp_path / 'child.yaml').write_text('services: {web: {image: nginx:1.27}}')
    result = run_discovery(tmp_path, runner=lambda *args: json.dumps({'services': {'web': {'image': 'nginx:1.27'}}}))
    assert result['completeness'] == 'complete'
    assert len(result['images']) == 1


def test_native_compose_empty_profiles_are_incomplete(tmp_path):
    (tmp_path / 'compose.yaml').write_text('services: {web: {image: nginx:1.27, profiles: [optional]}}')
    result = run_discovery(tmp_path, runner=lambda *args: '{"services": {}}')
    assert result['completeness'] != 'complete'
    assert any(d['code'] == 'no_active_services' for d in result['diagnostics'])


def test_default_override_uses_single_preferred_file(tmp_path):
    for name in ('compose.yaml', 'compose.override.yaml', 'docker-compose.override.yml'):
        (tmp_path / name).write_text('services: {web: {image: nginx:1.27}}')
    def runner(tool, args, cwd):
        assert args.count('-f') == 2
        assert any(value.endswith('compose.override.yaml') for value in args)
        return '{"services": {"web": {"image": "nginx:1.27"}}}'
    assert run_discovery(tmp_path, runner=runner)['completeness'] == 'complete'


def test_native_compose_reset_tag_is_owned_by_compose(tmp_path):
    (tmp_path / 'compose.yaml').write_text('services: {web: {image: nginx:1.27}}')
    (tmp_path / 'compose.override.yaml').write_text('services: {web: {ports: !reset []}}')
    result = run_discovery(tmp_path, runner=lambda *args: '{"services": {"web": {"image": "nginx:1.27"}}}')
    assert result['completeness'] == 'complete'
