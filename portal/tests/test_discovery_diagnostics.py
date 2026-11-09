"""Coverage and tuning regressions with local, deterministic render fixtures."""
import json
from pathlib import Path

import pytest
import yaml

from app.discovery_engine import run_discovery
from app.rendering import RendererError, renderer_failure_reason


def write(root, path, content):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding='utf-8')


def chart(root, path='', *, name='suite', metadata=''):
    write(root, str(Path(path) / 'Chart.yaml'), f'apiVersion: v2\nname: {name}\nversion: 1.0.0\n{metadata}')


def pod(name='suite', image='suite:1'):
    return yaml.safe_dump(dict(apiVersion='v1', kind='Pod', metadata=dict(name=name),
                               spec=dict(containers=[dict(name='app', image=image)])))


def test_disabled_dependency_and_library_are_complete_parent_coverage(tmp_path):
    chart(tmp_path, metadata='''dependencies:
- name: optional
  version: 1.0.0
  condition: optional.enabled
- name: common
  version: 1.0.0
''')
    write(tmp_path, 'values.yaml', 'optional: {enabled: false}')
    chart(tmp_path, 'charts/optional', name='optional')
    chart(tmp_path, 'charts/common', name='common', metadata='type: library\n')
    calls = []

    def runner(tool, args, cwd):
        calls.append(tool)
        return pod()

    result = run_discovery(tmp_path, runner=runner)
    assert calls == ['helm']
    assert result['completeness'] == 'complete'
    assert result['images'][0]['reference'] == 'suite:1'
    assert {d['code'] for d in result['diagnostics']} == {'helm_dependency_disabled', 'helm_library_chart'}
    assert all(d['severity'] == 'info' and d['blocking'] is False for d in result['diagnostics'])
    assert all(d['component_id'] and d['root_id'] for d in result['diagnostics'])


def test_disabled_available_dependency_does_not_hide_parent_render_failure(tmp_path):
    chart(tmp_path, metadata='dependencies: [{name: optional, version: 1.0.0, condition: optional.enabled}]')
    chart(tmp_path, 'charts/optional', name='optional')
    write(tmp_path, 'values.yaml', 'optional: {enabled: false}')

    def runner(*args):
        raise RendererError('PRIVATE-ERROR', value_paths=['storage.bucket'], reason='required_values')

    result = run_discovery(tmp_path, runner=runner)
    failure, = [d for d in result['diagnostics'] if d['blocking']]
    assert failure['code'] == 'native_render_failed'
    assert failure['value_paths'] == ['storage.bucket']
    assert result['completeness'] != 'complete'
    assert 'PRIVATE-ERROR' not in json.dumps(result)


def test_standalone_library_is_not_sent_to_renderer(tmp_path):
    chart(tmp_path, name='common', metadata='type: library\n')

    def runner(*args):
        pytest.fail('Helm library charts cannot be independently rendered')

    result = run_discovery(tmp_path, runner=runner)
    assert result['completeness'] == 'complete'
    assert result['roots'][0]['state'] == 'library'
    assert result['configurable_components'] == []


def test_known_custom_configuration_and_unknown_operator_coverage(tmp_path):
    resources = [dict(apiVersion=group + '/v1', kind=kind, metadata=dict(name=name))
                 for group, kind, name in [
                     ('cert-manager.io', 'Issuer', 'tls'),
                     ('trust.cert-manager.io', 'Bundle', 'roots'),
                     ('velero.io', 'BackupStorageLocation', 's3'),
                     ('velero.io', 'VolumeSnapshotLocation', 'volumes')]]
    write(tmp_path, 'resources.yaml', yaml.safe_dump_all(resources))
    result = run_discovery(tmp_path)
    assert result['completeness'] == 'complete'
    assert all(d['code'] == 'custom_resource_configuration' and not d['blocking'] for d in result['diagnostics'])
    write(tmp_path, 'operator.yaml', yaml.safe_dump_all([
        dict(apiVersion='operator.example/v1', kind='Database', metadata=dict(name=name))
        for name in ('one', 'two', 'three')]))
    result = run_discovery(tmp_path)
    issue, = [d for d in result['diagnostics'] if d['code'] == 'custom_resource_workloads_not_evaluated']
    assert issue['resource_kind'] == 'Database' and issue['occurrences'] == 3
    assert issue['blocking'] and result['completeness'] == 'partial'


def test_certificate_requests_retain_controller_workload_coverage_warning(tmp_path):
    write(tmp_path, 'resources.yaml', yaml.safe_dump_all([
        dict(apiVersion='cert-manager.io/v1', kind=kind, metadata=dict(name='tls'))
        for kind in ('Certificate', 'CertificateRequest')]))
    result = run_discovery(tmp_path)
    assert result['completeness'] == 'partial'
    assert {d['resource_kind'] for d in result['diagnostics']} == {'Certificate', 'CertificateRequest'}
    assert all(d['code'] == 'custom_resource_workloads_not_evaluated' and d['blocking'] for d in result['diagnostics'])


@pytest.mark.parametrize('stderr, expected', [
    ('failed to fetch https://user:PRIVATE@charts.invalid/chart.tgz', 'artifact_retrieval_failed'),
    ('unable to run helm pull --repo https://PRIVATE.invalid', 'artifact_retrieval_failed'),
    ('must specify --enable-helm', 'helm_unavailable'),
    ('values do not meet the specifications of the schema: PRIVATE', 'invalid_values_or_yaml'),
    ('error converting YAML to JSON: yaml: line 7: PRIVATE', 'invalid_values_or_yaml'),
    ('open PRIVATE.yaml: no such file or directory', 'missing_resource'),
    ('execution error at (chart/templates/config.yaml:2): please set global.host PRIVATE', 'required_values'),
    ('template: app: error calling fail: PRIVATE', 'template_error'),
    ('no matches for Id: PRIVATE; failed to find unique target for patch', 'patch_target_missing'),
    ('PRIVATE', 'render_failed'),
])
def test_native_failure_categories_do_not_copy_stderr(stderr, expected):
    assert renderer_failure_reason(stderr) == expected


def test_kustomize_retrieval_error_has_safe_action(tmp_path):
    write(tmp_path, 'kustomization.yaml', 'helmCharts: [{name: app, repo: https://charts.invalid}]')

    def runner(*args):
        raise RendererError('PRIVATE', reason='artifact_retrieval_failed')

    result = run_discovery(tmp_path, runner=runner)
    issue, = [d for d in result['diagnostics'] if d['code'] == 'native_render_failed']
    assert issue['reason'] == 'artifact_retrieval_failed' and issue['renderer'] == 'kustomize'
    assert 'locally' in issue['message'] and 'without network access' in issue['message']
    assert 'PRIVATE' not in json.dumps(result)


def test_postrenderer_failure_names_kustomize_and_keeps_component_owner(tmp_path):
    chart(tmp_path, 'charts/child', name='child')
    write(tmp_path, 'flux.yaml', '''apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: application}
spec:
  chart: {spec: {chart: charts/child}}
  postRenderers:
    - kustomize:
        patches: [{patch: '{}', target: {kind: Deployment, name: missing}}]
''')

    def runner(tool, *args):
        if tool == 'helm':
            return pod()
        raise RendererError('PRIVATE', reason='patch_target_missing')

    result = run_discovery(tmp_path, runner=runner)
    issue, = [d for d in result['diagnostics'] if d['code'] == 'native_render_failed']
    release, = [n for n in result['nodes'] if n['kind'] == 'HelmRelease']
    assert issue['renderer'] == 'kustomize' and issue['component_id'] == release['id']
    assert issue['reason'] == 'patch_target_missing' and result['images'] == []


@pytest.mark.parametrize('success', [False, True])
def test_source_values_parse_limitation_tracks_native_outcome_and_owner(tmp_path, success):
    chart(tmp_path, 'loki', name='loki')
    write(tmp_path, 'loki/values.yaml', 'bucket: first\nbucket: second\n')

    def runner(*args):
        if not success:
            raise RendererError('PRIVATE', reason='invalid_values_or_yaml')
        return pod()

    result = run_discovery(tmp_path, runner=runner)
    issue, = [d for d in result['diagnostics'] if d['path'] == 'loki/values.yaml']
    assert issue['reason'] == 'duplicate_keys'
    assert issue['root_id'] == result['roots'][0]['id'] == issue['component_id']
    assert issue['blocking'] is not success
    assert issue['code'] == ('source_values_parser_limitation' if success else 'invalid_or_unsupported_document')
    assert (result['completeness'] == 'complete') is success


def test_values_yaml_syntax_error_records_location_without_source_content(tmp_path):
    chart(tmp_path)
    write(tmp_path, 'values.yaml', 'password: [PRIVATE\n')

    def runner(*args):
        raise RendererError('PRIVATE', reason='invalid_values_or_yaml')

    result = run_discovery(tmp_path, runner=runner)
    issue, = [d for d in result['diagnostics'] if d['code'] == 'invalid_or_unsupported_document']
    assert issue['reason'] == 'invalid_yaml' and issue['line'] == 2
    assert 'PRIVATE' not in json.dumps(result)


def test_native_render_does_not_hide_unreadable_service_catalog(tmp_path):
    chart(tmp_path)
    write(tmp_path, 'values.yaml', 'services: {one: {}}\nservices: {two: {}}\n')
    result = run_discovery(tmp_path, runner=lambda *args: pod())
    issue, = [d for d in result['diagnostics'] if d['code'] == 'invalid_or_unsupported_document']
    assert issue['reason'] == 'duplicate_keys' and issue['blocking']
    assert result['completeness'] == 'partial'


def test_shared_chart_parse_diagnostics_keep_each_release_identity(tmp_path):
    chart(tmp_path, 'charts/child', name='child')
    write(tmp_path, 'charts/child/values.yaml', 'bucket: first\nbucket: second\n')
    write(tmp_path, 'flux.yaml', yaml.safe_dump_all([
        dict(apiVersion='helm.toolkit.fluxcd.io/v2', kind='HelmRelease', metadata=dict(name=name),
             spec=dict(chart=dict(spec=dict(chart='charts/child')))) for name in ('one', 'two')]))
    result = run_discovery(tmp_path, runner=lambda tool, args, cwd: pod(args[1]))
    diagnostics = [d for d in result['diagnostics'] if d['code'] == 'source_values_parser_limitation']
    releases = {n['id']: n['name'] for n in result['nodes'] if n['kind'] == 'HelmRelease'}
    assert len(diagnostics) == 2
    assert {d['component_id']: d['component_name'] for d in diagnostics} == releases
    assert all(d['blocking'] is False for d in diagnostics)


def test_identical_coverage_warnings_are_grouped_per_root_and_kind(tmp_path):
    for root_name in ('one', 'two'):
        chart(tmp_path, root_name, name=root_name)

    def runner(*args):
        return yaml.safe_dump_all([
            dict(apiVersion='operator.example/v1', kind=kind, metadata=dict(name=kind + str(index)))
            for kind in ('Database', 'Queue') for index in (1, 2)])

    result = run_discovery(tmp_path, runner=runner)
    warnings = [d for d in result['diagnostics'] if d['code'] == 'custom_resource_workloads_not_evaluated']
    assert len(warnings) == 4
    assert all(d['occurrences'] == 2 and d['blocking'] for d in warnings)
    assert len({(d['root_id'], d['resource_kind']) for d in warnings}) == 4


def test_successful_native_exit_with_invalid_workload_yaml_is_never_reused(tmp_path, monkeypatch):
    import base64
    from app.discovery_render_cache import RenderCache
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'x' * 32).decode())
    source = tmp_path / 'source'
    chart(source)
    write(source, 'values.yaml', 'enabled: true')
    calls = []

    def runner(*args):
        calls.append(1)
        return {'stdout': 'apiVersion: [PRIVATE', 'version': 'v1'}

    cache = RenderCache(runner, tmp_path / 'cache', 'source', lambda _: 'v1')
    for _ in range(2):
        result = run_discovery(source, runner=cache)
        assert any(d.get('reason') == 'invalid_rendered_document' for d in result['diagnostics'])
        assert not list((tmp_path / 'cache').glob('*.cache'))
        assert 'PRIVATE' not in json.dumps(result)
    assert len(calls) == 2 and cache.hits == 0


def test_component_inline_override_is_last_file_and_scoped_to_one_chart(tmp_path):
    for name in ('one', 'two'):
        chart(tmp_path, name, name=name)
        write(tmp_path, name + '/values.yaml', 'image: default\n')
    write(tmp_path, 'selected.yaml', 'image: selected\n')

    def runner(tool, args, cwd):
        values = yaml.safe_load((Path(args[2]) / 'values.yaml').read_text())
        for index, arg in enumerate(args):
            if index and args[index - 1] == '-f':
                values.update(yaml.safe_load(Path(arg).read_text()))
        return pod(Path(args[2]).name, values['image'])

    initial = run_discovery(tmp_path, runner=runner)
    component = next(c for c in initial['configurable_components'] if c['label'] == 'one')
    inline = 'image: tuned\ncomment: ' + 'x' * 600 + '\n'
    options = {'component_values': {component['id']: ['selected.yaml']}, 'component_overrides': {component['id']: inline}}
    tuned = run_discovery(tmp_path, options, runner=runner)
    assert {i['reference'] for i in tuned['images']} == {'tuned', 'default'}
    configuration = next(c for c in tuned['configurable_components'] if c['id'] == component['id'])
    assert configuration['values_yaml'] == inline and configuration['selected_values'] == ['selected.yaml']
    assert tuned == run_discovery(tmp_path, options, runner=runner)
    assert not list(tmp_path.glob('.discovery-*'))


@pytest.mark.parametrize('inline', ['x: [PRIVATE', 'apiVersion: v1\nkind: Secret', 'x: &item {value: PRIVATE}\ny: *item', '1: PRIVATE'])
def test_invalid_direct_component_override_fails_without_retaining_input(tmp_path, inline):
    chart(tmp_path)
    write(tmp_path, 'values.yaml', 'image: ordinary')
    initial = run_discovery(tmp_path, runner=lambda *args: pod())
    component = initial['configurable_components'][0]['id']
    result = run_discovery(tmp_path, {'component_overrides': {component: inline}}, runner=lambda *args: pytest.fail('invalid override must block rendering'))
    assert any(d['code'] == 'component_override_invalid' and d['component_id'] == component for d in result['diagnostics'])
    assert result['configurable_components'][0]['values_yaml'] == ''
    assert 'PRIVATE' not in json.dumps(result)


def test_secret_derived_images_and_override_stay_redacted(tmp_path):
    chart(tmp_path)
    write(tmp_path, 'values.yaml', 'image: ordinary')
    initial = run_discovery(tmp_path, runner=lambda *args: pod())
    component = initial['configurable_components'][0]['id']
    secret = 'PRIVATE-IMAGE-VALUE'

    def runner(*args):
        return pod(image='registry/' + secret) + '\n---\n' + yaml.safe_dump(dict(
            apiVersion='v1', kind='Secret', metadata=dict(name='credential'), stringData=dict(password=secret)))

    result = run_discovery(tmp_path, {'component_overrides': {
        component: f'image: {secret}', 'previous-component': f'image: {secret}',
        'unused-component': f'comment: {secret}', 'ordinary-unused': 'image: ordinary',
    }}, runner=runner)
    assert result['images'] == [] and result['completeness'] == 'partial'
    assert result['configurable_components'][0]['values_redacted'] is True
    assert result['_redacted_component_overrides'] == sorted([component, 'previous-component', 'unused-component'])
    assert secret not in json.dumps(result)
    assert any(d['code'] == 'secret_derived_image_not_retained' and d['blocking'] for d in result['diagnostics'])
