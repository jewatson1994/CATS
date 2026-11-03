import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from app.discovery_artifacts import LocalArtifactResolver
from app.discovery_engine import run_discovery
from test_discovery_engine import write


def chart_metadata(name, version):
    return yaml.safe_dump({'apiVersion': 'v2', 'name': name, 'version': version})


def write_product(source, values):
    write(source, 'Chart.yaml', chart_metadata('product', '1.0.0') +
          'sources: [https://gitlab.example.test/group/service.git]\n')
    write(source, 'values.yaml', values)


def pod(name, image):
    return yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name},
                           'spec': {'containers': [{'name': 'app', 'image': image}]}})


def render_static_pod(tool, args, cwd):
    assert tool == 'helm'
    template = Path(args[2]) / 'templates/pod.yaml'
    return template.read_text() if template.is_file() else ''


def approved_charts(directory, charts):
    """Build an exact-version, digest-pinned mirror outside the uploaded source."""
    entries = []
    for name, version, reference, files in charts:
        package = directory / f'{name}-{version}.zip'
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr(f'{name}/Chart.yaml', chart_metadata(name, version))
            for path, content in files.items():
                archive.writestr(f'{name}/{path}', content)
        entries.append({'kind': 'helm', 'reference': reference, 'version': version,
                        'path': package.name, 'sha256': hashlib.sha256(package.read_bytes()).hexdigest()})
    manifest = directory / 'approved.json'
    manifest.write_text(json.dumps({'version': 1, 'artifacts': entries}))
    return LocalArtifactResolver(manifest)


def test_product_renders_disabled_classic_and_oci_with_ordered_child_values(tmp_path):
    helm = shutil.which('helm')
    if not helm:
        pytest.skip('Native Helm is required for ordered chart rendering')
    source = tmp_path / 'upload'
    write_product(source, '''services:
  dashboards:
    enabled: false
    sourceType: helm
    helmRepo: {repoName: team-charts, repoUrl: 'https://approved.test/charts', chart: dashboard, version: 1.2.3}
    valuesFiles: [settings/first.yaml, settings/second.yaml]
  database:
    sourceType: oci
    ociRepo: {repoName: database-release, url: 'oci://registry.test/team/postgresql', tag: 2.0.1}
''')
    write(source, 'settings/first.yaml', 'imageRepository: private.test/ui\nimageTag: first\n')
    write(source, 'settings/second.yaml', 'imageTag: second\n')
    write(source, 'operator-values.yaml', 'imageTag: manual\n')
    pod_template = '''apiVersion: v1
kind: Pod
metadata: {name: {{ .Chart.Name }}}
spec:
  containers: [{name: app, image: "{{ .Values.imageRepository }}:{{ .Values.imageTag }}"}]
'''
    resolver = approved_charts(tmp_path, [
        ('dashboard', '1.2.3', 'https://approved.test/charts/dashboard',
         {'templates/pod.yaml': pod_template, 'values.yaml': 'imageRepository: ui\nimageTag: default\n'}),
        ('postgresql', '2.0.1', 'oci://registry.test/team/postgresql',
         {'templates/pod.yaml': pod_template, 'values.yaml': 'imageRepository: postgres\nimageTag: original\n'}),
    ])

    def native_runner(tool, args, cwd):
        assert tool == 'helm'
        return subprocess.run([helm, *args], cwd=cwd, capture_output=True, text=True,
                              check=True, timeout=30).stdout

    first = run_discovery(source, runner=native_runner, artifact_resolver=resolver)
    assert first['completeness'] == 'complete', first['diagnostics']
    assert {image['reference'] for image in first['images']} == {'private.test/ui:second', 'postgres:original'}
    assert len(first['artifact_provenance']) == 2
    dashboard = next(item for item in first['configurable_components'] if item['label'] == 'dashboards')
    selection = {'component_values': {dashboard['id']: ['operator-values.yaml']}}
    overridden = run_discovery(source, selection, runner=native_runner, artifact_resolver=resolver)
    assert overridden['completeness'] == 'complete', overridden['diagnostics']
    assert {image['reference'] for image in overridden['images']} == {'private.test/ui:manual', 'postgres:original'}


def test_fetched_product_recurses_and_missing_version_preserves_healthy_grandchild(tmp_path):
    source = tmp_path / 'upload'
    write_product(source, '''services:
  suite:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: suite, version: 4.0.0}
''')
    nested_catalog = '''services:
  missing:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: retired, version: 2.0.0}
  healthy:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: api, version: 3.1.0}
'''

    resolver = approved_charts(tmp_path, [
        ('suite', '4.0.0', 'https://approved.test/suite',
         {'values.yaml': nested_catalog, 'templates/pod.yaml': pod('suite', 'suite:4')}),
        ('retired', '1.0.0', 'https://approved.test/retired',
         {'templates/pod.yaml': pod('retired', 'must-not-substitute:1')}),
        ('api', '3.1.0', 'https://approved.test/api',
         {'templates/pod.yaml': pod('api', 'api:3.1')}),
    ])

    result = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    assert {item['reference'] for item in result['images']} == {'suite:4', 'api:3.1'}
    assert len(result['artifact_provenance']) == 2
    assert result['completeness'] == 'partial'
    assert any('missing' in json.dumps(item) and item['blocking'] for item in result['diagnostics'])


def test_ordered_parent_values_resolve_only_effective_versions_under_product_root(tmp_path):
    source = tmp_path / 'upload'
    write_product(source, '''services:
  web:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: frontend, version: 1.0.0}
  telemetry:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: metrics, version: 4.0.0}
''')
    write(source, 'production/base.yaml', '''services:
  web:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: frontend, version: 2.0.0}
''')
    write(source, 'production/site.yaml', 'services: {web: {helmRepo: {version: 3.0.0}}}\n')
    resolver = approved_charts(tmp_path, [
        ('frontend', '3.0.0', 'https://approved.test/frontend',
         {'templates/pod.yaml': pod('frontend', 'frontend:3')}),
        ('metrics', '4.0.0', 'https://approved.test/metrics',
         {'templates/pod.yaml': pod('metrics', 'metrics:4')}),
    ])
    selection = {'values_files': ['production/base.yaml', 'production/site.yaml']}
    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as acquire:
        result = run_discovery(source, selection, runner=render_static_pod, artifact_resolver=resolver)
    assert sorted(call.args for call in acquire.call_args_list) == [
        ('helm', 'https://approved.test/frontend', '3.0.0'),
        ('helm', 'https://approved.test/metrics', '4.0.0'),
    ]
    assert result['completeness'] == 'complete', result['diagnostics']
    root = next(root for root in result['roots'] if root['technology'] == 'helm' and root['path'] == '.')
    assert {(image['root_id'], image['reference']) for image in result['images']} == {
        (root['id'], 'frontend:3'), (root['id'], 'metrics:4')}


def test_catalog_cycle_cannot_repeat_fetch_or_render_or_hide_later_sibling(tmp_path):
    source = tmp_path / 'upload'
    write_product(source, '''services:
  a-loop:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: loop, version: 1.2.0}
  z-ready:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: ready, version: 2.1.0}
''')
    resolver = approved_charts(tmp_path, [
        ('loop', '1.2.0', 'https://approved.test/loop', {'values.yaml': '''services:
  self:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: loop, version: 1.2.0}
'''}),
        ('ready', '2.1.0', 'https://approved.test/ready',
         {'templates/pod.yaml': pod('ready', 'ready:2')}),
    ])
    rendered = []

    def track_render(tool, args, cwd):
        rendered.append(yaml.safe_load((Path(args[2]) / 'Chart.yaml').read_text())['name'])
        return render_static_pod(tool, args, cwd)

    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as acquire:
        result = run_discovery(source, runner=track_render, artifact_resolver=resolver)
    assert sorted(call.args for call in acquire.call_args_list) == [
        ('helm', 'https://approved.test/loop', '1.2.0'),
        ('helm', 'https://approved.test/ready', '2.1.0'),
    ]
    assert rendered.count('loop') <= 1
    assert {item['reference'] for item in result['images']} == {'ready:2'}
    assert result['completeness'] == 'partial'
    assert any(item['blocking'] and 'cycl' in json.dumps(item).lower() for item in result['diagnostics'])


def test_flux_chain_from_catalog_child_keeps_images_and_controller_edges_in_each_product(tmp_path):
    source = tmp_path / 'upload'
    for chart in ('first', 'second'):
        write_product(source / chart, '''services:
  management:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: manager, version: 1.0.0}
''')

    def release(chart, version):
        return {'apiVersion': 'helm.toolkit.fluxcd.io/v2', 'kind': 'HelmRelease', 'metadata': {'name': chart},
                'spec': {'chart': {'spec': {'chart': chart, 'version': version,
                                           'sourceRef': {'kind': 'HelmRepository', 'name': 'team'}}}}}

    repository = {'apiVersion': 'source.toolkit.fluxcd.io/v1', 'kind': 'HelmRepository',
                  'metadata': {'name': 'team'}, 'spec': {'url': 'https://approved.test'}}
    resolver = approved_charts(tmp_path, [
        ('manager', '1.0.0', 'https://approved.test/manager',
         {'templates/pod.yaml': yaml.safe_dump_all([repository, release('middle', '2.0.0')])}),
        ('middle', '2.0.0', 'https://approved.test/middle',
         {'templates/pod.yaml': yaml.safe_dump(release('leaf', '3.0.0'))}),
        ('leaf', '3.0.0', 'https://approved.test/leaf',
         {'templates/pod.yaml': pod('terminal', 'terminal:3')}),
    ])
    result = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    assert result['completeness'] == 'complete', result['diagnostics']
    assert len(result['artifact_provenance']) == 3
    roots = {r['id'] for r in result['roots'] if r['technology'] == 'helm' and r['path'] in ('first', 'second')}
    assert len(roots) == 2
    assert {(i['reference'], i['root_id']) for i in result['images']} == {('terminal:3', rid) for rid in roots}
    edges = {(e['source'], e['target'], e['kind']) for e in result['edges']}
    for rid in roots:
        nodes = {(n['kind'], n['name']): n for n in result['nodes'] if n['root_id'] == rid}
        source_node = nodes['HelmRepository', 'team']['id']
        middle = nodes['HelmRelease', 'middle']['id']
        leaf = nodes['HelmRelease', 'leaf']['id']
        workload = nodes['Pod', 'terminal']['id']
        assert (middle, leaf, 'declares') in edges and (leaf, workload, 'declares') in edges
        assert (middle, source_node, 'uses_source') in edges and (leaf, source_node, 'uses_source') in edges
        image = next(i for i in result['images'] if i['root_id'] == rid)
        evidence = image['provenance'][0]
        assert image['component_id'] == workload and evidence['path'].endswith('/leaf/Chart.yaml')
        assert evidence['sha256'] and evidence['rendered_sha256']


@pytest.mark.parametrize('packaged', [False, True], ids=['directory', 'tgz'])
def test_gitlab_archive_resolves_bundled_chart_and_repository_values_offline(tmp_path, packaged):
    archive_path = tmp_path / 'suite.zip'
    product_dir = 'suite-42e301/deploy/product'
    catalog = '''services:
  web:
    sourceType: helm
    helmRepo: {url: 'https://offline.example.test/charts', chart: frontend, version: 1.2.0}
    valuesFiles: [environment/site.yaml]
'''
    child = {'frontend/Chart.yaml': chart_metadata('frontend', '1.2.0'),
             'frontend/templates/pod.yaml': pod('web', 'web:site')}
    with zipfile.ZipFile(archive_path, 'w') as contents:
        contents.writestr(f'{product_dir}/Chart.yaml', chart_metadata('product', '2.0.0'))
        contents.writestr(f'{product_dir}/values.yaml', catalog)
        contents.writestr('suite-42e301/environment/site.yaml', 'environment: site\n')
        if packaged:
            package = io.BytesIO()
            with tarfile.open(fileobj=package, mode='w:gz') as tgz:
                for path, data in child.items():
                    entry = tarfile.TarInfo(path)
                    encoded = data.encode()
                    entry.size = len(encoded)
                    tgz.addfile(entry, io.BytesIO(encoded))
            contents.writestr(f'{product_dir}/charts/frontend-1.2.0.tgz', package.getvalue())
        else:
            for path, data in child.items():
                contents.writestr(f'{product_dir}/charts/{path}', data)

    def offline_render(tool, args, cwd):
        metadata = yaml.safe_load((Path(args[2]) / 'Chart.yaml').read_text())
        if metadata['name'] == 'frontend':
            assert args[3] == '-f'
            values = Path(args[4])
            assert values.relative_to(cwd).as_posix() == 'suite-42e301/environment/site.yaml'
            assert yaml.safe_load(values.read_text()) == {'environment': 'site'}
        return render_static_pod(tool, args, cwd)

    resolver = approved_charts(tmp_path, [])
    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as fetch:
        result = run_discovery(archive_path, runner=offline_render, artifact_resolver=resolver)
    fetch.assert_not_called()
    assert result['completeness'] == 'complete', result['diagnostics']
    root = next(r for r in result['roots'] if r['path'] == product_dir and r['technology'] == 'helm')
    assert [(i['reference'], i['root_id']) for i in result['images']] == [('web:site', root['id'])]
    assert [p['integrity'] for p in result.get('artifact_provenance', [])] == (['source-archive'] if packaged else [])


def test_unselected_alternate_values_do_not_request_or_create_additional_product_root(tmp_path):
    source = tmp_path / 'upload'
    declaration = '''services:
  web:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: frontend, version: VERSION}
'''
    write_product(source, declaration.replace('VERSION', '1.0.0'))
    write(source, 'environments/production/values.yaml', declaration.replace('VERSION', '2.0.0'))
    resolver = approved_charts(tmp_path, [
        ('frontend', '1.0.0', 'https://approved.test/frontend', {'templates/pod.yaml': pod('web', 'web:default')}),
    ])
    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as fetch:
        result = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    fetch.assert_called_once_with('helm', 'https://approved.test/frontend', '1.0.0')
    assert result['completeness'] == 'complete', result['diagnostics']
    assert [(r['technology'], r['path']) for r in result['roots']] == [('helm', '.')]
    assert [i['reference'] for i in result['images']] == ['web:default']


def test_lone_chart_metadata_explains_which_deployment_input_is_missing(tmp_path):
    write(tmp_path, 'Chart.yaml', chart_metadata('product', '1.0.0') +
          'sources: [https://gitlab.example.test/group/service.git]\n')
    result = run_discovery(tmp_path / 'Chart.yaml', runner=render_static_pod)
    root, = result['roots']
    assert root['technology'] == 'helm' and root['chart_name'] == 'product' and root['chart_version'] == '1.0.0'
    assert result['completeness'] != 'complete' and result['images'] == []
    diagnostic = next(d for d in result['diagnostics'] if d['code'] == 'chart_metadata_only')
    assert diagnostic['blocking'] and diagnostic['root_id'] == root['id']
    assert 'values.yaml' in diagnostic['message'] and 'upload' in diagnostic['message'].lower()


@pytest.mark.parametrize('with_parent', [False, True])
def test_service_catalog_rejects_yaml_merge_keys_before_chart_retrieval(tmp_path, with_parent):
    values = '''defaults: &defaults
  sourceType: helm
  helmRepo: {url: 'https://approved.test', chartName: frontend, version: 1.0.0}
services:
  web:
    <<: *defaults
'''
    if with_parent:
        write_product(tmp_path, values)
    else:
        write(tmp_path, 'values.yaml', values)
    resolver = approved_charts(tmp_path, [])
    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as fetch:
        result = run_discovery(tmp_path, runner=render_static_pod, artifact_resolver=resolver)
    fetch.assert_not_called()
    assert any(d['code'] == 'legacy_definition_unresolved' for d in result['diagnostics'])


def test_standalone_values_resolve_known_chart_and_identify_incomplete_service(tmp_path):
    source = tmp_path / 'product-values.yaml'
    source.write_text('''services:
  web:
    sourceType: helm
    helmRepo: {url: 'https://approved.test', chartName: frontend, version: 1.0.0}
  metrics: {sourceType: oci}
''')
    resolver = approved_charts(tmp_path, [
        ('frontend', '1.0.0', 'https://approved.test/frontend', {'templates/pod.yaml': pod('web', 'web:1')}),
    ])
    result = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    root, = result['roots']
    image, = result['images']
    assert image['reference'] == 'web:1' and image['root_id'] == root['id']
    assert result['completeness'] == 'partial'
    assert any(d.get('component_name') == 'metrics' and 'Repository' in d['message']
               for d in result['diagnostics'])
