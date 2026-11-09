import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from app.discovery_artifacts import LocalArtifactResolver
from app.discovery_engine import run_discovery
from app.discovery_helm_network import HelmNetworkResolver
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
    dashboard_node = next(item for item in first['nodes'] if item['id'] == dashboard['id'])
    assert dashboard_node['state'] == 'rendered' and dashboard_node['provenance'][0]['enabled'] is False
    selection = {'component_values': {dashboard['id']: ['operator-values.yaml']}}
    overridden = run_discovery(source, selection, runner=native_runner, artifact_resolver=resolver)
    assert overridden['completeness'] == 'complete', overridden['diagnostics']
    assert {image['reference'] for image in overridden['images']} == {'private.test/ui:manual', 'postgres:original'}


@pytest.mark.parametrize('gitlab_import', [False, True], ids=['uploaded-zip', 'gitlab-link'])
def test_catalog_chart_requires_source_approval_regardless_of_effective_enabled_flag(tmp_path, gitlab_import):
    reference = 'oci://oci.trueforge.org/truecharts/dokuwiki'
    source = tmp_path / 'product.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('product-123/Chart.yaml', chart_metadata('product', '1.0.0'))
        archive.writestr('product-123/values.yaml', f'''services:
  dokuwiki:
    enabled: false
    sourceType: oci
    ociRepo:
      repoName: dokuwiki
      url: {reference}
      tag: 16.3.0
      layerSelector: {{mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip, operation: extract}}
''')
        archive.writestr('product-123/enable.yaml', 'services: {dokuwiki: {enabled: true}}')
    resolver = HelmNetworkResolver()
    selected = 'enable.yaml' if gitlab_import else 'product-123/enable.yaml'
    with patch.object(resolver, '_get', side_effect=AssertionError('unexpected network access')), \
         patch.object(resolver, 'resolve', wraps=resolver.resolve) as acquire:
        for enabled, options in [(False, {}), (True, {'values_files': [selected]})]:
            result = run_discovery(source, options, runner=render_static_pod, artifact_resolver=resolver, gitlab_archive=gitlab_import)
            acquire.assert_called_once_with('helm', reference, '16.3.0')
            acquire.reset_mock()
            node, = result['nodes']
            assert node['state'] == 'unresolved' and node['name'] == 'dokuwiki'
            evidence, = node['provenance']
            assert evidence['reference'] == reference and evidence['version'] == '16.3.0' and evidence['enabled'] is enabled
            issue, = result['diagnostics']
            assert result['completeness'] == 'partial' and not result['images']
            assert issue['component_id'] == node['id'] and reference in issue['message']
            assert 'CATS_DISCOVERY_HELM_SOURCES' in issue['message']
    mirror = approved_charts(tmp_path, [('dokuwiki', '16.3.0', reference,
                                         {'templates/pod.yaml': pod('dokuwiki', 'wiki:test')})])
    approved = run_discovery(source, runner=render_static_pod, artifact_resolver=mirror, gitlab_archive=gitlab_import)
    chart = next(n for n in approved['nodes'] if n['kind'] == 'ChartReference')
    image, = approved['images']
    assert chart['state'] == 'rendered' and chart['provenance'][0]['enabled'] is False
    assert chart['provenance'][0]['chart_sha256'] == approved['artifact_provenance'][0]['sha256']
    assert image['reference'] == 'wiki:test' and approved['completeness'] == 'complete'
    assert {'source': chart['id'], 'target': image['component_id'], 'kind': 'declares'} in approved['edges']


def test_catalog_inline_values_determine_disabled_charts_distribution_images(tmp_path):
    from app.discovery_distributions import _selection

    helm = shutil.which('helm')
    if not helm:
        pytest.skip('Native Helm is required for catalog values rendering')
    source = tmp_path / 'product'
    write_product(source, '''services:
  dokuwiki:
    enabled: false
    sourceType: oci
    ociRepo: {repoName: dokuwiki, url: 'oci://charts.test/dokuwiki', tag: 16.3.0}
    valuesFiles: [site.yaml]
    values:
      image: {tag: inline}
      credential: PRIVATE-INLINE-VALUE
    valuesFrom: []
    postRenders: []
''')
    write(source, 'site.yaml', 'image: {repository: registry.test/wiki, tag: declared}')
    write(source, 'operator.yaml', 'image: {tag: selected}')
    resolver = approved_charts(tmp_path, [('dokuwiki', '16.3.0', 'oci://charts.test/dokuwiki', {
        'values.yaml': 'image: {repository: upstream/wiki, tag: default}',
        'templates/pod.yaml': pod('wiki', '{{ .Values.image.repository }}:{{ .Values.image.tag }}'),
        'templates/secret.yaml': '''apiVersion: v1
kind: Secret
metadata: {name: wiki}
stringData:
  password: {{ .Values.credential | quote }}
'''})])

    def runner(tool, args, cwd):
        assert tool == 'helm'
        return subprocess.run([helm, *args], cwd=cwd, capture_output=True, text=True, check=True, timeout=30).stdout

    options = {}
    for expected_tag in ('inline', 'selected'):
        inventory = run_discovery(source, options, runner=runner, artifact_resolver=resolver)
        assert inventory['completeness'] == 'complete', inventory['diagnostics']
        assert 'PRIVATE-INLINE-VALUE' not in json.dumps(inventory)
        chart, = [row for row in inventory['nodes'] if row['kind'] == 'ChartReference']
        assert chart['state'] == 'rendered' and chart['provenance'][0]['enabled'] is False
        confirmation = SimpleNamespace(id='confirmed', root_ids=[chart['root_id']], acknowledge_partial=False)
        item = SimpleNamespace(id='inventory', inventory=inventory, source_hash=inventory['source_hash'], content_hash='inventory')
        assert _selection(1, 'Without wiki', confirmation, item, [])['images'] == []
        selection = _selection(1, 'With wiki', confirmation, item, [chart['id']])
        assert selection['images'] == [f'registry.test/wiki:{expected_tag}']
        assert 'PRIVATE-INLINE-VALUE' not in json.dumps(selection)
        options = {'component_values': {chart['id']: ['operator.yaml']}}

    write(source, 'operator.yaml', 'image: {tag: PRIVATE-INLINE-VALUE}')
    inventory = run_discovery(source, options, runner=runner, artifact_resolver=resolver)
    assert not inventory['images'] and 'PRIVATE-INLINE-VALUE' not in json.dumps(inventory)
    assert any(row['code'] == 'secret_derived_image_not_retained' and row['component_id'] == chart['id']
               for row in inventory['diagnostics'])


@pytest.mark.parametrize('field,value', [
    ('values', ['PRIVATE-OVERRIDE']),
    ('valuesFrom', [{'kind': 'Secret', 'name': 'PRIVATE-OVERRIDE'}]),
    ('postRenders', [{'command': 'PRIVATE-OVERRIDE'}]),
    ('postRenderers', [{'command': 'PRIVATE-OVERRIDE'}]),
])
def test_catalog_unsupported_override_keeps_chart_digest_and_blocks_selection(tmp_path, field, value):
    from fastapi import HTTPException
    from app.discovery_distributions import _selection

    entry = {'enabled': False, 'sourceType': 'helm',
             'helmRepo': {'url': 'https://charts.test/', 'chart': 'wiki', 'version': '1.2.3'}, field: value}
    source = tmp_path / 'upload'
    write(source, 'catalog.yaml', yaml.safe_dump({'services': {'wiki': entry}}))
    resolver = approved_charts(tmp_path, [('wiki', '1.2.3', 'https://charts.test/wiki', {
        'templates/pod.yaml': pod('wiki', 'wiki:default')})])
    inventory = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    chart, = [row for row in inventory['nodes'] if row['kind'] == 'ChartReference']
    assert inventory['completeness'] == 'partial' and chart['state'] == 'unresolved'
    assert not inventory['images'] and 'PRIVATE-OVERRIDE' not in json.dumps(inventory)
    assert chart['provenance'][0]['chart_sha256'] == inventory['artifact_provenance'][0]['sha256']
    assert any(d['blocking'] and d['component_id'] == chart['id'] for d in inventory['diagnostics'])
    confirmation = SimpleNamespace(id='confirmed', root_ids=[chart['root_id']], acknowledge_partial=True)
    item = SimpleNamespace(id='inventory', inventory=inventory)
    with pytest.raises(HTTPException) as error:
        _selection(1, 'With wiki', confirmation, item, [chart['id']])
    assert error.value.status_code == 422 and 'wiki' in error.value.detail


def test_nested_catalog_from_inline_values_keeps_original_source_path(tmp_path):
    source = tmp_path / 'product'
    def entry(chart):
        return {'sourceType': 'helm', 'helmRepo': {'url': 'https://charts.test/', 'chart': chart, 'version': '1.0.0'}}

    product = entry('bundle')
    product['values'] = {'services': {'worker': entry('worker')}}
    write_product(source, yaml.safe_dump({'services': {'suite': product}}))
    resolver = approved_charts(tmp_path, [
        ('bundle', '1.0.0', 'https://charts.test/bundle', {}),
        ('worker', '1.0.0', 'https://charts.test/worker', {'templates/pod.yaml': pod('worker', 'worker:inline')}),
    ])
    inventory = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    assert inventory['completeness'] == 'complete', inventory['diagnostics']
    assert [row['reference'] for row in inventory['images']] == ['worker:inline']
    nested = next(row for row in inventory['nodes'] if row['kind'] == 'ChartReference' and row['name'] == 'worker')
    assert nested['provenance'][0]['path'] == 'values.yaml'
    assert '.discovery-values-' not in json.dumps(inventory)


def test_catalog_declarative_postrenderer_replaces_original_image(tmp_path):
    entry = {'sourceType': 'helm', 'helmRepo': {'url': 'https://charts.test/', 'chart': 'wiki', 'version': '1.2.3'},
             'postRenderers': [{'kustomize': {'images': [{'name': 'wiki', 'newTag': 'final'}]}}]}
    source = tmp_path / 'upload'
    write(source, 'catalog.yaml', yaml.safe_dump({'services': {'wiki': entry}}))
    resolver = approved_charts(tmp_path, [('wiki', '1.2.3', 'https://charts.test/wiki', {
        'templates/pod.yaml': pod('wiki', 'wiki:default')})])
    def runner(tool, args, cwd):
        if tool == 'helm':
            return render_static_pod(tool, args, cwd)
        assert tool == 'kustomize'
        config = yaml.safe_load((Path(args[1]) / 'kustomization.yaml').read_text())
        assert config['images'] == [{'name': 'wiki', 'newTag': 'final'}]
        return pod('wiki', 'wiki:final')

    inventory = run_discovery(source, runner=runner, artifact_resolver=resolver)
    assert inventory['completeness'] == 'complete', inventory['diagnostics']
    assert [row['reference'] for row in inventory['images']] == ['wiki:final']


def test_fetched_product_recurses_and_missing_version_preserves_healthy_grandchild(tmp_path):
    from app.discovery_distributions import _catalog

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
    enabled: false
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
    healthy = next(item for item in result['nodes'] if item['name'] == 'healthy')
    assert healthy['state'] == 'rendered' and healthy['provenance'][0]['enabled'] is False
    charts = {c['label']: c for c in _catalog(result, {healthy['root_id']})}
    assert charts['suite']['parent_chart_ids'] == []
    assert charts['healthy']['parent_chart_ids'] == charts['missing']['parent_chart_ids'] == [charts['suite']['id']]


@pytest.mark.parametrize('catalog', [True, False], ids=['product-aliases', 'standalone-flux'])
def test_shared_chart_images_preserve_separate_release_owners(tmp_path, catalog):
    from app.discovery_distributions import _selection

    source = tmp_path / 'upload'
    if catalog:
        entries = {name: {'enabled': enabled, 'sourceType': 'helm', 'helmRepo': {
            'url': 'https://approved.test', 'chart': 'shared', 'version': '1.2.3'}}
            for name, enabled in [('one', True), ('two', False)]}
        write_product(source, yaml.safe_dump({'services': entries}))
    else:
        # Keep the two release declarations in the same file and discovery root.
        releases = [{'apiVersion': 'helm.toolkit.fluxcd.io/v2', 'kind': 'HelmRelease',
                     'metadata': {'name': name}, 'spec': {'chart': {'spec': {
                         'chart': 'shared', 'version': '1.2.3', 'sourceRef': {'kind': 'HelmRepository', 'name': 'repo'}}}}}
                    for name in ('one', 'two')]
        write(source, 'releases.yaml', yaml.safe_dump_all(releases))
        write(source, 'repository.yaml', yaml.safe_dump({'apiVersion': 'source.toolkit.fluxcd.io/v1', 'kind': 'HelmRepository',
              'metadata': {'name': 'repo'}, 'spec': {'url': 'https://approved.test'}}))
    resolver = approved_charts(tmp_path, [
        ('shared', '1.2.3', 'https://approved.test/shared', {'templates/pod.yaml': pod('worker', 'worker:1')}),
    ])
    result = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    assert result['completeness'] == 'complete', result['diagnostics']
    owners = {n['id']: n for n in result['nodes'] if n['kind'] == ('ChartReference' if catalog else 'HelmRelease')}
    assert {n['name'] for n in owners.values()} == {'one', 'two'}
    assert all(n['state'] == 'rendered' for n in owners.values())
    archive_hash = hashlib.sha256((tmp_path / 'shared-1.2.3.zip').read_bytes()).hexdigest()
    for node in owners.values():
        evidence, = node['provenance']
        assert evidence['chart_sha256'] == archive_hash and evidence['chart_digest_kind'] == 'archive'
        assert evidence['version'] == '1.2.3'
    assert set(owners) <= {c['id'] for c in result['configurable_components']}
    if catalog:
        assert {n['name']: n['provenance'][0]['enabled'] for n in owners.values()} == {'one': True, 'two': False}
    assert [i['reference'] for i in result['images']] == ['worker:1', 'worker:1']
    image_components = {i['component_id'] for i in result['images']}
    assert len(image_components) == 2
    edges = [e for e in result['edges'] if e['kind'] == 'declares' and e['target'] in image_components]
    assert {e['source'] for e in edges} == set(owners) and len(edges) == 2

    selected = next(node for node in owners.values() if node['name'] == 'two')
    workload = next(edge['target'] for edge in edges if edge['source'] == selected['id'])
    confirmation = SimpleNamespace(id='confirmed', root_ids=[selected['root_id']], acknowledge_partial=False)
    item = SimpleNamespace(id='inventory', inventory=result, source_hash='source', content_hash='inventory')
    selection = _selection('service', 'Second release only', confirmation, item, [selected['id']])
    assert selection['images'] == ['worker:1']
    assert [image['component_id'] for image in selection['image_occurrences']] == [workload]


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
    from fastapi import HTTPException
    from app.discovery_distributions import _catalog, _selection

    source = tmp_path / 'upload'
    for chart in ('first', 'second'):
        write_product(source / chart, '''services:
  management:
    enabled: false
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
    item = SimpleNamespace(id='inventory', inventory=result, source_hash='source', content_hash='inventory')
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

        manager = nodes['ChartReference', 'management']['id']
        charts = {c['id']: c for c in _catalog(result, {rid})}
        assert charts[manager]['parent_chart_ids'] == []
        assert charts[middle]['parent_chart_ids'] == [manager] and charts[leaf]['parent_chart_ids'] == [middle]
        assert not charts[manager]['declared_enabled'] and all(charts[k]['declared_enabled'] for k in (middle, leaf))
        defaults = [key for key, chart in charts.items() if chart['default_enabled']]
        assert not set(defaults).intersection((manager, middle, leaf))
        confirmation = SimpleNamespace(id='confirmed', root_ids=[rid], acknowledge_partial=False)
        assert _selection(1, 'Default', confirmation, item, defaults)['images'] == []
        for invalid in ([middle, leaf], [manager, leaf]):
            with pytest.raises(HTTPException, match='Select an owning chart') as exc:
                _selection(1, 'Incomplete ownership', confirmation, item, invalid)
            assert exc.value.status_code == 422
        assert _selection(1, 'Enable manager', confirmation, item, [manager, middle, leaf])['images'] == ['terminal:3']


@pytest.mark.parametrize('packaged', [False, True], ids=['directory', 'tgz'])
@pytest.mark.parametrize('gitlab_import', [False, True], ids=['upload', 'gitlab-link'])
def test_gitlab_archive_resolves_bundled_chart_and_repository_values_offline(tmp_path, packaged, gitlab_import):
    archive_path = tmp_path / 'suite.zip'
    product_dir = 'suite-42e301/deploy/product'
    expected_prefix = '' if gitlab_import else 'suite-42e301/'
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
            assert values.relative_to(cwd).as_posix() == expected_prefix + 'environment/site.yaml'
            assert yaml.safe_load(values.read_text()) == {'environment': 'site'}
        return render_static_pod(tool, args, cwd)

    resolver = approved_charts(tmp_path, [])
    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as fetch:
        result = run_discovery(archive_path, runner=offline_render, artifact_resolver=resolver, gitlab_archive=gitlab_import)
    fetch.assert_not_called()
    assert result['completeness'] == 'complete', result['diagnostics']
    root = next(r for r in result['roots'] if r['path'] == expected_prefix + 'deploy/product' and r['technology'] == 'helm')
    assert [(i['reference'], i['root_id']) for i in result['images']] == [('web:site', root['id'])]
    assert [p['integrity'] for p in result.get('artifact_provenance', [])] == (['source-archive'] if packaged else [])
    child = next(n['provenance'][0] for n in result['nodes'] if n['kind'] == 'ChartReference')
    assert child['chart_digest_kind'] == ('archive' if packaged else 'tree') and len(child['chart_sha256']) == 64
    if packaged:
        assert child['chart_sha256'] == hashlib.sha256(package.getvalue()).hexdigest()


@pytest.mark.parametrize(('constraint', 'resolved'), [('1.2.0', False), ('~1.2.0', True)])
def test_vendored_helm_dependency_compares_exact_version_with_package_metadata(tmp_path, constraint, resolved):
    source = tmp_path / 'input'
    write(source, 'Chart.yaml', chart_metadata('suite', '1.0.0') + yaml.safe_dump({'dependencies': [
        {'name': 'worker', 'repository': 'https://approved.test', 'version': constraint}]}))
    write(source, 'templates/pod.yaml', pod('suite', 'suite:1'))
    member = tmp_path / 'worker'
    write(member, 'Chart.yaml', chart_metadata('worker', '1.2.3'))
    packages = source / 'charts'
    packages.mkdir()
    with tarfile.open(packages / 'worker-1.2.0.tgz', 'w:gz') as archive:
        archive.add(member, arcname='worker')

    result = run_discovery(source, runner=render_static_pod)
    dep, = [n for n in result['nodes'] if n['kind'] == 'HelmDependency']
    assert dep['provenance'][0]['declared_version'] == constraint
    if resolved:
        assert dep['state'] == 'resolved' and dep['provenance'][0]['version'] == '1.2.3'
        assert result['completeness'] == 'complete', result['diagnostics']
    else:
        assert dep['state'] == 'unresolved' and 'chart_sha256' not in dep['provenance'][0]
        assert not result['images']
        diagnostic = next(d for d in result['diagnostics'] if d['component_id'] == dep['id'])
        assert '1.2.3' in diagnostic['message'] and 'Expected' in diagnostic['message']


@pytest.mark.parametrize('matching_repo', [True, False])
def test_helm_dependency_range_retrieves_only_matching_locked_coordinate(tmp_path, matching_repo):
    source = tmp_path / 'input'
    declaration = {'name': 'worker', 'alias': 'task', 'repository': 'https://approved.test', 'version': '^1.2.0'}
    write(source, 'Chart.yaml', chart_metadata('suite', '1.0.0') + yaml.safe_dump({'dependencies': [declaration]}))
    write(source, 'Chart.lock', yaml.safe_dump({'digest': 'sha256:' + 'a' * 64, 'dependencies': [
        {'name': 'worker', 'repository': declaration['repository'] if matching_repo else 'https://other.test', 'version': '1.3.1'}]}))
    write(source, 'templates/pod.yaml', pod('suite', 'suite:1'))
    resolver = approved_charts(tmp_path, [('worker', '1.3.1', 'https://approved.test/worker', {})])
    with patch.object(resolver, 'resolve', wraps=resolver.resolve) as fetch:
        result = run_discovery(source, runner=render_static_pod, artifact_resolver=resolver)
    dep, = [n for n in result['nodes'] if n['kind'] == 'HelmDependency']
    if matching_repo:
        fetch.assert_called_once_with('helm', 'https://approved.test/worker', '1.3.1')
        evidence, = dep['provenance']
        assert dep['name'] == 'task' and dep['state'] == 'resolved'
        assert evidence['declared_version'] == '^1.2.0' and evidence['locked_version'] == evidence['version'] == '1.3.1'
        assert result['completeness'] == 'complete', result['diagnostics']
    else:
        fetch.assert_not_called()
        assert dep['state'] == 'unresolved' and not result['images']
        assert any('Chart.lock does not match' in d.get('message', '') for d in result['diagnostics'])


@pytest.mark.parametrize('packaged', [False, True], ids=['approved-mirror', 'bundled-package'])
def test_native_conditional_dependency_stays_with_parent_and_records_verified_content(tmp_path, packaged):
    helm = shutil.which('helm')
    if not helm:
        pytest.skip('Native Helm is required for conditional dependency rendering')
    source = tmp_path / 'source'
    write(source, 'Chart.yaml', chart_metadata('suite', '1.0.0') + '''dependencies:
  - name: worker
    alias: optional
    repository: https://approved.test
    version: 1.2.3
    condition: optional.enabled
''')
    write(source, 'values.yaml', 'optional: {enabled: false}')
    write(source, 'site.yaml', 'optional: {enabled: true}')
    write(source, 'templates/pod.yaml', pod('suite', 'suite:1'))
    resolver = approved_charts(tmp_path, [('worker', '1.2.3', 'https://approved.test/worker',
                                           {'templates/pod.yaml': pod('worker', 'worker:1')})])
    archive = tmp_path / 'worker-1.2.3.zip'
    if packaged:
        archive = source / 'charts/worker-1.2.3.tgz'
        archive.parent.mkdir()
        with tarfile.open(archive, mode='w:gz') as tgz:
            for name, content in [('Chart.yaml', chart_metadata('worker', '1.2.3')),
                                  ('templates/pod.yaml', pod('worker', 'worker:1'))]:
                entry = tarfile.TarInfo('worker/' + name)
                encoded = content.encode()
                entry.size = len(encoded)
                tgz.addfile(entry, io.BytesIO(encoded))
        resolver = None
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    def native_runner(tool, args, cwd):
        return subprocess.run([helm, *args], cwd=cwd, capture_output=True, text=True, check=True, timeout=30).stdout
    for enabled, selected in [(False, []), (True, ['site.yaml'])]:
        result = run_discovery(source, {'values_files': selected}, runner=native_runner, artifact_resolver=resolver)
        root, = result['roots']
        assert root['state'] == 'rendered'
        dep, = [n for n in result['nodes'] if n['kind'] == 'HelmDependency']
        evidence, = dep['provenance']
        assert dep['name'] == 'optional' and dep['state'] == 'resolved'
        assert evidence['selection_scope'] == 'parent' and evidence['condition'] == 'optional.enabled'
        assert evidence['enabled'] is enabled and evidence['chart'] == 'worker' and evidence['version'] == '1.2.3'
        assert evidence['chart_sha256'] == digest and evidence['chart_digest_kind'] == 'archive'
        assert {'source': root['id'], 'target': dep['id'], 'kind': 'declares'} in result['edges']
        assert result['completeness'] == 'complete'
        statuses = [d for d in result['diagnostics'] if d['code'] == 'helm_dependency_disabled']
        assert [d['component_id'] for d in statuses] == ([] if enabled else [dep['id']])
        assert all(d['severity'] == 'info' and d['blocking'] is False for d in statuses)
        assert {i['reference'] for i in result['images']} == ({'suite:1', 'worker:1'} if enabled else {'suite:1'})


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
  retired: {sourceType: oci, enabled: false}
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
    retired = next(item for item in result['nodes'] if item['name'] == 'retired')
    assert retired['state'] == 'unresolved' and retired['provenance'][0]['enabled'] is False
    assert any(d.get('component_id') == retired['id'] for d in result['diagnostics'])
