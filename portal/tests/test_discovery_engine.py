import io
import json
import tarfile
import zipfile
from pathlib import Path
import pytest
import yaml
from app.discovery_engine import run_discovery, DiscoveryError, _documents

def write(root, name, text):
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p

def test_kubernetes_deterministic_and_secrets(tmp_path):
    write(tmp_path, 'pod.yaml', 'apiVersion: v1\nkind: Pod\nmetadata: {name: web}\nspec:\n  containers: [{name: web, image: nginx:1.27, env: [{name: PASSWORD, value: NEVER_RETAIN}]}]\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: credentials}\nstringData: {password: NEVER_RETAIN}\n')
    a = run_discovery(tmp_path)
    assert a == run_discovery(tmp_path)
    assert a['images'][0]['reference'] == 'nginx:1.27'
    assert 'NEVER_RETAIN' not in json.dumps(a)
    assert a['completeness'] == 'complete'

@pytest.mark.parametrize('name', ['../escape.yaml', '/escape.yaml', 'C:/escape.yaml'])
def test_zip_traversal(tmp_path, name):
    p = tmp_path / 'input.zip'
    with zipfile.ZipFile(p, 'w') as z:
        z.writestr(name, 'x')
    with pytest.raises(DiscoveryError):
        run_discovery(p)

def test_zip_duplicate_and_symlink(tmp_path):
    p = tmp_path / 'input.zip'
    with zipfile.ZipFile(p, 'w') as z:
        z.writestr('a.yaml', 'x')
        z.writestr('A.yaml', 'y')
    with pytest.raises(DiscoveryError):
        run_discovery(p)
    with zipfile.ZipFile(p, 'w') as z:
        item = zipfile.ZipInfo('link')
        item.create_system = 3
        item.external_attr = 0o120777 << 16
        z.writestr(item, 'outside')
    with pytest.raises(DiscoveryError):
        run_discovery(p)

def test_tar_link(tmp_path):
    p = tmp_path / 'input.tar'
    with tarfile.open(p, 'w') as t:
        item = tarfile.TarInfo('link')
        item.type = tarfile.SYMTYPE
        item.linkname = '../escape'
        t.addfile(item)
    with pytest.raises(DiscoveryError):
        run_discovery(p)

def test_yaml_cycles_and_expansion():
    with pytest.raises(DiscoveryError):
        _documents('a: &a [*a]')

def test_render_failure_has_fixed_diagnostic(tmp_path):
    write(tmp_path, 'Chart.yaml', 'apiVersion: v2\nname: test\nversion: 1.0.0')
    def runner(*args):
        raise RuntimeError('SECRET_STDERR')
    result = run_discovery(tmp_path, runner=runner)
    assert result['completeness'] == 'blocked'
    assert 'SECRET_STDERR' not in json.dumps(result)

def test_flux_values_merge_and_target_precedence(tmp_path):
    write(tmp_path, 'chart/Chart.yaml', 'apiVersion: v2\nname: test\nversion: 1.0.0')
    write(tmp_path, 'flux.yaml', '''apiVersion: v1
kind: ConfigMap
metadata: {name: config}
data:
  values.yaml: "image: {tag: old, repository: nginx}"
  tag: forced
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: test}
spec:
  chart: {spec: {chart: chart}}
  valuesFrom:
    - {kind: ConfigMap, name: config}
    - {kind: ConfigMap, name: config, valuesKey: tag, targetPath: image.tag}
  values: {image: {tag: inline}}
''')
    captured = []
    def runner(tool, args, cwd):
        if '-f' in args:
            captured.append(yaml.safe_load(Path(args[args.index('-f') + 1]).read_text()))
        return 'apiVersion: v1\nkind: Pod\nmetadata: {name: test}\nspec: {containers: [{name: a, image: nginx:1}]}'
    result = run_discovery(tmp_path, runner=runner)
    assert captured == [{'image': {'repository': 'nginx', 'tag': 'forced'}}]
    assert result['edges']

def test_remote_chart_unresolved():
    result = run_discovery(None, {'reference': 'oci://example.test/chart', 'reference_kind': 'chart'})
    assert result['completeness'] == 'blocked'
    assert not result['images']

def test_compose_and_images(tmp_path):
    write(tmp_path, 'compose.yaml', 'services: {web: {image: nginx:1.27}}')
    write(tmp_path, 'images.txt', 'alpine:3.20\n')
    result = run_discovery(tmp_path)
    assert {i['reference'] for i in result['images']} == {'nginx:1.27', 'alpine:3.20'}

def test_generated_flux_release_uses_generated_values(tmp_path):
    write(tmp_path, 'parent/Chart.yaml', 'apiVersion: v2\nname: parent\nversion: 1.0.0')
    write(tmp_path, 'parent/charts/child/Chart.yaml', 'apiVersion: v2\nname: child\nversion: 1.0.0')
    calls = []
    generated = '''apiVersion: v1
kind: ConfigMap
metadata: {name: generated}
data: {values.yaml: 'image: {tag: generated}'}
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: generated-release}
spec:
  chart: {spec: {chart: remote-child}}
  valuesFrom: [{kind: ConfigMap, name: generated}]
'''
    def runner(tool, args, cwd):
        calls.append(args)
        if '-f' not in args:
            return generated
        assert yaml.safe_load(Path(args[args.index('-f')+1]).read_text()) == {'image': {'tag': 'generated'}}
        return 'apiVersion: v1\nkind: Pod\nmetadata: {name: child}\nspec: {containers: [{name: a, image: nginx:generated}]}'
    result = run_discovery(tmp_path, {'chart_map': {'remote-child': 'parent/charts/child'}}, runner)
    assert len(calls) == 2
    assert result['images'][0]['reference'] == 'nginx:generated'

def test_compose_fallback_never_claims_native_complete(tmp_path):
    write(tmp_path, 'compose.yaml', 'services: {web: {image: nginx:1.27}}')
    result = run_discovery(tmp_path)
    assert result['completeness'] == 'partial'
    assert result['nodes'][0]['state'] == 'selected'

def test_native_compose_whitelist_and_interpolation(tmp_path):
    write(tmp_path, 'compose.yaml', 'services: {web: {image: "nginx:${TAG}"}}')
    write(tmp_path, '.env', 'TAG=1.27\nPASSWORD=SECRET_VALUE\n')
    def runner(tool, args, cwd):
        assert tool == 'compose' and '--env-file' in args and 'config' in args
        return json.dumps({'services': {'web': {'image': 'nginx:1.27', 'environment': {'PASSWORD': 'SECRET_VALUE'}}}})
    result = run_discovery(tmp_path, runner=runner)
    assert result['images'][0]['reference'] == 'nginx:1.27'
    assert result['completeness'] == 'complete'
    assert 'SECRET_VALUE' not in json.dumps(result)

def test_native_compose_secret_image_is_not_retained(tmp_path):
    write(tmp_path, 'compose.yaml', 'services: {web: {image: "registry/${PASSWORD}:1"}}')
    write(tmp_path, '.env', 'PASSWORD=SECRET_VALUE\n')
    result = run_discovery(tmp_path, runner=lambda *args: json.dumps({'services': {'web': {'image': 'registry/SECRET_VALUE:1'}}}))
    assert not result['images']
    assert 'SECRET_VALUE' not in json.dumps(result)

def test_kustomize_raw_images_are_not_final(tmp_path):
    write(tmp_path, 'kustomization.yaml', 'resources: [pod.yaml]\nimages: [{name: nginx, newTag: updated}]')
    write(tmp_path, 'pod.yaml', 'apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec: {containers: [{name: app, image: nginx:old}]}')
    result = run_discovery(tmp_path)
    assert not result['images']
    assert result['completeness'] == 'blocked'
    rendered = 'apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec: {containers: [{name: app, image: nginx:updated}]}'
    result = run_discovery(tmp_path, runner=lambda *args: rendered)
    assert [i['reference'] for i in result['images']] == ['nginx:updated']

def test_known_secret_taint_in_image_and_metadata(tmp_path):
    write(tmp_path, 'manifest.yaml', 'apiVersion: v1\nkind: Secret\nmetadata: {name: token}\nstringData: {token: TOPSECRET}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: TOPSECRET}\nspec: {containers: [{name: app, image: "registry/TOPSECRET:1"}]}')
    result = run_discovery(tmp_path)
    assert 'TOPSECRET' not in json.dumps(result)
    assert not result['images']

def test_flux_declarative_postrenderer(tmp_path):
    write(tmp_path, 'charts/child/Chart.yaml', 'apiVersion: v2\nname: child\nversion: 1.0.0')
    write(tmp_path, 'flux.yaml', '''apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: {name: test}
spec:
  chart: {spec: {chart: charts/child}}
  postRenderers:
    - kustomize:
        images: [{name: nginx, newTag: final}]
''')
    calls = []
    def runner(tool, args, cwd):
        calls.append(tool)
        tag = 'final' if tool == 'kustomize' else 'old'
        return 'apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec: {containers: [{name: app, image: nginx:' + tag + '}]}'
    result = run_discovery(tmp_path, runner=runner)
    assert calls == ['helm', 'kustomize']
    assert [i['reference'] for i in result['images']] == ['nginx:final']

def test_trusted_custom_adapter(tmp_path):
    from app.discovery_engine import ADAPTERS, DiscoveryAdapter, register_adapter
    adapter = DiscoveryAdapter('test-custom', ('custom.txt',), handler=lambda *args: {'nodes': [{'kind': 'Service', 'name': 'app'}], 'images': [{'name': 'app', 'reference': 'nginx:1'}], 'secret': 'NOT_RETAINED'})
    register_adapter(adapter)
    try:
        write(tmp_path, 'custom.txt', 'custom format')
        result = run_discovery(tmp_path)
        assert result['images'][0]['reference'] == 'nginx:1'
        assert 'NOT_RETAINED' not in json.dumps(result)
    finally:
        ADAPTERS.remove(adapter)

def test_legacy_catalog_is_recognized_without_fetching(tmp_path):
    write(tmp_path, 'catalog.yaml', '''services:
  database:
    sourceType: helm
    helmRepo: {url: 'https://charts.example.test', chartName: database, version: 1.2.3}
''')
    result = run_discovery(tmp_path)
    assert result['roots'][0]['technology'] == 'legacy'
    assert result['nodes'][0]['kind'] == 'ChartReference'
    assert result['completeness'] == 'partial'
    assert any(d['code'] == 'legacy_chart_requires_local_artifact' for d in result['diagnostics'])

def test_yaml_parser_bounds_before_construction():
    with pytest.raises(DiscoveryError):
        _documents('[' * 100 + '1' + ']' * 100)
    with pytest.raises(DiscoveryError):
        _documents('value: .nan')

def test_native_compose_environment_taint(tmp_path):
    write(tmp_path, 'compose.yaml', 'services: {web: {image: nginx:1}}')
    result = run_discovery(tmp_path, runner=lambda *args: json.dumps({'services': {'web': {'image': 'registry/PRIVATE_PASSWORD:1', 'environment': {'PASSWORD': 'PRIVATE_PASSWORD'}}}}))
    assert 'PRIVATE_PASSWORD' not in json.dumps(result)
    assert not result['images']

def test_chart_in_charts_directory_is_a_root(tmp_path):
    write(tmp_path, 'charts/singularity/Chart.yaml', 'apiVersion: v2\nname: singularity\nversion: 1.0.0')
    calls = []
    def runner(tool, args, cwd):
        calls.append(tool)
        return 'apiVersion: v1\nkind: Pod\nmetadata: {name: root}\nspec: {containers: [{name: app, image: nginx:root}]}'
    result = run_discovery(tmp_path, runner=runner)
    assert calls == ['helm']
    assert result['roots'][0]['path'] == 'charts/singularity'
    assert result['images'][0]['reference'] == 'nginx:root'

def test_unknown_custom_resource_is_not_a_workload(tmp_path):
    write(tmp_path, 'custom.yaml', 'apiVersion: custom.example/v1\nkind: Application\nmetadata: {name: custom}\nspec: {containers: [{name: not-a-pod, image: false:positive}]}')
    result = run_discovery(tmp_path)
    assert not result['images']
    assert any(d['code'] == 'custom_resource_workloads_not_evaluated' for d in result['diagnostics'])

def test_workload_images_use_standard_pod_spec_locations(tmp_path):
    write(tmp_path, 'deployment.yaml', '''apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  unrelated: {containers: [{image: false:positive}]}
  template:
    spec:
      containers: [{name: app, image: nginx:1}]
      initContainers: [{name: init, image: busybox:1}]
''')
    result = run_discovery(tmp_path)
    assert {i['reference'] for i in result['images']} == {'nginx:1', 'busybox:1'}


def test_configuration_storage_and_service_graph(tmp_path):
    write(tmp_path, 'resources.yaml', yaml.safe_dump_all([
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'settings'}, 'data': {'value': 'not-persisted'}},
        {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'web'}, 'spec': {'selector': {'app': 'web'}}},
        {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'web', 'labels': {'app': 'web'}}, 'spec': {
            'containers': [{'name': 'web', 'image': 'nginx:1', 'envFrom': [{'configMapRef': {'name': 'settings'}}, {'secretRef': {'name': 'password'}}]}],
            'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'missing'}}]}}
    ]))
    result = run_discovery(tmp_path)
    kinds = {edge['kind'] for edge in result['edges']}
    assert {'uses_configuration', 'uses_volume', 'backed_by', 'selects_workload'} <= kinds
    assert any(node['kind'] == 'SecretReference' and node['state'] == 'unresolved' for node in result['nodes'])
    assert 'not-persisted' not in json.dumps(result)
    assert all('completeness' in node for node in result['nodes'] + result['images'])


def test_missing_checkout_artifacts(tmp_path):
    write(tmp_path, 'images.txt', 'nginx:1')
    write(tmp_path, 'asset.bin', 'version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 100')
    write(tmp_path, '.gitmodules', '[submodule "missing"]\n path = vendor/missing\n')
    result = run_discovery(tmp_path)
    assert {'missing_lfs_object', 'missing_submodule_content'} <= {d['code'] for d in result['diagnostics']}


def test_native_compose_graph(tmp_path):
    write(tmp_path, 'compose.yaml', 'services:\n  web: {image: nginx:1}\n  db: {image: postgres:16}\n')
    def runner(tool, args, cwd):
        return json.dumps({'services': {
            'web': {'image': 'nginx:1', 'depends_on': {'db': {}}, 'networks': {'private': {}}, 'volumes': [{'type': 'volume', 'source': 'data', 'target': '/data'}]},
            'db': {'image': 'postgres:16'}
        }})
    result = run_discovery(tmp_path, runner=runner)
    assert {'depends_on', 'uses_network', 'uses_volume'} <= {e['kind'] for e in result['edges']}
    assert all(n['state'] == 'rendered' for n in result['nodes'])


def test_duplicate_resource_identity_does_not_resolve_reference(tmp_path):
    for environment in ('dev', 'prod'):
        write(tmp_path, environment + '/config.yaml', 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: settings}\ndata: {environment: ' + environment + '}\n')
    write(tmp_path, 'pod.yaml', 'apiVersion: v1\nkind: Pod\nmetadata: {name: app}\nspec:\n  containers: [{name: app, image: nginx:1, envFrom: [{configMapRef: {name: settings}}]}]\n')
    result = run_discovery(tmp_path)
    assert 'ambiguous_resource_reference' in {d['code'] for d in result['diagnostics']}
    refs = [n for n in result['nodes'] if n['kind'] == 'ConfigMapReference']
    assert len(refs) == 1 and refs[0]['state'] == 'unresolved'
    assert any(e['target'] == refs[0]['id'] and e['kind'] == 'uses_configuration' for e in result['edges'])
    assert result['completeness'] == 'partial'
