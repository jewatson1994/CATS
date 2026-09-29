import json

import pytest

from app.service_definitions import DefinitionError, parse_definition


def catalog(extra=''):
    return '''services:
  cert-manager:
    sourceType: helm
    helmRepo:
      repoName: cert-manager
      url: https://charts.jetstack.io
      version: v1.20.2
''' + extra


def test_examples_and_exact_oci():
    result = parse_definition(catalog('''  confluence:
    enabled: false
    sourceType: helm
    helmRepo: {repoName: confluence, url: 'https://atlassian.github.io/data-center-helm-charts/', version: 2.0.13}
  dex-k8s-authenticator:
    sourceType: helm
    helmRepo: {repoName: fallback, chartName: dex-k8s-authenticator, url: 'https://wiremind.github.io/wiremind-helm-charts', version: 1.7.0}
  confluence-postgres:
    sourceType: oci
    ociRepo: {repoName: confluence-postgresql, url: 'oci://registry-1.docker.io/bitnamicharts/postgresql', tag: 15.5.38}
  dokuwiki:
    sourceType: oci
    ociRepo: {repoName: dokuwiki, url: 'oci://oci.trueforge.org/truecharts/dokuwiki', tag: 16.3.0}
'''))
    assert result['counts']['normalized'] == 5
    assert result['components'][2]['chart_name'] == 'dex-k8s-authenticator'
    assert result['components'][3]['reference'].endswith('/postgresql:15.5.38')
    json.dumps(result)


def test_singularity_sibling_oci_fields_and_deployment_disabled_components():
    result = parse_definition('''services:
  nginx:
    enabled: true
    sourceType: oci
    ociRepo: {url: 'oci://registry-1.docker.io/bitnamicharts'}
    repoName: nginx
    tag: "25.1.1"
  redis:
    enabled: false
    sourceType: oci
    ociRepo: {url: 'oci://registry-1.docker.io/bitnamicharts'}
    repoName: redis
    tag: "28.1.0"
  postgresql:
    enabled: false
    sourceType: oci
    ociRepo: {url: 'oci://registry-1.docker.io/bitnamicharts'}
    repoName: postgresql
    tag: "18.11.3"
''')
    assert result['counts'] == {'declared': 3, 'normalized': 3, 'unsupported': 0, 'unresolved': 0}
    assert [item['reference'] for item in result['components']] == [
        'oci://registry-1.docker.io/bitnamicharts/nginx:25.1.1',
        'oci://registry-1.docker.io/bitnamicharts/redis:28.1.0',
        'oci://registry-1.docker.io/bitnamicharts/postgresql:18.11.3',
    ]


@pytest.mark.parametrize('setting', ['true', 'false', 'null', 'whatever', '{}', '[]'])
def test_deployment_config_does_not_change_scope(setting):
    plain = parse_definition(catalog())
    assert parse_definition(catalog().replace('    sourceType:', f'    enabled: {setting}\n    sourceType:')) == plain


def test_forty_components_and_sibling_isolation():
    body = 'services:\n' + ''.join(f'  item{i}:\n    sourceType: helm\n    helmRepo: {{repoName: chart, url: "https://example.org", version: "1.2.3"}}\n' for i in range(40))
    result = parse_definition(body + '  broken: 4\n  unknown: {sourceType: git}\n  missing: {}\n')
    assert result['counts'] == {'declared': 43, 'normalized': 40, 'unsupported': 1, 'unresolved': 2}


def test_unrelated_urls_not_discovered():
    with pytest.raises(DefinitionError):
        parse_definition('services: {random: {url: "https://example.org"}}')
    result = parse_definition('services: {random: {url: "https://example.org"}}', 'singularity')
    assert result['components'][0]['status'] == 'unresolved'


@pytest.mark.parametrize('text', [
    'services: {}\nservices: {}',
    'services: {a: !!python/object/apply:os.system [echo nope]}',
    'services: &cycle {a: *cycle}',
    'services: {a: {<<: {sourceType: helm}}}',
    'services: [',
])
def test_unsafe_yaml(text):
    with pytest.raises(DefinitionError):
        parse_definition(text, 'singularity')


def test_bounded_acyclic_aliases():
    text = catalog().replace('  cert-manager:', '  cert-manager: &component') + '  clone: *component\n'
    assert parse_definition(text)['counts']['normalized'] == 2


@pytest.mark.parametrize('suffix,value,text', [
    ('BYTES', 10, catalog()), ('COMPONENTS', 1, catalog() + '  second: {}\n'),
    ('DEPTH', 3, catalog()), ('NODES', 3, catalog()), ('STRING_BYTES', 3, catalog()),
])
def test_limits(monkeypatch, suffix, value, text):
    monkeypatch.setenv('CATS_SERVICE_DEFINITION_MAX_' + suffix, str(value))
    with pytest.raises(DefinitionError):
        parse_definition(text, 'singularity')


@pytest.mark.parametrize('url', ['https://user:secret@example.org', 'https://example.org?token=secret', 'oci://user:secret@example.org/chart'])
def test_credentials_not_exposed(url):
    result = parse_definition(catalog().replace('https://charts.jetstack.io', url))
    assert result['components'][0]['status'] == 'unresolved'
    assert 'secret' not in json.dumps(result)


@pytest.mark.parametrize('version', ['latest', '*', '>=1.0', ''])
def test_exact_version_required(version):
    result = parse_definition(catalog().replace('v1.20.2', '"' + version + '"'))
    assert result['components'][0]['status'] == 'unresolved'


def test_alias_expansion_budget(monkeypatch):
    monkeypatch.setenv('CATS_SERVICE_DEFINITION_MAX_NODES', '80')
    text = 'a: &a [1, 2, 3, 4]\nb: &b [*a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b]\nservices: {}'
    with pytest.raises(DefinitionError):
        parse_definition(text, 'singularity')
