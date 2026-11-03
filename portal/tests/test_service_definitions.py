import json
from pathlib import Path

import pytest

from app.service_definitions import DefinitionError, parse_definition, parse_definition_mapping


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
    assert result['components'][3]['chart_name'] == 'postgresql'
    json.dumps(result)


def test_scanner_values_catalog_chart_names_and_repositories():
    fixture = Path(__file__).resolve().parents[2] / 'scanning-main/examples/services-values.yml'
    components = parse_definition(fixture.read_bytes())['components']
    assert [(c['chart_name'], c['repository'], c['version'], c['status']) for c in components] == [
        ('kube-prometheus-stack', 'https://prometheus-community.github.io/helm-charts', '27.20.0', 'normalized'),
        ('cert-manager', 'https://charts.jetstack.io', 'v1.18.2', 'normalized'),
    ]


def test_helm_catalog_field_precedence_and_validation():
    text = catalog().replace('      url:', '''      chartName: primary
      chart: alternate
      repoUrl: https://alternate.example
      url:''')
    component = parse_definition(text)['components'][0]
    assert (component['chart_name'], component['repository']) == ('primary', 'https://charts.jetstack.io')
    assert parse_definition(text.replace('chartName: primary', 'chartName: ../invalid'))['components'][0]['status'] == 'unresolved'
    alternate = text.replace('      url: https://charts.jetstack.io\n', '').replace(
        'https://alternate.example', 'https://user:secret@alternate.example')
    component = parse_definition(alternate)['components'][0]
    assert component['status'] == 'unresolved' and 'secret' not in json.dumps(component)


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


@pytest.mark.parametrize('source_type', ['helm', 'oci'])
def test_explicit_source_without_repository_is_detected_but_not_acquired(source_type):
    document = {'services': {'missing': {'sourceType': source_type, 'url': 'https://unrelated.example'}}}
    result = parse_definition_mapping(document)
    assert result == parse_definition(json.dumps(document))
    assert result['counts'] == {'declared': 1, 'normalized': 0, 'unsupported': 0, 'unresolved': 1}
    component, = result['components']
    assert component['source_type'] == source_type and component['reference'] is None
    assert 'repository' in component['reason'].lower()


def test_mapping_rechecks_combined_limits_and_rejects_non_string_keys(monkeypatch):
    entries = {'chart': {'sourceType': 'helm'}}
    with pytest.raises(DefinitionError, match='Mapping keys must be strings'):
        parse_definition_mapping({'services': entries, 'extra': {1: 'x'}})
    monkeypatch.setenv('CATS_SERVICE_DEFINITION_MAX_COMPONENTS', '1')
    with pytest.raises(DefinitionError, match='component limit'):
        parse_definition_mapping({'services': {**entries, 'another': {'sourceType': 'oci'}}})


def test_merged_catalog_keeps_a_combined_text_budget(monkeypatch):
    monkeypatch.setenv('CATS_SERVICE_DEFINITION_MAX_BYTES', '60')
    with pytest.raises(DefinitionError, match='byte limit'):
        parse_definition_mapping({'services': {'one': {'sourceType': 'helm', 'note': 'a' * 25},
                                               'two': {'sourceType': 'oci', 'note': 'b' * 25}}})


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


@pytest.mark.parametrize('version', ['*', '>=1.0', ''])
def test_exact_version_required(version):
    result = parse_definition(catalog().replace('v1.20.2', '"' + version + '"'))
    assert result['components'][0]['status'] == 'unresolved'


def test_latest_is_a_normalized_helm_declaration():
    result = parse_definition(catalog().replace('v1.20.2', 'latest'))
    assert result['components'][0]['status'] == 'normalized'
    assert result['components'][0]['version'] == 'latest'


def test_alias_expansion_budget(monkeypatch):
    monkeypatch.setenv('CATS_SERVICE_DEFINITION_MAX_NODES', '80')
    text = 'a: &a [1, 2, 3, 4]\nb: &b [*a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b]\nservices: {}'
    with pytest.raises(DefinitionError):
        parse_definition(text, 'singularity')


@pytest.mark.parametrize('embedded_tag', [False, True])
def test_oci_release_aliases_preserve_chart_identity(embedded_tag):
    url = 'oci://registry-1.docker.io/bitnamicharts/postgresql'
    if embedded_tag:
        url += ':15.5.38'
    body = 'services:\n' + ''.join(
        f'  {alias}-postgres:\n'
        f'    enabled: false\n'
        f'    sourceType: oci\n'
        f'    ociRepo: {{repoName: {alias}-postgresql, url: "{url}", tag: "15.5.38"}}\n'
        for alias in ('confluence', 'jira')
    )
    components = parse_definition(body)['components']
    assert [c['logical_name'] for c in components] == ['confluence-postgres', 'jira-postgres']
    assert all(c['status'] == 'normalized' and c['chart_name'] == 'postgresql' for c in components)
    assert all(c['reference'] == 'oci://registry-1.docker.io/bitnamicharts/postgresql:15.5.38' for c in components)


def test_oci_embedded_version_conflict_is_rejected():
    result = parse_definition("""services:
  db:
    sourceType: oci
    ociRepo: {repoName: db-release, url: "oci://registry.example/charts/postgresql:15.5.37", tag: "15.5.38"}
""")
    assert result['components'][0]['status'] == 'unresolved'
