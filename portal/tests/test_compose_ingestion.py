from io import BytesIO
from pathlib import Path
import json
import tarfile
import zipfile

import pytest

from app.compose_ingestion import (
    ComposeInputError, MAX_VARIABLE_BYTES, discover, stage_uploads, validate_variables,
)


def put(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return name


def parse(tmp_path, text, **kwargs):
    put(tmp_path, 'compose.yaml', text)
    return discover(tmp_path, ['compose.yaml'], **kwargs)


def codes(result):
    return {issue['code'] for issue in result['issues']}


@pytest.mark.parametrize('definition', ['', '{}'])
def test_empty_named_resources_are_valid_declarations(tmp_path, definition):
    result = parse(tmp_path, f'''services:
  web:
    image: nginx:1
    volumes: ["data:/data"]
    networks: [egress, default]
volumes:
  data: {definition}
networks:
  egress: {definition}
  default: {definition}
''')
    assert result['complete'], result['issues']
    assert result['images'] == ['nginx:1']
    config = result['services'][0]['configuration']
    assert config['volumes_definitions']['data'] == {}
    assert config['networks_definitions']['egress'] == {}


def test_missing_named_resources_still_require_declarations(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    volumes: ["default:/data"]
    networks: [default, missing]
''')
    assert result['complete']
    assert all(not issue['blocking'] for issue in result['issues'])
    assert codes(result) == {'missing_volumes', 'missing_networks'}
    assert len(result['issues']) == 2
    assert result['images'] == ['nginx:1']


def test_implicit_default_network_is_valid(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    networks: [default]\n')
    assert result['complete'], result['issues']


def test_missing_variable_messages_identify_names_without_custom_text(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    environment:
      PASSWORD: ${DB_PASSWORD:?private-sentinel}
      TOKEN: ${API_TOKEN?other-sentinel}
      OPTION: ${UNSET_OPTION}
''')
    messages = [issue['message'] for issue in result['issues']]
    for name in ('DB_PASSWORD', 'API_TOKEN', 'UNSET_OPTION'):
        assert any(name in message for message in messages)
    assert len(messages) == 3
    assert 'sentinel' not in json.dumps(result)
    assert result['images'] == ['nginx:1']
    assert result['complete']
    assert all(not issue['blocking'] and issue['service'] == 'web' for issue in result['issues'])


def test_ordered_merge_anchors_profiles_and_redaction(tmp_path):
    put(tmp_path, '.env', 'REGISTRY=example.org\nTAG=2\nPASSWORD=private-sentinel\n')
    put(tmp_path, 'runtime.env', 'TOKEN=another-sentinel\n')
    put(tmp_path, 'compose.yaml', '''
x-default: &default
  image: ${REGISTRY}/web:${TAG:-1}
  environment:
    PASSWORD: ${PASSWORD}
services:
  web:
    <<: *default
    env_file: runtime.env
    command: [run, private-sentinel]
    ports: ["8080:80"]
    volumes: ["data:/data"]
    cap_add: [NET_ADMIN]
  disabled:
    image: debug:1
    profiles: [debug]
  duplicate:
    image: example.org/web:2
volumes:
  data: {}
''')
    put(tmp_path, 'override.yaml', '''
services:
  web:
    command: [other, another-sentinel]
    ports: ["9090:80"]
    volumes: ["other:/data:ro"]
    cap_add: [NET_ADMIN]
volumes:
  other: {}
''')
    result = discover(tmp_path, ['compose.yaml', 'override.yaml'])
    assert result['complete'], result['issues']
    assert result['images'] == ['example.org/web:2']
    assert [s['name'] for s in result['services']] == ['web', 'duplicate']
    web = result['services'][0]
    assert web['source_files'] == ['compose.yaml', 'override.yaml']
    assert len(web['configuration']['ports']) == 2
    assert web['configuration']['volumes'][0]['source'] == 'other'
    assert web['configuration']['volumes'][0]['read_only'] is True
    assert web['configuration']['cap_add'] == ['NET_ADMIN']
    assert 'private-sentinel' not in json.dumps(result)
    assert 'another-sentinel' not in json.dumps(result)
    assert discover(tmp_path, ['compose.yaml'], ['debug'])['images'][-1] == 'debug:1'


@pytest.mark.parametrize(('expression', 'env', 'expected'), [
    ('${TAG:-fallback}', '', 'fallback'),
    ('${TAG-fallback}', 'TAG=\n', ''),
    ('${TAG:-fallback}', 'TAG=\n', 'fallback'),
    ('${TAG+yes}', 'TAG=\n', 'yes'),
    ('${TAG:+yes}', 'TAG=\n', ''),
    ('${TAG:+yes}', 'TAG=x\n', 'yes'),
    ('${TAG:-${OTHER:-nested}}', '', 'nested'),
    ('$TAG', 'TAG=direct\n', 'direct'),
])
def test_interpolation_operators(tmp_path, expression, env, expected):
    put(tmp_path, '.env', env)
    result = parse(tmp_path, f'services:\n  web:\n    image: repo{expression}\n')
    assert result['images'] == ['repo' + expected]
    assert result['complete'], result['issues']


def test_host_environment_is_never_used(tmp_path, monkeypatch):
    monkeypatch.setenv('IMAGE', 'host/secret:latest')
    result = parse(tmp_path, 'services:\n  web:\n    image: ${IMAGE:?do not leak this sentinel}\n')
    assert not result['images']
    assert 'required_variable' in codes(result)
    assert 'sentinel' not in json.dumps(result)
    assert 'host/secret' not in json.dumps(result)


def test_unresolved_non_image_does_not_block_image_discovery_or_trigger_finding(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    privileged: ${PRIV}\n    environment:\n      SECRET: ${SECRET}\n')
    assert result['images'] == ['nginx:1']
    assert 'COMPOSE-PRIVILEGED' not in {item['finding'] for item in result['findings']}
    assert result['complete']
    assert all(not issue['blocking'] for issue in result['issues'])
    assert result['services'][0]['configuration']['privileged'] == '[unresolved]'


@pytest.mark.parametrize('image', ['${IMAGE:?required}', 'registry/app:${TAG}', '${IMAGE}'])
def test_unresolved_image_still_blocks_with_runtime_notes(tmp_path, image):
    result = parse(tmp_path, f'''services:
  web:
    image: {image}
    environment:
      PASSWORD: ${{PASSWORD:?private-sentinel}}
    volumes: ["/host/config:/config"]
''')
    assert not result['complete']
    assert not result['images']
    assert any(issue['code'] == 'unresolved_image' and issue['blocking'] for issue in result['issues'])
    assert all(not issue['blocking'] for issue in result['issues'] if issue['code'] != 'unresolved_image')
    assert 'private-sentinel' not in json.dumps(result)


def test_unresolved_profiles_cannot_silently_omit_images(tmp_path):
    result = parse(tmp_path, '''services:
  web: {image: 'nginx:1'}
  worker:
    image: redis:7
    profiles: ["${PROFILE:?required}"]
''')
    assert not result['complete']
    assert any(issue['code'] == 'unresolved_profiles' and issue['blocking'] for issue in result['issues'])


def test_missing_runtime_and_build_inputs_are_review_notes(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    build: absent-context
    env_file: absent.env
    environment: [PASSWORD]
    volumes: ["/host/config:/config", "data:/data"]
    networks: [external]
    secrets: [password]
    configs: [settings]
secrets:
  password: {external: true}
configs:
  settings: {file: absent.conf}
volumes:
  data: {external: true}
networks:
  external: {external: true}
''')
    assert result['complete'], result['issues']
    assert result['images'] == ['nginx:1']
    assert {'missing_build_input', 'missing_env_file', 'unresolved_environment',
            'external_bind_input', 'external_volumes', 'external_networks',
            'external_secrets', 'missing_configs'} <= codes(result)
    assert all(not issue['blocking'] for issue in result['issues'])
    assert result['services'][0]['configuration']['environment'] == {'PASSWORD': '[redacted]'}


def test_merge_reset_and_override(tmp_path):
    put(tmp_path, 'compose.yaml', 'services:\n  web:\n    image: nginx:1\n    command: [old]\n    ports: ["80:80"]\n    environment: {A: secret, B: secret}\n')
    put(tmp_path, 'override.yaml', 'services:\n  web:\n    command: [new]\n    ports: !override ["81:80"]\n    environment: !reset {}\n')
    result = discover(tmp_path, ['compose.yaml', 'override.yaml'])
    assert result['complete']
    config = result['services'][0]['configuration']
    assert config['ports'][0]['published'] == '81'
    assert len(config['ports']) == 1
    assert config['environment'] == {}


def test_required_optional_env_files_and_runtime_secrets(tmp_path):
    put(tmp_path, 'config.env', 'PASSWORD=password-sentinel\n')
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    env_file:
      - path: missing.env
        required: false
      - config.env
    healthcheck:
      test: [CMD, password-sentinel]
    labels:
      secret: password-sentinel
''')
    assert result['complete']
    assert result['services'][0]['configuration']['environment'] == {'PASSWORD': '[redacted]'}
    assert 'password-sentinel' not in json.dumps(result)
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    env_file: missing.env\n')
    assert 'missing_env_file' in codes(result)


def test_build_image_and_missing_config_inputs(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    build:
      context: .
      args:
        PASSWORD: password-sentinel
    secrets: [credential]
    configs: [settings]
  worker:
    build: .
secrets:
  credential:
    external: true
configs:
  settings:
    file: absent.conf
''')
    assert result['images'] == ['nginx:1']
    assert {'image_and_build', 'build_only', 'missing_build_input', 'external_secrets', 'missing_configs'} <= codes(result)
    assert 'password-sentinel' not in json.dumps(result)
    assert not result['complete']


def test_explicit_platform_not_scanned_as_default(tmp_path):
    result = parse(tmp_path, 'services:\n  arm:\n    image: nginx:1\n    platform: linux/arm64\n')
    assert not result['complete']
    assert result['images'] == []
    assert result['services'][0]['image'] == 'nginx:1'
    assert 'unsupported_platform' in codes(result)


def test_local_paths_relative_to_first_file(tmp_path):
    put(tmp_path, 'app/compose.yaml', 'services:\n  web:\n    image: nginx:1\n    env_file: values.env\n')
    put(tmp_path, 'app/values.env', 'FOO=bar\n')
    put(tmp_path, 'elsewhere/override.yaml', 'services:\n  web:\n    privileged: true\n')
    result = discover(tmp_path, ['app/compose.yaml', 'elsewhere/override.yaml'])
    assert result['complete']
    assert result['findings'][0]['finding'] == 'COMPOSE-PRIVILEGED'


def test_disabled_profile_dependency_is_a_review_note(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    depends_on: [db]
  db:
    image: postgres:1
    profiles: [data]
''')
    assert 'missing_dependency' in codes(result)
    assert result['complete']
    assert result['services'][0]['status'] == 'resolved'


@pytest.mark.parametrize('text', [
    'services: &loop {web: *loop}',
    'services:\n  web: !!python/object/apply:os.system [echo unsafe]',
    'services:\n  web:\n    image: [nginx:1]',
    'services:\n  web:\n    image: "http://user:password-sentinel@registry/image"',
    'services:\n  web:\n    image: [invalid',
])
def test_invalid_yaml_and_image_are_safe(tmp_path, text):
    result = parse(tmp_path, text)
    assert not result['complete']
    assert 'password-sentinel' not in json.dumps(result)


def test_nested_yaml_limit(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    x-deep: ' + '[' * 100 + '0' + ']' * 100)
    assert not result['complete']


def test_unsupported_extends_keeps_explicit_image_with_issue(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    extends: {file: remote.yaml, service: base}\n')
    assert result['images'] == ['nginx:1']
    assert 'unsupported_feature' in codes(result)


def test_default_pair_discovery(tmp_path):
    put(tmp_path, 'app/compose.yaml', 'services:\n  web:\n    image: nginx:1\n')
    put(tmp_path, 'app/compose.override.yaml', 'services:\n  web:\n    image: nginx:2\n')
    result = discover(tmp_path, [])
    assert result['images'] == ['nginx:2']
    assert result['sources'] == ['app/compose.yaml', 'app/compose.override.yaml']


@pytest.mark.parametrize('name', ['Compose.txt', 'compose.main.yaml(2)', 'deployment'])
@pytest.mark.parametrize('explicit', [False, True])
def test_uploaded_compose_detected_regardless_of_filename(tmp_path, name, explicit):
    from app.compose_scan import prepare_compose
    stage_uploads(tmp_path, [(b'services: {web: {image: "nginx:1"}}', name),
                             (b'TAG=1', '.env'), (b'\x00\xff', 'companion.bin')])
    payload = {'compose_enabled': True, 'compose_files': [name] if explicit else []}
    result = prepare_compose(tmp_path, payload)
    assert result['complete'], result['issues']
    assert result['sources'] == [name]
    assert payload['image_list'] == 'nginx:1'
    assert (tmp_path / 'images.txt').read_text().strip() == 'nginx:1'
    assert not (tmp_path / '.cats-compose').exists()


def test_actual_local_deployment_is_detected_without_file_order(tmp_path):
    source = Path(__file__).resolve().parents[2] / 'templates' / 'compose.local.yaml'
    staged = stage_uploads(tmp_path, [(source.read_bytes(), source.name)])
    result = discover(staged['root'], [])
    assert result['complete'], result['issues']
    assert {'portal', 'scan-worker'} <= {service['name'] for service in result['services']}


@pytest.mark.parametrize('base_name', ['Compose.txt', 'compose.yaml'])
def test_multiple_content_detected_documents_require_order(tmp_path, base_name):
    put(tmp_path, base_name, 'services: {web: {image: "nginx:1"}}')
    put(tmp_path, 'compose.main.yaml(2)', 'services: {web: {image: "nginx:2"}}')
    ambiguous = discover(tmp_path, [])
    assert codes(ambiguous) == {'compose_selection'}
    assert ambiguous['images'] == []
    assert not ambiguous['complete']
    ordered = discover(tmp_path, [base_name, 'compose.main.yaml(2)'])
    assert ordered['complete'], ordered['issues']
    assert ordered['images'] == ['nginx:2']
    reversed_order = discover(tmp_path, ['compose.main.yaml(2)', base_name])
    assert reversed_order['images'] == ['nginx:1']


def test_companion_yaml_is_not_selected_as_compose(tmp_path):
    put(tmp_path, 'Compose.txt', 'services: {web: {image: "nginx:1"}}')
    put(tmp_path, 'settings.yaml', 'logging: {level: debug}')
    result = discover(tmp_path, [])
    assert result['complete'], result['issues']
    assert result['sources'] == ['Compose.txt']


@pytest.mark.parametrize('limits', [{'max_files': 1}, {'max_total': 45}, {'max_file': 35}])
def test_content_detection_enforces_limits_including_binary_companions(tmp_path, limits):
    put(tmp_path, 'Compose.txt', 'services: {web: {image: "nginx:1"}}')
    (tmp_path / 'companion.bin').write_bytes(b'\xff' * 40)
    result = discover(tmp_path, [], **limits)
    assert not result['complete']
    assert codes(result) == {'invalid_input'}
    assert result['images'] == []


def archive(entries):
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w') as output:
        for name, value in entries:
            output.writestr(name, value)
    return stream.getvalue()


def test_stage_archive_and_standalone(tmp_path):
    result = stage_uploads(tmp_path, [(archive([('app/compose.yaml', 'services: {}')]), 'bundle.zip'), (b'PASSWORD=private', '.env')])
    assert result['root'] == tmp_path / '.cats-compose'
    assert result['files'] == ['.env', 'app/compose.yaml']
    assert (result['root'] / 'app/compose.yaml').read_text() == 'services: {}'


@pytest.mark.parametrize('name', ['../outside', '/absolute', 'C:/outside', 'a/../../escape', 'a\\..\\escape', 'nul.txt'])
def test_archive_path_attacks_rejected(tmp_path, name):
    with pytest.raises(ComposeInputError):
        stage_uploads(tmp_path, [(archive([(name, 'secret-sentinel')]), 'bundle.zip')])
    assert not (tmp_path / '.cats-compose').exists()


def test_duplicate_archive_paths_rejected(tmp_path):
    with pytest.raises(ComposeInputError):
        stage_uploads(tmp_path, [(archive([('app.yaml', 'a'), ('APP.yaml', 'b')]), 'bundle.zip')])


def test_tar_symlink_rejected(tmp_path):
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as output:
        entry = tarfile.TarInfo('link')
        entry.type = tarfile.SYMTYPE
        entry.linkname = '../../outside'
        output.addfile(entry)
    with pytest.raises(ComposeInputError):
        stage_uploads(tmp_path, [(stream.getvalue(), 'bundle.tar')])


def test_zip_symlink_rejected(tmp_path):
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w') as output:
        entry = zipfile.ZipInfo('link')
        entry.create_system = 3
        entry.external_attr = 0o120777 << 16
        output.writestr(entry, '../outside')
    with pytest.raises(ComposeInputError):
        stage_uploads(tmp_path, [(stream.getvalue(), 'bundle.zip')])


def test_traversal_references_rejected(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    env_file: ../outside.env\n')
    assert 'missing_env_file' in codes(result)
    assert result['complete']
    assert result['services'][0]['configuration']['environment'] == {}


def test_env_interpolation_is_per_file_before_merge(tmp_path):
    put(tmp_path, '.env', 'TAG=1\n')
    put(tmp_path, 'compose.yaml', 'services:\n  web:\n    image: nginx:${TAG}\n    environment: {TAG: 2}\n')
    put(tmp_path, 'override.yaml', 'services:\n  web:\n    image: nginx:${TAG}\n')
    assert discover(tmp_path, ['compose.yaml', 'override.yaml'])['images'] == ['nginx:1']


def test_yaml_12_scalar_behavior(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: on\n    ports: [1:20]\n')
    assert result['images'] == ['on']
    assert result['services'][0]['configuration']['ports'][0]['target'] == '20'
    assert result['services'][0]['configuration']['ports'][0]['published'] == '1'


def test_yaml_duplicate_keys_rejected(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: first\n    image: second\n')
    assert not result['complete']
    assert result['images'] == []


def test_sensitive_structural_interpolation_is_not_retained_or_scanned(tmp_path):
    put(tmp_path, '.env', 'TOKEN=sensitive-value-932\n')
    result = parse(tmp_path, 'services:\n  web:\n    image: registry/${TOKEN}/image:1\n    hostname: ${TOKEN}\n')
    assert 'sensitive-value-932' not in json.dumps(result)
    assert not result['images']
    assert 'sensitive_interpolation' in codes(result)


def test_explicit_security_checks(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    user: "0:0"\n    cap_add: [SYS_ADMIN]\n    security_opt: ["seccomp:unconfined"]\n    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n    ports: ["8080:80"]\n')
    assert {'COMPOSE-DOCKER-SOCKET', 'COMPOSE-CAPABILITIES', 'COMPOSE-ROOT-USER', 'COMPOSE-UNCONFINED', 'COMPOSE-PUBLISHED-PORTS', 'COMPOSE-NO-RESOURCE-LIMITS'} <= {f['finding'] for f in result['findings']}
    assert 'external_bind_input' in codes(result)


def test_invalid_ports_shape_is_not_silently_interpretedted(tmp_path):
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    ports: "8080:80"\n')
    assert result['complete']
    assert any(issue['code'] == 'compose_schema' and not issue['blocking'] for issue in result['issues'])
    assert result['images'] == ['nginx:1']
    assert not result['services'][0]['configuration']['ports']


def test_resource_short_to_long_override_preserves_source(tmp_path):
    put(tmp_path, 'compose.yaml', 'services:\n  web:\n    image: nginx:1\n    volumes: ["data:/data"]\nvolumes: {data: {}}\n')
    put(tmp_path, 'override.yaml', 'services:\n  web:\n    volumes:\n      - target: /data\n        read_only: true\n')
    result = discover(tmp_path, ['compose.yaml', 'override.yaml'])
    mount = result['services'][0]['configuration']['volumes'][0]
    assert mount['source'] == 'data'
    assert mount['read_only'] is True


def test_yaml_alias_expansion_bounded_before_construction(tmp_path):
    text = 'a: &a [0, 0, 0, 0, 0]\n'
    for name in 'bcdefgh':
        previous = chr(ord(name) - 1)
        text += name + ': &' + name + ' [' + ', '.join(['*' + previous] * 5) + ']\n'
    result = parse(tmp_path, text + 'services: {web: {image: nginx:1}}\n')
    assert not result['complete']
    assert result['images'] == []


def test_env_file_and_dependency_short_long_forms_merge(tmp_path):
    put(tmp_path, 'first.env', 'A=one\n')
    put(tmp_path, 'second.env', 'B=two\n')
    put(tmp_path, 'compose.yaml', 'services:\n  web:\n    image: nginx:1\n    env_file: first.env\n    depends_on: [db]\n  db: {image: postgres:1}\n  cache: {image: redis:1}\n')
    put(tmp_path, 'override.yaml', 'services:\n  web:\n    env_file: [second.env]\n    depends_on:\n      cache: {condition: service_started}\n')
    result = discover(tmp_path, ['compose.yaml', 'override.yaml'])
    assert result['complete'], result['issues']
    config = result['services'][0]['configuration']
    assert set(config['environment']) == {'A', 'B'}
    assert set(config['depends_on']) == {'db', 'cache'}


def test_secret_in_top_level_network_configuration_is_redacted(tmp_path):
    put(tmp_path, '.env', 'TOKEN=network-sensitive-972\n')
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:1\n    networks: [private]\nnetworks:\n  private:\n    name: ${TOKEN}\n')
    assert 'network-sensitive-972' not in json.dumps(result)
    assert result['complete']
    assert any(issue['code'] == 'sensitive_interpolation' and not issue['blocking'] for issue in result['issues'])


@pytest.mark.parametrize(('source', 'expected'), [
    (r'VALUE="line\nreturn\rtab\tbackslash\\quote\""', 'line\nreturn\rtab\tbackslash\\quote"'),
    ('VALUE="actual-value" # comment with "quotes"', 'actual-value'),
    ('VALUE="hash # stays inside" # outside', 'hash # stays inside'),
    (r"VALUE='literal\n${OTHER}'", r'literal\n${OTHER}'),
    (r"VALUE='It\'s literal'", "It's literal"),
])
def test_dotenv_single_line_quoted_values(source, expected):
    from app.compose_ingestion import _dotenv
    issues = []
    result = _dotenv(source, {}, lambda *args: issues.append(args))
    assert result == {'VALUE': expected}
    assert issues == []


@pytest.mark.parametrize('source', [
    r'VALUE="unsupported\u0041"',
    r'VALUE="unsupported\x41"',
    'VALUE="closed" trailing',
    'VALUE="unterminated',
])
def test_dotenv_unsupported_quoted_inputs_are_actionable(source):
    from app.compose_ingestion import _dotenv
    issues = []
    assert _dotenv(source, {}, lambda *args: issues.append(args)) == {}
    assert issues[0][0] == 'unsupported_dotenv'
    assert source not in str(issues)


def test_dotenv_comment_quotes_do_not_change_resolved_image(tmp_path):
    put(tmp_path, '.env', 'TAG="stable" # note containing "quotes"\n')
    result = parse(tmp_path, 'services:\n  web:\n    image: nginx:${TAG}\n')
    assert result['images'] == ['nginx:stable']
    assert result['complete'], result['issues']


def test_windows_drive_bind_is_an_explicit_review_note(tmp_path):
    result = parse(tmp_path, "services:\n  web:\n    image: nginx:1\n    volumes: ['C:\\config:/config:ro']\n")
    assert result['images'] == ['nginx:1']
    assert 'unresolved_bind_input' in codes(result)
    assert result['complete']
    assert all(not issue['blocking'] for issue in result['issues'])
    assert result['services'][0]['status'] == 'resolved'
    assert result['services'][0]['configuration']['volumes'][0]['source'] == '[unresolved]'


def test_missing_variables_merge_actual_references_without_values(tmp_path):
    put(tmp_path, 'compose.yaml', '''services:
  web:
    image: nginx:1
    environment:
      FIRST: ${SHARED}
      SECOND: ${SHARED}
      DEFAULT: ${DEFAULTED:-stable}
      ESCAPED: $${LITERAL}
  worker:
    image: redis:7
    environment: {VALUE: '${SHARED:?private-message-sentinel}'}
''')
    put(tmp_path, 'override.yaml', '''services:
  web:
    environment: {THIRD: '${SHARED}'}
''')
    result = discover(tmp_path, ['compose.yaml', 'override.yaml'])
    assert result['missing_variables'] == [{
        'name': 'SHARED', 'required': True,
        'sources': ['compose.yaml', 'override.yaml'], 'services': ['web', 'worker'],
    }]
    assert 'private-message-sentinel' not in json.dumps(result)
    assert result['complete']
    assert all(not issue['blocking'] for issue in result['issues'])


@pytest.mark.parametrize(('expression', 'expected'), [
    ('${MISSING}', [('MISSING', False)]),
    ('$MISSING', [('MISSING', False)]),
    ('${MISSING?private ${IGNORED}}', [('MISSING', True)]),
    ('${MISSING:?private ${IGNORED}}', [('MISSING', True)]),
    ('${EMPTY?message}', []),
    ('${EMPTY:?message}', [('EMPTY', True)]),
    ('${MISSING:-${NESTED}}', [('NESTED', False)]),
    ('${MISSING-${NESTED:?message}}', [('NESTED', True)]),
    ('${SET:-${IGNORED}}', []),
    ('${EMPTY-${IGNORED}}', []),
    ('${EMPTY:-${NESTED}}', [('NESTED', False)]),
    ('${EMPTY+${NESTED}}', [('NESTED', False)]),
    ('${EMPTY:+${IGNORED}}', []),
    ('${MISSING+${IGNORED}}', []),
    ('${SET:+${NESTED:?message}}', [('NESTED', True)]),
    ('$${ESCAPED} $$ESCAPED ${MISSING:-$${ALSO_ESCAPED}}', []),
])
def test_missing_variables_follow_only_evaluated_expression_branches(tmp_path, expression, expected):
    result = parse(tmp_path, f'''services:
  web:
    image: nginx:1
    environment:
      VALUE: '{expression}'
''', variables={'SET': 'present', 'EMPTY': ''})
    assert [(row['name'], row['required']) for row in result['missing_variables']] == expected
    assert result['complete'], result['issues']


def test_explicit_variables_win_dotenv_and_expand_dependencies(tmp_path, monkeypatch):
    monkeypatch.setenv('TAG', 'host-value')
    put(tmp_path, '.env', '''FIRST=${REGISTRY}/first:${TAG}
REGISTRY=bundled.example
TAG=${UNUSED:?private-message}
SECOND=${REGISTRY}/second:${TAG}
''')
    result = parse(tmp_path, '''services:
  web: {image: '${FIRST}'}
  worker: {image: '${SECOND}'}
''', variables={'REGISTRY': 'supplied.example', 'TAG': '2'})
    assert result['images'] == ['supplied.example/first:2', 'supplied.example/second:2']
    assert result['missing_variables'] == []
    assert result['complete'], result['issues']
    assert 'host-value' not in json.dumps(result)
    assert 'private-message' not in json.dumps(result)


def test_explicit_empty_variable_overrides_dotenv(tmp_path):
    put(tmp_path, '.env', 'TAG=bundled\n')
    result = parse(tmp_path, '''services:
  empty: {image: 'repo${TAG-default}'}
  fallback: {image: 'repo${TAG:-fallback}'}
''', variables={'TAG': ''})
    assert result['images'] == ['repo', 'repofallback']
    assert result['missing_variables'] == []


def test_explicit_values_are_literal_even_when_dotenv_references_them():
    from app.compose_ingestion import _dotenv, _expand
    literal = r'${SHOULD_NOT_EXPAND}$$literal\value'
    issues, missing = [], []
    issue = lambda *args: issues.append(args)
    record_missing = lambda *args: missing.append(args)
    variables = validate_variables({'VALUE': literal})
    assert _expand('${VALUE}', variables, issue, missing=record_missing) == literal
    assert _dotenv('VALUE=old\nOTHER=${VALUE}\n', variables, issue,
                   overrides=variables, missing=record_missing) == {'VALUE': literal, 'OTHER': literal}
    assert issues == missing == []


def test_missing_variables_attribute_dotenv_and_env_file_references(tmp_path):
    put(tmp_path, '.env', 'TAG=${RELEASE}\n')
    put(tmp_path, 'runtime.env', 'PASSWORD=${RUNTIME_PASSWORD:?private-message}\n')
    result = parse(tmp_path, '''services:
  web:
    image: nginx:${TAG}
    env_file: runtime.env
''')
    assert result['missing_variables'] == [
        {'name': 'RELEASE', 'required': False, 'sources': ['.env'], 'services': []},
        {'name': 'RUNTIME_PASSWORD', 'required': True, 'sources': ['runtime.env'], 'services': ['web']},
    ]
    resolved = discover(tmp_path, ['compose.yaml'], variables={'RELEASE': 'stable', 'RUNTIME_PASSWORD': 'private-value'})
    assert resolved['images'] == ['nginx:stable']
    assert resolved['missing_variables'] == []
    assert resolved['complete']
    assert 'private-value' not in json.dumps(resolved)


def test_missing_inherited_environment_excludes_unset_env_file_keys(tmp_path):
    put(tmp_path, 'runtime.env', 'UNSET\nRAW=${NOT_INTERPOLATED}\n')
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    env_file: {path: runtime.env, format: raw}
    environment: [NEEDED, SUPPLIED, EMPTY]
''', variables={'SUPPLIED': 'private-value', 'EMPTY': ''})
    assert result['missing_variables'] == [
        {'name': 'NEEDED', 'required': False, 'sources': ['compose.yaml'], 'services': ['web']},
    ]
    assert set(result['services'][0]['configuration']['environment']) == {'RAW', 'NEEDED', 'SUPPLIED', 'EMPTY'}
    assert result['complete']
    assert 'private-value' not in json.dumps(result)


def test_inactive_profile_missing_values_are_omitted(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    environment: {OPTION: '${SHARED}'}
  debug:
    image: '${DEBUG_IMAGE}'
    profiles: [debug]
    environment: {REQUIRED: '${SHARED:?message}'}
''')
    assert result['missing_variables'] == [
        {'name': 'SHARED', 'required': False, 'sources': ['compose.yaml'], 'services': ['web']},
    ]
    enabled = discover(tmp_path, ['compose.yaml'], ['debug'])
    assert {row['name'] for row in enabled['missing_variables']} == {'SHARED', 'DEBUG_IMAGE'}
    assert next(row for row in enabled['missing_variables'] if row['name'] == 'SHARED')['required']


def test_missing_profile_variable_remains_actionable(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    profiles: ['${PROFILE}']
''')
    assert result['missing_variables'] == [
        {'name': 'PROFILE', 'required': False, 'sources': ['compose.yaml'], 'services': ['web']},
    ]
    assert not result['complete']


def test_explicit_secrets_remain_redacted_when_runtime_environment_overrides_them(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    hostname: ${API_TOKEN}
    environment: {API_TOKEN: other-private-value, PASSWORD: '${PASSWORD}'}
    command: ['${PASSWORD}']
''', variables={'API_TOKEN': 'token-private-value', 'PASSWORD': 'password-private-value'})
    serialized = json.dumps(result)
    assert 'token-private-value' not in serialized
    assert 'password-private-value' not in serialized
    assert 'other-private-value' not in serialized
    assert result['services'][0]['configuration']['hostname'] == '[unresolved]'
    assert result['missing_variables'] == []
    assert result['images'] == ['nginx:1']


def test_interpolated_secret_environment_keys_are_not_retained_as_missing_names(tmp_path):
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    environment:
      - ${TOKEN}
      - PREFIX_${TOKEN}=other-private-value
''', variables={'TOKEN': 'private_value_sentinel'})
    assert result['complete']
    assert result['missing_variables'] == []
    assert 'private_value_sentinel' not in json.dumps(result)
    assert 'other-private-value' not in json.dumps(result)
    assert result['services'][0]['configuration']['environment'] == {'[redacted]': '[redacted]'}


def test_interpolated_secret_env_file_path_is_redacted_in_metadata(tmp_path):
    put(tmp_path, 'private-value-sentinel.env', 'PASSWORD=${REQUIRED:?private-message}\n')
    result = parse(tmp_path, '''services:
  web:
    image: nginx:1
    env_file: ${TOKEN}.env
''', variables={'TOKEN': 'private-value-sentinel'})
    assert result['complete']
    assert 'private-value-sentinel' not in json.dumps(result)
    assert result['missing_variables'] == [
        {'name': 'REQUIRED', 'required': True, 'sources': ['[redacted]'], 'services': ['web']},
    ]
    assert next(issue for issue in result['issues'] if issue['code'] == 'required_variable')['source'] == '[redacted]'


@pytest.mark.parametrize('variables', [
    None, [], 'private-value', 1, True,
    {'BAD-NAME': 'private-value'}, {'9BAD': 'private-value'}, {'': 'private-value'},
    {'A' * 129: 'private-value'}, {3: 'private-value'}, {'NUL\x00NAME': 'private-value'},
    {'UNICODE_é': 'private-value'}, {'VALUE': False}, {'VALUE': None},
    {'VALUE': ['private-value']}, {'VALUE': {'nested': 'private-value'}},
    {'VALUE': 'x' * 8193}, {'VALUE': 'private-value\x00'}, {'VALUE': '\ud800'},
    {f'VALUE_{i}': 'private-value' for i in range(201)},
    {f'VALUE_{i}': 'é' * 8192 for i in range(4)},
])
def test_validate_variables_rejects_invalid_inputs_without_values(variables):
    with pytest.raises(ComposeInputError) as error:
        validate_variables(variables)
    assert 'private-value' not in str(error.value)
    assert 'BAD-NAME' not in str(error.value)


def test_validate_variables_allows_boundaries_and_returns_copy():
    variables = {'A' * 128: 'x' * 8192, **{f'VALUE_{i}': '' for i in range(199)}}
    assert validate_variables(variables) == variables
    assert validate_variables(variables) is not variables
    assert validate_variables({}) == {}


def test_validate_variables_limits_encoded_json_bytes():
    variables = {f'VALUE_{i}': 'x' * 8192 for i in range(7)}
    variables['LAST'] = ''
    overhead = len(json.dumps(variables, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    variables['LAST'] = 'x' * (MAX_VARIABLE_BYTES - overhead)
    assert validate_variables(variables) == variables
    variables['LAST'] += 'x'
    with pytest.raises(ComposeInputError, match='total size'):
        validate_variables(variables)


def test_discover_rejects_invalid_explicit_values_safely(tmp_path):
    result = parse(tmp_path, 'services: {web: {image: nginx:1}}', variables={'TOKEN': ['private-value']})
    assert not result['complete']
    assert codes(result) == {'invalid_input'}
    assert result['missing_variables'] == []
    assert 'private-value' not in json.dumps(result)
