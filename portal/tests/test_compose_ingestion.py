from io import BytesIO
from pathlib import Path
import json
import tarfile
import zipfile

import pytest

from app.compose_ingestion import ComposeInputError, discover, stage_uploads


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
