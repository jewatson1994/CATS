import hashlib
import io
import json
from contextlib import contextmanager
from types import SimpleNamespace
from zipfile import ZipFile, ZipInfo
import pytest
import yaml
from app import remediation_delivery as delivery


def shared_renderers(monkeypatch, run):
    def lint(tool, args, cwd, **kwargs):
        assert tool == 'helm' and args[0] == 'lint'
        assert 'env' not in kwargs
        assert (cwd / 'Chart.yaml').exists() or (cwd / 'api/Chart.yaml').exists()
        assert not (cwd / 'auth.json').exists()
        return {'stdout': run([tool, *args]).stdout}
    def template(chart, **kwargs):
        assert 'env' not in kwargs
        assert chart.is_relative_to(kwargs['source_root'])
        args = ['helm', 'template', kwargs['release'], str(chart), '--namespace', kwargs['namespace']]
        for value in kwargs.get('values', []):
            args += ['--values', str(value)]
        for value in kwargs.get('set_values', []):
            args += ['--set-string', value]
        return {'stdout': run(args).stdout}
    monkeypatch.setattr(delivery, 'isolated_runner', lint)
    monkeypatch.setattr(delivery, 'helm_template', template)


def retained(tmp_path, entries=None):
    folder = tmp_path / "r1"
    folder.mkdir(exist_ok=True)
    path = folder / "candidate.zip"
    with ZipFile(path, "w") as archive:
        for name, content in (entries or {"manifest.json": "{}"}).items():
            archive.writestr(name, content)
    return SimpleNamespace(job_key="r1", artifact_path=str(path),
        artifact_digest="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest())


def test_retained_candidate_requires_original_integrity_and_directory(tmp_path):
    record = retained(tmp_path)
    assert delivery.retained_candidate(record, tmp_path).name == "candidate.zip"
    record.artifact_digest = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="integrity"):
        delivery.retained_candidate(record, tmp_path)
    record.job_key = "../r1"
    with pytest.raises(ValueError, match="unavailable"):
        delivery.retained_candidate(record, tmp_path)


@pytest.mark.parametrize("names", [["../escape"], ["/escape"], ["a\\escape"], ["C:escape"],
    ["a", "a"], ["a/b", "a//b"], ["a./escape"], ["a /escape"]])
def test_archive_entries_reject_escape_and_aliases(names):
    stream = io.BytesIO()
    with ZipFile(stream, "w") as archive:
        for name in names:
            entry = ZipInfo(name)
            entry.filename = name  # Preserve hostile separators on Windows too.
            archive.writestr(entry, "x")
    with ZipFile(stream) as archive, pytest.raises(ValueError, match="Unsafe"):
        delivery.checked_inventory(archive)


def test_archive_symlink_rejected():
    stream = io.BytesIO()
    with ZipFile(stream, "w") as archive:
        entry = ZipInfo("candidate/link")
        entry.external_attr = 0o120777 << 16
        archive.writestr(entry, "../../escape")
    with ZipFile(stream) as archive, pytest.raises(ValueError):
        delivery.checked_inventory(archive)


def test_materialization_changes_image_fields_not_policy_text():
    source = "old/api:patched"
    dest = "registry/team/api@sha256:" + "a" * 64
    content = yaml.safe_dump({"spec": {"containers": [{"image": source}]},
        "annotation": source, "description": "see " + source, "image": source + "-other"})
    result = yaml.safe_load(delivery.materialize({"manifest.yaml": content}, {source: dest})["manifest.yaml"])
    assert result["spec"]["containers"][0]["image"] == dest
    assert result["annotation"] == source
    assert result["description"] == "see " + source
    assert result["image"] == source + "-other"
    template = '{{ if .Values.enabled }}\nimage: "' + source + '" # image\nannotation: "' + source + '"\n{{ end }}'
    result = delivery.materialize({"templates/pod.yaml": template}, {source: dest})["templates/pod.yaml"]
    assert 'image: "' + dest + '"' in result
    assert 'annotation: "' + source + '"' in result


def test_recursive_yaml_rejected():
    with pytest.raises(ValueError, match="Recursive"):
        delivery.materialize({"values.yaml": "loop: &loop [*loop]"}, {})


def test_vendored_binary_dependency_is_preserved_during_image_materialization():
    package = b"\x1f\x8b\x08\xff\x00binary dependency"
    assert delivery.materialize({"api/charts/common-1.0.0.tgz": package},
        {"old/app:1": "registry/app@sha256:" + "a" * 64}) == {
            "api/charts/common-1.0.0.tgz": package}


@pytest.mark.parametrize("values", [["../override.yaml"], ["/override.yaml"], ["C:/override.yaml"],
    ["a\\override.yaml"], ["a//override.yaml"], ["a/./override.yaml"], ["missing.yaml"],
    ["override.yaml", "override.yaml"], "override.yaml", [None]])
def test_values_overrides_are_confined_to_retained_files(values):
    with pytest.raises(ValueError):
        delivery.checked_values_files(values, {"override.yaml", "a/override.yaml"})


@pytest.mark.parametrize('repeated', [False, True])
@pytest.mark.parametrize('set_override', [False, True])
def test_delivery_preserves_ordered_custom_values(tmp_path, monkeypatch, repeated, set_override):
    from pathlib import Path
    overrides = ["overrides/base.yaml", "overrides/service.yaml"]
    manifest = ({"helm_render_settings": [{"chart_root": "api", "values": overrides,
        "release": release, "namespace": namespace} for release, namespace in
        [("retained-release", "production"), ("second-release", "staging")]]} if repeated else
        {"values_files": overrides, "render_settings": {"release": "retained-release", "namespace": "production"}})
    if set_override:
        for settings in manifest.get('helm_render_settings', [manifest.get('render_settings')]):
            settings['set'] = ['replicas=4']
    record = retained(tmp_path, {"manifest.json": json.dumps(manifest),
        "candidate/api/Chart.yaml": "apiVersion: v2\nname: api\nversion: 1.0.0\n",
        "candidate/api/values.yaml": "replicas: 1\nnested: {keep: yes, replace: old}\nitems: [old]\n",
        "candidate/overrides/base.yaml": "replicas: 2\nnested: {replace: base}\nitems: [base]\n",
        "candidate/overrides/service.yaml": "replicas: 3\nnested: {replace: final}\nitems: [final]\n"})
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    calls = []
    expected = {"replicas": '4' if set_override else 3, "nested": {"keep": True, "replace": "final"}, "items": ["final"]}
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == 'template' and args[2] == 'cats-values':
            assert args[-2:] == ['--set-string', 'replicas=4']
            selected = [Path(args[index + 1]).name for index, arg in enumerate(args) if arg == '--values']
            assert selected == ['values-0.yaml', 'values-1.yaml']
            return SimpleNamespace(stdout=yaml.safe_dump(expected))
        if args[1] == "template":
            assert (args[2], args[args.index("--namespace") + 1]) in {
                ("retained-release", "production"), ("second-release", "staging")}
        if args[1] in {"lint", "template", "package"}:
            assert "--values" not in args
            chart = Path(args[3] if args[1] == "template" else args[2])
            embedded = yaml.safe_load((chart / "values.yaml").read_text())
            assert embedded == expected
        if args[1] == "package":
            import tarfile
            with tarfile.open(Path(args[args.index("--destination") + 1]) / "api-1.0.0.tgz", "w:gz") as package:
                package.add(chart, arcname="api")
        return SimpleNamespace(returncode=0, stdout="", stderr="Digest: sha256:" + "a" * 64 if args[1] == "push" else "")
    monkeypatch.setattr(delivery.subprocess, "run", run)
    shared_renderers(monkeypatch, run)
    result, path = delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 1, tmp_path)
    assert result["values_files"] == overrides
    assert result["values_embedded"] is True
    render_calls = ["lint", "template"] * (2 if repeated else 1)
    values_calls = ["template"] * ((2 if repeated else 1) if set_override else 0)
    assert [args[1] for args in calls] == [*values_calls, *render_calls, "package", "push"]
    with ZipFile(path) as output:
        assert json.loads(output.read("lineage.json"))["values_files"] == overrides
        assert yaml.safe_load(output.read("candidate/api/values.yaml")) == expected
    calls.clear()
    checkpoints = []
    retried, _ = delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"},
                                  2, tmp_path, checkpoint=checkpoints.append)
    assert [args[1] for args in calls] == [*values_calls, *render_calls, "push"]
    assert retried["artifact_identities"] == result["artifact_identities"]
    assert checkpoints[0]["artifact_identities"][1]["identity_type"] == "oci_manifest"
    assert "signature_status" not in checkpoints[0]["artifact_identities"][1]
    assert checkpoints[-1]["artifact_identities"][1]["signature_status"] == "not_requested"
    cached = next((Path(record.artifact_path).parent / "delivery-packages").rglob("*.tgz"))
    cached.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity mismatch"):
        delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 3, tmp_path)


@pytest.mark.parametrize('image,source',[
    ({'registry':'old.example:5443','repository':'team/api','tag':'patched'},'old.example:5443/team/api:patched'),
    ({'repository':'old.example/team/api','tag':'patched'},'old.example/team/api:patched'),
    ({'registry':'old.example','repository':'team/api','digest':'sha256:'+'b'*64,'tag':'ignored'},'old.example/team/api@sha256:'+'b'*64),
])
def test_materialization_split_images_require_exact_complete_identity(image,source):
    destination = 'new.example:5443/team/image-one@sha256:'+'a'*64
    content = yaml.safe_dump({'image':{**image,'pullPolicy':'Always'},'unmatched':{'registry':'old.example','repository':'team/api','tag':'original'},'annotation':source})
    result = yaml.safe_load(delivery.materialize({'values.yaml':content},{source:destination})['values.yaml'])
    assert result['image']['digest'] == 'sha256:'+'a'*64
    assert result['image']['tag'] == ''
    if 'registry' in image:
        assert result['image']['registry'] == 'new.example:5443'
        assert result['image']['repository'] == 'team/image-one'
    else:
        assert result['image']['repository'] == 'new.example:5443/team/image-one'
    assert result['image']['pullPolicy'] == 'Always'
    assert result['unmatched']['tag'] == 'original' and result['annotation'] == source


def test_split_materialization_does_not_guess_defaults_or_change_partial_matches():
    data = {'image':{'registry':'old.example','repository':'api'},'other':{'repository':'old.example/api','tag':'other'}}
    result = yaml.safe_load(delivery.materialize({'values.yaml':yaml.safe_dump(data)},
        {'old.example/api:patched':'new.example/api@sha256:'+'a'*64})['values.yaml'])
    assert result == data


@pytest.mark.parametrize("registry_changed", [False, True])
@pytest.mark.parametrize("signing_outcome", [None, "verified", "failed"])
def test_delivery_uses_archive_hash_then_registry_manifest_and_preserves_r1(tmp_path, monkeypatch, registry_changed, signing_outcome):
    archive_name = "images/" + "a" * 32 + ".tar"
    image_content = b"retained-image-archive"
    tar_digest = "sha256:" + hashlib.sha256(image_content).hexdigest()
    manifest_digest = "sha256:" + "b" * 64
    record = retained(tmp_path, {"manifest.json": json.dumps({"images": [{
        "archive_path": archive_name, "artifact_sha256": tar_digest, "remediated": "local/api:validated"}]}),
        archive_name: image_content, "candidate/manifest.yaml": "image: local/api:validated\n"})
    original_digest = record.artifact_digest
    calls = []
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    def run(args, **kwargs):
        calls.append(args)
        assert kwargs.get("shell") is None
        if args[1] == "copy":
            from pathlib import Path
            Path(args[args.index("--digestfile") + 1]).write_text(manifest_digest)
        observed = "sha256:" + "c" * 64 if registry_changed else manifest_digest
        return SimpleNamespace(returncode=0, stdout=observed if args[1] == "inspect" else "", stderr="")
    monkeypatch.setattr(delivery.subprocess, "run", run)
    from app import signing
    def sign(reference, config, credentials, env):
        assert reference.endswith("@" + manifest_digest)
        assert "DOCKER_CONFIG" in env
        if signing_outcome == "failed":
            raise RuntimeError("private-key-secret")
        return {"signature_status": "verified", "signature": {"image": reference}}
    monkeypatch.setattr(signing, "sign_and_verify", sign)
    if registry_changed:
        with pytest.raises(ValueError, match="identity differs"):
            delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example:5443", "namespace": "team"}, 1, tmp_path)
        assert delivery.retained_candidate(record, tmp_path).exists()
        return
    result, path = delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example:5443", "namespace": "team"}, 1, tmp_path,
        signing_material=({}, {}) if signing_outcome else None)
    assert result["signing_status"] == (signing_outcome or "not_requested")
    assert "private-key-secret" not in json.dumps(result)
    identity = result["artifact_identities"][0]
    assert identity["digest"] == manifest_digest
    assert identity["digest"] != tar_digest
    assert identity["reference"].startswith("registry.example:5443/team/")
    assert identity["reference"].endswith("@" + manifest_digest)
    assert record.artifact_digest == original_digest
    assert [args[1] for args in calls] == ["copy", "inspect"]
    with ZipFile(path) as output:
        assert manifest_digest in output.read("candidate/manifest.yaml").decode()
    assert delivery.retained_candidate(record, tmp_path).exists()


def test_delivery_failure_retains_candidate_and_sanitizes_error(tmp_path, monkeypatch):
    name = "images/" + "a" * 32 + ".tar"
    record = retained(tmp_path, {"manifest.json": json.dumps({"images": [{"archive_path": name,
        "artifact_sha256": hashlib.sha256(b"archive").hexdigest(), "remediated": "local:tag"}]}), name: b"archive"})
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    monkeypatch.setattr(delivery.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="secret-password"))
    with pytest.raises(ValueError) as error:
        delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 1, tmp_path)
    assert "secret-password" not in str(error.value)
    assert delivery.retained_candidate(record, tmp_path).exists()


def test_helm_ignoring_rewritten_digest_is_not_published(tmp_path, monkeypatch):
    name = "images/" + "a" * 32 + ".tar"
    digest = "sha256:" + "b" * 64
    record = retained(tmp_path, {
        "manifest.json": json.dumps({"images": [{"archive_path": name,
            "artifact_sha256": hashlib.sha256(b"archive").hexdigest(), "remediated": "local:tag"}]}),
        name: b"archive", "candidate/Chart.yaml": "apiVersion: v2\nname: example\nversion: 1.0.0\n",
        "candidate/values.yaml": "image: local:tag\n"})
    monkeypatch.setattr(delivery.shutil, "which", lambda name: name)
    monkeypatch.setattr(delivery, "decrypt_secret", lambda value: "")
    @contextmanager
    def trust(_destination):
        yield None, {}
    monkeypatch.setattr(delivery, "destination_trust", trust)
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "copy":
            from pathlib import Path
            Path(args[args.index("--digestfile") + 1]).write_text(digest)
        output = digest if args[1] == "inspect" else ""
        if args[1] == "template":
            output = "spec:\n  containers:\n  - image: local:tag\n"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(delivery.subprocess, "run", run)
    shared_renderers(monkeypatch, run)
    checkpoints = []
    with pytest.raises(ValueError, match="Rendered Helm images"):
        delivery.deliver(record, {"name": "Team", "endpoint": "https://registry.example"}, 1, tmp_path,
                         checkpoint=checkpoints.append)
    assert checkpoints[-1]["artifact_identities"][0]["digest"] == digest
    assert not any(args[1] in {"package", "push"} for args in calls)
    assert delivery.retained_candidate(record, tmp_path).exists()


@pytest.mark.parametrize('include_defaults', [True, False])
def test_delivery_materializes_set_with_helm_string_and_list_semantics(tmp_path, monkeypatch, include_defaults):
    import shutil
    import subprocess
    helm = shutil.which('helm')
    if not helm:
        pytest.skip('Helm is needed to verify native values semantics')
    # The fixture chart/template is fixed trusted content. Production uses the
    # shared isolated action; this host test verifies Helm's actual merge rules.
    def template(chart, **kwargs):
        assert kwargs['source_root'] == chart.parent
        assert not (chart.parent / 'auth.json').exists()
        args = [helm, 'template', kwargs['release'], str(chart)]
        for value in kwargs['values']:
            args += ['--values', str(value)]
        for value in kwargs['set_values']:
            args += ['--set-string', value]
        return {'stdout': subprocess.run(args, capture_output=True, text=True, check=True).stdout}
    monkeypatch.setattr(delivery, 'helm_template', template)
    settings = delivery.checked_render_settings({'values': ['overrides.yaml'], 'set': [
        'enabled=true', r'labels.app\.example/name=demo', r'items[1]=one\,two', 'image=old/app:patched']},
        {'overrides.yaml'})
    name, content = delivery.embedded_instance_values({'api/values.yaml': 'enabled: false\nkeep: original\nremove: default\n',
        'overrides.yaml': 'items: [zero, old]\nremove: null\n'}, {'chart_root': 'api', **settings}, include_defaults=include_defaults)
    expected = {'enabled': 'true', 'labels': {'app.example/name': 'demo'},
                'items': ['zero', 'one,two'], 'image': 'old/app:patched'}
    expected.update({'keep': 'original'} if include_defaults else {'remove': None})
    assert name == 'api/values.yaml' and yaml.safe_load(content) == expected
    destination = 'registry/app@sha256:' + 'a' * 64
    assert yaml.safe_load(delivery.materialize({name: content}, {'old/app:patched': destination})[name])['image'] == destination


def test_delivery_rejects_ambiguous_repeated_chart_before_publication(tmp_path, monkeypatch):
    record = retained(tmp_path, {'manifest.json': json.dumps({'helm_render_settings': [
        {'chart_root': '.', 'release': 'blue'}, {'chart_root': '.', 'release': 'green', 'values': ['green.yaml']}]}),
        'candidate/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n',
        'candidate/green.yaml': 'replicas: 2\n'})
    monkeypatch.setattr(delivery.subprocess, 'run', lambda *args, **kwargs: pytest.fail('No publication for ambiguous package'))
    with pytest.raises(ValueError, match='differing values'):
        delivery.deliver(record, {'name': 'Team', 'endpoint': 'https://registry.example'}, 1, tmp_path)


def test_chart_roots_allow_repository_charts_directory_and_explicit_dependency():
    files = {'charts/api/Chart.yaml', 'charts/api/charts/common/Chart.yaml', 'charts/web/Chart.yaml'}
    assert delivery.helm_chart_roots(files) == {'charts/api', 'charts/web'}
    selected = [{'chart_root': name} for name in ['charts/api', 'charts/api/charts/common', 'charts/web']]
    assert [item['chart_root'] for item in delivery.checked_helm_render_settings(selected, files)] == [
        'charts/api', 'charts/api/charts/common', 'charts/web']
    with pytest.raises(ValueError, match='cover every chart'):
        delivery.checked_helm_render_settings(selected[:2], files)


def test_delivery_rejects_dependency_values_that_would_change_parent_before_publication(tmp_path, monkeypatch):
    record = retained(tmp_path, {'manifest.json': json.dumps({'helm_render_settings': [
        {'chart_root': 'api'}, {'chart_root': 'api/charts/common', 'values': ['override.yaml']}]}),
        'candidate/api/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n',
        'candidate/api/charts/common/Chart.yaml': 'apiVersion: v2\nname: common\nversion: 1.0.0\n',
        'candidate/override.yaml': 'enabled: true\n'})
    monkeypatch.setattr(delivery.subprocess, 'run', lambda *args, **kwargs: pytest.fail('No publication for overlapping charts'))
    with pytest.raises(ValueError, match='separately configured nested charts'):
        delivery.deliver(record, {'name': 'Team', 'endpoint': 'https://registry.example'}, 1, tmp_path)
