"""Failure injection stays confined to the explicitly retained fixture subtree."""
import hashlib
import json
from types import SimpleNamespace

import pytest

import harbor_graph_qualification as qualification
from harbor_graph_qualification import LABEL, check_quarantine_scope


def expected(namespace='qualification/final-graph'):
    return {'fixture': LABEL, 'namespace': namespace,
            'source': 'https://source.example', 'target': 'https://target.example'}


@pytest.mark.parametrize('namespace', ['qualification', 'qualification/final-graph', 'qualification/team/final-graph'])
def test_quarantine_accepts_exact_confirmed_qualification_subtree(namespace):
    check_quarantine_scope(expected(namespace), 'https://target.example', namespace + '/service/application')


@pytest.mark.parametrize('namespace', ['approved', 'qualification/../approved', 'qualification/',
                                     'qualification/*', 'qualification//nested'])
def test_quarantine_rejects_nonliteral_or_nonqualification_namespace(namespace):
    with pytest.raises(AssertionError):
        check_quarantine_scope(expected(namespace), 'https://target.example', namespace + '/service/application')


@pytest.mark.parametrize('repository', ['qualification/other/application', 'qualification/final-graph-extra/application',
                                      'approved/service/application', 'qualification/final-graph'])
def test_quarantine_rejects_objects_outside_exact_retained_subtree(repository):
    with pytest.raises(AssertionError):
        check_quarantine_scope(expected(), 'https://target.example', repository)


def test_quarantine_rejects_unconfirmed_target_source_and_unlabeled_fixture():
    for changes, confirmed in [({}, 'https://source.example'), ({'target': 'https://source.example'}, 'https://source.example'),
                               ({'fixture': 'production'}, 'https://target.example')]:
        with pytest.raises(AssertionError):
            check_quarantine_scope({**expected(), **changes}, confirmed, 'qualification/final-graph/service/application')


LINK_PATHS = (
    '_layers/sha256/{checksum}/link',
    '_manifests/revisions/sha256/{checksum}/link',
    '_manifests/tags/current/index/sha256/{checksum}/link',
    '_manifests/tags/current/current/link',
)


@pytest.fixture
def stored_fixture(tmp_path, monkeypatch):
    from app import release_oci
    root, volume = tmp_path / 'workspace', tmp_path / 'storage'
    root.mkdir()
    content = b'owned synthetic successor layer'
    checksum = hashlib.sha256(content).hexdigest()
    digest = 'sha256:' + checksum
    data = volume / 'docker/registry/v2/blobs/sha256' / checksum[:2] / checksum / 'data'
    data.parent.mkdir(parents=True)
    data.write_bytes(content)
    document = expected()
    target = {'repository': document['namespace'] + '/service/application', 'digest': digest}
    document.update(omissions={'missing-layer': target}, receipts={'first': {
        'release': {'signature': {'digest': 'sha256:' + 'a' * 64}}, 'release_objects': []}})
    (root / 'expected.json').write_text(json.dumps(document), encoding='utf-8')
    repositories = volume / 'docker/registry/v2/repositories'
    repositories.mkdir(parents=True)

    def link(repository, template, identity=digest):
        path = repositories / repository / template.format(checksum=identity[7:])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(identity, encoding='ascii')
        return path

    monkeypatch.setattr(qualification, 'fetch', lambda *args: {'digest': 'sha256:' + 'b' * 64, 'artifacts': []})
    return SimpleNamespace(ctx=SimpleNamespace(root=root, oci=release_oci),
        args=SimpleNamespace(case='missing-layer', registry_root=volume,
            confirm_target=document['target'], phase='quarantine'),
        root=root, volume=volume, document=document, data=data, content=content,
        digest=digest, repository=target['repository'], link=link)


def test_global_blob_quarantine_checks_all_link_types_and_restores_exact_bytes(stored_fixture):
    fixture = stored_fixture
    links = [fixture.link(fixture.repository, template) for template in LINK_PATHS]
    unrelated = fixture.link('approved/unrelated', LINK_PATHS[0], 'sha256:' + 'c' * 64)
    qualification.quarantine(fixture.ctx, fixture.args)
    held = fixture.data.with_name('data.cats-qualification-missing-layer')
    assert not fixture.data.exists() and held.read_bytes() == fixture.content
    record = json.loads((fixture.root / 'injections/missing-layer.json').read_text())
    assert record['owned_repository_link_count'] == len(LINK_PATHS)
    fixture.args.phase = 'restore'
    qualification.quarantine(fixture.ctx, fixture.args)
    assert fixture.data.read_bytes() == fixture.content and not held.exists()
    assert all(path.read_text() == fixture.digest for path in links)
    assert unrelated.read_text() == 'sha256:' + 'c' * 64


@pytest.mark.parametrize('template', LINK_PATHS)
def test_shared_global_blob_is_rejected_before_any_quarantine(stored_fixture, monkeypatch, template):
    fixture = stored_fixture
    fixture.link(fixture.repository, LINK_PATHS[0])
    foreign = fixture.link('qualification/other-run/application', template)
    monkeypatch.setattr(qualification, 'fetch', lambda *args: pytest.fail('Sharing must be checked before network verification'))
    with pytest.raises(AssertionError, match='shared outside the exact qualification subtree'):
        qualification.quarantine(fixture.ctx, fixture.args)
    assert fixture.data.read_bytes() == fixture.content
    assert foreign.read_text() == fixture.digest
    assert not fixture.data.with_name('data.cats-qualification-missing-layer').exists()
    assert not (fixture.root / 'injections').exists()


def test_unreferenced_global_blob_cannot_be_quarantined(stored_fixture):
    fixture = stored_fixture
    with pytest.raises(AssertionError, match='no owned repository references'):
        qualification.quarantine(fixture.ctx, fixture.args)
    assert fixture.data.read_bytes() == fixture.content


def test_invalid_repository_link_prevents_global_quarantine(stored_fixture):
    fixture = stored_fixture
    fixture.link(fixture.repository, LINK_PATHS[0])
    malformed = fixture.link('qualification/other-run/application', LINK_PATHS[-1])
    malformed.write_bytes(b' ' * 257 + fixture.digest.encode('ascii'))
    with pytest.raises(AssertionError, match='Invalid registry repository link'):
        qualification.quarantine(fixture.ctx, fixture.args)
    assert fixture.data.read_bytes() == fixture.content
