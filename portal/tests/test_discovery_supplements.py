import hashlib
import io
import zipfile
from pathlib import Path
import pytest
from app.discovery_supplements import apply_supplements
from app.compose_ingestion import ComposeInputError


def item(source, target='.'):
    return dict(plaintext=source, target_path=target, source_id='a'*32,
                source_hash=hashlib.sha256(source.read_bytes()).hexdigest(),
                parent_job_id='parent', parent_inventory_id='inventory', parent_content_hash='1'*64)


def test_add_only_overlay_preserves_original_and_hashes(tmp_path):
    base=tmp_path/'base'; base.mkdir()
    (base/'original.yaml').write_text('original')
    source=tmp_path/'values.yaml'; source.write_text('image: nginx:1')
    result=apply_supplements(base, [item(source, 'chart')])
    assert (base/'original.yaml').read_text() == 'original'
    assert (base/'chart/values.yaml').read_text() == 'image: nginx:1'
    assert result[0]['parent_inventory_id'] == 'inventory'
    assert result[0]['files'] == [{'path':'chart/values.yaml', 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}]
    assert 'plaintext' not in result[0]
    with pytest.raises(ComposeInputError):
        apply_supplements(base, [item(source, 'chart')])


@pytest.mark.parametrize('name', ['../outside.yaml', '/absolute.yaml'])
def test_unsafe_archives_rejected(tmp_path, name):
    base=tmp_path/'base'; base.mkdir()
    source=tmp_path/'inputs.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr(name, 'image: nginx:1')
    with pytest.raises(ComposeInputError):
        apply_supplements(base, [item(source)])
    assert list(base.iterdir()) == []


def test_combined_limit_and_case_collision(tmp_path, monkeypatch):
    from app import compose_ingestion as compose
    base=tmp_path/'base'; base.mkdir()
    (base/'VALUES.YAML').write_text('original')
    source=tmp_path/'values.yaml'; source.write_text('new')
    with pytest.raises(ComposeInputError):
        apply_supplements(base, [item(source)])
    monkeypatch.setattr(compose, 'MAX_FILES', 1)
    with pytest.raises(ComposeInputError):
        apply_supplements(base, [item(source, 'other')])


def test_engine_rerenders_augmented_source_without_mutating_original(tmp_path):
    from app.discovery_engine import run_discovery
    source=tmp_path/'source'; source.mkdir()
    (source/'base.yaml').write_text('apiVersion: v1\nkind: Pod\nmetadata: {name: base}\nspec: {containers: [{name: base, image: nginx:1}]}\n')
    dependency=tmp_path/'dependency.yaml'
    dependency.write_text('apiVersion: v1\nkind: Pod\nmetadata: {name: dependency}\nspec: {containers: [{name: dependency, image: redis:7}]}\n')
    old=run_discovery(source)
    new=run_discovery(source, supplemental_inputs=[item(dependency)])
    assert {image['reference'] for image in old['images']} == {'nginx:1'}
    assert {image['reference'] for image in new['images']} == {'nginx:1', 'redis:7'}
    assert old['source_hash'] != new['source_hash']
    assert not (source/'dependency.yaml').exists()
    assert new['supplemental_provenance'][0]['parent_job_id'] == 'parent'


def test_remove_supplements_preserves_unrelated_sources(tmp_path):
    from app.discovery_supplements import remove_supplement_sources
    from types import SimpleNamespace
    folder=tmp_path/('a'*32); folder.mkdir()
    (folder/'values.yaml').write_text('ciphertext')
    unrelated=tmp_path/'other'; unrelated.write_text('keep')
    remove_supplement_sources(tmp_path, [SimpleNamespace(payload={'supplements':[
        {'source_id':'a'*32, 'filename':'values.yaml'},
        {'source_id':'a'*32, 'filename':'../../other'}]})])
    assert not (folder/'values.yaml').exists()
    assert unrelated.read_text() == 'keep'
