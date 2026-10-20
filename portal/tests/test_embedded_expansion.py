"""Explicit Canonical aliases and signed stream boundaries remain fail closed."""
import base64
from copy import deepcopy
import gzip
import hashlib
import json
import pytest
from app.embedded_intelligence import canonical
from app.embedded_payload import PayloadReader, payload_paths
from app.vex_intelligence import _parse
from test_embedded_intelligence import env, package, install, record


def usn():
    return {'@context':'https://openvex.dev/ns/v0.2.0',
        '@id':'https://github.com/canonical/ubuntu-security-notices/blob/main/vex/usn/USN-1234-1.json',
        'author':'Canonical Ltd.','timestamp':'2026-10-18T00:00:00Z','version':1,
        'statements':[{'vulnerability':{'name':'USN-1234-1','@id':'https://ubuntu.com/security/notices/USN-1234-1',
            'aliases':['CVE-2026-1234','CVE-2026-5678','CVE-2026-1234']},'status':'fixed',
            'products':[{'@id':'pkg:deb/ubuntu/example@1.2?arch=source&distro=noble'}]}]}


def test_usn_expands_only_explicit_unique_cves_and_preserves_original():
    raw=usn(); parsed=_parse(canonical(raw))
    assert parsed[0]==raw
    assert [row[0] for row in parsed[-1]]==['CVE-2026-1234','CVE-2026-5678']
    assert all(row[2]=='fixed' and row[1]['distro']=='noble' for row in parsed[-1])
    assert 'USN-1234-1'==parsed[0]['statements'][0]['vulnerability']['name']


@pytest.mark.parametrize('change',['author','url','status','no_alias','bad_alias','foreign_product'])
def test_usn_alias_adapter_rejects_unverified_relationships(change):
    doc=usn(); statement=doc['statements'][0]
    if change=='author':doc['author']='Other publisher'
    if change=='url':statement['vulnerability']['@id']='https://unrelated.test/USN-1234-1'
    if change=='status':statement['status']='not_affected'
    if change=='no_alias':statement['vulnerability']['aliases']=[]
    if change=='bad_alias':statement['vulnerability']['aliases']=['CVE-2026-1234','CVE-invalid']
    if change=='foreign_product':statement['products']=[{'@id':'pkg:rpm/redhat/example@1'}]
    with pytest.raises(ValueError):_parse(canonical(doc))


def test_primary_cve_does_not_fan_out_aliases():
    doc=usn();doc['statements'][0]['vulnerability']['name']='CVE-2026-1234'
    assert [row[0] for row in _parse(canonical(doc))[-1]]==['CVE-2026-1234']


def test_alias_expansion_limit_checked_before_materialization():
    doc=usn();doc['statements'][0]['products']*=5001
    with pytest.raises(ValueError,match='normalized statement count'):_parse(canonical(doc))


def shard(env,directory,split_at=1):
    path=directory/'intelligence.jsonl.gz';raw=path.read_bytes();path.unlink()
    blocks=[raw[:split_at],raw[split_at:]]
    manifest=json.loads((directory/'manifest.json').read_bytes());parts=[]
    for i,block in enumerate(blocks):
        name=f'intelligence.jsonl.gz.part{i:04d}';(directory/name).write_bytes(block)
        parts.append(dict(name=name,bytes=len(block),sha256=hashlib.sha256(block).hexdigest()))
    manifest['payload_parts']=parts
    (directory/'manifest.json').write_bytes(canonical(manifest))
    (directory/'manifest.sig').write_bytes(base64.b64encode(env[2].sign(canonical(manifest))))
    return manifest


def test_split_inside_gzip_header_imports_and_repeats(env):
    directory=package(env);manifest=shard(env,directory)
    with PayloadReader(payload_paths(directory,manifest)) as reader:
        assert reader.read(2)==b'\x1f\x8b'
        with pytest.raises(ValueError):reader.read(-1)
    assert install(env,directory)=='installed'
    assert install(env,directory)=='unchanged'


def test_corrupt_shard_rejected_without_import(env):
    directory=package(env);shard(env,directory)
    path=directory/'intelligence.jsonl.gz.part0001'
    raw=bytearray(path.read_bytes());raw[5]^=1;path.write_bytes(raw)
    assert install(env,directory)=='failed'


def test_shard_path_order_and_traversal_rejected(env):
    directory=package(env);manifest=shard(env,directory)
    manifest['payload_parts'][0]['name']='../outside.gz'
    with pytest.raises(ValueError,match='ordered payload'):payload_paths(directory,manifest)


def test_failed_import_can_retry_on_same_connection_pool(env):
    bad=record();bad['url']='https://wrong.test/feed'
    assert install(env,package(env,1,[bad]))=='failed'
    assert install(env,package(env,2))=='installed'
