"""Immutable attestation routing and live revocation over cached objects."""
import base64
import io
import json

import pytest

from app import oci_attestations as attestations, oci_proxy as proxy
from test_oci_proxy import registry, setup, digest


@pytest.fixture
def attested(setup, monkeypatch):
    s = setup
    subject = 'registry.example/team/image@' + s.image
    receipt = dict(subject=subject, purpose='cyber-approval',
        predicate_type=attestations.PREDICATE_TYPES['cyber-approval'], evidence={'approval': 'sha256:' + 'e' * 64})
    statement = {'_type': 'https://in-toto.io/Statement/v1',
        'subject': [{'name': subject.rsplit('@', 1)[0], 'digest': {'sha256': s.image[7:]}}],
        'predicateType': receipt['predicate_type'],
        'predicate': dict(schemaVersion=1, subject=subject, purpose=receipt['purpose'], evidence=receipt['evidence'])}
    envelope = dict(payloadType='application/vnd.in-toto+json',
        payload=base64.b64encode(json.dumps(statement).encode()).decode(),
        signatures=[dict(keyid='', sig=base64.b64encode(b'transport-only-test-signature').decode())])
    payload, config = json.dumps(envelope).encode(), b'{}'
    blobs = {digest(payload): payload, digest(config): config}
    def descriptor(content, media):
        return dict(digest=digest(content), size=len(content), mediaType=media)
    document = dict(schemaVersion=2, mediaType='application/vnd.oci.image.manifest.v1+json',
        config=descriptor(config, 'application/vnd.oci.empty.v1+json'),
        layers=[descriptor(payload, attestations.ATTESTATION_TYPE)])
    raw = json.dumps(document).encode()
    s.attestation_digest, s.payload_digest = digest(raw), digest(payload)
    s.tag = s.image.replace(':', '-') + '.att'
    s.documents[s.attestation_digest] = raw
    # The tag deliberately points elsewhere: the signed immutable inventory wins.
    s.documents[s.tag] = b'unapproved mutable tag'
    s.inventory = dict(**descriptor(raw, document['mediaType']), tag=s.tag,
        blobs=sorted(blobs), receipts=[receipt])
    transport = proxy.client(None)
    transport.fetch_blob = lambda repo, identity, cache: cache.get(identity) or cache.store(identity, io.BytesIO(blobs[identity]))
    monkeypatch.setattr(proxy, 'client', lambda mapping: transport)
    monkeypatch.setattr(proxy.oci_attestation_inventory, 'inventory', lambda db, mapping, root, decision:
        s.inventory if root == s.image and decision.allowed else None)
    monkeypatch.setattr(proxy.oci_attestation_inventory, 'candidate_subjects', lambda db, mapping, identity:
        {s.image} if identity == s.attestation_digest else set())
    s.transport, s.blobs, s.statement, s.envelope, s.document = transport, blobs, statement, envelope, document
    return s


@pytest.mark.parametrize('first', ['tag', 'digest', 'referrers'])
def test_native_attestation_routes_use_signed_inventory_and_recheck_cached_revocation(attested, first):
    s = attested
    prefix = '/v2/project/image/'
    routes = dict(tag='manifests/' + s.tag, digest='manifests/' + s.attestation_digest,
                  referrers='referrers/' + s.image)
    response = s.client.get(prefix + routes[first])
    assert response.status_code == 200
    if first == 'referrers':
        assert response.json()['manifests'][0]['digest'] == s.attestation_digest
    else:
        assert response.headers['Docker-Content-Digest'] == s.attestation_digest
    assert ('team/image', s.tag) not in s.fetches
    assert s.client.head(prefix + routes['tag']).status_code == 200
    assert s.client.get(prefix + 'blobs/' + s.payload_digest).content == s.blobs[s.payload_digest]
    s.allowed.clear()
    for route in [*routes.values(), 'blobs/' + s.payload_digest]:
        assert s.client.get(prefix + route).status_code == 403


def test_changed_release_inventory_revokes_cached_attestation_even_with_same_subject(attested):
    s = attested
    prefix = '/v2/project/image/'
    assert s.client.get(prefix + 'manifests/' + s.tag).status_code == 200
    assert s.client.get(prefix + 'blobs/' + s.payload_digest).status_code == 200
    s.inventory = None
    for route in ('manifests/' + s.tag, 'manifests/' + s.attestation_digest, 'blobs/' + s.payload_digest):
        assert s.client.get(prefix + route).status_code == 403
    assert s.client.get(prefix + 'referrers/' + s.image).json()['manifests'] == []


def test_attestation_filter_and_unrelated_blob_are_scoped(attested):
    s = attested
    prefix = '/v2/project/image/'
    assert s.client.get(prefix + 'blobs/' + s.payload_digest).status_code == 403
    assert s.client.get(prefix + 'referrers/' + s.image, params={'artifactType': attestations.ATTESTATION_TYPE}).json()['manifests'][0]['digest'] == s.attestation_digest
    assert s.client.get(prefix + 'referrers/' + s.image, params={'artifactType': 'unknown/type'}).json()['manifests'] == []
    assert s.client.get('/v2/another/image/manifests/' + s.tag).status_code == 404


@pytest.mark.parametrize('tamper', ['subject', 'predicate', 'config', 'layer', 'incomplete'])
def test_attestation_transport_fails_closed_on_wrong_bound_or_incomplete_graph(attested, tamper):
    s = attested
    if tamper == 'subject':
        s.statement['subject'][0]['digest']['sha256'] = 'a' * 64
    elif tamper == 'predicate':
        s.statement['predicate']['subject'] = 'other.example/unapproved@' + s.image
    elif tamper == 'config':
        content = b'{"config":{"Cmd":["unapproved"]}}'
        s.document['config'].update(digest=digest(content), size=len(content))
        s.blobs[digest(content)] = content
    elif tamper == 'layer':
        s.document['layers'][0]['mediaType'] = 'application/octet-stream'
    else:
        s.inventory['receipts'].append(dict(s.inventory['receipts'][0], evidence={'missing': 'sha256:' + 'a' * 64}))
    if tamper in ('subject', 'predicate'):
        s.envelope['payload'] = base64.b64encode(json.dumps(s.statement).encode()).decode()
        payload = json.dumps(s.envelope).encode()
        s.document['layers'][0].update(digest=digest(payload), size=len(payload))
        s.blobs[digest(payload)] = payload
    raw = json.dumps(s.document).encode()
    s.attestation_digest = digest(raw)
    s.documents[s.attestation_digest] = raw
    s.inventory.update(digest=s.attestation_digest, size=len(raw),
        blobs=sorted({s.document['config']['digest'], *(item['digest'] for item in s.document['layers'])}))
    assert s.client.get('/v2/project/image/manifests/' + s.tag).status_code == 502


def test_revocation_during_attestation_fetch_denies_response(attested):
    s = attested
    original = s.transport.fetch_manifest
    def fetch(*args):
        result = original(*args)
        s.allowed.clear()
        return result
    s.transport.fetch_manifest = fetch
    assert s.client.get('/v2/project/image/manifests/' + s.tag).status_code == 403


def test_referrers_rechecks_inventory_after_same_subject_release_switch(attested):
    s = attested
    original = s.transport.fetch_manifest
    def fetch(*args):
        result = original(*args)
        if args[1] == s.attestation_digest:
            # The image remains authorized, but the successor release no longer
            # grants this attestation while its bytes are being retrieved.
            s.inventory = None
        return result
    s.transport.fetch_manifest = fetch
    assert s.client.get('/v2/project/image/referrers/' + s.image).status_code == 403
