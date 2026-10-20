"""Repository contracts: strict ingestion, independent trust and offline verification."""
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from app.database import Base
from app.vex_models import VexDocument, VexStatement
from app.vex_intelligence import configure_source, ingest_document, evaluate, evaluate_batch, intelligence_token, _VERIFIED
from app.vex_snapshot import export_snapshot, import_snapshot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
PID = 'pkg:apk/wolfi/libtest@1.0?arch=x86_64&distro=wolfi'
CTX = {'purl': PID, 'version': '1.0', 'distro': 'wolfi'}

def raw(status='not_affected', key='doc', issued=NOW, product=PID, **extra):
    return json.dumps({'@context': 'https://openvex.dev/ns/v0.2.0', '@id': key, 'version': 1,
                       'timestamp': issued.isoformat(), 'statements': [{'vulnerability': {'name': 'CVE-2026-12345'},
                       'products': [{'@id': product}], 'status': status, 'justification': 'vulnerable_code_not_present'}], **extra}).encode()

@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()

def source(db, name='publisher'):
    public = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return configure_source(db, name, public_key=public, trusted=True, trust_reason='Test publisher authority', authoritative_prefixes=['pkg:apk/wolfi/'])

def ingest(db, src, payload):
    return ingest_document(db, src.id, payload, verification='signature', _proof=_VERIFIED)

def test_unverified_and_forged_verification(db):
    s = source(db)
    ingest_document(db, s.id, raw())
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'unverified'
    with pytest.raises(ValueError, match='Verification'):
        ingest_document(db, s.id, raw(), verification='signature')

def test_exact_matching_scopes_and_dedupe(db):
    s = source(db)
    a = ingest(db, s, raw())
    assert ingest(db, s, raw()).id == a.id
    assert db.scalar(select(func.count(VexStatement.id))) == 1
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'not_affected'
    for ctx in ({}, {'package': 'libtest', 'version': '1.0'}, {**CTX, 'version': '2.0'}, {**CTX, 'distro': 'alpine'}, {**CTX, 'digest': 'sha256:123'}, {**CTX, 'purl': PID.replace('x86_64', 'aarch64')}):
        assert evaluate(db, 'CVE-2026-12345', ctx, NOW)['status'] == 'no_vex'
    token = intelligence_token(db)
    s.authoritative_prefixes = ['pkg:apk/other/']
    db.flush()
    assert intelligence_token(db) != token
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'unverified'

def test_stale_conflict_and_withdrawn(db):
    s = source(db)
    ingest(db, s, raw(issued=NOW-timedelta(days=31)))
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'stale'
    ingest(db, s, raw(issued=NOW))
    ingest(db, source(db, 'other'), raw('affected'))
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'conflicting'
    assert evaluate_batch(db, [{'cve': 'CVE-2026-12345', 'context': CTX}], NOW)[0]['valid_until']
    ingest(db, s, raw(issued=NOW+timedelta(seconds=1), withdrawn=True))
    result = evaluate(db, 'CVE-2026-12345', CTX, NOW+timedelta(seconds=2))
    assert result['status'] == 'affected'
    assert 'withdrawn' in result['reasons']

def test_strict_json_and_versionless(db):
    s = source(db)
    for payload in (b'{"x":1,"x":2}', b'[]', b'{}', b'{"x":NaN}', b'x'*4194305):
        with pytest.raises(ValueError):
            ingest_document(db, s.id, payload)
    ingest(db, s, raw(product='pkg:apk/wolfi/libtest'))
    assert evaluate(db, 'CVE-2026-12345', {'purl': 'pkg:apk/wolfi/libtest'}, NOW)['status'] == 'no_vex'

def test_signed_snapshot_tamper_atomic_and_scope(db):
    signing = Ed25519PrivateKey.generate()
    private = signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    s = source(db)
    s.public_key = public
    ingest(db, s, raw())
    payload = export_snapshot(db, s.id, private)
    assert import_snapshot(db, s.id, payload)['count'] == 1
    assert db.scalar(select(func.count(VexDocument.id))) == 1
    envelope = json.loads(payload)
    envelope['manifest']['documents'][0]['raw'] += 'x'
    with pytest.raises(ValueError, match='signature'):
        import_snapshot(db, s.id, json.dumps(envelope).encode())
    s.authoritative_prefixes = ['pkg:apk/other/']
    with pytest.raises(ValueError, match='scope'):
        import_snapshot(db, s.id, payload)
    assert db.scalar(select(func.count(VexDocument.id))) == 1

def test_official_fixtures_parse(db):
    s = configure_source(db, 'examples')
    root = Path(__file__).parent / 'fixtures' / 'vex'
    for name in ('openvex-official-fixed.json', 'csaf-official-example.json', 'redhat-cve-2024-3094.json'):
        document = ingest_document(db, s.id, (root / name).read_bytes())
        assert document.format in ('openvex', 'csaf')


def test_fetch_rejects_nonpublic_dns_and_scope(db, monkeypatch):
    from app.vex_intelligence import sync_source_document
    s = source(db)
    s.allowed_hosts = ['publisher.example']
    monkeypatch.setattr('socket.getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('127.0.0.1', 443))])
    with pytest.raises(ValueError, match='nonpublic'):
        sync_source_document(db, s.id, 'https://publisher.example/vex.json')
    for url in ('http://publisher.example/vex', 'https://evil.example/vex', 'https://user:pass@publisher.example/vex', 'https://publisher.example:444/vex'):
        with pytest.raises(ValueError, match='scope'):
            sync_source_document(db, s.id, url)


def test_snapshot_prevalidation_and_wrong_key(db):
    import base64
    import hashlib
    from app.vex_snapshot import _canonical
    signing = Ed25519PrivateKey.generate()
    s = source(db)
    s.public_key = signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    valid, invalid = raw(), b'{}'
    manifest = {'schema': 'cats-vex-snapshot/v1', 'source': s.name, 'allowed_hosts': [], 'authoritative_prefixes': s.authoritative_prefixes,
                'documents': [{'raw': base64.b64encode(d).decode(), 'sha256': hashlib.sha256(d).hexdigest()} for d in (valid, invalid)]}
    envelope = {'manifest': manifest, 'signature': base64.b64encode(signing.sign(_canonical(manifest))).decode()}
    with pytest.raises(ValueError):
        import_snapshot(db, s.id, _canonical(envelope))
    assert db.scalar(select(func.count(VexDocument.id))) == 0
    manifest['documents'].pop()
    envelope['signature'] = base64.b64encode(signing.sign(_canonical(manifest))).decode()
    assert import_snapshot(db, s.id, _canonical(envelope))['count'] == 1
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'not_affected'
    s.public_key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'unverified'
    with pytest.raises(ValueError, match='signature'):
        import_snapshot(db, s.id, _canonical(envelope))


def test_fetch_conditionals_and_redirect_no_follow(db, monkeypatch):
    from app.vex_intelligence import sync_source_document
    import urllib3
    s = source(db)
    s.allowed_hosts = ['publisher.example']
    monkeypatch.setattr('socket.getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('8.8.8.8', 443))])
    class Response:
        status = 200
        headers = {'ETag': 'v1'}
        def __init__(self):
            self.body = raw()
        def read(self, *a, **k):
            body, self.body = self.body, b''
            return body
        def close(self):
            pass
    calls = []
    response = Response()
    class Pool:
        def __init__(self, *a, **kwargs):
            assert a[0] == '8.8.8.8'
            assert kwargs['assert_hostname'] == 'publisher.example'
            assert kwargs['server_hostname'] == 'publisher.example'
        def urlopen(self, *a, **kwargs):
            assert kwargs['redirect'] is False
            calls.append(kwargs)
            return response
        def close(self):
            pass
    monkeypatch.setattr(urllib3, 'HTTPSConnectionPool', Pool)
    assert sync_source_document(db, s.id, 'https://publisher.example/vex')['status'] == 'ingested'
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'not_affected'
    response.status = 304
    assert sync_source_document(db, s.id, 'https://publisher.example/vex')['status'] == 'not_modified'
    assert calls[-1]['headers']['If-None-Match'] == 'v1'
    response.status = 302
    with pytest.raises(ValueError, match='HTTP 302'):
        sync_source_document(db, s.id, 'https://publisher.example/vex')

def test_revision_immutable(db):
    s = source(db)
    doc = ingest(db, s, raw())
    db.commit()
    doc.raw_text = '{}'
    with pytest.raises(ValueError, match='immutable'):
        db.flush()
    db.rollback()

@pytest.mark.parametrize('changes', [{'name': None}, {'name': ' '}, {'name': 'x'*201}, {'trusted': 'false'}, {'enabled': 1}, {'max_age_days': True}, {'max_age_days': '30'}, {'allowed_hosts': 'example.com'}, {'allowed_hosts': [None]}, {'allowed_hosts': ['*.example.com']}, {'authoritative_prefixes': [1]}, {'public_key': 'not a public key'}, {'trust_reason': 1}])
def test_source_rejects_malformed_configuration(db, changes):
    with pytest.raises(ValueError):
        configure_source(db, **{'name': 'test', **changes})

def test_source_disable_and_health(db):
    from app.vex_intelligence import list_sources
    s = configure_source(db, 'disabled', enabled=False)
    assert not s.enabled and list_sources(db)[0]['health'] == 'disabled'
    with pytest.raises(ValueError, match='disabled'):
        ingest_document(db, s.id, raw())

def test_explicit_document_version_requires_observed_version(db):
    s = source(db)
    document = json.loads(raw(product='pkg:apk/wolfi/libtest'))
    document['statements'][0]['products'][0]['version'] = '1.0'
    ingest(db, s, json.dumps(document).encode())
    assert evaluate(db, 'CVE-2026-12345', {'purl': 'pkg:apk/wolfi/libtest'}, NOW)['status'] == 'no_vex'
    assert evaluate(db, 'CVE-2026-12345', {'purl': 'pkg:apk/wolfi/libtest', 'version': '1.0'}, NOW)['status'] == 'not_affected'

def test_stale_affected_evidence_prevents_safe_reduction(db):
    ingest(db, source(db, 'one'), raw('affected', issued=NOW-timedelta(days=31)))
    ingest(db, source(db, 'two'), raw('not_affected'))
    result = evaluate(db, 'CVE-2026-12345', CTX, NOW)
    assert result['status'] == 'under_investigation'
    assert 'stale' in result['reasons']

@pytest.mark.parametrize('envelope', [{}, {'manifest': []}, {'manifest': {}, 'signature': []}])
def test_snapshot_malformed_envelope_is_validation_error(db, envelope):
    s = source(db)
    with pytest.raises(ValueError):
        import_snapshot(db, s.id, json.dumps(envelope).encode())

def test_csaf_duplicate_product_identity_rejected(db):
    s = source(db)
    product = {'product_id': 'p', 'name': 'label', 'product_identification_helper': {'purl': PID}}
    document = {'document': {'category': 'csaf_vex', 'csaf_version': '2.0', 'tracking': {'id': 'doc', 'version': '1', 'current_release_date': NOW.isoformat()}},
                'product_tree': {'full_product_names': [product, product]}, 'vulnerabilities': []}
    with pytest.raises(ValueError, match='Duplicate CSAF'):
        ingest_document(db, s.id, json.dumps(document).encode())


def test_revision_bulk_sql_is_immutable(db):
    from sqlalchemy import update
    doc = ingest(db, source(db), raw())
    db.commit()
    with pytest.raises(Exception, match='immutable'):
        db.execute(update(VexDocument).where(VexDocument.id == doc.id).values(raw_text='{}'))
    db.rollback()
    assert db.get(VexDocument, doc.id).raw_text != '{}'


def test_assessment_defers_raw_vendor_documents(db):
    from sqlalchemy import event
    src = source(db)
    ingest(db, src, raw())
    db.expire_all()
    queries = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)
    event.listen(db.bind, 'before_cursor_execute', capture)
    try:
        assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'not_affected'
    finally:
        event.remove(db.bind, 'before_cursor_execute', capture)
    assert queries
    assert all('raw_text' not in sql for sql in queries)


def test_assessment_history_bound_never_returns_partial_safe_conclusion(db, monkeypatch):
    monkeypatch.setattr('app.vex_intelligence.MAX_EVALUATION_CANDIDATES', 2)
    src = source(db)
    for index in range(2):
        ingest(db, src, raw(key=f'doc-{index}'))
    assert evaluate(db, 'CVE-2026-12345', CTX, NOW)['status'] == 'not_affected'
    ingest(db, src, raw('affected', key='third'))
    result = evaluate(db, 'CVE-2026-12345', CTX, NOW)
    assert result == {'status': 'under_investigation', 'statements': [],
                      'valid_until': None, 'reasons': ['candidate_limit']}


def test_assessment_pairs_do_not_load_unrequested_cross_products(db, monkeypatch):
    monkeypatch.setattr('app.vex_intelligence.MAX_EVALUATION_CANDIDATES', 1)
    src = source(db)
    ingest(db, src, raw())
    other = PID.replace('libtest', 'other')
    payload = json.loads(raw(product=other))
    payload['statements'][0]['vulnerability']['name'] = 'CVE-2026-54321'
    ingest(db, src, json.dumps(payload).encode())
    results = evaluate_batch(db, [
        {'cve': 'CVE-2026-12345', 'context': {**CTX, 'purl': other}},
        {'cve': 'CVE-2026-54321', 'context': CTX}], NOW)
    assert [item['status'] for item in results] == ['no_vex', 'no_vex']
