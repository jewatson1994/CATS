"""Verifier helper checks use small declared fixtures; acceptance runs use the real package."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.intelligence_models import IntelligenceRecord
from app.vex_models import VexSource, VexDocument, VexStatement

spec = importlib.util.spec_from_file_location('verify_embedded', Path(__file__).resolve().parents[2] / 'scripts/verify-embedded-intelligence.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


@pytest.mark.parametrize('purl,expected', [
    ('pkg:npm/@scope/example@1.2.3?arch=x#src', ('npm', ('@scope',), 'example')),
    ('pkg:npm/%40scope/example', ('npm', ('@scope',), 'example')),
    ('pkg:maven/org.apache/name@2.0', ('maven', ('org.apache',), 'name')),
    ('pkg:rpm/redhat/lib%40name@0:1.2-1?arch=x', ('rpm', ('redhat',), 'lib@name')),
    ('pkg:pypi/example', ('pypi', (), 'example')),
    ('opaque:example', None), ('pkg:', None), ('pkg:npm/', None)])
def test_package_name_preserves_decoded_namespace_and_name(purl, expected):
    assert verify.package_name(purl) == expected


@pytest.fixture
def database():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        meta = []
        for index, (key, name, cve, purl, scope) in enumerate([
            ('ubuntu-vex', 'Canonical Ubuntu VEX', 'CVE-2026-1000', 'pkg:deb/ubuntu/example@1?distro=noble', {'distro': 'noble'}),
            ('redhat-vex', 'Red Hat CSAF VEX', 'CVE-1999-0710', 'pkg:rpm/redhat/squid@2.5.STABLE3-6.3E.13?arch=i386&epoch=7',
                {'csaf_product_context': {'publisher': 'https://www.redhat.com', 'products': [{'cpe': 'cpe:/o:redhat:enterprise_linux:3::as'}]}}),
            ('suse-vex', 'SUSE CSAF VEX', 'CVE-2015-4588', 'pkg:rpm/suse/libwmf@0_2-7?upstream=libwmf-0:0_2-7.src.rpm',
                {'csaf_product_context': {'publisher': 'https://www.suse.com/', 'products': [{'cpe': 'cpe:/o:suse:sled:15:sp3'}]}}),
        ]):
            source = VexSource(name=name, enabled=True, trusted=True, max_age_days=30,
                               allowed_hosts=['example.test'], authoritative_prefixes=[purl.split('@')[0]])
            db.add(source); db.flush()
            issued = NOW - timedelta(days=100 if index == 1 else 1)
            document = VexDocument(source_id=source.id, sha256='document-' + key, raw_text='{}', format='fixture',
                document_key=key, version='1', issued_at=issued, source_url='https://example.test/' + key,
                verification='tls', withdrawn=False)
            db.add(document); db.flush()
            from app.vex_intelligence import _identity
            identity = dict(_identity({'id': purl}), **scope)
            for repeat in range(2 if index == 0 else 1):
                db.add(VexStatement(document_id=document.id, cve=cve, product_id=purl, identity=identity, status='fixed'))
            meta.append({'id': key, 'name': name, 'acquired_at': NOW.isoformat()})
        db.add(IntelligenceRecord(source_id=source.id, kind='advisory', record_id='test', cve='CVE-2015-4588',
            product='publisher-local-id', data={}, sha256='advisory', acquired_at=NOW,
            source_url='https://example.test/a', package_version='test'))
        db.commit()
        yield db, {'sources': meta}
    engine.dispose()


def test_exact_counts_distinguish_rows_pairs_and_package_names(database):
    db, _ = database
    result = verify.database_coverage(db, NOW)
    assert result['totals']['statements'] == 4
    assert result['totals']['unique_vex_cve_product_pairs'] == 3
    assert result['totals']['unique_cves_across_all_categories'] == 3
    assert result['totals']['unique_product_ids_across_all_categories'] == 4
    assert result['totals']['unique_package_names'] == 3
    assert result['totals']['versioned_purl_statements'] == 4
    assert result['totals']['versioned_csaf_context_statements'] == 2
    assert result['totals']['versioned_distro_statements'] == 2
    assert result['totals']['statuses'] == {'fixed': 4}
    ubuntu = next(source for source in result['by_source'] if source['name'] == 'Canonical Ubuntu VEX')
    assert ubuntu['statements'] == 2
    assert ubuntu['unique_cve_product_pairs'] == 1
    assert result['freshness_as_of'] == NOW.isoformat()
    assert result['totals']['freshness_identity_eligible_statements'] == 3
    assert result['totals']['freshness_identity_eligible_statuses'] == {'fixed': 3}
    assert result['totals']['freshness_identity_eligible_csaf_context_statements'] == 1
    assert result['totals']['freshness_identity_eligible_distro_statements'] == 2
    assert ubuntu['freshness_identity_eligible_statements'] == 2


def test_scoped_examples_keep_stale_now_separate_from_historical_match(database):
    db, manifest = database
    result = verify.scoped_lookup_examples(db, manifest, NOW)
    assert result['redhat-vex']['current']['status'] == 'stale'
    assert not result['redhat-vex']['current_fresh_match']
    assert result['redhat-vex']['selection']['mode'] == 'historical_seed_fallback'
    assert not result['redhat-vex']['selection']['selected_statement_current_usable']
    assert result['redhat-vex']['source_as_of']['result']['status'] == 'fixed'
    for example in result.values():
        assert example['wrong_context']['current']['status'] == 'no_vex'
        assert example['wrong_context']['source_as_of']['status'] == 'no_vex'
        assert example['wrong_purl']['status'] == 'no_vex'
    assert result['ubuntu-vex']['current_fresh_match']
    assert result['suse-vex']['current_fresh_match']
    assert result['ubuntu-vex']['selection']['mode'] == 'current_fresh'
    assert result['suse-vex']['selection']['mode'] == 'current_fresh'


def test_wrong_scope_preserves_original_identity():
    original = {'purl': 'pkg:rpm/suse/example@1', 'csaf_product_context': {'publisher': 'suse', 'products': [{'cpe': 'original'}]}}
    changed, _ = verify.wrong_scope(original)
    assert changed['purl'] == original['purl']
    assert original['csaf_product_context']['products'] == [{'cpe': 'original'}]
    assert changed['csaf_product_context'] != original['csaf_product_context']


@pytest.mark.parametrize('scenario,expected', [
    ('fresh', 1), ('at-expiry', 0), ('stale', 0), ('future', 0),
    ('disabled', 0), ('untrusted', 0), ('withdrawn', 0), ('unverified', 0),
    ('changed-tls-host', 0), ('valid-signature', 1), ('rotated-key', 0),
    ('outside-authority', 0), ('unversioned', 0)])
def test_freshness_identity_rows_require_all_individual_preconditions(database, scenario, expected):
    import hashlib
    db, _ = database
    source = VexSource(name='eligibility-' + scenario, enabled=scenario != 'disabled', trusted=scenario != 'untrusted',
                       max_age_days=30, allowed_hosts=['example.test'], public_key='current-public-key',
                       authoritative_prefixes=['pkg:deb/ubuntu/'])
    db.add(source); db.flush()
    days = {'at-expiry': 30, 'stale': 31, 'future': -1}.get(scenario, 1)
    issued = NOW - timedelta(days=days)
    verification = 'signature' if scenario in ('valid-signature', 'rotated-key') else 'unverified' if scenario == 'unverified' else 'tls'
    verification_key = hashlib.sha256(('old-public-key' if scenario == 'rotated-key' else source.public_key).encode()).hexdigest()
    document = VexDocument(source_id=source.id, sha256='eligibility-' + scenario, raw_text='{}', format='fixture',
        document_key=scenario, version='1', issued_at=issued, verification=verification,
        verification_key=verification_key, withdrawn=scenario == 'withdrawn',
        source_url='https://' + ('previous.example.test' if scenario == 'changed-tls-host' else 'example.test') + '/document')
    db.add(document); db.flush()
    purl = 'pkg:deb/' + ('other' if scenario == 'outside-authority' else 'ubuntu') + '/example'
    identity = {'purl': purl}
    if scenario != 'unversioned':
        purl += '@1'
        identity.update(purl=purl, version='1')
    db.add(VexStatement(document_id=document.id, cve='CVE-2026-1001', product_id=purl,
                        identity=identity, status='affected'))
    db.commit()
    result = verify.freshness_identity_coverage(db, [source], NOW)[source.id]
    assert result['freshness_identity_eligible_statements'] == expected
    assert result['freshness_identity_eligible_statuses'] == ({'affected': 1} if expected else {})


def add_redhat_candidate(db, scenario='fresh'):
    import hashlib
    from copy import deepcopy
    from sqlalchemy import select
    source = db.scalar(select(VexSource).where(VexSource.name == 'Red Hat CSAF VEX'))
    source.public_key = 'current-test-key'
    original = db.scalar(select(VexStatement).join(VexDocument).where(VexDocument.source_id == source.id))
    identity = deepcopy(original.identity)
    purl = original.product_id
    days = {'stale': 31, 'at-expiry': 30, 'future': -1}.get(scenario, 1)
    document = VexDocument(source_id=source.id, sha256='candidate-' + scenario, raw_text='{}', format='fixture',
        document_key='candidate-' + scenario, version='1', issued_at=NOW-timedelta(days=days),
        source_url='https://' + ('old.example.test' if scenario == 'changed-host' else 'example.test') + '/candidate',
        verification='unverified' if scenario == 'unverified' else 'signature' if scenario in ('signature', 'rotated-key') else 'tls',
        verification_key=hashlib.sha256(('old-key' if scenario == 'rotated-key' else source.public_key).encode()).hexdigest(),
        withdrawn=scenario == 'withdrawn')
    db.add(document); db.flush()
    if scenario == 'outside-authority':
        purl = purl.replace('/redhat/', '/different/')
        identity['purl'] = purl
    if scenario == 'unversioned':
        identity.pop('version')
    if scenario == 'no-context':
        identity.pop('csaf_product_context')
    statement = VexStatement(document_id=document.id, cve='CVE-2026-2000', product_id=purl,
                             identity=identity, status='fixed')
    db.add(statement)
    if scenario == 'conflicting':
        db.add(VexStatement(document_id=document.id, cve=statement.cve, product_id=purl,
                            identity=identity, status='affected'))
    if scenario == 'superseded':
        db.add(VexDocument(source_id=source.id, sha256='candidate-new-revision', raw_text='{}', format='fixture',
            document_key=document.document_key, version='2', issued_at=NOW-timedelta(hours=12),
            source_url=document.source_url, verification='tls', withdrawn=True))
    db.commit()
    return source, document, statement


@pytest.mark.parametrize('scenario', ['fresh', 'signature'])
def test_scoped_examples_prefer_current_usable_candidate_over_historical_seed(database, scenario):
    db, manifest = database
    _, document, statement = add_redhat_candidate(db, scenario)
    result = verify.scoped_lookup_examples(db, manifest, NOW)['redhat-vex']
    assert result['cve'] == statement.cve
    assert result['document_id'] == document.id
    assert result['selection']['mode'] == 'current_fresh'
    assert result['selection']['selected_statement_current_usable']
    assert result['current_fresh_match']
    assert result['current']['status'] == 'fixed'
    assert result['wrong_context']['current']['status'] == 'no_vex'
    assert result['wrong_context']['source_as_of']['status'] == 'no_vex'
    assert result['wrong_purl']['status'] == 'no_vex'


@pytest.mark.parametrize('scenario', ['stale', 'at-expiry', 'future', 'withdrawn', 'unverified',
    'changed-host', 'rotated-key', 'outside-authority', 'unversioned', 'no-context', 'conflicting', 'superseded'])
def test_scoped_examples_do_not_label_ineligible_or_unresolved_candidates_fresh(database, scenario):
    db, manifest = database
    add_redhat_candidate(db, scenario)
    result = verify.scoped_lookup_examples(db, manifest, NOW)['redhat-vex']
    assert result['cve'] == 'CVE-1999-0710'
    assert result['selection']['mode'] == 'historical_seed_fallback'
    assert not result['selection']['selected_statement_current_usable']
    assert not result['current_fresh_match']


@pytest.mark.parametrize('flag', ['enabled', 'trusted'])
def test_scoped_examples_require_current_source_trust_and_enablement(database, flag):
    db, manifest = database
    source, _, _ = add_redhat_candidate(db)
    setattr(source, flag, False)
    db.commit()
    with pytest.raises(RuntimeError, match='active trusted authority'):
        verify.scoped_lookup_examples(db, manifest, NOW)


def test_scoped_examples_report_bounded_document_fallback_without_absence_claim(database, monkeypatch):
    db, manifest = database
    add_redhat_candidate(db, 'fresh')
    add_redhat_candidate(db, 'unverified')
    monkeypatch.setattr(verify, 'FRESH_EXAMPLE_DOCUMENT_LIMIT', 1)
    result = verify.scoped_lookup_examples(db, manifest, NOW)['redhat-vex']
    assert result['selection']['mode'] == 'historical_seed_fallback'
    assert result['selection']['fresh_documents_examined'] == 1
    assert result['selection']['fresh_statements_evaluated'] == 0
    assert 'not an exhaustive claim' in result['selection']['scope']


def test_scoped_examples_obey_candidate_evaluation_bound(database, monkeypatch):
    db, manifest = database
    add_redhat_candidate(db, 'conflicting')
    monkeypatch.setattr(verify, 'EXAMPLE_STATEMENT_LIMIT', 1)
    result = verify.scoped_lookup_examples(db, manifest, NOW)['redhat-vex']
    assert result['selection']['mode'] == 'historical_seed_fallback'
    assert result['selection']['fresh_statements_evaluated'] == 1
