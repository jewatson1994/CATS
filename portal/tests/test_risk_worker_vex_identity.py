"""Worker integration: package identity and containing-image identity stay separate."""
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import finding_classification as fc, policy_data
from app.database import Base
from app.models import Execution, Finding, FindingClassificationState, FindingObservation, Service
from app.risk_worker import refresh_assessment
from app.vex_intelligence import _VERIFIED, configure_source, ingest_document

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)
CVE = 'CVE-2026-12345'
VERSION = '3.0.2-0ubuntu1.15'
PURL = 'pkg:deb/ubuntu/openssl@' + VERSION + '?arch=amd64&distro=ubuntu-22.04'
IMAGE_DIGEST = 'sha256:' + 'a' * 64
PACKAGE_DIGEST = 'sha256:' + 'b' * 64
OTHER_DIGEST = 'sha256:' + 'c' * 64
OCI_PURL = 'pkg:oci/example/app@1'


@pytest.fixture
def assess(monkeypatch):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(name='container package scope', service_key='container-package-scope')
        db.add(service)
        db.flush()
        execution = Execution(service_id=service.id, execution_key='scan', scanned_at=NOW,
                              complete=True, raw_payload={})
        finding = Finding(service_id=service.id, cve=CVE, severity='high', first_seen=NOW,
                          episode_started=NOW, last_seen=NOW, active=True)
        db.add_all([execution, finding])
        db.flush()
        db.add(FindingClassificationState(service_id=service.id, algorithm=2,
                                          config_digest='test', findings=1))
        monkeypatch.setattr(fc, '_service_configuration', lambda *args: {})
        monkeypatch.setattr(fc, 'status', lambda *args: ('current', 0))
        monkeypatch.setattr(policy_data, 'risk_catalog_token', lambda: 'stable')
        feed = {'state': 'LOADED', 'metadata': {'score_date': NOW.isoformat(),
                                               'date_released': NOW.isoformat()}}
        monkeypatch.setattr(policy_data, 'review_intelligence_snapshot', lambda *args: {
            'kev': feed, 'epss': feed, 'findings': {CVE: {'epss': .1, 'kev': False}}})

        def run(product=None, *, purl=PURL, version=VERSION, image_digest=IMAGE_DIGEST,
                evidence_extra=None, purl_key='purl', finding_cve=CVE, vex_cves=(CVE,),
                vex_status='not_affected', intelligence=None, expected_uncertain=None):
            finding.cve = finding_cve
            if intelligence is not None:
                monkeypatch.setattr(policy_data, 'review_intelligence_snapshot', lambda requested, *args: {
                    'kev': feed, 'epss': feed,
                    'findings': {cve: intelligence.get(cve, {}) for cve in requested}})
            source = configure_source(db, 'Fixture publisher', allowed_hosts=['publisher.example'],
                                      trusted=True, trust_reason='Fixture package/image authority',
                                      authoritative_prefixes=['pkg:deb/ubuntu/', 'pkg:oci/example/'])
            document = {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'fixture-document',
                        'version': 1, 'timestamp': NOW.isoformat(), 'statements': [{
                            'vulnerability': {'name': cve}, 'products': [product or {'@id': PURL}],
                            'status': vex_status, 'justification': 'vulnerable_code_not_present'}
                            for cve in vex_cves]}
            ingest_document(db, source.id, json.dumps(document).encode(), verification='tls',
                            source_url='https://publisher.example/vex.json', _proof=_VERIFIED)
            evidence = {purl_key: purl, **(evidence_extra or {})}
            observation = FindingObservation(finding_id=finding.id, execution_id=execution.id,
                                             image='registry.example/app:1', image_digest=image_digest,
                                             package='openssl', installed_version=version, evidence=evidence)
            db.add(observation)
            db.commit()
            observation_id = observation.id
            assessment = refresh_assessment(db, service.id, NOW)
            result = assessment.details[0]['observations'][0]
            assert result['observation_id'] == observation_id
            assert result['image_digest'] == image_digest
            assert result['installed_version'] == version
            assert finding.active and finding.severity == 'high'
            assert assessment.provenance['scan_current']
            if expected_uncertain is None:
                expected_uncertain = result['vex']['status'] != 'not_affected'
            assert result['uncertain'] is expected_uncertain
            return result

        yield run
    engine.dispose()


@pytest.mark.parametrize('purl_key', ['purl', 'package_url'])
def test_container_image_digest_does_not_block_exact_vendor_package(assess, purl_key):
    result = assess(purl_key=purl_key)
    assert result['vex']['status'] == 'not_affected'
    identity = result['vex']['statements'][0]['identity']
    assert identity['purl'] == PURL
    assert identity['version'] == VERSION
    assert identity['distro'] == 'ubuntu-22.04'
    assert 'digest' not in identity
    assert 'Applicable trusted VEX not affected' in result['reasons']


@pytest.mark.parametrize('observed', [
    {'version': '3.0.2-0ubuntu1.16'},
    {'purl': PURL.replace('/openssl@', '/libssl@')},
    {'purl': PURL.replace('amd64', 'arm64')},
    {'purl': PURL.replace('ubuntu-22.04', 'ubuntu-24.04')},
    {'evidence_extra': {'distro': 'ubuntu-24.04'}},
    {'evidence_extra': {'package_digest': PACKAGE_DIGEST}},
    {'purl': None},
    {'purl': {'unexpected': 'object'}},
])
def test_worker_requires_exact_package_version_product_and_scope(assess, observed):
    result = assess(**observed)
    assert result['vex']['status'] == 'no_vex'
    assert result['vex']['statements'] == []
    assert 'Applicable trusted VEX not affected' not in result['reasons']


@pytest.mark.parametrize('package_digest, expected', [
    (PACKAGE_DIGEST, 'not_affected'),
    (None, 'no_vex'),
    (IMAGE_DIGEST, 'no_vex'),
    (OTHER_DIGEST, 'no_vex'),
])
def test_worker_uses_only_explicit_package_digest_for_package_assertion(assess, package_digest, expected):
    result = assess({'@id': PURL, 'digest': PACKAGE_DIGEST},
                    evidence_extra={'package_digest': package_digest})
    assert result['vex']['status'] == expected


@pytest.mark.parametrize('explicit_digest, expected', [
    (None, 'not_affected'),
    (PACKAGE_DIGEST, 'not_affected'),
    (OTHER_DIGEST, 'no_vex'),
])
def test_worker_retains_purl_digest_and_rejects_contradictory_evidence(assess, explicit_digest, expected):
    purl = PURL + '&digest=' + PACKAGE_DIGEST
    result = assess({'@id': purl}, purl=purl, evidence_extra={'package_digest': explicit_digest})
    assert result['vex']['status'] == expected


@pytest.mark.parametrize('observed_digest, expected', [
    (IMAGE_DIGEST, 'not_affected'),
    (OTHER_DIGEST, 'no_vex'),
    (None, 'no_vex'),
])
def test_worker_preserves_exact_oci_image_digest_boundary(assess, observed_digest, expected):
    result = assess({'@id': OCI_PURL, 'digest': IMAGE_DIGEST}, purl=OCI_PURL, version='1',
                    image_digest=observed_digest, evidence_extra={'package_digest': IMAGE_DIGEST})
    assert result['vex']['status'] == expected


def test_worker_rejects_oci_image_digest_contradicting_purl(assess):
    purl = OCI_PURL + '?digest=' + IMAGE_DIGEST
    result = assess({'@id': purl}, purl=purl, version='1', image_digest=OTHER_DIGEST)
    assert result['vex']['status'] == 'no_vex'


@pytest.mark.parametrize('checksum, expected', [(PACKAGE_DIGEST, 'not_affected'), (OTHER_DIGEST, 'no_vex')])
def test_worker_preserves_exact_checksum_qualifier_without_digest_aliasing(assess, checksum, expected):
    product = {'@id': PURL + '&checksum=' + PACKAGE_DIGEST}
    result = assess(product, purl=PURL + '&checksum=' + checksum)
    assert result['vex']['status'] == expected


ALIAS_CVE = 'CVE-2026-99999'


@pytest.mark.parametrize('alias_signal', [
    {'epss': None, 'kev': False}, {'epss': .2, 'kev': None}, {},
])
def test_worker_missing_alias_enrichment_cannot_reduce_risk(assess, alias_signal):
    result = assess(evidence_extra={'aliases': [ALIAS_CVE]}, vex_cves=(CVE, ALIAS_CVE),
        intelligence={CVE: {'epss': .1, 'kev': False}, ALIAS_CVE: alias_signal},
        expected_uncertain=True)
    assert result['vex']['status'] == 'not_affected'
    assert result['score'] >= 75 and result['band'] == 'high'
    assert 'Applicable trusted VEX not affected' not in result['reasons']
    assert 'Uncertainty floor applied' in result['reasons']


@pytest.mark.parametrize('alias_kev', [False, True])
def test_worker_complete_alias_enrichment_uses_worst_signals(assess, alias_kev):
    result = assess(evidence_extra={'aliases': [ALIAS_CVE]}, vex_cves=(CVE, ALIAS_CVE),
        intelligence={CVE: {'epss': .1, 'kev': False}, ALIAS_CVE: {'epss': .9, 'kev': alias_kev}},
        expected_uncertain=False)
    assert result['vex']['status'] == 'not_affected'
    assert result['epss'] == .9 and result['kev'] is alias_kev
    assert result['score'] == (95 if alias_kev else 19.62)


def test_worker_ghsa_requires_enrichment_only_for_its_mapped_cves(assess):
    result = assess(finding_cve='GHSA-abcd-efgh-ijkl', evidence_extra={'aliases': [CVE]},
        intelligence={CVE: {'epss': .1, 'kev': False}}, expected_uncertain=False)
    assert result['vex']['lookup_cves'] == [CVE]
    assert result['vex']['status'] == 'not_affected'
    assert result['kev'] is False and result['epss'] == .1
    assert result['score'] == 16.62


@pytest.mark.parametrize('evidence', [
    {'aliases': [CVE] * 8 + [ALIAS_CVE]},
    {'aliases': [CVE], 'alias_count': 9, 'aliases_truncated': True},
])
def test_worker_alias_overflow_remains_uncertain_with_affected_vex(assess, evidence):
    result = assess(evidence_extra=evidence, vex_status='affected',
        intelligence={CVE: {'epss': .1, 'kev': False}}, expected_uncertain=True)
    assert result['vex']['status'] == 'affected'
    assert result['identity']['alias_overflow']
    assert result['kev'] is None
    assert result['score'] == 76.5
    assert 'Uncertainty floor applied' in result['reasons']
