"""Scanner observations must establish exact identity before VEX can reduce risk."""
from copy import deepcopy
from datetime import timedelta
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.container_intelligence import observation_identity, evaluate_container_batch
from app.vex_intelligence import ingest_document
from app.vex_models import VexDocument, VexStatement
from test_vex_repository import db, source, ingest, raw, NOW, PID

CVE = 'CVE-2026-12345'


def observation(purl=PID, version='1.0', **evidence):
    return SimpleNamespace(evidence={'purl': purl, **evidence},
                           installed_version=version, image_digest='sha256:image-manifest')


def evaluate_observation(db, observed, cve=CVE):
    identity = observation_identity(observed)
    item = {'cve': cve, 'aliases': identity['aliases'], 'context': identity['context'],
            'identity': identity}
    return identity, evaluate_container_batch(db, [item], NOW)[0]


def assert_unresolved(result):
    assert result['status'] not in ('not_affected', 'fixed')
    assert not any(statement['accepted'] for statement in result['statements'])


def test_exact_observation_retains_provenance_and_uses_package_not_image_digest(db):
    ingest(db, source(db), raw())
    observed = observation(
        scanner_distro={'id': 'wolfi', 'versionID': '20230201'},
        scanner_artifact={'id': 'scanner-123', 'type': 'apk', 'metadata': {'architecture': 'x86_64'}},
        scanner_source={'type': 'directory', 'target': '/scan/rootfs'},
        sbom_artifact={'id': 'scanner-123', 'metadata': {'originPackage': 'libtest-source'}},
        sbom_distro={'id': 'wolfi'}, sbom_source={'type': 'directory'},
        image_provenance={'imageID': 'sha256:image', 'architecture': 'amd64'})
    original = deepcopy(observed.evidence)
    identity, result = evaluate_observation(db, observed)
    assert result['status'] == 'not_affected'
    assert result['exact_candidate_count'] == 1 and result['cve_present'] is True
    assert identity['context']['purl'] == PID
    assert 'digest' not in identity['context']
    assert identity['image_digest'] == observed.image_digest
    for key in original.keys() - {'purl'}:
        assert identity[key] == original[key]
    assert observed.evidence == original


@pytest.mark.parametrize('changed', [
    PID.replace('@1.0', '@1.1'),
    PID.replace('/wolfi/', '/alpine/'),
    PID.replace('distro=wolfi', 'distro=alpine-3.20'),
    PID.replace('x86_64', 'aarch64'),
    PID.replace('x86_64', 'amd64'),
    PID.replace('libtest@', 'libtest-dev@'),
    PID.replace('pkg:apk/', 'pkg:deb/'),
    PID.replace('?arch=x86_64&distro=wolfi', '?distro=wolfi&arch=x86_64'),
    PID + '#usr/lib',
])
def test_similar_packages_never_match_exact_statement(db, changed):
    ingest(db, source(db), raw())
    identity, result = evaluate_observation(db, observation(changed, version=None))
    assert_unresolved(result)
    assert identity['raw_purl'] == changed
    assert result['exact_candidate_count'] == 0 and result['cve_present'] is True
    assert 'cve_present_without_exact_product' in result['reasons']
    assert result['rejected_candidates'][0]['sample_only'] is True
    assert result['rejected_candidates'][0]['reason'] == 'different_product_identity_sample'


@pytest.mark.parametrize('version,evidence', [
    ('1.1', {}), ('', {}), (1, {}),
    ('1.0', {'distro': 'alpine'}),
    ('1.0', {'distro': ''}),
    ('1.0', {'package_digest': 'sha256:unmatched-package'}),
])
def test_explicit_conflicting_identity_cannot_be_dropped(db, version, evidence):
    ingest(db, source(db), raw())
    _, result = evaluate_observation(db, observation(version=version, **evidence))
    assert_unresolved(result)
    if 'package_digest' not in evidence:
        assert result['applicability_state'] == 'missing_context'


def test_purl_version_is_sufficient_when_separate_version_absent(db):
    ingest(db, source(db), raw())
    identity, result = evaluate_observation(db, observation(version=None))
    assert identity['context']['version'] == '1.0'
    assert result['status'] == 'not_affected'


@pytest.mark.parametrize('purl', [None, 8, {}, '', 'https://example/libtest',
    'pkg:apk/wolfi/libtest', 'pkg:apk/wolfi/libtest@',
    ' pkg:apk/wolfi/libtest@1.0', 'pkg:apk/wolfi/lib test@1.0',
    'pkg:apk/wolfi/lib%20test@1.0', 'pkg:apk/wolfi/lib%00test@1.0',
    'pkg:apk/wolfi/../libtest@1.0', 'pkg:apk/wolfi/lib%GGtest@1.0',
    'pkg:apk/wolfi/lib%FFtest@1.0',
    'pkg:apk/wolfi/libtest@1.0?arch=x86_64&arch=aarch64',
    'pkg:apk/wolfi/libtest@1.0?arch=',
    'pkg:apk/wolfi/' + 'x' * 1500 + '@1.0'])
def test_missing_or_malformed_package_identity_fails_closed(db, purl):
    ingest(db, source(db), raw())
    identity, result = evaluate_observation(db, observation(purl, version=None))
    assert_unresolved(result)
    assert identity['reasons'] and not identity['context']
    assert result['applicability_state'] == 'missing_context'


@pytest.mark.parametrize('purl', [
    'pkg:apk/wolfi/libtest@1.0?arch=%FF',
    'pkg:apk/wolfi/libtest@1.0#../lib',
    'pkg:apk/wolfi/libtest%7F@1.0',
    'pkg:apk/wolfi/libtest@1.0%7F',
])
def test_malformed_exact_identifier_cannot_authorize_not_affected(db, purl):
    ingest(db, source(db), raw(product=purl))
    identity, result = evaluate_observation(db, observation(purl, version=None))
    assert_unresolved(result)
    assert identity['reasons']
    assert result['applicability_state'] == 'missing_context'


@pytest.mark.parametrize('purl', [None, PID.replace('libtest@', 'libtest-bin@')])
def test_source_binary_metadata_never_substitutes_package_identity(db, purl):
    ingest(db, source(db), raw())
    observed = observation(purl, scanner_artifact={'name': 'libtest-bin', 'metadata': {
        'source': 'libtest', 'sourceVersion': '1.0', 'sourceRpm': 'libtest-1.0.src.rpm',
        'originPackage': 'libtest'}}, sbom_artifact={'purl': PID, 'upstreams': [{'name': 'libtest', 'version': '1.0'}]})
    identity, result = evaluate_observation(db, observed)
    assert_unresolved(result)
    assert identity['scanner_artifact']['metadata']['source'] == 'libtest'
    assert identity['raw_purl'] == purl
    assert result['exact_candidate_count'] == 0


def test_ubuntu_codename_and_source_relationship_do_not_create_equivalence(db):
    statement = 'pkg:deb/ubuntu/openssl@3.0.2?distro=jammy'
    publisher = source(db)
    publisher.authoritative_prefixes = ['pkg:deb/ubuntu/']
    ingest(db, publisher, raw(product=statement))
    observed = observation('pkg:deb/ubuntu/libssl3@3.0.2?arch=amd64&distro=ubuntu-22.04', version='3.0.2',
        scanner_distro={'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': 'jammy'},
        sbom_artifact={'metadata': {'source': 'openssl', 'sourceVersion': '3.0.2', 'architecture': 'amd64'}})
    _, result = evaluate_observation(db, observed)
    assert_unresolved(result)
    assert result['cve_present'] is True and result['exact_candidate_count'] == 0


def test_scanner_cve_alias_only_enables_exact_product_and_never_rewrites_raw_id(db):
    ingest(db, source(db), raw())
    observed = observation(aliases=[CVE, CVE.lower(), 'GHSA-abcd-efgh-ijkl', 7])
    identity, result = evaluate_observation(db, observed, cve='GHSA-abcd-efgh-ijkl')
    assert result['status'] == 'not_affected'
    assert result['lookup_cves'] == [CVE]
    assert result['exact_candidate_count'] == 1
    assert observed.evidence['aliases'][0] == CVE
    observed.evidence['purl'] = PID.replace('x86_64', 'aarch64')
    _, mismatch = evaluate_observation(db, observed, cve='GHSA-abcd-efgh-ijkl')
    assert_unresolved(mismatch)
    assert mismatch['cve_present'] is True


@pytest.mark.parametrize('aliases', [None, CVE, {'id': CVE}, ['libtest'], ['CVE-not-valid'], [None, 1]])
def test_unusable_aliases_cannot_infer_a_cve(db, aliases):
    ingest(db, source(db), raw())
    _, result = evaluate_observation(db, observation(aliases=aliases), cve='GHSA-abcd-efgh-ijkl')
    assert_unresolved(result)
    assert result['cve_present'] is False
    assert 'cve_absent_from_vex' in result['reasons']


def test_alias_input_bound_does_not_create_unbounded_lookup(db):
    ingest(db, source(db), raw())
    _, result = evaluate_observation(db, observation(aliases=['GHSA-unknown'] * 8 + [CVE]), cve='GHSA-original')
    assert_unresolved(result)
    assert result['lookup_cves'] == ['GHSA-original']


def csaf_document():
    return {'document': {'category': 'csaf_vex', 'csaf_version': '2.0',
        'publisher': {'namespace': 'https://publisher.example'},
        'tracking': {'id': 'scoped', 'version': '1', 'current_release_date': NOW.isoformat()}},
        'product_tree': {'full_product_names': [
            {'product_id': 'package', 'name': 'Package', 'product_identification_helper': {'purl': PID}},
            {'product_id': 'platform', 'name': 'Platform', 'product_identification_helper': {'cpe': 'cpe:/o:vendor:platform:1'}}],
            'relationships': [{'category': 'default_component_of', 'product_reference': 'package',
                'relates_to_product_reference': 'platform',
                'full_product_name': {'product_id': 'combined', 'name': 'Package on platform'}}]},
        'vulnerabilities': [{'cve': CVE, 'product_status': {'known_not_affected': ['combined']}}]}


PRODUCT_CONTEXT = {'publisher': 'https://publisher.example', 'products': [{'cpe': 'cpe:/o:vendor:platform:1'}]}


@pytest.mark.parametrize('context', [None,
    {'publisher': 'https://other.example', 'products': [{'cpe': 'cpe:/o:vendor:platform:1'}]},
    {'publisher': 'https://publisher.example', 'products': [{'cpe': 'cpe:/o:vendor:platform:2'}]},
])
def test_csaf_product_scope_requires_explicit_exact_publisher_context(db, context):
    ingest(db, source(db), json.dumps(csaf_document()).encode())
    evidence = {'scanner_distro': {'id': 'platform', 'versionID': '1'},
                'image_provenance': {'labels': {'vendor': 'vendor', 'platform': '1'}},
                'scanner_artifact': {'cpes': ['cpe:/o:vendor:platform:1']}}
    if context is not None:
        evidence['csaf_product_context'] = context
    identity, result = evaluate_observation(db, observation(**evidence))
    assert_unresolved(result)
    assert result['exact_candidate_count'] == 1 and result['cve_present'] is True
    expected = 'missing_product_context' if context is None else 'product_context_mismatch'
    assert expected in result['rejected_candidates'][0]['reason']
    assert identity['context'].get('csaf_product_context') == context


def test_csaf_exact_explicit_product_context_matches(db):
    ingest(db, source(db), json.dumps(csaf_document()).encode())
    _, result = evaluate_observation(db, observation(csaf_product_context=PRODUCT_CONTEXT))
    assert result['status'] == 'not_affected'
    assert result['statements'][0]['accepted'] is True


@pytest.mark.parametrize('context', [[], {}, {'publisher': 'publisher', 'products': []},
    {'publisher': 'publisher', 'products': [{'name': 'Platform'}]},
    {'publisher': 'publisher', 'products': [None]},
    {'publisher': 'publisher', 'products': [{'cpe': 4}]},
    {'publisher': 'publisher', 'products': [{'cpe': 'x' * 1501}]},
    {'publisher': 'publisher', 'products': [{'cpe': 'cpe:/o:vendor:platform:1'}] * 33}])
def test_malformed_explicit_product_context_fails_closed(db, context):
    ingest(db, source(db), raw())
    identity, result = evaluate_observation(db, observation(csaf_product_context=context))
    assert_unresolved(result)
    assert identity['reasons'] == ['invalid_product_context']
    assert result['applicability_state'] == 'missing_context'


@pytest.mark.parametrize('condition,expected', [('stale', 'stale'), ('future', 'no_vex'),
    ('withdrawn', 'withdrawn'), ('disabled', 'unverified'), ('untrusted', 'unverified'),
    ('wrong_authority', 'unverified'), ('unverified', 'unverified')])
def test_exact_identity_does_not_override_trust_or_freshness(db, condition, expected):
    publisher = source(db)
    issued = NOW - timedelta(days=publisher.max_age_days + 1) if condition == 'stale' else NOW + timedelta(seconds=1) if condition == 'future' else NOW
    payload = raw(issued=issued, withdrawn=condition == 'withdrawn')
    if condition == 'unverified':
        ingest_document(db, publisher.id, payload)
    else:
        ingest(db, publisher, payload)
    if condition == 'disabled': publisher.enabled = False
    if condition == 'untrusted': publisher.trusted = False
    if condition == 'wrong_authority': publisher.authoritative_prefixes = ['pkg:apk/other/']
    db.flush()
    _, result = evaluate_observation(db, observation())
    assert_unresolved(result)
    assert result['status'] == expected
    assert result['exact_candidate_count'] == 1 and result['cve_present'] is True


def test_conflict_remains_unresolved_even_when_both_exact_candidates_are_accepted(db):
    ingest(db, source(db, 'safe'), raw())
    ingest(db, source(db, 'affected'), raw(status='affected'))
    _, result = evaluate_observation(db, observation())
    assert result['status'] == 'conflicting'
    assert result['applicability_state'] == 'conflicting'
    assert len(result['statements']) == 2
    assert all(statement['accepted'] for statement in result['statements'])


def test_current_safe_statement_with_stale_competitor_remains_under_investigation(db):
    ingest(db, source(db, 'current'), raw())
    old = source(db, 'old')
    ingest(db, old, raw(status='affected', issued=NOW - timedelta(days=old.max_age_days + 1)))
    _, result = evaluate_observation(db, observation())
    assert result['status'] == 'under_investigation'
    assert 'stale' in result['reasons']


def test_duplicate_ingestion_and_duplicate_aliases_count_one_candidate(db):
    publisher = source(db)
    first = ingest(db, publisher, raw())
    assert ingest(db, publisher, raw()).id == first.id
    assert db.scalar(select(func.count(VexDocument.id))) == 1
    assert db.scalar(select(func.count(VexStatement.id))) == 1
    _, result = evaluate_observation(db, observation(aliases=[CVE, CVE, CVE.lower()]))
    assert result['status'] == 'not_affected'
    assert result['exact_candidate_count'] == 1 and len(result['statements']) == 1


def test_unsupported_csaf_relationship_does_not_flatten_product_scope(db):
    document = csaf_document()
    document['product_tree']['relationships'][0]['category'] = 'vendor_custom_relation'
    ingest(db, source(db), json.dumps(document).encode())
    _, result = evaluate_observation(db, observation(csaf_product_context=PRODUCT_CONTEXT))
    assert_unresolved(result)
    assert result['exact_candidate_count'] == 0


def test_unsupported_document_format_cannot_install_a_safe_statement(db):
    payload = json.loads(raw())
    payload['@context'] = 'https://openvex.dev/ns/v99'
    with pytest.raises(ValueError, match='Unsupported VEX'):
        ingest(db, source(db), json.dumps(payload).encode())
    _, result = evaluate_observation(db, observation())
    assert_unresolved(result)
    assert result['cve_present'] is False


@pytest.mark.parametrize('alias_status,alias_product,expected', [
    (None, PID, 'under_investigation'),
    ('not_affected', PID.replace('x86_64', 'aarch64'), 'under_investigation'),
    ('fixed', PID, 'conflicting'),
    ('affected', PID, 'conflicting'),
    ('not_affected', PID, 'not_affected'),
])
def test_each_distinct_cve_alias_requires_its_own_consistent_applicability(db, alias_status, alias_product, expected):
    publisher = source(db)
    ingest(db, publisher, raw())
    alias_cve = 'CVE-2026-99999'
    if alias_status:
        payload = json.loads(raw(status=alias_status, key='alias', product=alias_product))
        payload['statements'][0]['vulnerability']['name'] = alias_cve
        ingest(db, publisher, json.dumps(payload).encode())
    _, result = evaluate_observation(db, observation(aliases=[alias_cve, CVE]))
    assert result['status'] == expected
    assert result['lookup_cves'] == sorted([CVE, alias_cve])
    if expected == 'under_investigation':
        assert 'incomplete_alias_applicability' in result['reasons']


RPM = 'pkg:rpm/redhat/dbus@1.12.20-8.el9?arch=x86_64&distro=rhel-9.6&epoch=1'
GO = 'pkg:golang/stdlib@1.24.11'


def test_rpm_epoch_representation_is_normalized_without_rewriting_raw_identity(db):
    publisher = source(db)
    publisher.authoritative_prefixes = ['pkg:rpm/redhat/']
    ingest(db, publisher, raw(product=RPM))
    observed = observation(RPM, version='1:1.12.20-8.el9')
    identity, result = evaluate_observation(db, observed)
    assert result['status'] == 'not_affected'
    assert identity['raw_purl'] == RPM and identity['context']['purl'] == RPM
    assert identity['context']['version'] == '1.12.20-8.el9'
    assert identity['raw_installed_version'] == '1:1.12.20-8.el9'
    assert identity['version_normalization'] == {'kind': 'rpm_epoch_qualifier',
        'raw': '1:1.12.20-8.el9', 'version': '1.12.20-8.el9', 'epoch': '1'}
    assert observed.installed_version == '1:1.12.20-8.el9'


@pytest.mark.parametrize('purl,version', [
    (RPM, '2:1.12.20-8.el9'), (RPM, '1:1.12.20-9.el9'),
    (RPM.replace('&epoch=1', ''), '1:1.12.20-8.el9'),
    (RPM.replace('epoch=1', 'epoch=01'), '1:1.12.20-8.el9'),
    (RPM.replace('pkg:rpm/', 'pkg:deb/'), '1:1.12.20-8.el9'),
    (RPM.replace('epoch=1', 'epoch=x'), 'x:1.12.20-8.el9'),
])
def test_rpm_epoch_equivalence_requires_exact_epoch_version_and_ecosystem(db, purl, version):
    publisher = source(db)
    publisher.authoritative_prefixes = ['pkg:rpm/redhat/', 'pkg:deb/redhat/']
    ingest(db, publisher, raw(product=purl))
    identity, result = evaluate_observation(db, observation(purl, version=version))
    assert_unresolved(result)
    assert identity['version_normalization'] is None
    assert identity['raw_installed_version'] == version


@pytest.mark.parametrize('evidence_key', ['scanner_artifact', 'sbom_artifact'])
def test_go_stdlib_prefix_requires_exact_raw_artifact_tuple(db, evidence_key):
    publisher = source(db)
    publisher.authoritative_prefixes = ['pkg:golang/']
    ingest(db, publisher, raw(product=GO))
    artifact = {'name': 'stdlib', 'type': 'go-module', 'purl': GO, 'version': 'go1.24.11'}
    observed = observation(GO, version='go1.24.11', **{evidence_key: artifact})
    identity, result = evaluate_observation(db, observed)
    assert result['status'] == 'not_affected'
    assert identity['context']['purl'] == GO
    assert identity['raw_installed_version'] == 'go1.24.11'
    assert identity['version_normalization'] == {'kind': 'go_stdlib_prefix',
        'raw': 'go1.24.11', 'version': '1.24.11', 'evidence': evidence_key}
    assert observed.installed_version == 'go1.24.11'


@pytest.mark.parametrize('change', ['missing', 'type', 'version', 'purl', 'name', 'module', 'ecosystem'])
def test_go_prefix_is_not_a_generic_version_equivalence(db, change):
    purl = GO.replace('stdlib', 'example.com/module') if change == 'module' else GO.replace('golang', 'generic') if change == 'ecosystem' else GO
    artifact = {'name': 'stdlib', 'type': 'go-module', 'purl': purl, 'version': 'go1.24.11'}
    if change in ('type', 'version', 'purl', 'name'):
        artifact[change] = 'different'
    if change == 'missing':
        artifact = None
    publisher = source(db)
    publisher.authoritative_prefixes = ['pkg:golang/', 'pkg:generic/']
    ingest(db, publisher, raw(product=purl))
    identity, result = evaluate_observation(db, observation(purl, version='go1.24.11', scanner_artifact=artifact))
    assert_unresolved(result)
    assert identity['version_normalization'] is None


@pytest.mark.parametrize('status,expected', [('not_affected', 'under_investigation'),
    ('fixed', 'under_investigation'), ('affected', 'affected')])
def test_alias_overflow_preserves_uncertainty_with_bounded_lookup(db, status, expected):
    ingest(db, source(db), raw(status=status))
    observed = observation(aliases=[CVE] * 8 + ['CVE-2026-99999'])
    identity, result = evaluate_observation(db, observed)
    assert identity['alias_overflow'] is True and identity['alias_count'] == 9
    assert len(identity['aliases']) == 8
    assert result['lookup_cves'] == [CVE]
    assert result['status'] == expected
    assert 'alias_limit' in result['reasons']
    assert len(observed.evidence['aliases']) == 9


def test_omitted_alias_prevents_claim_that_cve_is_absent(db):
    omitted = 'CVE-2026-99999'
    data = json.loads(raw())
    data['statements'][0]['vulnerability']['name'] = omitted
    ingest(db, source(db), json.dumps(data).encode())
    identity, result = evaluate_observation(db, observation(aliases=[CVE] * 8 + [omitted]))
    assert identity['alias_overflow'] is True
    assert result['status'] == 'no_vex'
    assert result['cve_present'] is None
    assert 'alias_limit' in result['reasons']
    assert 'cve_absent_from_vex' not in result['reasons']


@pytest.mark.parametrize('metadata', [{'alias_count': 1000, 'aliases_truncated': True},
    {'alias_count': 9}, {'aliases_truncated': True}])
def test_scanner_omitted_alias_evidence_cannot_clear_primary_cve(db, metadata):
    ingest(db, source(db), raw())
    identity, result = evaluate_observation(db, observation(aliases=None, **metadata))
    assert identity['alias_overflow'] is True
    assert result['lookup_cves'] == [CVE]
    assert result['status'] == 'under_investigation'
    assert 'alias_limit' in result['reasons']
