"""Controlled VEX integration using identities grounded in retained installed metadata.
Positive statements here are test evidence, not real-corpus coverage claims.
"""
from copy import deepcopy
import json
from datetime import timedelta
import pytest
from app.vex_intelligence import configure_source, ingest_document, evaluate_batch, _VERIFIED
from app.container_intelligence import evaluate_container_batch
from app.package_identity_resolution import resolve_package_identity
from app.risk_profiles import score_observation, DEFAULT_POLICY
from test_vex_repository import db, raw
from test_package_identity_resolution import deb_identity, NOW

CVE = 'CVE-2026-12345'
URL = 'https://github.com/canonical/ubuntu-security-notices/blob/main/vex/cve/2026/CVE-2026-12345.json'

def statement(db, product, *, status='not_affected', url=URL, key='source', issued=NOW, withdrawn=False, digest=None):
    src = configure_source(db, 'Canonical test authority', trusted=True,
        trust_reason='Controlled test authority', authoritative_prefixes=['pkg:deb/ubuntu/'],
        allowed_hosts=['github.com', 'security-metadata.canonical.com'])
    payload = raw(status=status, key=key, product=product, issued=issued, withdrawn=withdrawn)
    if digest is not None:
        document = json.loads(payload)
        document['statements'][0]['products'][0]['digest'] = digest
        payload = json.dumps(document).encode()
    return ingest_document(db, src.id, payload, verification='tls', source_url=url, _proof=_VERIFIED)

def item(identity=None, **extra):
    observed = deepcopy(identity or deb_identity())
    return {'cve': CVE, 'context': observed['context'], 'identity': observed, **extra}

def source_pid(identity=None):
    result = resolve_package_identity(identity or deb_identity(), now=NOW)
    return next(c['context']['purl'] for c in result['candidates'] if c['relationship'] == 'installed_binary_to_source')

def test_source_identity_can_establish_exact_vex_without_overwriting_original(db):
    row = item(); original = deepcopy(row['identity'])
    statement(db, source_pid())
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'not_affected'
    assert result['direct_candidate_count'] == 0 and result['resolved_candidate_count'] == 1
    assert result['resolved_applicable_count'] == 1 and result['direct_applicable_count'] == 0
    assert row['context'] == original['context']
    assert row['identity']['resolution']['observed_identity'] == original
    assert result['statements'][0]['identity_kind'] == 'authoritative_resolved'
    # Re-evaluation does not recursively copy the previous explanation.
    evaluate_container_batch(db, [row], NOW)
    assert 'resolution' not in row['identity']['resolution']['observed_identity']

@pytest.mark.parametrize('change', [
    lambda p: p.replace('3.0.2-0ubuntu1.26', '3.0.2-0ubuntu1.25'),
    lambda p: p.replace('arch=source', 'arch=amd64'),
    lambda p: p.replace('distro=jammy', 'distro=noble'),
    lambda p: p.replace('/ubuntu/', '/debian/'),
    lambda p: p.replace('@3.0.2', '@1:3.0.2'),
])
def test_derived_identity_never_uses_nearby_version_arch_distro_vendor_or_epoch(db, change):
    statement(db, change(source_pid()))
    result = evaluate_container_batch(db, [item()], NOW)[0]
    assert result['status'] not in ('not_affected', 'fixed')
    assert result['resolved_applicable_count'] == 0

@pytest.mark.parametrize('url', [
    'https://github.com/other/ubuntu-security-notices/blob/main/vex/cve/2026/CVE-2026-12345.json',
    'https://github.com/canonical/other/blob/main/vex/cve/2026/CVE-2026-12345.json',
])
def test_publisher_scope_is_not_just_github_hostname(db, url):
    statement(db, source_pid(), url=url)
    result = evaluate_container_batch(db, [item()], NOW)[0]
    assert result['status'] == 'no_vex'
    assert result['rejected_candidates'][0]['reason'] == 'derived_publisher_scope_mismatch'

def test_direct_and_derived_disagreement_is_visible_and_cannot_lower_risk(db):
    row = item()
    statement(db, row['context']['purl'], status='affected', key='direct')
    statement(db, source_pid())
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'conflicting'
    assert 'direct_derived_conflict' in result['reasons']
    score = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex=result)
    reference = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex={'status':'affected'})
    assert score['uncertain'] and score['score'] >= reference['score']

@pytest.mark.parametrize('mode', ['withdrawn', 'conflicting_installed_architecture'])
def test_observed_tuple_or_published_vex_uncertainty_still_blocks_safe_conclusion(db, mode):
    row = item(); statement(db, row['context']['purl'], key='direct')
    if mode == 'conflicting_installed_architecture':
        row['identity']['sbom_artifact']['metadata']['architecture'] = 'arm64'
    else:
        statement(db, source_pid(), withdrawn=True)
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'under_investigation'


@pytest.mark.parametrize('mode', [
    'missing_codename', 'missing_source_version', 'source_conflict', 'stale', 'future',
    'unsupported_qualifier', 'package_digest', 'mutable_image', 'incomplete_first_record',
    'malformed_first_record', 'malformed_distro',
])
@pytest.mark.parametrize('status', ['not_affected', 'fixed'])
def test_source_failure_never_hides_another_verified_binary_conflict(db, mode, status):
    row = item()
    identity = row['identity']
    identity['scanner_artifact'] = deepcopy(identity['sbom_artifact'])
    identity['scanner_artifact']['metadata']['architecture'] = 'arm64'
    if mode == 'missing_codename':
        del identity['sbom_distro']['versionCodename']
    elif mode == 'missing_source_version':
        del identity['sbom_artifact']['metadata']['sourceVersion']
    elif mode == 'source_conflict':
        identity['sbom_artifact']['metadata']['source'] = 'other-source'
    elif mode == 'stale':
        identity['evidence_valid_until'] = (NOW-timedelta(seconds=1)).isoformat()
    elif mode == 'future':
        identity['observed_at'] = (NOW+timedelta(seconds=1)).isoformat()
    elif mode == 'unsupported_qualifier':
        product = row['context']['purl'] + '&repository_url=https%3A%2F%2Fexample.test'
        row['context'].update(purl=product, product_id=product)
        identity['raw_purl'] = product
        identity['sbom_artifact']['purl'] = identity['scanner_artifact']['purl'] = product
    elif mode == 'package_digest':
        row['context']['digest'] = 'sha256:' + 'b' * 64
    elif mode == 'mutable_image':
        identity['image_digest'] = 'mutable:tag'
    elif mode == 'incomplete_first_record':
        del identity['sbom_artifact']['foundBy']
    elif mode == 'malformed_first_record':
        identity['sbom_artifact']['locations'][0]['path'] = []
        identity['sbom_artifact']['locations'][0]['realPath'] = []
    elif mode == 'malformed_distro':
        identity['sbom_distro']['versionCodename'] = []
    statement(db, row['context']['purl'], key='direct', status=status, digest=row['context'].get('digest'))
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'under_investigation'
    assert 'installed_binary_metadata_conflict' in result['reasons']
    assert 'identity_resolution_uncertain' in result['reasons']
    assert result['resolved_applicable_count'] == 0
    score = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex=result)
    reference = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex={'status': 'affected'})
    assert score['uncertain'] and score['score'] >= reference['score']


@pytest.mark.parametrize('mode', ['source_conflict', 'source_version_conflict', 'stale', 'resolver_overflow'])
@pytest.mark.parametrize('status', ['not_affected', 'fixed'])
def test_direct_exact_match_survives_unusable_source_relationship(db, monkeypatch, mode, status):
    row = item(); statement(db, row['context']['purl'], key='direct', status=status)
    original = deepcopy(row['context'])
    if mode == 'source_conflict':
        row['identity']['sbom_artifact']['metadata']['source'] = 'conflicting-source'
    elif mode == 'source_version_conflict':
        row['identity']['scanner_artifact'] = deepcopy(row['identity']['sbom_artifact'])
        row['identity']['scanner_artifact']['metadata']['sourceVersion'] = '3.0.2-0ubuntu1.25'
    elif mode == 'stale':
        row['identity']['evidence_valid_until'] = (NOW-timedelta(seconds=1)).isoformat()
    else:
        from app import package_identity_resolution
        monkeypatch.setattr(package_identity_resolution, 'resolve_package_identity',
            lambda observed, now: resolve_package_identity(observed, now=now, max_candidates=1))
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == status
    assert result['direct_applicable_count'] == 1 and result['resolved_applicable_count'] == 0
    assert 'identity_resolution_uncertain' not in result['reasons']
    assert row['context'] == original
    assert row['identity']['resolution']['reasons']


@pytest.mark.parametrize('mode', ['source_conflict', 'stale'])
def test_unusable_relationship_cannot_apply_derived_safe_evidence(db, mode):
    row = item(); statement(db, source_pid())
    if mode == 'source_conflict':
        row['identity']['sbom_artifact']['metadata']['source'] = 'conflicting-source'
    else:
        row['identity']['evidence_valid_until'] = (NOW-timedelta(seconds=1)).isoformat()
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] not in ('not_affected', 'fixed')
    assert result['direct_applicable_count'] == 0 and result['resolved_applicable_count'] == 0
    score = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex=result)
    reference = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex={'status':'affected'})
    assert score['score'] >= reference['score']

def test_aliases_require_complete_applicability(db):
    statement(db, source_pid())
    result = evaluate_container_batch(db, [item(aliases=['CVE-2026-99999'])], NOW)[0]
    assert result['status'] == 'under_investigation'
    assert 'incomplete_alias_applicability' in result['reasons']

def test_fixed_keeps_original_observation_and_does_not_resolve_finding(db):
    row = item(); statement(db, source_pid(), status='fixed')
    before = deepcopy(row['context'])
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'fixed' and row['context'] == before
    assert score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex=result)['score'] > 0

@pytest.mark.parametrize('expiry', [(NOW-timedelta(days=1)).isoformat(), 'bad date'])
def test_internal_expired_candidate_defense_in_depth(db, expiry):
    row = item(); statement(db, row['context']['purl'], key='direct'); statement(db, source_pid())
    candidates = resolve_package_identity(row['identity'], now=NOW)['candidates']
    for c in candidates:
        if c['kind'] == 'authoritative_resolved': c['valid_until'] = expiry
    result = evaluate_batch(db, [row], NOW, diagnostics=True, identity_candidates=[candidates])[0]
    assert result['status'] == 'under_investigation' and 'stale_mapping' in result['reasons']

def test_expansion_overflow_is_conservative(db):
    row = item(); statement(db, row['context']['purl'], key='direct')
    candidate = resolve_package_identity(row['identity'], now=NOW)['candidates'][-1]
    candidates = [dict(candidate, context=dict(candidate['context'], purl=candidate['context']['purl']+str(n))) for n in range(9)]
    result = evaluate_batch(db, [row], NOW, diagnostics=True, identity_candidates=[candidates])[0]
    assert result['status'] == 'under_investigation' and 'identity_candidate_limit' in result['reasons']

def test_resolver_revision_invalidates_saved_assessments(db, monkeypatch):
    from app import risk_profiles, finding_classification, policy_data
    from app.risk_models import RiskAssessment
    from app.models import Service
    from app.package_identity_resolution import RESOLVER_VERSION
    svc=Service(name='identity',service_key='identity'); db.add(svc); db.flush()
    row=RiskAssessment(service_id=svc.id, as_of=NOW, valid_until=NOW+timedelta(days=1), provenance={}, summary={}, details=[])
    db.add(row); db.flush()
    monkeypatch.setattr(finding_classification, '_service_configuration', lambda *a: {})
    monkeypatch.setattr(finding_classification, 'status', lambda *a: ('current',0))
    monkeypatch.setattr(policy_data, 'intelligence_status', lambda: {})
    assert 'identity_resolver_changed' in risk_profiles.latest_assessment(db,svc.id,NOW)['stale_reasons']
    current=RiskAssessment(service_id=svc.id, as_of=NOW, valid_until=NOW+timedelta(days=1),
        provenance={'identity_resolver_version':RESOLVER_VERSION}, summary={}, details=[])
    db.add(current); db.flush()
    assert 'identity_resolver_changed' not in risk_profiles.latest_assessment(db,svc.id,NOW)['stale_reasons']


@pytest.mark.parametrize('bad_code', [{'bad': 'shape'}, ['jammy'], 1, 'invalid codename'])
@pytest.mark.parametrize('bad_key,other_key', [
    ('sbom_distro', 'scanner_distro'), ('scanner_distro', 'sbom_distro')])
@pytest.mark.parametrize('status', ['not_affected', 'fixed'])
def test_malformed_distro_does_not_hide_conflicting_direct_scope(db, bad_code, bad_key, other_key, status):
    row = item()
    row['identity'][bad_key] = {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': bad_code}
    row['identity'][other_key] = {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': 'noble'}
    statement(db, row['context']['purl'], status=status, key='direct')
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'under_investigation'
    assert 'identity_resolution_uncertain' in result['reasons']
    assert row['identity']['resolution']['reasons'] == ['distribution_codename_release_conflict']
    score = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex=result)
    reference = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex={'status':'affected'})
    assert score['score'] >= reference['score']


@pytest.mark.parametrize('bad_code', [{'bad': 'shape'}, ['jammy'], 1, 'invalid codename'])
@pytest.mark.parametrize('status', ['not_affected', 'fixed'])
def test_malformed_source_distro_without_contradiction_keeps_direct_match(db, bad_code, status):
    row = item()
    row['identity']['sbom_distro']['versionCodename'] = bad_code
    statement(db, row['context']['purl'], status=status, key='direct')
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == status
    assert result['direct_applicable_count'] == 1
    assert result['resolved_applicable_count'] == 0
    assert row['identity']['resolution']['reasons'] == ['invalid_distribution_codename']


@pytest.mark.parametrize('position', [0, 1])
@pytest.mark.parametrize('status', ['not_affected', 'fixed'])
def test_malformed_location_sibling_does_not_allow_direct_risk_lowering(db, position, status):
    row = item()
    artifact = row['identity']['sbom_artifact']
    artifact['locations'].insert(position, {'path': ['bad-shape'], 'annotations': {'evidence': 'primary'}})
    artifact['metadata']['architecture'] = 'arm64'
    statement(db, row['context']['purl'], status=status, key='direct')
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == 'under_investigation'
    assert row['identity']['resolution']['reasons'] == ['installed_binary_metadata_conflict']
    score = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex=result)
    reference = score_observation(DEFAULT_POLICY, severity='high', epss=.1, kev=False, vex={'status':'affected'})
    assert score['score'] >= reference['score']


@pytest.mark.parametrize('gap', ['binary_arch', 'binary_name', 'wrapper_name', 'distro_version', 'both_distro_versions', 'distro_codename'])
@pytest.mark.parametrize('status', ['not_affected', 'fixed'])
def test_incomplete_identity_metadata_without_contradiction_preserves_direct(db, gap, status):
    row = item()
    if gap == 'binary_arch':
        row['identity']['sbom_artifact']['metadata'].pop('architecture')
    elif gap == 'binary_name':
        row['identity']['sbom_artifact']['metadata'].pop('package')
    elif gap == 'wrapper_name':
        row['identity']['sbom_artifact'].pop('name')
    elif gap in ('distro_version', 'both_distro_versions'):
        row['identity']['sbom_distro'].pop('versionID')
        if gap == 'both_distro_versions':
            row['identity']['scanner_distro'].pop('version')
    else:
        # A direct codename PURL is still valid even when the retained source
        # mapping lacks the OS codename needed to independently derive it.
        purl = row['context']['purl'].replace('distro=ubuntu-22.04', 'distro=jammy')
        row['context'].update(purl=purl, product_id=purl, distro='jammy')
        row['identity']['sbom_artifact']['purl'] = purl
        row['identity']['sbom_distro']['versionCodename'] = ['bad-shape']
    statement(db, row['context']['purl'], status=status, key='direct')
    result = evaluate_container_batch(db, [row], NOW)[0]
    assert result['status'] == status
    assert result['direct_applicable_count'] == 1
    assert result['resolved_applicable_count'] == 0
    assert row['identity']['resolution']['outcome'] == 'insufficient_identity_evidence'
