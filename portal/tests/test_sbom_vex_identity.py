"""Both VEX consumers use the same conservative retained-identity adapter."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select, update, delete

from app.container_intelligence import observation_identities, identity_source_generation
from app import native_vex as nv
from app.native_vex_models import VexDispositionService, VexObservationDisposition, VexDispositionPolicy
from app.models import FindingClassificationState, SbomComponent
from app.risk_models import RiskAssessment
from app.risk_worker import refresh_assessment
from app.risk_profiles import latest_assessment
from app.sbom_components import retain_components
from test_native_vex import db, setup, enable, excluded, NOW
from test_risk_worker_vex_identity import assess, PURL, VERSION, IMAGE_DIGEST


def observed(purl=None, version=None, **evidence):
    return SimpleNamespace(evidence={'purl': purl, **evidence}, installed_version=version,
        image_digest=IMAGE_DIGEST, image='registry.example/app:1', execution_id=12)


def binding(purl=PURL, version=VERSION, **changes):
    return {'status': 'matched', 'reasons': [], 'component_id': 42,
        'evidence': {'purl': purl}, 'installed_version': version, 'image_digest': IMAGE_DIGEST,
        'provenance': {'execution_id': 12, 'component_ref': 'artifact-1',
            'binding_kind': 'component_id', 'image': 'registry.example/app:1',
            'image_digest': IMAGE_DIGEST}, **changes}


def recover_with(monkeypatch, result):
    from app import sbom_components
    calls = []
    def recover(db, observations):
        calls.append(observations)
        return [deepcopy(result) for _ in observations]
    monkeypatch.setattr(sbom_components, 'recover_identities', recover)
    return calls


def test_complete_scanner_identity_never_queries_retained_inventory(monkeypatch):
    calls = recover_with(monkeypatch, binding(status='conflict'))
    identity = observation_identities(None, [observed(PURL, VERSION)])[0]
    assert identity['context']['purl'] == PURL
    assert 'sbom_binding' not in identity and not calls


@pytest.mark.parametrize('purl,version,evidence', [
    (PURL, VERSION + 'wrong', {}),
    (PURL, VERSION, {'distro': 'another-distribution'}),
    ('pkg:deb/ubuntu/invalid%GG@1', '1', {}),
    (123, VERSION, {}),
])
def test_explicit_scanner_contradictions_are_not_repaired(monkeypatch, purl, version, evidence):
    calls = recover_with(monkeypatch, binding())
    identity = observation_identities(None, [observed(purl, version, **evidence)])[0]
    assert not identity['context'] and identity['reasons']
    assert not calls


def test_exact_binding_fills_missing_identity_and_retains_scanner_evidence(monkeypatch):
    calls = recover_with(monkeypatch, binding())
    observation = observed(component_id='artifact-1', aliases=['CVE-2026-12345'],
        scanner_artifact={'id': 'artifact-1', 'metadata': {'note': 'original'}})
    before = deepcopy(observation.evidence)
    identity = observation_identities(None, [observation])[0]
    assert len(calls) == 1 and calls[0] == [observation]
    assert identity['context']['purl'] == PURL and identity['raw_installed_version'] == VERSION
    assert identity['raw_purl'] is None and identity['scanner_identity']['raw_purl'] is None
    assert identity['scanner_identity']['raw_installed_version'] is None
    assert identity['sbom_binding']['status'] == 'matched'
    assert identity['sbom_binding']['component_id'] == 42
    assert identity['scanner_identity']['component_id'] == 'artifact-1'
    assert identity['scanner_artifact'] == before['scanner_artifact']
    assert identity['aliases'] == before['aliases'] and observation.evidence == before


@pytest.mark.parametrize('status', ['missing', 'ambiguous', 'conflict', 'scope_missing'])
def test_failed_binding_is_visible_and_cannot_supply_identity(monkeypatch, status):
    recover_with(monkeypatch, binding(status=status, reasons=['sbom_' + status]))
    identity = observation_identities(None, [observed(component_id='artifact-1')])[0]
    assert not identity['context']
    assert identity['sbom_binding']['status'] == status
    assert 'sbom_' + status in identity['reasons']
    assert identity['scanner_identity']['raw_purl'] is None


def test_batch_recovery_only_includes_incomplete_observations(monkeypatch):
    calls = recover_with(monkeypatch, binding())
    complete, incomplete = observed(PURL, VERSION), observed(component_id='artifact-1')
    identities = observation_identities(None, [complete, incomplete, complete])
    assert calls == [[incomplete]]
    assert [identity['context']['purl'] for identity in identities] == [PURL] * 3
    assert ['sbom_binding' in identity for identity in identities] == [False, True, False]


def test_native_consumer_retains_recovered_identity_and_original_evidence(db, monkeypatch):
    service, finding, observations, source = setup(db)
    observation = observations[0]
    original_purl = observation.evidence['purl']
    observation.evidence = {'component_id': 'artifact-1'}
    db.commit()
    recover_with(monkeypatch, binding(purl=original_purl, version='1.0'))
    enable(db)
    result = nv.evaluate_service(db, service.id, now=NOW)
    db.commit()
    assert result.summary['excluded_observations'] == 1
    assert excluded(db, finding)
    retained = db.scalar(select(VexObservationDisposition).where(
        VexObservationDisposition.evaluation_id == result.id)).evidence
    assert retained['identity']['sbom_binding']['status'] == 'matched'
    assert retained['identity']['scanner_identity']['raw_purl'] is None
    assert retained['identity']['context']['purl'] == original_purl
    assert retained['identity']['resolution']['resolver_version'].endswith('/v2')
    assert observation.evidence == {'component_id': 'artifact-1'}


def test_informational_risk_uses_the_same_recovery_adapter(assess, monkeypatch):
    recover_with(monkeypatch, binding())
    result = assess(purl=None, evidence_extra={'component_id': 'artifact-1'})
    assert result['vex']['status'] == 'not_affected'
    assert result['identity']['context']['purl'] == PURL
    assert result['identity']['scanner_identity']['raw_purl'] is None
    assert result['identity']['sbom_binding']['status'] == 'matched'


def test_identity_generation_is_independent_of_native_policy_enabled(db):
    service, finding, observations, source = setup(db)
    before = identity_source_generation(db, service.id)
    db.execute(update(VexDispositionService).where(VexDispositionService.service_id == service.id)
        .values(generation=VexDispositionService.generation + 1))
    assert identity_source_generation(db, service.id) == before + 1


def retained_setup(db):
    service, finding, observations, source = setup(db)
    observation = observations[0]
    purl = observation.evidence['purl']
    observation.evidence = {'component_id': 'artifact-1', 'sbom_digest': 'sha256:' + 'd' * 64,
        'image_platform': 'linux/amd64'}
    observation.image_digest = IMAGE_DIGEST
    retain_components(db, observation.execution_id, [{
        'component_id': 'artifact-1', 'name': observation.package, 'version': observation.installed_version,
        'purl': purl, 'image': observation.image, 'image_digest': IMAGE_DIGEST,
        'image_manifest_digest': IMAGE_DIGEST, 'image_platform': 'linux/amd64',
        'sbom_digest': 'sha256:' + 'd' * 64, 'sbom_format': 'syft-json'}])
    db.commit()
    return service, finding, observation, source


def prepare_risk(db, service, finding, monkeypatch, now=NOW):
    from app import finding_classification as fc, policy_data
    db.add(FindingClassificationState(service_id=service.id, algorithm=2,
        config_digest='test', findings=1))
    db.commit()
    monkeypatch.setattr(fc, '_service_configuration', lambda *args: {})
    monkeypatch.setattr(fc, 'status', lambda *args: ('current', 0))
    monkeypatch.setattr(policy_data, 'risk_catalog_token', lambda: 'stable')
    feed = {'state': 'LOADED', 'metadata': {'score_date': now.isoformat(), 'date_released': now.isoformat()}}
    monkeypatch.setattr(policy_data, 'review_intelligence_snapshot', lambda *args: {
        'kev': feed, 'epss': feed, 'findings': {finding.cve: {'epss': .1, 'kev': False}}})
    monkeypatch.setattr(policy_data, 'intelligence_status', lambda: {'kev': feed, 'epss': feed})


def test_real_retained_binding_drives_both_consumers_without_changing_scanner_rows(db, monkeypatch):
    service, finding, observation, source = retained_setup(db)
    original = deepcopy(observation.evidence)
    prepare_risk(db, service, finding, monkeypatch)
    native = nv.evaluate_service(db, service.id, now=NOW)
    risk = refresh_assessment(db, service.id, NOW)
    native_evidence = db.scalar(select(VexObservationDisposition).where(
        VexObservationDisposition.evaluation_id == native.id)).evidence
    risk_evidence = risk.details[0]['observations'][0]
    assert native.summary['excluded_observations'] == 1
    assert risk_evidence['vex']['status'] == 'not_affected'
    for identity in (native_evidence['identity'], risk_evidence['identity']):
        assert identity['sbom_binding']['status'] == 'matched'
        assert identity['sbom_binding']['provenance']['binding_kind'] == 'exact_component_id'
        assert identity['scanner_identity']['raw_purl'] is None
        assert identity['raw_purl'] is None
        assert identity['resolution']['observed_identity']['sbom_binding']['status'] == 'matched'
    assert observation.evidence == original and finding.active and finding.severity == 'critical'


def test_reporter_null_artifact_placeholders_recover_through_both_consumers(db, monkeypatch):
    service, finding, observation, source = retained_setup(db)
    row = db.scalar(select(SbomComponent))
    artifact = {'id': 'artifact-1', 'name': observation.package, 'version': observation.installed_version,
        'purl': row.data['purl'], 'type': 'apk', 'language': '', 'metadataType': 'apk-db-entry',
        'foundBy': 'apk-db-cataloger', 'metadata': {'package': observation.package, 'architecture': 'x86_64'}}
    row.data = {**row.data, 'sbom_artifact': json.dumps(artifact)}
    # report-to-portal.sh constructs these keys even when Grype omits them.
    observation.evidence = {**observation.evidence, 'purl': None, 'scanner_artifact': {
        'id': 'artifact-1', 'name': observation.package, 'version': observation.installed_version,
        'purl': None, 'type': 'apk', 'language': None, 'metadataType': None,
        'foundBy': None, 'metadata': None}}
    db.commit()
    original = deepcopy(observation.evidence)
    prepare_risk(db, service, finding, monkeypatch)
    native = nv.evaluate_service(db, service.id, now=NOW)
    risk = refresh_assessment(db, service.id, NOW)
    native_evidence = db.scalar(select(VexObservationDisposition).where(
        VexObservationDisposition.evaluation_id == native.id)).evidence
    assert native.summary['excluded_observations'] == 1
    assert risk.details[0]['observations'][0]['vex']['status'] == 'not_affected'
    for identity in (native_evidence['identity'], risk.details[0]['observations'][0]['identity']):
        assert identity['sbom_binding']['status'] == 'matched'
        assert identity['scanner_artifact'] == original['scanner_artifact']
        assert identity['scanner_identity']['scanner_artifact'] == original['scanner_artifact']
        assert identity['sbom_artifact'] == artifact
    assert observation.evidence == original


def test_recovered_apk_distro_conflict_cannot_authorize_direct_exclusion(db, monkeypatch):
    service, finding, observation, source = retained_setup(db)
    row = db.scalar(select(SbomComponent))
    row.data = {**row.data, 'sbom_distro': json.dumps({'id': 'wolfi', 'versionID': '3.20'})}
    observation.evidence = {**observation.evidence, 'scanner_distro': {'name': 'alpine', 'version': '3.20'}}
    db.commit()
    original = deepcopy(observation.evidence)
    prepare_risk(db, service, finding, monkeypatch)
    native = nv.evaluate_service(db, service.id, now=NOW)
    risk = refresh_assessment(db, service.id, NOW)
    native_evidence = db.scalar(select(VexObservationDisposition).where(
        VexObservationDisposition.evaluation_id == native.id)).evidence
    risk_evidence = risk.details[0]['observations'][0]
    assert native.summary['excluded_observations'] == 0
    assert risk_evidence['vex']['status'] == 'no_vex'
    for identity in (native_evidence['identity'], risk_evidence['identity']):
        assert identity['sbom_binding']['status'] == 'conflict'
        assert identity['sbom_binding']['reasons'] == ['sbom_scanner_metadata_conflict']
        assert not identity['context']
    assert observation.evidence == original


@pytest.mark.parametrize('structured', [True, False])
def test_recovered_source_relationship_requires_installed_metadata_in_both_consumers(db, monkeypatch, structured):
    from test_package_identity_resolution import deb_identity, NOW as observed_at
    from test_package_identity_vex import statement, source_pid
    from app.models import Execution
    service, finding, observations, source = setup(db)
    observation = observations[0]
    identity = deb_identity()
    artifact = identity['sbom_artifact']
    observation.package = artifact['name']
    observation.installed_version = artifact['version']
    observation.image_digest = identity['image_digest']
    observation.evidence = {'component_id': artifact['id'], 'sbom_digest': 'sha256:' + 'd' * 64,
        'image_platform': 'linux/amd64'}
    db.get(Execution, observation.execution_id).scanned_at = observed_at
    component = {
        'component_id': artifact['id'], 'name': artifact['name'], 'version': artifact['version'],
        'purl': artifact['purl'], 'image': observation.image, 'image_digest': identity['image_digest'],
        'image_manifest_digest': identity['image_digest'], 'image_platform': 'linux/amd64',
        'sbom_digest': 'sha256:' + 'd' * 64, 'sbom_format': 'syft-json',
        'source_name': artifact['metadata']['source'], 'source_version': artifact['version']}
    if structured:
        component.update({field: json.dumps(identity[field]) for field in (
            'sbom_artifact', 'sbom_distro', 'sbom_descriptor')})
    retain_components(db, observation.execution_id, [component])
    statement(db, source_pid(identity))
    db.commit()
    prepare_risk(db, service, finding, monkeypatch, observed_at)
    native = nv.evaluate_service(db, service.id, now=observed_at)
    risk = refresh_assessment(db, service.id, observed_at)
    native_evidence = db.scalar(select(VexObservationDisposition).where(
        VexObservationDisposition.evaluation_id == native.id)).evidence
    for evidence in (native_evidence, risk.details[0]['observations'][0]['vex']):
        assert evidence['status'] == ('not_affected' if structured else 'no_vex')
        assert evidence['direct_applicable_count'] == 0
        assert evidence['resolved_applicable_count'] == int(structured)
        if structured:
            assert evidence['statements'][0]['identity_kind'] == 'authoritative_resolved'
    assert native.summary['excluded_observations'] == int(structured)


@pytest.mark.parametrize('mutation', ['update', 'delete'])
def test_component_mutation_stales_informational_risk_while_native_policy_disabled(db, monkeypatch, mutation):
    from app.remediation_jobs import native_vex_token
    service, finding, observation, source = retained_setup(db)
    prepare_risk(db, service, finding, monkeypatch)
    assert not db.get(VexDispositionPolicy, 1).enabled
    assessment = refresh_assessment(db, service.id, NOW)
    db.commit()
    assert not latest_assessment(db, service.id, NOW)['stale']
    before = native_vex_token(db, service.id, NOW)
    row = db.scalar(select(SbomComponent))
    if mutation == 'update':
        db.execute(update(SbomComponent).where(SbomComponent.id == row.id).values(
            data={**row.data, 'version': 'wrong-version'}))
    else:
        db.execute(delete(SbomComponent).where(SbomComponent.id == row.id))
    assert native_vex_token(db, service.id, NOW) == before
    report = latest_assessment(db, service.id, NOW)
    assert report['stale'] and 'identity_source_changed' in report['stale_reasons']
    assert report['id'] == assessment.id


@pytest.mark.parametrize('consumer', ['risk', 'native'])
def test_component_change_during_evaluation_cannot_publish(db, monkeypatch, consumer):
    service, finding, observation, source = retained_setup(db)
    prepare_risk(db, service, finding, monkeypatch)
    changed = False
    def mutate():
        nonlocal changed
        if not changed:
            db.execute(delete(SbomComponent))
            changed = True
    with pytest.raises(ValueError, match='changed'):
        if consumer == 'risk':
            refresh_assessment(db, service.id, NOW, check=mutate)
        else:
            nv.evaluate_service(db, service.id, now=NOW, check=mutate)
    db.rollback()
    assert db.scalar(select(RiskAssessment)) is None
    assert not excluded(db, finding)
