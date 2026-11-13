"""Full CATS keeps publisher-owned evidence distinct from local assessment work."""
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import main, models as m, finding_classification as classification, native_vex, service_posture
from app.activity_queries import service_activity_page
from app.portable_release_capture import capture
from app.replica_import import reconcile
from app.replica_models import ReplicaEvidenceRecord, ReplicaRelease, ReplicaServiceState
from app.replica_views import actor_labels
from app.service_evidence import current_execution, current_execution_id_query
from test_replica_import import replica_import, verified
from test_replica_evidence_api import seed_rich_evidence


@pytest.fixture
def mixed(replica_import, monkeypatch):
    f = replica_import
    monkeypatch.setenv('CATS_MODE', 'full')
    seed_rich_evidence(f)
    state = capture(f.origin, f.service, {'source_execution_id': f.execution.id})
    incoming = verified(f)
    incoming['state'] = state
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    f.imported = f.db.get(m.Service, result['service_id'])
    f.local = f.db.get(m.Service, 51)
    f.release = f.db.get(ReplicaRelease, result['release_id'])
    f.local_execution = m.Execution(service_id=f.local.id, execution_key='local-scan',
        scanned_at=f.now + timedelta(days=1), complete=True, raw_payload={})
    f.db.add(f.local_execution)
    f.db.commit()
    return f


def test_mixed_correlated_scan_selection_never_falls_back_after_imported_state_loss(mixed):
    f = mixed
    signed_id = f.db.get(ReplicaServiceState, f.imported.id).active_execution_id
    query = select(m.Service.id, current_execution_id_query(m.Service).correlate(m.Service).scalar_subquery())
    assert dict(f.db.execute(query).all()) == {f.local.id: f.local_execution.id, f.imported.id: signed_id}
    f.db.delete(f.db.get(ReplicaServiceState, f.imported.id))
    f.db.commit()
    assert current_execution(f.db, f.imported) is None
    assert current_execution(f.db, f.local).id == f.local_execution.id


def test_full_mode_keeps_imported_actor_labels_and_activity_separate(mixed):
    f = mixed
    imported = f.db.scalar(select(m.PoamEntry).where(m.PoamEntry.service_id == f.imported.id))
    local = m.PoamEntry(service_id=f.local.id, item_type='vulnerability', title='Local item', description='Local description',
        remediation='Local remediation', created_by_id=f.user.id)
    f.db.add(local)
    f.db.commit()
    labels = actor_labels([imported, local])
    assert labels[id(imported)]['created_by'] == 'upstream-author'
    assert id(local) not in labels
    captured = service_activity_page(f.db, f.imported.id)
    assert captured['imported'] is True
    assert captured['events'][0]['actor']['display_name'] == 'audit-only-reviewer'
    assert 'imported' not in service_activity_page(f.db, f.local.id)


def test_local_maintenance_preserves_imported_classifications_and_posture(mixed):
    f = mixed
    before = list(f.db.execute(select(m.FindingClassification.__table__).where(
        m.FindingClassification.service_id == f.imported.id)).mappings())
    assert before
    assert classification.refresh(f.db.get_bind(), f.imported.id, full=True) is None
    assert service_posture.rebuild(f.db.get_bind(), 'services', [f.imported.id]) == 0
    with pytest.raises(ValueError, match='publisher'):
        native_vex.evaluate_service(f.db, f.imported.id)
    after = list(f.db.execute(select(m.FindingClassification.__table__).where(
        m.FindingClassification.service_id == f.imported.id)).mappings())
    assert after == before
    assert classification.refresh(f.db.get_bind(), f.local.id, full=True)['service_id'] == f.local.id


def test_mixed_portfolio_keeps_captured_counts_and_only_loads_local_projections(mixed, monkeypatch):
    f = mixed
    display = f.release.evidence_state['extension']['display']
    local_services = dict(display['services_row'], version='local-version')
    local_cyber = dict(display['cyber_row'], status='Local posture')
    calls = []
    def load(db, kind, ids, configurations, now):
        calls.append((kind, ids))
        assert ids == [f.local.id]
        return {f.local.id: local_services if kind == 'services' else local_cyber}, {
            'services': 1, 'stale': 0, 'missing': 0, 'recomputed': 1, 'refreshing': False, 'preparing': 0}
    monkeypatch.setattr(service_posture, '_load', load)
    monkeypatch.setattr(service_posture, 'shadow_enabled', lambda: False)
    services = [f.local, f.imported]
    configs = {item.id: main.configuration_for_service(f.db, item) for item in services}
    rows, _, metadata = service_posture.services_rows(f.db, services, configs, {}, f.now)
    values = {row['service'].id: row for row in rows}
    assert values[f.imported.id]['version'] == display['services_row']['version']
    assert values[f.local.id]['version'] == 'local-version'
    cyber, _ = service_posture.cyber_rows(f.db, services, configs, {}, f.now)
    assert cyber[f.imported.id]['status'] == display['cyber_row']['status']
    assert cyber[f.local.id]['status'] == 'Local posture'
    assert calls == [('services', [f.local.id]), ('cyber', [f.local.id])]
    assert metadata['services'] == 2 and metadata['imported'] == 1


def test_mixed_vex_predicates_use_publisher_decisions_only_for_imported_findings(mixed):
    f = mixed
    imported_finding = f.db.scalar(select(m.Finding).where(m.Finding.service_id == f.imported.id))
    imported_observation = f.db.scalar(select(m.FindingObservation).where(
        m.FindingObservation.finding_id == imported_finding.id))
    local_finding = m.Finding(service_id=f.local.id, cve='CVE-2026-9999', severity='High',
        first_seen=f.now, episode_started=f.now, last_seen=f.now, active=True)
    f.db.add(local_finding)
    f.db.flush()
    local_observation = m.FindingObservation(finding_id=local_finding.id,
        execution_id=f.local_execution.id, image='local/image', evidence={})
    f.db.add(local_observation)
    f.db.commit()
    # There is no local VEX evaluation. The imported decision remains effective.
    assert dict(f.db.execute(select(m.Finding.id, native_vex.finding_excluded(m.Finding.id, f.now))).all()) == {
        imported_finding.id: True, local_finding.id: False}
    observations = dict(f.db.execute(select(m.FindingObservation.id,
        native_vex.observation_excluded(m.FindingObservation.id, f.now))).all())
    assert observations[imported_observation.id] is True
    assert observations[local_observation.id] is False


def test_assessment_namespace_disambiguates_imported_and_local_ids(mixed):
    from app import risk_routes
    from app.risk_models import RiskAssessment, RiskPolicyVersion
    f = mixed
    imported = f.db.scalar(select(ReplicaEvidenceRecord).where(ReplicaEvidenceRecord.kind == 'risk_assessments'))
    policy = RiskPolicyVersion(name='Local policy', version=1, configuration={}, digest='f' * 64, created_by='local')
    f.db.add(policy)
    f.db.flush()
    local = RiskAssessment(id=imported.id, service_id=f.local.id, policy_id=policy.id,
        source_execution_id=f.local_execution.id, as_of=f.now, valid_until=f.now+timedelta(days=1),
        provenance={}, summary={'rating': 'Local'}, details=[])
    f.db.add(local)
    f.db.commit()
    auth = SimpleNamespace(has=lambda permission, service_id=None: True)
    assert risk_routes.assessment(imported.id, auth, f.db)['summary']['rating'] == 'Local'
    captured = risk_routes.assessment(imported.id, auth, f.db, imported=True)
    assert captured['imported'] and captured['service_id'] == f.imported.id
    assert captured['summary']['rating'] == 'Moderate'


def test_local_classification_and_posture_rebuild_still_match_live_policy_in_mixed_database(mixed):
    from app.replica_models import ReplicaFindingDecision
    f = mixed
    local_finding = m.Finding(service_id=f.local.id, cve='CVE-2026-8888', severity='Critical',
        first_seen=f.now-timedelta(days=200), episode_started=f.now-timedelta(days=200),
        last_seen=f.now, active=True)
    f.db.add(local_finding)
    f.db.flush()
    f.db.add(m.FindingObservation(finding_id=local_finding.id, execution_id=f.local_execution.id,
        image='local/critical', evidence={}))
    f.db.commit()
    configurations = service_posture.resolve_configurations(f.db, [f.local.id, f.imported.id],
        main.get_configuration(f.db))
    assert '_replica_execution_id' not in configurations[f.local.id]
    assert '_replica_execution_id' in configurations[f.imported.id]
    assert classification.refresh(f.db.get_bind(), f.local.id, now=f.now, full=True)
    assert classification.current_services(f.db, [f.local.id, f.imported.id], configurations, f.now) == {
        f.local.id, f.imported.id}
    eligible, excepted, noncompliant = classification.predicates(configurations, f.now)
    decisions = {row[0]: row[1:] for row in f.db.execute(select(
        m.FindingClassification.finding_id, eligible, excepted, noncompliant))}
    assert decisions[local_finding.id] == (True, False, True)
    for imported in f.db.scalars(select(ReplicaFindingDecision).where(
            ReplicaFindingDecision.service_id == f.imported.id)):
        assert decisions[imported.finding_id] == (imported.eligible, imported.excepted, imported.noncompliant)
    assert service_posture.rebuild(f.db.get_bind(), 'services', [f.local.id, f.imported.id], now=f.now) == 1
    f.db.expire_all()
    rows, _, meta = service_posture.services_rows(f.db, [f.local, f.imported], configurations,
        main.get_configuration(f.db), f.now)
    rendered = {row['service'].id: row for row in rows}
    assert rendered[f.local.id]['compliant'] is False
    assert len(rendered[f.local.id]['noncompliant']) == 1
    assert rendered[f.imported.id]['compliant'] == f.release.evidence_state['extension']['display']['services_row']['compliant']
    assert not meta['preparing']


def test_portfolio_configuration_does_not_hydrate_imported_finding_decisions(mixed):
    from sqlalchemy import event
    from app.replica_findings import configuration
    f = mixed
    statements = []
    def collect(connection, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(f.db.get_bind(), 'before_cursor_execute', collect)
    try:
        values = service_posture.resolve_configurations(f.db, [f.local.id, f.imported.id], main.CONFIG_DEFAULTS)
        assert values[f.imported.id]['_replica_findings'] == {}
        assert not any('FROM replica_finding_decisions' in statement for statement in statements)
        assert configuration(f.db, f.imported.id, main.CONFIG_DEFAULTS)['_replica_findings']
        assert any('FROM replica_finding_decisions' in statement for statement in statements)
    finally:
        event.remove(f.db.get_bind(), 'before_cursor_execute', collect)
