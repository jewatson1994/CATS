"""Durable runtime candidate identity, exact offline scanner receipts and isolation."""
import base64
from datetime import timedelta
import gzip
import hashlib
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import main
from app.database import Base
from app.execution_summaries import payload_digest
from app.models import Execution, Group, Service, ServiceVersion
from app.oci_models import OCIManifest, OCIRepository, OCIUpstream
from app.runtime_image_manifests import IMAGE_TYPES, INDEX_BLOCKER, INDEX_TYPES
from app.runtime_candidate_assessment import claim_allowed, dispatch_pending, process
from app.runtime_candidates import RuntimeReleaseCandidate, assessment_for_review, reconcile
from app.runtime_models import RuntimeEnvironment, now
from app.scan_coordination import ScanJob


REPO = 'registry.internal/project/api'
PIN = REPO + '@sha256:' + 'a' * 64


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///' + (tmp_path / 'app.sqlite').as_posix())
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(main, 'PUBLIC_JOB_ROOT', tmp_path / 'jobs')
    with sessions() as db:
        service = Service(service_key='test-service', name='Test service', lifecycle_status='active',
                          groups=[Group(name='Engineering')])
        env = RuntimeEnvironment(name='staging', cluster_role='validation', kind='kubernetes', service_scope='all')
        db.add_all([service, env])
        db.flush()
        mapping = OCIRepository(service_id=service.id, public_repository='project/api', upstream_repository='project/api',
                                upstream=OCIUpstream(name='internal', endpoint='https://registry.internal'))
        db.add(mapping)
        db.commit()
        yield db, sessions, service, env, mapping
    engine.dispose()


def application(*refs, **extra):
    components = [dict(workload_kind='Deployment', workload='api', workload_uid='controller', container_kind='regular',
                       container='main' + str(i), image_id=ref, image_ref=REPO + ':latest', app_version='1.2', **extra)
                  for i, ref in enumerate(refs)]
    return SimpleNamespace(id=1, name='api', identity='a'*64, components=components)


def document(kind, fmt, reference, content=b'{}'):
    return {'category': kind, 'format': fmt, 'image': reference, 'name': fmt + '.json', 'bytes': len(content),
            'sha256': hashlib.sha256(content).hexdigest(), 'encoding': 'gzip+base64',
            'content': base64.b64encode(gzip.compress(content)).decode()}


def complete(db, job, service, pin=PIN, **changes):
    version = db.scalar(select(ServiceVersion).where(ServiceVersion.service_id == service.id, ServiceVersion.version == job.service_version))
    if not version:
        version = ServiceVersion(service_id=service.id, version=job.service_version)
        db.add(version)
        db.flush()
    scope = 'distribution' if job.payload.get('runtime_candidate_artifact') else 'evidence'
    raw = dict(execution_id='public:' + job.id, complete=True, scan_scope=scope, scanned_at=now().isoformat(),
        service={'id': service.service_key, 'version': version.version, 'name': service.name}, fixable_only=True,
        artifact_type='image', service_overview={'images': [{'image': pin, 'digest': pin.split('@')[1]}]},
        sbom_components=[{'name': 'test-lib', 'version': '1', 'image': pin}], findings=[
            {'cve': 'CVE-2025-1234', 'severity': 'High', 'image': pin, 'package': 'test-lib', 'installed_version': '1'}],
        evidence_documents=[document('sbom', 'syft-json', pin), document('scanner', 'grype-json', pin)])
    raw.update(changes)
    execution = Execution(service_id=service.id, service_version_id=version.id, execution_key='public:' + job.id,
        scanned_at=now(), complete=True, scan_scope=scope, raw_payload=raw, payload_digest=payload_digest(raw))
    db.add(execution)
    db.flush()
    job.status, job.finished_at = 'complete', now()
    job.payload = {**job.payload, 'ingested': True, 'pipeline_execution_id': execution.id}
    db.flush()
    return execution


def test_durable_queue_offline_completion_and_reuse(runtime):
    db, sessions, service, env, _ = runtime
    candidate = reconcile(db, env, service, [application(PIN)], 'default')
    assert candidate.status == 'draft' and candidate.proposed_version == '1.2'
    assert reconcile(db, env, service, [application(PIN)], 'default').id == candidate.id
    db.commit()
    dispatch_pending(sessions)
    db.refresh(candidate)
    job = db.get(ScanJob, candidate.jobs[PIN])
    assert job.payload['image_list'] == PIN and claim_allowed(db, job)
    assert job.payload['credential_policy'] == 'service'
    isolated = job.payload
    job.payload = {**isolated, 'chart_url': 'oci://other.example/disallowed'}
    assert not claim_allowed(db, job)
    job.payload = isolated
    assert candidate.assessment_status == 'scanning'
    source = complete(db, job, service)
    candidate.assessed_at = now() - timedelta(minutes=5)
    db.commit()
    dispatch_pending(sessions)
    db.refresh(candidate)
    assert candidate.assessment_status == 'ready' and candidate.approval_id is None
    ready = assessment_for_review(db, candidate, service)
    assert ready['ready'], ready['blockers']
    evidence = ready['runtime_evidence']
    assert evidence['assessments'][0]['execution_id'] == source.id
    assert evidence['findings'][0]['cve'] == 'CVE-2025-1234'
    assert evidence['findings'][0]['vex']['status'] and 'epss' in evidence['findings'][0]
    assert evidence['findings'][0]['score'] > 0 and not evidence['comparison']['baseline_available']
    assert evidence == assessment_for_review(db, candidate, service)['runtime_evidence']
    assert service.current_version_id is None
    candidate.status = 'submitted'
    new_pin = REPO + '@sha256:' + 'b'*64
    new = reconcile(db, env, service, [application(PIN, new_pin)], 'default')
    process(db, new)
    assert new.jobs[PIN] == job.id and new.jobs[new_pin] != job.id
    assert db.scalar(select(func.count()).select_from(ScanJob)) == 2
    assert not candidate.current and candidate.status == 'submitted'
    with pytest.raises(ValueError, match='no longer eligible'):
        assessment_for_review(db, candidate, service)


def test_unknowns_role_and_assignment_preserved(runtime):
    db, sessions, service, env, mapping = runtime
    external = 'untrusted.example/private/tool@sha256:' + 'f'*64
    app = application(external, '', chart_name='api', chart_version='1.3')
    app.components[1]['image_ref'] = 'untrusted.example/private/tool:unknown'
    candidate = reconcile(db, env, service, [app], 'default')
    db.commit()
    dispatch_pending(sessions)
    db.refresh(candidate)
    review = assessment_for_review(db, candidate, service)
    assert candidate.assessment_status == 'blocked' and not candidate.jobs and not review['ready']
    assert 'CI chart archive' in str(review['blockers']) and 'no immutable repository digest' in str(review['blockers'])
    assert review['runtime_evidence']['images'][0]['reference'] == external
    assert review['runtime_evidence']['charts'][0]['digest'] is None
    env.cluster_role = 'production'
    db.flush()
    with pytest.raises(ValueError, match='no longer eligible'):
        assessment_for_review(db, candidate, service)
    reconcile(db, env, service, [], 'default')
    assert not candidate.current


def test_dispatch_failure_preserves_concurrent_submission(runtime, monkeypatch):
    from app import runtime_candidate_assessment
    db, sessions, service, env, _ = runtime
    candidate = reconcile(db, env, service, [application(PIN)], 'default')
    db.commit()

    def failed_dispatch(session, row, admission):
        with sessions() as reviewer:
            submitted = reviewer.get(RuntimeReleaseCandidate, row.id)
            submitted.status, submitted.assessment_status = 'submitted', 'ready'
            reviewer.commit()
        raise ValueError('Scanner coordinator interrupted')

    monkeypatch.setattr(runtime_candidate_assessment, 'process', failed_dispatch)
    dispatch_pending(sessions)
    db.refresh(candidate)
    assert candidate.status == 'submitted' and candidate.assessment_status == 'ready' and not candidate.assessment_error


def test_confirmed_discovery_chart_source_and_dependency_evidence(runtime, tmp_path, monkeypatch):
    from pathlib import Path
    from app.artifact_catalog import assign_artifact, register_artifact
    from app.cyber_approval_evidence import freeze
    from app.discovery_engine import run_discovery
    from app.discovery_helm_network import CHART_LAYER
    from app.discovery_models import DiscoveryConfirmation, DiscoveryInventory
    from app.discovery_sources import encrypted_writer
    from app.durable_jobs import DurableJob
    from app.models import User
    from app.runtime_candidate_assessment import chart_key
    from app.runtime_candidates import checksum
    from test_artifact_submissions import _tar
    from test_cyber_approvals import auth

    db, _, service, env, _ = runtime
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', base64.urlsafe_b64encode(b'c' * 32).decode())
    uploads = tmp_path / 'discovery'
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(uploads))
    files = {'api/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.3.0\ndependencies:\n- name: library\n  version: 2.0.0\n'}
    library = _tar({'library/Chart.yaml': 'apiVersion: v2\nname: library\nversion: 2.0.0\ntype: library\n'})
    content = _tar({**files, 'api/charts/library-2.0.0.tgz': library})
    original = tmp_path / 'api.tgz'
    original.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    inventory = run_discovery(original, runner=lambda *args: 'apiVersion: v1\nkind: Pod\nmetadata: {name: api}\n'
                              'spec: {containers: [{name: api, image: "' + PIN + '"}]}')
    assert inventory['completeness'] == 'complete', inventory['diagnostics']
    inventory['archive_hash'] = digest
    folder = uploads / ('d' * 32)
    folder.mkdir(parents=True)
    target = folder / original.name
    with encrypted_writer(target, folder.name) as encrypted:
        encrypted.write(content)
    owner = User(username='chart-owner', display_name='Owner')
    source_job = DurableJob(id='b' * 32, kind='discovery', status='completed', result={'inventory_id': 'a' * 32},
        payload=dict(group_id=service.groups[0].id, source_id=folder.name, filename=original.name, source_hash=digest))
    db.add_all([owner, source_job])
    db.flush()
    item = DiscoveryInventory(id='a' * 32, job_id=source_job.id, group_id=service.groups[0].id, inventory=inventory,
                              source_hash=digest, content_hash=checksum(inventory))
    db.add(item)
    db.flush()
    observed = application(PIN, chart_name='api', chart_version='1.3.0', helm_release='api',
                           helm_namespace='default', chart_digest='sha256:' + digest)
    candidate = reconcile(db, env, service, [observed], 'default')
    key = chart_key(candidate.inventory['charts'][0])
    process(db, candidate)
    assert key not in candidate.jobs
    confirmation = DiscoveryConfirmation(id='c' * 32, service_id=service.id, confirmed_by=owner.id, inventory_id=item.id,
        root_ids=[next(root['id'] for root in inventory['roots'] if root.get('chart_name') == 'api')])
    db.add(confirmation)
    db.flush()
    encrypted_bytes = target.read_bytes()
    target.write_bytes(encrypted_bytes[:-1] + bytes([encrypted_bytes[-1] ^ 1]))
    process(db, candidate)
    assert key not in candidate.jobs
    target.write_bytes(encrypted_bytes)
    process(db, candidate)
    chart = db.get(ScanJob, candidate.jobs[key])
    assert claim_allowed(db, chart) and chart.payload['credential_policy'] == 'public'
    assert (main.PUBLIC_JOB_ROOT / chart.id / 'retained-chart.tgz').read_bytes() == content
    eligible = confirmation.root_ids
    confirmation.root_ids = []
    db.flush()
    assert not claim_allowed(db, chart)
    confirmation.root_ids = eligible
    db.flush()
    complete(db, db.get(ScanJob, candidate.jobs[PIN]), service)
    execution = complete(db, chart, service, artifact_type='helm', helm_source_files=files, findings=[])
    source_job.result = {**source_job.result, 'source_expired': True}
    target.unlink()
    chart_matches = []
    for media in (CHART_LAYER, 'application/octet-stream', IMAGE_TYPES[0]):
        artifact = register_artifact(db, digest='sha256:' + digest, media_type=media)
        assign_artifact(db, service_id=service.id, artifact_id=artifact.id)
        if media != IMAGE_TYPES[0]:
            chart_matches.append(artifact.id)
    result = process(db, candidate)
    assert result['ready'], result['blockers']
    receipt = next(r for r in result['runtime_evidence']['assessments'] if r['kind'] == 'chart')
    assert [match['artifact_id'] for match in receipt['catalog_matches']] == chart_matches
    context = receipt['discovery']
    assert context['confirmation_id'] == confirmation.id and context['content_hash'] == item.content_hash
    dependency, = context['dependencies']
    assert (dependency['name'], dependency['version'], dependency['digest_kind']) == ('library', '2.0.0', 'archive')
    assert dependency['sha256'] == hashlib.sha256(library).hexdigest() and dependency['parent_id'] == context['root_id']
    assert receipt['dependencies'][0]['vendored'] and receipt['dependencies'][0]['file'] == 'charts/library-2.0.0.tgz'
    db.commit()
    snapshot = freeze(db, service, auth(service.id), assessment_for_review(db, candidate, service), tmp_path / 'frozen')
    frozen_receipt, = [r for r in snapshot['runtime_evidence']['assessments'] if r['kind'] == 'chart']
    assert frozen_receipt['catalog_matches'] == receipt['catalog_matches']
    frozen_chart, = [artifact for artifact in snapshot['artifacts'] if artifact['kind'] == 'chart']
    assert frozen_chart['digest'] == 'sha256:' + digest and Path(frozen_chart['path']).read_bytes() == content
    chart.finished_at = execution.scanned_at = now() - timedelta(days=400)
    db.flush()
    process(db, candidate)
    retry = db.get(ScanJob, candidate.jobs[key])
    assert retry.id != chart.id and retry.payload['runtime_discovery_source'] == context and claim_allowed(db, retry)
    assert (main.PUBLIC_JOB_ROOT / retry.id / 'retained-chart.tgz').read_bytes() == content


def test_registry_resolution_separates_desired_and_observed(runtime, monkeypatch):
    from app import oci_proxy
    from app.runtime_registry_resolution import resolve_requests
    db, sessions, service, env, mapping = runtime
    media = 'application/vnd.oci.image.manifest.v1+json'
    raw = json.dumps({'mediaType': media, 'schemaVersion': 2, 'layers': [], 'config': {
        'mediaType': 'application/vnd.oci.image.config.v1+json', 'size': 32, 'digest': 'sha256:' + 'e' * 64}}).encode()
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    pin = REPO + '@' + digest
    requests = []
    def fetch(repo, ref):
        requests.append((repo, ref))
        return raw, media, digest
    monkeypatch.setattr(oci_proxy, 'client', lambda binding: SimpleNamespace(fetch_manifest=fetch, timeout=10))
    app = application('')
    row = reconcile(db, env, service, [app], 'default')
    db.commit()
    desired = db.get(RuntimeReleaseCandidate, resolve_requests(sessions, row.id, [1]))
    assert requests == [('project/api', 'latest')]
    assert desired.id != row.id
    assert desired.inventory['registry_resolutions'][REPO + ':latest']['digest'] == digest
    assert desired.inventory['images'] == [{'reference': pin, 'kind': 'image', 'digest': digest, 'desired': True, 'observed': False}]
    assert reconcile(db, env, service, [app], 'default').id == desired.id
    process(db, desired)
    assert db.get(ScanJob, desired.jobs[pin]).payload['image_list'] == pin
    assert 'no immutable repository digest' in str(desired.inventory['blockers'])
    # A bare ID matching the concrete Pod spec pin becomes manifest identity
    # only after verifying the manifest bytes for that same service repository.
    app.components[0].update(image_id=digest, image_ref=pin, desired_image=pin)
    row = reconcile(db, env, service, [app], 'default')
    db.commit()
    assert row.inventory['blockers']
    proven = db.get(RuntimeReleaseCandidate, resolve_requests(sessions, row.id, [1]))
    assert requests[-1] == ('project/api', digest) and not proven.inventory['blockers']
    assert proven.inventory['images'][0]['observed'] and proven.inventory['images'][0]['desired']
    app.components[0]['image_id'] = 'sha256:' + 'e' * 64
    wrong = reconcile(db, env, service, [app], 'default')
    db.commit()
    assert resolve_requests(sessions, wrong.id, [1]) == wrong.id
    assert wrong.inventory['blockers'] and not wrong.inventory['images'][0]['observed']
    app.components[0].update(image_id='', image_ref='untrusted.example/some/repo:latest', desired_image='')
    external = reconcile(db, env, service, [app], 'default')
    db.commit()
    assert resolve_requests(sessions, external.id, [1]) == external.id and len(requests) == 2


def test_conflicting_qualified_tag_retains_requested_repository(runtime):
    db, _, service, env, _ = runtime
    desired = 'registry.internal/another-team/api:latest'
    app = application(PIN)
    app.components[0].update(image_ref=desired, desired_image=desired)
    row = reconcile(db, env, service, [app], 'default')
    assert row.inventory['unresolved_image_requests'] == [desired]
    assert row.inventory['images'][0]['reference'] == PIN
    process(db, row)
    complete(db, db.get(ScanJob, row.jobs[PIN]), service)
    process(db, row)
    review = assessment_for_review(db, row, service)
    assert not review['ready']
    assert any(desired in blocker and 'repository differs' in blocker for blocker in review['blockers'])


def test_conflicting_pod_pin_survives_converged_controller_and_image_id(runtime):
    db, _, service, env, _ = runtime
    requested = REPO + '@sha256:' + 'c' * 64
    app = application(PIN)
    app.components[0].update(image_ref=requested, desired_image=PIN)
    row = reconcile(db, env, service, [app], 'default')
    assert {item['reference'] for item in row.inventory['images'] if item['desired']} == {requested, PIN}
    assert {item['reference'] for item in row.inventory['images'] if item['observed']} == {PIN}
    assert any('Pod image pin differs' in blocker for blocker in row.inventory['blockers'])


@pytest.mark.parametrize('bare,media', [(False, INDEX_TYPES[0]), (True, INDEX_TYPES[1])])
def test_equal_index_digest_never_proves_platform_assessment(runtime, bare, media):
    from app.runtime_registry_resolution import resolve_requests
    db, sessions, service, env, mapping = runtime
    manifests = [{'mediaType': IMAGE_TYPES[0], 'digest': 'sha256:' + digit * 64, 'size': 100} for digit in ('a', 'b')]
    raw = json.dumps({'schemaVersion': 2, 'mediaType': media, 'manifests': manifests})
    digest = 'sha256:' + hashlib.sha256(raw.encode()).hexdigest()
    pin = REPO + '@' + digest
    app = application(digest if bare else pin)
    app.components[0].update(image_ref=pin, desired_image=pin)
    row = reconcile(db, env, service, [app], 'default')
    if not bare:
        process(db, row)
        complete(db, db.get(ScanJob, row.jobs[pin]), service, pin=pin)
        process(db, row)
        db.commit()
        review = assessment_for_review(db, row, service)
        assert review['ready'], review['blockers']
    db.add(OCIManifest(repository_id=mapping.id, digest=digest, media_type=media, content=raw))
    db.commit()
    if bare:
        proven = resolve_requests(sessions, row.id, [1])
        row = db.get(RuntimeReleaseCandidate, proven)
        assert row.inventory['registry_resolutions'][pin]['media_type'] == media
        assert row.inventory['images'] == [dict(kind='image', reference=pin, desired=True, observed=False, digest=digest)]
    process(db, row)
    review = assessment_for_review(db, row, service)
    assert not review['ready'] and INDEX_BLOCKER in str(review['blockers'])
    assert review['runtime_evidence']['assessments'][0]['status'] == 'unavailable'


@pytest.mark.parametrize('metadata,reason', [
    ({'mediaType': INDEX_TYPES[0]}, INDEX_BLOCKER), ({'manifestDigest': 'sha256:' + 'b' * 64}, 'different platform manifest')])
def test_native_scanner_platform_evidence_blocks_conflicting_pin(runtime, metadata, reason):
    db, _, service, env, _ = runtime
    row = reconcile(db, env, service, [application(PIN)], 'default')
    process(db, row)
    syft = json.dumps({'source': {'type': 'image', 'metadata': metadata}}).encode()
    complete(db, db.get(ScanJob, row.jobs[PIN]), service, evidence_documents=[
        document('sbom', 'syft-json', PIN, syft), document('scanner', 'grype-json', PIN)])
    process(db, row)
    result = assessment_for_review(db, row, service)
    assert not result['ready'] and reason in str(result['blockers'])


def test_stale_jobs_and_foreign_payload_cannot_authorize(runtime):
    db, _, service, env, mapping = runtime
    candidate = reconcile(db, env, service, [application(PIN)], 'default')
    process(db, candidate)
    job = db.get(ScanJob, candidate.jobs[PIN])
    wrong = REPO + '@sha256:' + 'e'*64
    execution = complete(db, job, service, pin=wrong)
    assert not process(db, candidate)['ready']
    assert 'exactly the observed' in str(assessment_for_review(db, candidate, service)['blockers'])
    execution.raw_payload = {**execution.raw_payload, 'evidence_documents': []}
    db.flush()
    assert 'integrity' in str(assessment_for_review(db, candidate, service)['blockers'])
    mapping.suspended = True
    db.flush()
    assert not claim_allowed(db, job)
    reconcile(db, env, service, [], 'default')
    assert not candidate.current


def test_rollout_drift_cannot_be_submitted_and_inventory_is_immutable(runtime):
    db, _, service, env, _ = runtime
    candidate = reconcile(db, env, service, [application(PIN, desired_image=REPO + ':next')], 'default')
    assert 'Await rollout convergence' in str(candidate.inventory['blockers'])
    candidate.proposed_version = 'changed'
    with pytest.raises(ValueError, match='immutable'):
        db.flush()
    db.rollback()


def test_active_release_comparison_reports_changes_and_unknowns(runtime, monkeypatch):
    from app import release_revisions
    from app.cyber_approvals import CyberApproval, digest
    from app.runtime_candidate_assessment import _comparison
    db, _, service, env, _ = runtime
    row = reconcile(db, env, service, [application(PIN)], 'default')
    process(db, row)
    old_pin = 'sha256:' + '3' * 64
    old = {'version': '1.0', 'artifacts': [
        {'kind': 'image', 'reference': REPO + '@' + old_pin, 'digest': old_pin},
        {'kind': 'image', 'reference': 'registry.internal/project/old@' + old_pin, 'digest': old_pin},
        {'kind': 'chart', 'name': 'api', 'version': '1.0', 'digest': old_pin}],
        'findings': {'vulnerabilities': [{'cve': 'CVE-2024-1234', 'severity': 'Critical'}]},
        'risk_intelligence': {'findings': {'CVE-2024-1234': {'kev': True}}}}
    source = complete(db, db.get(ScanJob, row.jobs[PIN]), service)
    approval = CyberApproval(service_id=service.id, source_execution_id=source.id, variant='current_service',
                             snapshot=old, snapshot_digest=digest(old))
    db.add(approval)
    db.flush()
    monkeypatch.setattr(release_revisions, 'active_revision', lambda *args: SimpleNamespace(id=81, approval_id=approval.id))
    result = process(db, row)
    assert result['ready'], result['blockers']
    evidence = result['runtime_evidence']
    delta = evidence['comparison']
    assert delta['version'] == '1.0'
    assert [a['name'] for a in delta['removed']] == ['api', 'registry.internal/project/old']
    assert delta['updated'][0]['before'][0]['digest'] == old_pin
    assert delta['new_vulnerabilities'] == ['CVE-2025-1234'] and delta['resolved_vulnerabilities'] == ['CVE-2024-1234']
    assert delta['risk']['before_posture']['known_exploited_cves'] == ['CVE-2024-1234']
    assert delta['risk']['after_posture']['severity_counts'] == {'high': 1}
    partial = _comparison(db, service, {**evidence, 'inventory_blockers': ['missing pin']}, False)
    assert partial['removed'] is None and partial['resolved_vulnerabilities'] is None
