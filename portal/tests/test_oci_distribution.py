"""Pull actual published selected-image bytes through the live authorization path."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import cyber_approvals, cyber_release_publication, main, oci_authorization, oci_proxy, release_oci, signing
from app.cyber_approvals import digest as snapshot_digest
from app.models import Execution, Finding, Service
from app.oci_models import OCIPrincipal, OCIRepository, OCIUpstream
from app.service_evidence import current_execution
from test_cyber_approval_evidence import distribution_case, SELECTED, EXCLUDED
from test_cyber_release_publication import environment as publication_environment
from test_portal import SessionLocal, setup_function


@pytest.fixture
def published_distribution(distribution_case, publication_environment, monkeypatch, tmp_path, request):
    case, registry = distribution_case, publication_environment
    mode = getattr(request, 'param', 'project')
    pin = registry.approval.snapshot['artifacts'][0]['digest']
    config, credentials = signing.job_material({}, 'push')
    monkeypatch.setattr(signing, 'configuration', lambda _: {'fingerprint': registry.fingerprint,
        'public_key': config['signing_public_key'], 'enabled': True, 'private_key': 'fixture'})
    monkeypatch.setattr(main, 'configuration_for_service', lambda *args: {
        **main.CONFIG_DEFAULTS, 'compliance_mode': 'raw', 'overdue_days': '1', 'raw_due_rules': '[]',
        'hardening_overdue_days': '1'})
    # Emit the complete Cosign schema required by the proxy, retaining the
    # publication fixture's real signing key and immutable registry graph.
    private = serialization.load_pem_private_key(base64.b64decode(credentials['CATS_SIGNING_PRIVATE_KEY']), None)
    def sign_and_verify(reference, config, credentials, env):
        host, repository, digest = release_oci._reference(reference)
        target = registry.Registry(host, repository)
        payload = cyber_release_publication.canonical({'critical': {
            'type': 'cosign container image signature', 'image': {'docker-manifest-digest': digest}},
            'optional': config.get('approval_annotations', {})})
        layer = target.upload(payload, 'application/vnd.dev.cosign.simplesigning.v1+json')
        layer['annotations'] = {'dev.cosignproject.cosign/signature':
            base64.b64encode(private.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()}
        content = cyber_release_publication.canonical({'schemaVersion': 2, 'mediaType': release_oci.MANIFEST_TYPE,
            'config': target.upload(b'{}', 'application/vnd.oci.empty.v1+json'), 'layers': [layer]})
        target.request('PUT', target.api + '/manifests/' + digest.replace(':', '-', 1) + '.sig', body=content)
        return {'signature_status': 'verified', 'signature': {'key_fingerprint': registry.fingerprint}}
    monkeypatch.setattr(signing, 'sign_and_verify', sign_and_verify)
    with SessionLocal() as db:
        baseline = db.scalar(select(Finding).where(Finding.cve == 'CVE-1'))
        baseline.episode_started = datetime.now(timezone.utc) - timedelta(days=200)
        db.commit()
    if mode == 'risk':
        import test_cyber_approval_evidence as cases
        original_payload = cases.payload
        def selected_payload(identity, when, findings):
            body = original_payload(identity, when, ['CVE-1'])
            for finding in body['findings']:
                finding['image'] = SELECTED
                finding['image_digest'] = pin
            return body
        monkeypatch.setattr(cases, 'payload', selected_payload)
    if mode.startswith('policy'):
        import test_cyber_approval_evidence as cases
        original_payload = cases.payload
        sequence = 0
        def selected_policy_payload(identity, when, findings):
            nonlocal sequence
            sequence += 1
            body = original_payload(identity, when - timedelta(days=3) if sequence == 1 else when, findings)
            body['policy_findings'] = [{'finding': 'Selected workload has privileged access',
                'severity': 'High', 'scanner': 'trivy', 'target': SELECTED}]
            if sequence == 2 and mode != 'policy':
                body['policy_findings'] = []
                body['complete'] = mode != 'policy_incomplete'
            return body
        monkeypatch.setattr(cases, 'payload', selected_policy_payload)
        case.scan([(SELECTED, pin)])
        if mode != 'policy':
            case.scan([(SELECTED, pin)])
    case.scan([(SELECTED, pin)])
    params = {'distribution_id': case.selected['id']}
    ready = case.client.get(case.ready, params=params).json()
    assert ready['ready'], ready['blockers']
    created = case.client.post('/api/cyber-approvals', headers=case.headers,
        json={'service_key': 'payments-service', **params,
              'expected_source_execution_id': ready['source_execution_id']})
    assert created.status_code == 200, created.text
    approval_id = created.json()['id']
    decided = case.client.post(f'/api/cyber-approvals/{approval_id}/decision', headers=case.headers,
        json={'decision': 'approved', 'rationale': 'Reviewed selected distribution.'})
    assert decided.status_code == 200, decided.text
    with SessionLocal() as db:
        approval = db.get(cyber_approvals.CyberApproval, approval_id)
        receipt = cyber_release_publication.publish(db, approval, approval.destination, lambda _: None)
        assert receipt['status'] == 'published'
        approval.publication, approval.publish_status = receipt, 'published'
        repository = receipt['artifacts'][0]['reference'].split('/', 1)[1].split('@', 1)[0]
        upstream = OCIUpstream(name='published', endpoint='https://approved.example')
        db.add(upstream)
        db.flush()
        mapping = OCIRepository(public_repository=repository if mode == 'exact' else 'team/*',
            upstream_repository=repository if mode == 'exact' else 'team/*', upstream_id=upstream.id,
            service_id=approval.service_id if mode == 'exact' else None)
        db.add(mapping)
        db.flush()
        db.add(OCIPrincipal(name='selected', secret_hash=hashlib.sha256(b'secret').hexdigest(),
            repository_ids=[mapping.id], expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
        db.commit()
        service_id, mapping_id = approval.service_id, mapping.id
        assert current_execution(db, db.get(Service, service_id)).id == case.baseline_execution
        assert not main.service_view(db.get(Service, service_id), datetime.now(timezone.utc),
                                     main.configuration_for_service(db, None))['compliant']

    # Publication uses real immutable OCI graphs and cryptographic signatures;
    # isolate only registry I/O, never the proxy's authorization or caching.
    class Transport:
        def fetch_manifest(self, repository, reference):
            store = registry.stores.get(('approved.example', repository), {})
            raw = store.get('manifests', {}).get(reference)
            if raw is None:
                raise oci_proxy.RegistryError('Missing manifest', 404)
            return raw, 'application/vnd.oci.image.manifest.v1+json', snapshot_digest(json.loads(raw))

        def fetch_blob(self, repository, reference, cache):
            raw = registry.stores[('approved.example', repository)]['blobs'][reference]
            return cache.get(reference) or cache.store(reference, BytesIO(raw))

        def referrers(self, repository, reference):
            return {'manifests': []}

    monkeypatch.setattr(oci_proxy, 'SessionLocal', SessionLocal)
    monkeypatch.setattr(oci_proxy, 'client', lambda _: Transport())
    monkeypatch.setenv('CATS_OCI_CACHE_DIR', str(tmp_path / 'cache'))
    client = TestClient(oci_proxy.app)
    client.headers['Authorization'] = 'Basic ' + base64.b64encode(b'selected:secret').decode()
    return SimpleNamespace(case=case, registry=registry, client=client, approval_id=approval_id,
        service_id=service_id, mapping_id=mapping_id, digest=pin, repository=repository,
        path=f'/v2/{repository}/', blob=registry.layer['digest'])


@pytest.mark.parametrize('published_distribution', ['exact', 'project'], indirect=True)
def test_selected_distribution_pull_and_cached_revocation(published_distribution):
    s = published_distribution
    response = s.client.get(s.path + 'manifests/' + s.digest)
    assert response.status_code == 200, response.text
    assert response.headers['Docker-Content-Digest'] == s.digest
    assert s.client.get(s.path + 'blobs/' + s.blob).content == b'actual container filesystem bytes'
    assert s.client.get(s.path + 'referrers/' + s.digest).status_code == 200
    # The excluded image exists upstream but has no selected-distribution authority.
    excluded = s.repository.rsplit('/', 1)[0] + '/optional'
    s.registry.stores['approved.example', excluded] = s.registry.stores['approved.example', s.repository]
    assert s.client.get(f'/v2/{excluded}/manifests/{s.digest}').status_code in (403, 404)
    with SessionLocal() as db:
        db.get(cyber_approvals.CyberApproval, s.approval_id).revoked_at = datetime.now(timezone.utc)
        db.commit()
    for route in ('manifests/' + s.digest, 'blobs/' + s.blob, 'referrers/' + s.digest):
        assert s.client.get(s.path + route).status_code == 403


@pytest.mark.parametrize('change', ['selection', 'scope_only', 'missing_distribution', 'version', 'payload',
    'new_scan', 'pending_scan', 'job_provenance', 'service_ownership', 'incomplete', 'revision_pointer', 'policy'])
def test_distribution_evidence_rechecked_after_cache(published_distribution, change):
    from app.discovery_models import DiscoveryConfirmation
    from app.release_revisions import ServiceActiveRelease
    from app.scan_coordination import ScanJob
    s = published_distribution
    assert s.client.get(s.path + 'manifests/' + s.digest).status_code == 200
    if change == 'new_scan':
        s.case.scan([(SELECTED, s.digest)])
    elif change == 'pending_scan':
        admitted = s.case.client.post(f"/api/services/payments-service/distributions/{s.case.selected['id']}/scan",
            headers=s.case.headers, json={})
        assert admitted.status_code == 200, admitted.text
    else:
        with SessionLocal() as db:
            approval = db.get(cyber_approvals.CyberApproval, s.approval_id)
            execution = db.get(Execution, approval.source_execution_id)
            snapshot = deepcopy(approval.snapshot)
            if change == 'selection':
                snapshot['distribution']['images'] = [EXCLUDED]
            elif change == 'scope_only':
                snapshot.pop('distribution')
            elif change == 'missing_distribution':
                snapshot['distribution']['id'] = 'missing'
            elif change == 'version':
                snapshot['source_version_id'] = s.case.baseline_version
            elif change == 'payload':
                execution.raw_payload = {**execution.raw_payload, 'findings': [{'cve': 'tampered'}]}
            elif change == 'job_provenance':
                job = db.get(ScanJob, execution.execution_key.removeprefix('public:'))
                job.payload = {**job.payload, 'definition_context': {}}
            elif change == 'service_ownership':
                other = Service(service_key='other', name='Other')
                db.add(other)
                db.flush()
                db.get(DiscoveryConfirmation, 'confirmed').service_id = other.id
            elif change == 'incomplete':
                execution.complete = False
            elif change == 'revision_pointer':
                db.add(ServiceActiveRelease(service_id=s.service_id, revision_id=None))
            elif change == 'policy':
                db.get(OCIRepository, s.mapping_id).policy = {'allow_unreviewed': True}
            approval.snapshot = snapshot
            approval.snapshot_digest = snapshot_digest(snapshot)
            # Keep publication binding intact to test the distribution validation itself.
            receipt = deepcopy(approval.publication)
            receipt['manifest']['snapshot_digest'] = approval.snapshot_digest
            approval.publication = receipt
            db.commit()
    for route in ('manifests/' + s.digest, 'blobs/' + s.blob, 'referrers/' + s.digest):
        assert s.client.get(s.path + route).status_code == 403, (change, route)


@pytest.mark.parametrize('published_distribution', ['risk'], indirect=True)
@pytest.mark.parametrize('change', ['revoked', 'expired'])
def test_distribution_uses_live_exceptions_and_preserves_finding_age(published_distribution, change):
    from app.models import ExceptionRecord
    s = published_distribution
    path = s.path + 'manifests/' + s.digest
    assert s.client.get(path).status_code == 403
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        finding = db.scalar(select(Finding).where(Finding.service_id == s.service_id, Finding.cve == 'CVE-1'))
        exception = ExceptionRecord(finding_id=finding.id, justification='Reviewed', approved_by='Cyber',
            starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=1))
        db.add(exception)
        db.commit()
        identity = exception.id
    assert s.client.get(path).status_code == 200
    with SessionLocal() as db:
        exception = db.get(ExceptionRecord, identity)
        if change == 'revoked':
            exception.revoked_at = now
        else:
            exception.expires_at = now - timedelta(seconds=1)
        db.commit()
    assert s.client.get(path).status_code == 403


@pytest.mark.parametrize('published_distribution,expected', [
    ('policy', 403), ('policy_gap', 200), ('policy_incomplete', 403)], indirect=['published_distribution'])
def test_distribution_policy_age_survives_rescan_until_complete_absence(published_distribution, expected):
    from app.models import PolicyFinding
    s = published_distribution
    with SessionLocal() as db:
        assert db.scalar(select(PolicyFinding.id).where(PolicyFinding.service_id == s.service_id)) is None
    assert s.client.get(s.path + 'manifests/' + s.digest).status_code == expected


@pytest.mark.parametrize('policy,reason', [({'max_scan_age_days': 1}, 'scan_stale'),
    ({'max_approval_age_days': 1}, 'approval_window_elapsed')])
def test_distribution_mapping_age_limits(published_distribution, policy, reason):
    s = published_distribution
    with SessionLocal() as db:
        mapping = db.get(OCIRepository, s.mapping_id)
        mapping.policy = policy
        mapping.service_id = s.service_id
        mapping.upstream_repository = s.repository
        decision = oci_authorization.authorize(db, mapping, s.digest,
            datetime.now(timezone.utc) + timedelta(days=2))
        assert not decision.allowed and decision.reason == reason
