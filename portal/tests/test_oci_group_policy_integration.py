"""Real OCI HTTP authorization applies the requested service's owning-group rules."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.execution_summaries import payload_digest
from app.models import Execution, Group, PortalSetting, Service, ServiceGroup, ServiceImage, ServiceVersion
from app.oci_group_policy import DEFAULT_POLICY
from app.oci_models import OCIRepository, OCIServicePullAccess
from app.release_validity import new_validity
from test_oci_proxy import digest, registry


def _findings(s, severity):
    return [] if severity is None else [dict(cve='CVE-2026-12345', severity=severity,
        image=s.source, image_digest=s.image, fixable=True)]


@pytest.fixture
def grouped(registry):
    s = registry
    s.source = 'registry.example/team/image@' + s.image
    s.groups, s.services, s.versions, s.approvals, s.payloads, s.paths = {}, {}, {}, {}, {}, {}
    s.scan_number = 0
    now = datetime.now(timezone.utc) - timedelta(minutes=1)
    with s.sessions() as db:
        mapping = db.get(OCIRepository, s.mapping_id)
        mapping.public_repository = mapping.upstream_repository = 'team/*'
        mapping.service_id = None
        for key, mode, severity in [('A', 'approved_release', 'Critical'),
                                    ('B', 'compliance', None), ('C', 'both', None)]:
            group = Group(name='Group ' + key)
            service = Service(service_key='group-' + key.lower(), name='Service ' + key)
            db.add_all([group, service]); db.flush()
            version = ServiceVersion(service_id=service.id, version='1.0')
            db.add(version); db.flush()
            service.current_version_id = version.id
            db.add(ServiceGroup(service_id=service.id, group_id=group.id))
            db.add(PortalSetting(key=f'group:{group.id}:oci_pull_policy', group_id=group.id,
                                value=json.dumps(dict(DEFAULT_POLICY, mode=mode))))
            raw = dict(service={'id': service.service_key, 'version': version.version},
                scanned_at=now.isoformat(), complete=True, fixable_only=True, scan_scope='service',
                findings=_findings(s, severity), policy_findings=[], skipped_images=[], skipped_charts=[],
                service_overview={'images': [{'image': s.source, 'digest': s.image}]})
            execution = Execution(service_id=service.id, service_version_id=version.id,
                execution_key='group-' + key + '-original', scanned_at=now, complete=True,
                scan_scope='service', raw_payload=raw, payload_digest=payload_digest(raw))
            db.add(execution); db.flush()
            if mode != 'compliance':
                snapshot = dict(service_id=service.id, source_execution_id=execution.id,
                    source_version_id=version.id, source_payload_digest=payload_digest(raw),
                    approval_validity=new_validity(now), artifacts=[dict(kind='image',
                        reference=s.source, digest=s.image)])
                approval = CyberApproval(service_id=service.id, source_execution_id=execution.id,
                    variant='current', status='approved', snapshot=snapshot,
                    snapshot_digest=snapshot_digest(snapshot), decided_at=now)
                db.add(approval); db.flush()
                s.approvals[key] = approval.id
            s.groups[key], s.services[key], s.versions[key] = group.id, service.id, version.id
            s.payloads[key] = raw
            s.paths[key] = f'/v2/team/{service.id}/image/'
        db.commit()
    return s


def _reads(s, key, status=200):
    for method in ('GET', 'HEAD'):
        for route in ('manifests/' + s.image, 'blobs/' + s.blob):
            response = s.client.request(method, s.paths[key] + route)
            assert response.status_code == status, (key, method, route, response.text)
    response = s.client.get(s.paths[key] + 'referrers/' + s.image)
    assert response.status_code == status, (key, response.text)


def _policy(s, key, **changes):
    with s.sessions() as db:
        row = db.query(PortalSetting).filter_by(key=f'group:{s.groups[key]}:oci_pull_policy').one()
        row.value = json.dumps({**json.loads(row.value), **changes})
        db.commit()


def _rescan(s, key, *, severity=None, complete=True, mutate=None):
    s.scan_number += 1
    now = datetime.now(timezone.utc) - timedelta(milliseconds=1)
    raw = deepcopy(s.payloads[key])
    raw.update(scanned_at=now.isoformat(), findings=_findings(s, severity), complete=complete)
    if mutate:
        mutate(raw)
    with s.sessions() as db:
        execution = Execution(service_id=s.services[key], service_version_id=s.versions[key],
            execution_key=f'group-{key}-scan-{s.scan_number}', scanned_at=now, complete=complete,
            scan_scope='service', raw_payload=raw, payload_digest=payload_digest(raw))
        db.add(execution); db.commit()


@pytest.mark.parametrize('public', [False, True], ids=['private', 'public'])
def test_groups_apply_independent_rules_to_identical_upstream_bytes(grouped, public):
    s = grouped
    if public:
        with s.sessions() as db:
            db.add_all([OCIServicePullAccess(service_id=identity, public=True)
                        for identity in s.services.values()]); db.commit()
        s.client.headers.pop('Authorization')
    for key in ('A', 'B', 'C'):
        _reads(s, key)
    # Group A expressly accepts Cyber's release decision despite Criticals.
    # A warmed shared registry/blob cache cannot transfer that authority to B/C.
    for key in ('B', 'C'):
        _rescan(s, key, severity='Critical')
        _reads(s, key, 403)
    _reads(s, 'A')


def test_changing_group_mode_rechecks_cached_objects_without_borrowing_approval(grouped):
    s = grouped
    _reads(s, 'A')
    _reads(s, 'B')  # No CyberApproval exists for B; its exact clean scan grants access.
    for mode in ('approved_release', 'both'):
        _policy(s, 'B', mode=mode)
        _reads(s, 'B', 403)
        _reads(s, 'A')
    _policy(s, 'B', mode='compliance')
    _reads(s, 'B')


def test_both_requires_approval_even_with_clean_scan(grouped):
    s = grouped
    _reads(s, 'C')
    with s.sessions() as db:
        db.get(CyberApproval, s.approvals['C']).revoked_at = datetime.now(timezone.utc)
        db.commit()
    _reads(s, 'C', 403)
    # Changing the group to compliance-only deliberately removes Cyber approval
    # from its criteria; public/private and exact scan evidence still apply.
    _policy(s, 'C', mode='compliance')
    _reads(s, 'C')


def test_stricter_severity_rule_invalidates_warm_cache_only_for_owning_group(grouped):
    s = grouped
    _rescan(s, 'B', severity='High')
    _reads(s, 'B')
    _reads(s, 'C')
    _policy(s, 'B', blocked_severity='High')
    _reads(s, 'B', 403)
    _reads(s, 'C')
    _policy(s, 'B', blocked_severity='Critical')
    _reads(s, 'B')


@pytest.mark.parametrize('key', ['A', 'B', 'C'])
def test_new_incomplete_scan_only_blocks_modes_that_require_compliance(grouped, key):
    s = grouped
    _reads(s, key)
    _rescan(s, key, complete=False)
    _reads(s, key, 200 if key == 'A' else 403)


@pytest.mark.parametrize('key', ['A', 'B', 'C'])
def test_group_policy_does_not_remove_private_login_requirement(grouped, key):
    s = grouped
    _reads(s, key)
    credentials = s.client.headers.pop('Authorization')
    _reads(s, key, 401)
    s.client.headers['Authorization'] = credentials
    _reads(s, key)


@pytest.mark.parametrize('change', ['repository', 'digest', 'missing_inventory'])
def test_compliance_cannot_borrow_clean_scan_from_other_image_or_service(grouped, change):
    s = grouped
    _reads(s, 'B')
    def alter(raw):
        if change == 'repository':
            raw['service_overview']['images'][0]['image'] = 'registry.example/other/image@' + s.image
        elif change == 'digest':
            raw['service_overview']['images'][0] = dict(image='registry.example/team/image@sha256:' + 'f' * 64,
                                                        digest='sha256:' + 'f' * 64)
        else:
            raw['service_overview']['images'] = []
    _rescan(s, 'B', mutate=alter)
    _reads(s, 'B', 403)
    _reads(s, 'A')


def test_compliance_does_not_authorize_unscanned_tag_target(grouped):
    s = grouped
    _reads(s, 'B')
    raw = json.dumps({'schemaVersion': 2, 'config': {'digest': s.blob, 'size': 10},
                     'layers': [], 'annotations': {'unscanned': 'true'}}).encode()
    identity = digest(raw)
    s.documents['latest'] = s.documents[identity] = raw
    for reference in ('latest', identity):
        response = s.client.get(s.paths['B'] + 'manifests/' + reference)
        assert response.status_code == 403, response.text


def test_compliance_only_does_not_require_an_active_release_pointer(grouped):
    from app.release_revisions import ServiceActiveRelease
    s = grouped
    with s.sessions() as db:
        db.add(ServiceActiveRelease(service_id=s.services['B'], revision_id=None))
        db.commit()
    # A legacy/missing release pointer cannot silently turn compliance-only
    # routing into a second requirement for Cyber approval, including tag pulls.
    response = s.client.get(s.paths['B'] + 'manifests/latest')
    assert response.status_code == 200, response.text
    _reads(s, 'B')
    _policy(s, 'B', mode='both')
    _reads(s, 'B', 403)


def test_both_checks_compliance_at_the_signed_distribution_location(grouped, monkeypatch):
    from app import release_revisions as revisions
    from app.oci_models import OCIPrincipal
    s = grouped
    with s.sessions() as db:
        project = db.get(OCIRepository, s.mapping_id)
        mapping = OCIRepository(public_repository='stable/image', upstream_repository='old/image',
            service_id=s.services['C'], upstream_id=project.upstream_id)
        db.add(mapping); db.flush()
        machine = db.get(OCIPrincipal, s.machine_id)
        machine.repository_ids = [*machine.repository_ids, mapping.id]
        approval = db.get(CyberApproval, s.approvals['C'])
        approval.snapshot = dict(approval.snapshot,
            release_revision={'artifact_ids': [1], 'base_revision_id': None})
        approval.snapshot_digest = snapshot_digest(approval.snapshot)
        binding = dict(repository_id=mapping.id, upstream_id=mapping.upstream_id,
            endpoint=mapping.upstream.endpoint, public_repository=mapping.public_repository,
            mapping_upstream_repository='old/image', upstream_repository='team/image',
            tag='latest', artifact_id=1, digest=s.image)
        manifest = dict(artifacts=[dict(id=1, digest=s.image)], distribution_bindings=[binding])
        revision = revisions.ReleaseRevision(service_id=s.services['C'], approval_id=approval.id,
            manifest=manifest, manifest_digest=snapshot_digest(manifest))
        db.add(revision); db.flush()
        db.add_all([revisions.ReleaseRevisionState(revision_id=revision.id, decision='approved'),
            revisions.ServiceActiveRelease(service_id=s.services['C'], revision_id=revision.id)])
        db.commit()
        mapping_id = mapping.id
    # Detached-signature verification has its own suite. Keep actual approval,
    # pointer, signed-location binding, scan rules, graph and cache authorization.
    monkeypatch.setattr(revisions, 'validate_current_revision', lambda *args: None)
    s.paths['C'] = f'/v2/stable/{s.services["C"]}/image/'
    response = s.client.get(s.paths['C'] + 'manifests/latest')
    assert response.status_code == 200, response.text
    _reads(s, 'C')
    assert ('team/image', 'latest') in s.fetches or ('team/image', s.image) in s.fetches
    _rescan(s, 'C', severity='Critical')
    _reads(s, 'C', 403)
    _rescan(s, 'C')
    _reads(s, 'C')
    with s.sessions() as db:
        db.get(OCIRepository, mapping_id).upstream_repository = 'tampered/image'
        db.commit()
    _reads(s, 'C', 403)


@pytest.fixture
def popup(grouped, monkeypatch):
    from app import oci_proxy, oci_pull_instructions as instructions
    from test_oci_pull_instructions import viewer
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example')
    def network_forbidden(*args):
        raise AssertionError('Pull instructions must not contact a registry')
    monkeypatch.setattr(oci_proxy, 'client', network_forbidden)
    s = grouped
    with s.sessions() as db:
        image = ServiceImage(service_id=s.services['B'], image_reference=s.source, image_digest=s.image)
        db.add(image); db.commit()
        auth = viewer(db, s.services['B'])
        yield SimpleNamespace(s=s, db=db, image=image,
            pull=lambda: instructions.pull_instructions('group-b', image.id, db, auth))


def test_compliance_popup_advertises_unapproved_clean_image_and_rechecks_mode(popup):
    p = popup
    result = p.pull()
    assert result['status'] == 'available', result
    assert result['routes'][0]['command'] == f'docker pull cats.example/team/{p.s.services["B"]}/image@{p.s.image}'
    assert result['routes'][0]['login_required'] is True
    assert not p.db.query(CyberApproval).filter_by(service_id=p.s.services['B']).count()
    _policy(p.s, 'B', mode='both')
    p.db.expire_all()
    result = p.pull()
    assert result['status'] == 'unavailable' and not result['routes']


@pytest.fixture
def relocated_popup(popup):
    p = popup
    source = 'build.example/team/base@' + p.s.image
    execution = p.db.query(Execution).filter_by(service_id=p.s.services['B']).one()
    raw = deepcopy(execution.raw_payload)
    raw['service_overview']['images'] = [dict(image=source, digest=p.s.image)]
    execution.raw_payload, execution.payload_digest = raw, payload_digest(raw)
    p.image.image_reference = source
    now = datetime.now(timezone.utc)
    snapshot = dict(service_id=p.s.services['B'], source_execution_id=execution.id,
        source_version_id=p.s.versions['B'], source_payload_digest=execution.payload_digest,
        approval_validity=new_validity(now), artifacts=[dict(kind='image', reference=source, digest=p.s.image)])
    approval = CyberApproval(service_id=p.s.services['B'], source_execution_id=execution.id,
        variant='current', status='approved', snapshot=snapshot, snapshot_digest=snapshot_digest(snapshot),
        decided_at=now, revoked_at=now, publish_status='queued')
    p.db.add(approval); p.db.flush()
    p.target_digest = 'sha256:' + 'd' * 64
    artifact = dict(kind='image', reference='registry.example/team/relocated@' + p.target_digest,
        digest=p.target_digest, source_digest=p.s.image, scan_identity_retained=True,
        identity_resolution='retained-evidence', verification_status='verified')
    approval.publication = dict(status='queued', verification_status='verified', signature_status='verified',
        artifacts=[artifact], manifest=dict(approval_id=approval.id,
            snapshot_digest=approval.snapshot_digest, artifacts=[artifact]))
    p.db.commit()
    p.approval = approval
    return p


def test_compliance_popup_retains_verified_relocation_after_revocation_queue(relocated_popup):
    p = relocated_popup
    for mode in ('compliance', 'approved_release', 'both', 'compliance'):
        _policy(p.s, 'B', mode=mode)
        p.db.expire_all()
        result = p.pull()
        if mode == 'compliance':
            assert result['status'] == 'available', result
            assert result['routes'][0]['reference'] == f'cats.example/team/{p.s.services["B"]}/relocated@{p.target_digest}'
        else:
            assert result['status'] == 'unavailable' and not result['routes']


@pytest.mark.parametrize('corruption', ['snapshot', 'manifest', 'signature', 'source_digest'])
def test_compliance_popup_rejects_unverified_relocation_identity(relocated_popup, corruption):
    p = relocated_popup
    assert p.pull()['status'] == 'available'
    if corruption == 'snapshot':
        p.approval.snapshot = dict(p.approval.snapshot, service_id=p.s.services['A'])
    else:
        receipt = deepcopy(p.approval.publication)
        if corruption == 'manifest':
            receipt['manifest']['approval_id'] += 1
        elif corruption == 'signature':
            receipt['signature_status'] = 'unverified'
        else:
            receipt['artifacts'][0]['source_digest'] = 'sha256:' + 'e' * 64
            receipt['manifest']['artifacts'] = deepcopy(receipt['artifacts'])
        p.approval.publication = receipt
    p.db.commit()
    result = p.pull()
    assert result['status'] == 'unavailable' and not result['routes']
