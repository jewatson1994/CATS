import json
from datetime import datetime, timezone
from types import SimpleNamespace as N

from app.frontend_governance import project_governance
from app.frontend_remediations import project_remediations


def service():
    return N(id=7, service_key='service', name='Service', groups=[], credentials='SECRET')


def test_finding_projection_excludes_execution_and_authentication_internals():
    data = {'can': {}}
    project_governance(data, 'finding.html', {'service': service(), 'finding': N(id=3, cve='CVE-1', secret='SECRET'), 'evidence': {'description': '<script>alert(1)</script>', 'urls': ['https://example.com'], 'cvss': [{'vector': 'vector', 'metrics': {'baseScore': 9, 'secret': 'SECRET'}}], 'credentials': 'SECRET'}, 'current_observations': [{'image': 'image', 'package': 'package', 'raw_payload': 'SECRET'}]}, lambda permission, sid: sid == 7, {})
    assert 'SECRET' not in json.dumps(data)
    assert data['evidence']['cvss'] == [{'vector': 'vector', 'baseScore': 9}]
    assert data['can']['remediation.execute'] == {'7': True}


def test_poam_projection_excludes_request_and_actor_secrets():
    data = {'can': {}}
    entry = N(id=9, service=service(), created_by=N(display_name='Creator', password='SECRET'), approved_by=N(display_name='Reviewer', token='SECRET'), due_date=datetime(2026, 9, 30, tzinfo=timezone.utc), secret='SECRET')
    project_governance(data, 'poam_entry.html', {'entry': entry, 'can_change': False, 'history': [N(action='updated', actor=N(display_name='Reviewer', token='SECRET'), detail={'title': 'Safe', 'credentials': 'SECRET'})], 'pending_change': N(request_type='poam_update', proposed_payload='SECRET')}, None, {})
    assert 'SECRET' not in json.dumps(data)
    assert data['entry']['due_input'] == '2026-09-30T00:00'
    assert data['history'][0]['detail'] == {'title': 'Safe'}
    assert data['can_change'] is False


def test_scoped_reviews_never_allow_self_approval_or_completed_requests():
    workflows = [N(id=i, service=service(), service_id=sid, request_type=kind, requested_by_id=requester, status=status, requested_by=N(display_name='Creator', password='SECRET'), justification='Reason', raw_payload='SECRET') for i, sid, kind, requester, status in [(1, 7, 'poam_update', 4, 'pending'), (2, 7, 'poam_complete', 5, 'pending'), (3, 8, 'exception', 5, 'pending'), (4, 7, 'archive', 5, 'approved')]]
    calls = []
    def can(permission, sid):
        calls.append((permission, sid))
        return sid == 7
    data = {'can': {}, 'next_path': '/requests'}
    project_remediations(data, 'requests.html', {'current_user': N(id=4), 'workflows': workflows, 'workflow_statuses': {1: 'pending', 2: 'pending'}}, can, {})
    assert [row['can_review'] for row in data['workflows']] == [False, True, False, False]
    assert ('poam.review', 7) in calls and ('exception.review', 8) in calls
    assert 'SECRET' not in json.dumps(data)


def test_remediation_report_projects_snapshots_not_paths_credentials_or_raw_payloads():
    job = N(job_key='job', status='failed', artifact_path='SECRET', credentials='SECRET', raw_payload='SECRET', before_snapshot={'vulnerabilities': {'Critical': 2, 'secret': 'SECRET'}, 'images': 1, 'secret': 'SECRET'}, after_snapshot={}, changed_artifacts=[{'path': 'values.yaml', 'changes': ['Update'], 'source': 'SECRET'}], configuration_changes=[{'rule_id': 'rule', 'source_mapping': {'template': 'chart.yaml', 'credentials': 'SECRET'}}], validation_results={'checks': {'helm_template': {'status': 'PASS', 'credentials': 'SECRET'}}, 'raw': 'SECRET'}, stages={'patch': {'status': 'failed', 'secret': 'SECRET'}}, logs=['Failed'], failure_reason='Unable to patch')
    data = {'can': {}, 'next_path': '/remediations'}
    project_remediations(data, 'remediation_report.html', {'service': service(), 'job': job}, lambda *args: False, {})
    assert 'SECRET' not in json.dumps(data)
    assert data['job']['has_artifact'] is True
    assert data['job']['before_snapshot']['vulnerabilities']['Critical'] == 2
    assert data['job']['validation'][0]['status'] == 'PASS'


def test_report_keeps_patch_blockers_and_worker_identity():
    job = N(job_key='job', patched_images=[{'original': 'ubuntu:test', 'classification': 'REVIEW REQUIRED',
        'reason': 'Mirror policy missing', 'patch_status': 'FAILED', 'patch_job_id': 'patch-1'}])
    data = {'can': {}, 'next_path': '/remediations'}
    project_remediations(data, 'remediation_report.html', {'service': service(), 'job': job}, lambda *args: False, {})
    assert data['job']['patched_images'][0]['reason'] == 'Mirror policy missing'
    assert data['job']['patched_images'][0]['patch_job_id'] == 'patch-1'


def test_final_delivery_evidence_is_separate_and_missing_measurements_stay_unknown():
    evidence = {'status': 'VERIFIED', 'offlineVerified': True, 'network': {'isolated': True, 'external_chart_fetches': 0, 'external_image_pulls': 0, 'credentials': 'SECRET'}, 'raw_payload': 'SECRET'}
    job = N(job_key='job', delivery_attempts=[N(id=41, status='download_ready', result={'validation_type': 'offline-bundle', 'service': {'id': 7, 'version': 'v2', 'credentials': 'SECRET'}, 'materialized_digest': 'digest', 'verification': evidence})], validation_results={'deployment': {'status': 'FAILED'}})
    data = {'can': {}, 'next_path': '/remediations'}
    project_remediations(data, 'remediation_report.html', {'service': service(), 'job': job}, lambda *args: True, {})
    attempt = data['job']['delivery_attempts'][0]
    assert attempt['verification']['offlineVerified'] is True
    assert attempt['verification']['network']['external_image_pulls'] == 0
    assert attempt['service'] == {'id': 7, 'version': 'v2'}
    assert data['job']['candidate_validation']['status'] == 'FAILED'
    assert data['job']['original_validation']['offlineVerified'] is None
    assert data['job']['original_validation']['network']['isolated'] is None
    assert 'SECRET' not in json.dumps(data)
