"""Compare an independently retained publisher BOE with a live replica.

No scanner, assessment, database write, or registry mutation is performed. The
source archive must come from System A's approval download, not System B. Native
page/API checks use stable content identities and explicitly describe their
scope; the signed context and archive comparison covers every retained field.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
from urllib.parse import quote, urlencode
from zipfile import ZipFile

from nginx_replica_acceptance import _require, verify_manifest_binding
from nginx_workflow_integration import API


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def checksum(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def normalize_state(state):
    """Ignore database row order, preserving identities, timestamps and list data."""
    result = deepcopy(state)
    for section in ('records', 'extension'):
        for name, value in result.get(section, {}).items():
            if isinstance(value, list):
                result[section][name] = sorted(value, key=canonical)
    if isinstance(result.get('activity'), list):
        result['activity'] = sorted(result['activity'], key=canonical)
    return result


def archive_content(raw, *, max_unpacked=2 * 1024**3):
    """Inspect without extraction; reject duplicate names and expansion bombs."""
    inventory = {}
    with ZipFile(BytesIO(raw)) as archive:
        members = archive.infolist()
        _require(sum(item.file_size for item in members) <= max_unpacked, 'BOE exceeds unpacked limit')
        _require(len({item.filename for item in members}) == len(members), 'Duplicate BOE member')
        for item in members:
            inventory[item.filename] = {'bytes': item.file_size, 'digest': checksum(archive.read(item))}
        _require('replica-service.json' in inventory, 'BOE has no captured service state')
        state = json.loads(archive.read('replica-service.json'))
    return state, inventory


def compare_evidence(source_archive, replica_archive, context, receipt):
    """Fail on any missing/changed evidence, reporting all domains independently."""
    manifest_digest = verify_manifest_binding(context, context['release']['id'], receipt)
    expected_digest = receipt['manifest']['evidence']['digest']
    _require(checksum(source_archive) == expected_digest, 'System A BOE differs from source receipt')
    _require(checksum(replica_archive) == expected_digest, 'System B BOE differs from source receipt')
    source, source_files = archive_content(source_archive)
    imported, imported_files = archive_content(replica_archive)
    _require(source_files == imported_files, 'System B BOE members differ from System A')
    expected = normalize_state(source)
    actual = normalize_state(context['original_evidence'])
    _require(normalize_state(imported) == actual, 'System B API differs from its signed BOE')
    _require(set(expected) == set(actual), 'Captured service top-level fields differ')
    domains = {}
    for section, values in expected.items():
        compared = values.items() if section in ('records', 'extension') else [(None, values)]
        for name, value in compared:
            domain = section + ('.' + name if name is not None else '')
            other = actual.get(section, {}).get(name) if name is not None else actual.get(section)
            _require(value == other, f'Reconstruction mismatch: {domain}')
            domains[domain] = {'equal': True, 'sha256': checksum(canonical(value)),
                              'count': len(value) if isinstance(value, (list, dict)) else None}
    _require(expected == actual, 'System B contains unexpected captured evidence fields')
    release, manifest = context['release'], context['manifest']
    for name in ('approved_at', 'expires_at'):
        # API serialization may remove +00:00 for SQLite; compare UTC instants.
        from datetime import datetime, timezone
        def instant(value):
            if not value:
                return None
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        signed = manifest.get('approval', manifest)
        _require(instant(release.get(name)) == instant(signed.get(name)), f'{name} differs from signed release')
    return {'equal': True, 'manifest_digest': manifest_digest, 'evidence_digest': expected_digest,
            'evidence_bytes': len(source_archive), 'domains': domains,
            'archive_members': source_files, 'normalization': 'Unordered relational rows only; all source IDs, timestamps and nested evidence retained'}


def _fields(row, names):
    return {name: row.get(name) for name in names}


def _bag(rows):
    return Counter(canonical(row) for row in rows)


def verify_native_views(api, state):
    """Compare reconstructed native read views against captured publisher values.

    Detailed history, risk, findings, artifacts and POA&M values are asserted.
    The exchange preview exposes inventory counts, with full row values retained
    in the independently compared signed context. Extension-only records such as
    global lineage and historical Cyber approvals are explicitly identified.
    """
    records, extension = state['records'], state.get('extension', {})
    service = records['services'][0]
    key = quote(service['service_key'], safe='')
    path = '/services/' + key
    report = {}

    def checked(name, count, fields):
        report[name] = {'equal': True, 'count': count, 'fields': fields}

    def paged(base, collection, page_field='total_pages'):
        result, page = [], 1
        while True:
            payload = api.page(base + ('&' if '?' in base else '?') + f'page={page}')
            result.extend(payload.get(collection, []))
            total = payload.get(page_field, 1)
            _require(type(total) is int and 1 <= total <= 10000, 'Invalid native API pagination')
            if page >= total:
                return result
            page += 1

    overview = api.page(path + '?overview=true')
    fields = ('service_key', 'name', 'description', 'owner', 'poc', 'manual_version')
    _require(_fields(overview['view']['service'], fields) == _fields(service, fields), 'Native service metadata differs')
    checked('services', 1, fields)
    versions = {row['id']: row['version'] for row in records['service_versions']}
    expected_version = versions.get(service.get('current_version_id'))
    if expected_version:
        _require(overview['view']['version'] == expected_version, 'Native service version differs')
    checked('service_versions', len(versions), ['current version', 'scan history version selector'])

    artifacts = api.page(path + '?artifacts=true')
    image_fields = ('image_digest', 'image_reference', 'scan_status', 'scan_error', 'lifecycle_status')
    expected_images = {}
    for row in records['service_images']:
        identity = (row.get('image_digest') or row['image_reference']).casefold()
        expected_images.setdefault(identity, []).append(row)
    native_images = {(row['image'].get('image_digest') or row['image']['image_reference']).casefold(): row
                     for row in artifacts['image_inventory']}
    _require(set(expected_images) <= set(native_images), 'Native image inventory is incomplete')
    for identity, rows in expected_images.items():
        # Multiple references to one immutable image are intentionally grouped.
        native = native_images[identity]
        _require({row['image_reference'] for row in rows} <= set(native['references']), 'Native image reference is missing')
        _require(native['count'] >= len(rows), 'Native grouped image count is incomplete')
        row = next((row for row in rows if row['image_reference'] == native['image']['image_reference']), None)
        _require(row is not None, 'Native image representative is not in approved inventory')
        for field in image_fields:
            if field != 'image_reference':
                _require(native['image'].get(field) == row.get(field), 'Native image inventory differs: ' + field)
    checked('service_images', len(records['service_images']), image_fields)
    status = api.get('/api/services/' + key + '/artifacts/images/status')
    by_id = {row['id']: row for row in status['images']}
    for row in native_images.values():
        image = row['image']
        _require(by_id[image['id']]['status'] == (image.get('scan_status') or 'never_scanned') and
                 by_id[image['id']]['error'] == image.get('scan_error'), 'Image status polling changed publisher evidence')
    after_poll = api.page(path + '?artifacts=true')
    _require(after_poll['image_inventory'] == artifacts['image_inventory'], 'Image status polling mutated native inventory')
    artifact_fields = ('artifact_type', 'artifact_name', 'chart_name', 'chart_version', 'source_type')
    native_artifacts = [row for row in artifacts['artifact_rows'] if not row.get('retained_scan')]
    _require(_bag(_fields(row, artifact_fields) for row in records['service_artifacts']) ==
             _bag(_fields(row['artifact'], artifact_fields) for row in native_artifacts), 'Native chart/artifact inventory differs')
    checked('service_artifacts', len(native_artifacts), artifact_fields)
    expected_revisions = {}
    for row in records['service_artifact_revisions']:
        if row['revision_number'] > expected_revisions.get(row['artifact_id'], {}).get('revision_number', 0):
            expected_revisions[row['artifact_id']] = row
    _require(_bag(_fields(row, ('checksum', 'revision_number')) for row in expected_revisions.values()) ==
             _bag(_fields(row['revision'], ('checksum', 'revision_number')) for row in native_artifacts if row['revision']),
             'Native latest artifact revisions differ')
    checked('service_artifact_revisions', len(expected_revisions), ['latest checksum', 'latest revision_number'])

    for version in sorted(set(versions.values())):
        history = paged(path + '/history?' + urlencode({'version': version, 'page_size': 50}), 'snapshots')
        expected = [row for row in records['executions'] if versions.get(row.get('service_version_id'),
                    row['raw_payload'].get('service', {}).get('version')) == version]
        _require(len(history) == len(expected), 'Native scan history count differs')
        # Keys are locally generated, so compare the immutable evidence itself.
        def scan(row):
            return {'complete': row['complete'], 'source_files': sorted(row['source_files']),
                    'service': _fields(row['data'].get('service', {}), ('id', 'name', 'version')),
                    'sbom': [_fields(item, ('name', 'version', 'purl', 'image')) for item in row['data'].get('sbom_components', [])]}
        wanted = [{'complete': row['complete'], 'source_files': sorted(row['raw_payload'].get('helm_source_files', {})),
                   'data': row['raw_payload']} for row in expected]
        _require(_bag(scan(row) for row in history) == _bag(scan(row) for row in wanted), 'Native scan/SBOM history differs')
    checked('executions', len(records['executions']), ['complete', 'source file names', 'service identity/version', 'SBOM name/version/purl/image'])

    findings, policies = {}, {}
    for selection in ('active', 'resolved', 'exceptions', 'vex_excluded'):
        base = path + '?' + urlencode({'findings_view': 'raw', 'finding_state': selection, 'page_size': 250})
        for collection, target in (('findings', findings), ('policy_findings', policies)):
            for row in paged(base, collection):
                target[row['id']] = row
    for collection, actual, fields in [('findings', findings, ('cve', 'severity', 'active')),
            ('policy_findings', policies, ('finding', 'title', 'severity', 'active', 'framework', 'target', 'description', 'remediation'))]:
        _require(_bag(_fields(row, fields) for row in records[collection]) ==
                 _bag(_fields(row, fields) for row in actual.values()), 'Native ' + collection + ' differs')
        checked(collection, len(actual), fields)

    poams = paged(path + '?poam=true&page_size=50', 'entries', 'page_count')
    fields = ('item_type', 'title', 'description', 'remediation', 'ticket', 'status', 'service_version')
    _require(_bag(_fields(row, fields) for row in records['poam_entries']) ==
             _bag(_fields(row, fields) for row in poams), 'Native POA&M entries differ')
    checked('poam_entries', len(poams), fields)
    history_rows = []
    for row in poams:
        detail = api.page('/poam/entries/' + str(row['id']))
        history_rows.extend(detail['history'])
    def actor(identity):
        return state.get('actors', {}).get(str(identity), 'Unavailable original identity') if identity is not None else None
    expected_history = [dict(_fields(row, ('action', 'note')), actor=actor(row.get('actor_user_id')))
                        for row in records['poam_history']]
    _require(_bag(_fields(row, ('action', 'note', 'actor')) for row in history_rows) == _bag(expected_history),
             'Native POA&M history content differs')
    checked('poam_history', len(history_rows), ['action', 'note', 'original actor identity'])

    risk = api.get('/api/risk/services/' + key)
    assessments = [row for row in extension.get('risk_assessments', []) if not row.get('provenance', {}).get('preview')]
    _require(len(risk['history']) == len(assessments), 'Native risk history count differs')
    for summary in risk['history']:
        actual = api.get('/api/risk/assessments/' + str(summary['id']))
        expected = next(row for row in assessments if row['id'] == actual['source_assessment_id'])
        fields = tuple(set(expected) - {'id', 'service_id'})
        _require(_fields(actual, fields) == _fields(expected, fields), 'Native risk assessment differs')
    fields = ('kind', 'decision', 'payload', 'created_by')
    _require(_bag(_fields(row, fields) for row in risk['decisions']) ==
             _bag(_fields(row, fields) for row in extension.get('risk_decisions', [])), 'Native risk decisions differ')
    checked('risk_assessments', len(assessments), ['all assessment fields except remapped local IDs'])
    checked('risk_decisions', len(risk['decisions']), fields)
    native = api.get('/api/risk/services/' + key + '/native-vex')
    context = extension.get('native_vex_context', {})
    for name in ('current', 'enabled', 'pending'):
        if name in context:
            _require(native[name] == context[name], 'Native VEX applicability differs')
    checked('native_vex_context', 1, ['current', 'enabled', 'pending'])
    evaluation = native.get('evaluation')
    if evaluation:
        expected = next(row for row in extension['vex_disposition_evaluations'] if row['id'] == evaluation['id'])
        _require(evaluation == expected, 'Native VEX evaluation differs')
    observed = []
    cursors = set()
    while True:
        observed.extend(native.get('items', []))
        cursor = native.get('next_after')
        if cursor is None:
            break
        _require(cursor not in cursors and len(cursors) < 10000, 'Native VEX pagination did not terminate')
        cursors.add(cursor)
        native = api.get('/api/risk/services/' + key + '/native-vex?after=' + str(cursor))
    expected = [row for row in extension.get('vex_observation_dispositions', [])
                if evaluation and row['evaluation_id'] == evaluation['id']]
    restored = []
    for row in observed:
        original = {name: value for name, value in row.items()
                    if name not in ('source_finding_id', 'source_observation_id', 'verified_not_affected', 'effective_disposition')}
        original.update(finding_id=row['source_finding_id'], observation_id=row['source_observation_id'])
        restored.append(original)
    _require(_bag(restored) == _bag(expected), 'Native VEX observation evidence differs')
    checked('vex_observation_dispositions', len(observed), ['all fields with remapped IDs restored'])
    documents = extension.get('vex_documents', [])
    if risk['history']:
        for document in documents:
            actual = api.get('/api/risk/assessments/' + str(risk['history'][0]['id']) + '/documents/' + str(document['id']))
            _require(actual == document, 'Native original VEX document differs')
        checked('vex_documents', len(documents), ['all original fields and raw text'])
    activity = paged(path + '?activity=true&page_size=100', 'events', 'page_count')
    activity_fields = ('id', 'action')
    expected = [dict(_fields(row, activity_fields), actor_name=actor(row.get('actor_user_id')) or 'System')
                for row in state.get('activity', [])]
    _require(_bag(_fields(row, (*activity_fields, 'actor_name')) for row in activity) == _bag(expected),
             'Native service activity differs')
    checked('activity', len(activity), [*activity_fields, 'original actor identity'])
    for template in ('ppsm', 'assets'):
        page = api.page(path + '/exchange?' + urlencode({'template': template}))
        configured = [row for row in records['inventory_records']
                      if row['dataset'] == template and row['version'] == page['version']]
        _require(page['row_count'] >= len({row['record_key'] for row in configured}),
                 'Native inventory preview is missing configured rows: ' + template)
        for name, value in (page.get('metadata') or {}).items():
            expected = next(iter(records['service_metadata']), {}).get('values', {}).get(name)
            _require(value == expected, 'Native mission metadata differs: ' + name)
        checked('exchange.' + template, page['row_count'], ['configured row lower bound', 'visible mission metadata'])
    report['context_only_domains'] = sorted(set(records) - set(report)) + sorted('extension.' + name
        for name in extension if name not in report)
    report['scope'] = ('Every source field is compared in signed context/BOE. Native checks compare the listed public fields; '
                       'extension-only records and non-displayed fields remain inspectable in the existing release evidence view.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-evidence', type=Path, required=True)
    parser.add_argument('--source-receipt', type=Path, required=True)
    parser.add_argument('--replica-url', required=True)
    parser.add_argument('--ca-bundle', type=Path, help='Trusted private deployment CA bundle; TLS verification stays enabled')
    parser.add_argument('--username', required=True)
    parser.add_argument('--password-env', default='CATS_QUALIFICATION_PASSWORD')
    parser.add_argument('--release-id', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--skip-native', action='store_true', help='For historical releases only; report omission explicitly')
    args = parser.parse_args()
    api = API(args.replica_url)
    if args.ca_bundle:
        api.session.verify = str(args.ca_bundle)
    api.login(args.username, os.environ[args.password_env])
    path = f'/api/replica/releases/{args.release_id}'
    context = api.get(path + '/context')
    raw = api.request('GET', path + '/evidence').content
    report = compare_evidence(args.source_evidence.read_bytes(), raw, context,
                              json.loads(args.source_receipt.read_text(encoding='utf-8-sig')))
    if not args.skip_native:
        _require(context['release']['status'] == 'active', 'Native views require the active release')
        report['native_views'] = verify_native_views(api, context['original_evidence'])
        _require(api.get(path + '/context')['original_evidence'] == context['original_evidence'],
                 'Read-only view checks changed retained evidence')
    else:
        report['native_views'] = {'skipped': 'Historical release; native service views show the active release'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'equal': report['equal'], 'domains': len(report['domains']),
                      'archive_members': len(report['archive_members']), 'report': str(args.output)}))


if __name__ == '__main__':
    main()
