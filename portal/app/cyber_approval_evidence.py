"""Freeze approval evidence without resolving mutable tags or reconstructing scans."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED, BadZipFile

import yaml
from sqlalchemy import select
from .models import (Execution, RemediationExecution, Finding, PolicyFinding,
                     ExceptionRecord, PolicyExceptionRecord, PoamEntry)
from .deployment_bundle import safe_path, file_digest, dependency_inventory, workload_images
from .execution_summaries import payload_digest
from .overview import normalize_overview

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _row(row):
    return {column.key: getattr(row, column.key) for column in row.__table__.columns}


def _identity(reference, digest=None):
    reference = str(reference or '').strip().removeprefix('oci://')
    embedded = reference.rsplit('@', 1)[1] if '@' in reference else None
    if digest is not None and not DIGEST.fullmatch(str(digest)):
        raise ValueError('Invalid retained image digest: ' + reference)
    digest = digest or embedded
    if not DIGEST.fullmatch(str(digest or '')) or (embedded and embedded != digest):
        raise ValueError('Missing or inconsistent immutable image digest: ' + reference)
    repository = reference.split('@')[0]
    if ':' in repository.rsplit('/', 1)[-1]:
        repository = repository.rsplit(':', 1)[0]
    if not repository or any(c.isspace() for c in repository):
        raise ValueError('Invalid artifact reference')
    return repository + '@' + digest, digest


def _charts(files):
    """Validate every retained root and require vendored exact dependencies."""
    result = []
    with tempfile.TemporaryDirectory(prefix='cats-approval-chart-') as temporary:
        root = Path(temporary)
        for name, content in files.items():
            target = root / safe_path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if not isinstance(content, (str, bytes)):
                raise ValueError('Unsupported retained chart source encoding')
            target.write_bytes(content.encode() if isinstance(content, str) else content)
        chart_paths = {PurePosixPath(name) for name in files if PurePosixPath(name).name == 'Chart.yaml'}
        charts = [str(name) for name in chart_paths
                  if not any(parent / 'Chart.yaml' in chart_paths for parent in name.parent.parents)]
        for name in sorted(charts):
            directory = PurePosixPath(name).parent
            metadata = yaml.safe_load((root / name).read_text(encoding='utf-8'))
            if not isinstance(metadata, dict) or not metadata.get('name') or not metadata.get('version'):
                raise ValueError('Retained chart lacks name or version')
            chart_name = str(metadata['name'])
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', chart_name):
                raise ValueError('Invalid retained chart name')
            dependencies = dependency_inventory(root / directory, strict=True)
            sources = {str(PurePosixPath(key).relative_to(directory)): value for key, value in files.items()
                       if PurePosixPath(key).is_relative_to(directory)}
            result.append({'kind': 'chart', 'name': chart_name, 'version': str(metadata['version']),
                           'source_root': str(directory), 'sources': sources, 'dependencies': dependencies})
    return result


def readiness(db, service, variant='current_service', remediation_id=None):
    db.refresh(service)
    blockers = []
    execution = db.scalar(select(Execution).where(Execution.service_id == service.id,
        Execution.service_version_id == service.current_version_id, Execution.scan_scope == 'service')
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1).execution_options(populate_existing=True)) if service.current_version_id else None
    result = {'ready': False, 'blockers': blockers, 'execution': execution, 'remediation': None,
              'artifacts': [], 'overview': {}, 'variant': variant}
    if variant not in {'current_service', 'cats_remediated'}:
        blockers.append('Unsupported release variant.')
    if execution is None:
        blockers.append('A service scan for the exact current version is required.')
        return result
    payload = json.loads(json.dumps(execution.raw_payload or {}))
    if not execution.complete:
        blockers.append('The latest service scan is incomplete.')
    if execution.payload_digest and execution.payload_digest != payload_digest(payload):
        blockers.append('Retained scan digest mismatch.')
    if not payload.get('sbom_components'):
        blockers.append('Retained SBOM component evidence is required for Export All.')
    raw = payload.get('service_overview') or {}
    overview = normalize_overview(raw, skipped_images=payload.get('skipped_images') or [],
        skipped_charts=payload.get('skipped_charts') or [], incomplete=not execution.complete, digest_resolver=None)
    for item in overview['missing_evidence']:
        blockers.append(f"Missing {item.get('type', 'scan')} evidence: {item.get('item')} - {item.get('reason')}")
    if overview['warnings']:
        blockers.append('Retained render warnings require resolution before approval.')
    files = dict(payload.get('helm_source_files') or payload.get('source_files') or {})
    values = list(payload.get('helm_values_files') or [])
    resources = raw.get('rendered_resources') or payload.get('rendered_resources') or []
    rendered = yaml.safe_dump_all(resources, sort_keys=False) if resources else ''
    image_rows = list(raw.get('images') or raw.get('container_images') or [])
    image_rows.extend({'image': row['image'], 'digest': row.get('image_digest')}
        for row in payload.get('findings', []) if row.get('image') and row.get('image_digest'))
    candidate_path = None
    record = None
    if variant == 'cats_remediated':
        record = db.get(RemediationExecution, remediation_id) if remediation_id else None
        result['remediation'] = record
        if not record or record.service_id != service.id or record.source_execution_id != execution.id or record.source_version_id != service.current_version_id:
            blockers.append('Candidate must belong to the exact current service scan and version.')
        else:
            if record.remediation_status != 'complete' or record.verification_status != 'verified':
                blockers.append('Candidate remediation and deployment verification must be complete.')
            scans = record.scan_results or {}
            if any((scans.get(key) or {}).get('status') != 'PASS' for key in ('configuration', 'vulnerabilities')):
                blockers.append('Successful retained candidate configuration and vulnerability scans are required.')
            if (record.workflow_inputs or {}).get('excluded_charts') or (record.workflow_inputs or {}).get('validation_skipped'):
                blockers.append('Partial or unverified candidates cannot be approved.')
            try:
                from . import main
                from .remediation_delivery import retained_candidate, checked_inventory
                candidate_path = retained_candidate(record, main.REMEDIATION_JOB_ROOT)
                with ZipFile(candidate_path) as archive:
                    names = checked_inventory(archive)
                    manifest = json.loads(archive.read('manifest.json'))
                    if manifest.get('source_execution_id') != execution.id or manifest.get('source_version_id') != service.current_version_id:
                        raise ValueError('Candidate source identity mismatch')
                    deployment = manifest.get('deployment_manifest') or {}
                    if not deployment.get('deployment'):
                        raise ValueError('Candidate deployment inventory is unavailable')
                    for name, item in (deployment.get('files') or {}).items():
                        if name not in names:
                            raise ValueError('Candidate deployment file is missing')
                        with archive.open(name) as stream:
                            digest = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
                        if digest != item.get('sha256') or archive.getinfo(name).file_size != item.get('bytes'):
                            raise ValueError('Candidate deployment file digest mismatch')
                    if not deployment.get('files'):
                        raise ValueError('Candidate deployment file inventory is missing')
                    files = {name[10:]: archive.read(name) for name in names if name.startswith('candidate/') and not name.endswith('/')}
                    values = list(manifest.get('values_files') or [])
                    rendered = archive.read('scans/rendered-after.yaml').decode('utf-8')
                    config_scan = json.loads(archive.read('scans/trivy-config-after.json'))
                    if not isinstance(config_scan, dict):
                        raise ValueError('Candidate configuration scan evidence is invalid')
                    replacements = {}
                    for item in manifest.get('images') or []:
                        if not item.get('remediated'):
                            raise ValueError('Candidate contains an unresolved image')
                        reference, digest = _identity(item['remediated'], item.get('remediated_digest'))
                        replacements[item.get('original')] = {'image': item['remediated'], 'digest': digest}
                        if not item.get('evidence') or any(value != 'complete' for value in item['evidence'].values()):
                            raise ValueError('Candidate patched image scan evidence is incomplete')
                    patched = list((record.scan_results or {}).get('images') or {})
                    if len(patched) != len(manifest.get('images') or []):
                        raise ValueError('Candidate patched image scan inventory mismatch')
                    vulnerability_scans = {}
                    for patch in patched:
                        for name in (f'scans/{patch}-grype-after.json', f'sbom/{patch}.json'):
                            if name not in names or not isinstance(json.loads(archive.read(name)), dict):
                                raise ValueError('Candidate image scanner/SBOM artifact is unavailable')
                        name = f'scans/{patch}-grype-full-after.json'
                        if name not in names:
                            name = f'scans/{patch}-grype-after.json'
                        vulnerability_scans[patch] = json.loads(archive.read(name))
                    image_rows = [replacements.get(item.get('image') or item.get('reference'), item) if isinstance(item, dict) else replacements.get(item, item) for item in image_rows]
                    image_rows.extend(replacements.values())
                    result['candidate_manifest'] = manifest
                    result['candidate_config_scan'] = config_scan
                    result['candidate_vulnerability_scans'] = vulnerability_scans
            except (ValueError, OSError, KeyError, TypeError, BadZipFile) as exc:
                blockers.append(str(exc))
    helm_required = bool(files or rendered or values or raw.get('charts') or raw.get('helm_charts')
                         or payload.get('helm_charts') or payload.get('chart_inputs') or candidate_path)
    if helm_required and not files:
        blockers.append('Complete retained Helm chart sources are required for approved publication.')
    if helm_required and not rendered.strip():
        blockers.append('Retained rendered deployment evidence is required.')
    for name in values:
        if name not in files:
            blockers.append('Missing retained scan values file: ' + str(name))
    charts = []
    try:
        charts = _charts(files)
        if files and not charts:
            blockers.append('No complete retained root Helm chart was found.')
    except (ValueError, OSError, yaml.YAMLError, tarfile.TarError) as exc:
        blockers.append(str(exc))
    # Charts discovered by the scanner must be represented, never quietly omitted.
    known = {(item['name'], item['version']) for item in charts}
    known.update((item['name'], item['version']) for chart in charts
                 for item in chart['dependencies'] if item.get('vendored'))
    for item in ([] if candidate_path else raw.get('charts') or raw.get('helm_charts') or []):
        if not isinstance(item, dict) or (str(item.get('name') or item.get('chart') or ''), str(item.get('version') or '')) not in known:
            blockers.append('A scanned chart cannot be matched to retained exact chart sources.')
    identities = {}
    for item in image_rows:
        reference = item.get('image') or item.get('reference') or item.get('name') if isinstance(item, dict) else item
        digest = item.get('digest') or item.get('image_digest') if isinstance(item, dict) else None
        try:
            pinned, digest = _identity(reference, digest)
            if reference in identities and identities[reference]['digest'] != digest:
                raise ValueError('Conflicting retained image digests: ' + reference)
            identities[reference] = {'kind': 'image', 'reference': pinned, 'digest': digest}
        except ValueError as exc:
            blockers.append(str(exc))
    try:
        for reference in workload_images(rendered):
            if reference not in identities:
                pinned, digest = _identity(reference)
                identities[reference] = {'kind': 'image', 'reference': pinned, 'digest': digest}
    except (ValueError, yaml.YAMLError) as exc:
        blockers.append('Rendered image has no retained immutable identity: ' + str(exc))
    if record and candidate_path:
        overview = normalize_overview({'source': 'Verified remediation candidate', 'images': image_rows,
            'charts': [{'name': item['name'], 'version': item['version']} for item in charts]}, digest_resolver=None)
    if not identities and not charts:
        blockers.append('No complete retained image or chart inventory is available.')
    inventory = {}
    for source, item in identities.items():
        artifact = inventory.setdefault(item['reference'], {**item, 'source_references': []})
        artifact['source_references'].append(source)
    result.update(ready=not blockers, overview=overview, payload=payload, source_files=files,
        rendered=rendered, values_files=values, candidate_path=candidate_path,
        artifacts=list(inventory.values()) + charts)
    return result


def _package_chart(artifact, path):
    with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
        for name, content in sorted(artifact['sources'].items()):
            content = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(artifact['name'] + '/' + safe_path(name))
            info.size, info.mode, info.mtime = len(content), 0o644, 0
            archive.addfile(info, io.BytesIO(content))


def freeze(db, service, auth, readiness, folder: Path):
    if not readiness['ready'] or readiness['blockers']:
        raise ValueError('Approval evidence is not ready')
    # Recheck mutable source state at the moment the snapshot is made.
    fresh = globals()['readiness'](db, service, readiness['variant'],
        readiness['remediation'].id if readiness['remediation'] else None)
    if not fresh['ready'] or fresh['execution'].id != readiness['execution'].id:
        raise ValueError('Approval evidence changed; refresh readiness')
    readiness = fresh
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    execution, record = readiness['execution'], readiness['remediation']
    exceptions = [_row(row) for row in db.scalars(select(ExceptionRecord).join(Finding).where(Finding.service_id == service.id))]
    exceptions += [_row(row) for row in db.scalars(select(PolicyExceptionRecord).join(PolicyFinding).where(PolicyFinding.service_id == service.id))]
    snapshot = {'schema_version': 'cats.cyber-approval/v1', 'variant': readiness['variant'],
        'service_id': service.id, 'service_key': service.service_key, 'version': service.current_version.version,
        'source_execution_id': execution.id, 'source_version_id': execution.service_version_id,
        'scan_date': execution.scanned_at.isoformat(), 'overview': readiness['overview'],
        'evidence_scope': 'verified-remediation-candidate' if record else 'current-service-scan',
        'findings': {'summary': record.after_snapshot, 'configuration': readiness['candidate_config_scan'],
                     'vulnerability_scans': readiness['candidate_vulnerability_scans']} if record else {'vulnerabilities': readiness['payload'].get('findings', []), 'configuration': readiness['payload'].get('policy_findings', [])},
        'mitigations': [_row(row) for row in db.scalars(select(PoamEntry).where(PoamEntry.service_id == service.id))],
        'exceptions': exceptions, 'remediation': _row(record) if record else None, 'artifacts': []}
    snapshot = json.loads(_json(snapshot))
    snapshot['source_payload_digest'] = payload_digest(readiness['payload'])
    for index, item in enumerate(readiness['artifacts']):
        artifact = {key: value for key, value in item.items() if key != 'sources'}
        if item['kind'] == 'chart':
            path = folder / f'chart-{index}.tgz'
            _package_chart(item, path)
            artifact.update(path=str(path.resolve()), digest=file_digest(path))
        snapshot['artifacts'].append(artifact)
    from .service_exports import write_all
    evidence = folder / 'all.zip'
    baseline = folder / 'current-service-all.zip' if record else evidence
    with baseline.open('wb') as output:
        exported = write_all(output, service, db, auth)
    unavailable = [item['name'] for item in exported.get('entries', []) if item.get('status') != 'included']
    if unavailable:
        raise ValueError('Export All evidence unavailable: ' + ', '.join(unavailable))
    if record:
        shutil.copyfile(readiness['candidate_path'], folder / 'candidate.zip')
        snapshot['candidate'] = {'path': str((folder / 'candidate.zip').resolve()), 'digest': file_digest(folder / 'candidate.zip')}
        snapshot['current_service_evidence'] = {'path': str(baseline.resolve()), 'digest': file_digest(baseline), 'evidence_scope': 'current-service-baseline-not-candidate'}
    with ZipFile(evidence, 'w' if record else 'a', ZIP_DEFLATED) as archive:
        if record:
            archive.write(baseline, 'current-service-baseline/all.zip')
            archive.write(folder / 'candidate.zip', 'verified-candidate/candidate.zip')
            archive.writestr('verified-candidate/configuration-scan.json', _json(readiness['candidate_config_scan']))
        if record:
            from openpyxl import Workbook
            workbook = Workbook()
            workbook.remove(workbook.active)
            for name, content in [('Candidate findings', snapshot['findings']), ('Candidate scans', record.scan_results), ('Mitigations', snapshot['mitigations']), ('Exceptions', snapshot['exceptions'])]:
                sheet = workbook.create_sheet(name)
                sheet.append(['Evidence scope', 'Record'])
                entries = content if isinstance(content, list) else [content]
                for entry in entries:
                    sheet.append(['Verified remediation candidate' if name.startswith('Candidate') else 'Service context at approval', _json(entry)])
            stream = io.BytesIO()
            workbook.save(stream)
            workbook.close()
            archive.writestr('verified-candidate/evidence.xlsx', stream.getvalue())
        archive.writestr('frozen-snapshot.json', _json(snapshot))
        archive.writestr('source-scan.json', _json(readiness['payload']))
        archive.writestr('scan-values-files.json', _json(readiness['values_files']))
        archive.writestr('rendered.yaml', readiness['rendered'])
        for name, content in readiness['source_files'].items():
            archive.writestr('chart-sources/' + safe_path(name), content)
        for item in snapshot['artifacts']:
            if item['kind'] == 'chart':
                archive.write(item['path'], 'charts/' + Path(item['path']).name)
    final = globals()['readiness'](db, service, readiness['variant'], record.id if record else None)
    if (not final['ready'] or final['execution'].id != execution.id
            or payload_digest(final['payload']) != payload_digest(readiness['payload'])
            or (record and file_digest(readiness['candidate_path']) != record.artifact_digest)):
        raise ValueError('Service evidence changed while freezing; retry the request')
    snapshot['evidence'] = {'path': str(evidence.resolve()), 'digest': file_digest(evidence), 'format': 'cats-export-all-v1', 'evidence_scope': snapshot['evidence_scope']}
    return snapshot
