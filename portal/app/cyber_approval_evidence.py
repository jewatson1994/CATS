"""Freeze approval evidence without resolving mutable tags or reconstructing scans."""
from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED, BadZipFile

import yaml
from sqlalchemy import select
from .models import (RemediationExecution, Finding, PolicyFinding,
                     ExceptionRecord, PolicyExceptionRecord, PoamEntry)
from .deployment_bundle import safe_path, file_digest, dependency_inventory, workload_images
from .execution_summaries import payload_digest
from .overview import normalize_overview, parse_image_reference
from .service_evidence import current_execution
from .policy_data import review_intelligence_snapshot

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _row(row):
    return {column.key: getattr(row, column.key) for column in row.__table__.columns}


def _repository_identity(reference):
    parsed = parse_image_reference(reference)
    registry = parsed['registry']
    if registry in {'index.docker.io', 'registry-1.docker.io'}:
        registry = 'docker.io'
    repository = parsed['repository']
    if registry == 'docker.io' and repository == '—':
        repository = 'library'
    return registry, repository, parsed['artifact']


def _identity(reference, digest=None):
    reference = str(reference or '').strip().removeprefix('oci://')
    embedded = reference.rsplit('@', 1)[1] if '@' in reference else None
    # Scanner evidence may retain Docker/Syft's full repository digest.
    if isinstance(digest, str) and '@' in digest:
        retained_reference, retained_digest = digest.rsplit('@', 1)
        if (not retained_reference or '@' in retained_reference
                or any(c.isspace() for c in retained_reference)
                or _repository_identity(retained_reference) != _repository_identity(reference)):
            raise ValueError('Retained image digest repository does not match: ' + reference)
        digest = retained_digest
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
    review_notes = []
    execution = current_execution(db, service) if service.current_version_id is not None else None
    result = {'ready': False, 'blockers': blockers, 'execution': execution, 'remediation': None,
              'artifacts': [], 'overview': {}, 'variant': variant, 'review_notes': review_notes,
              'version': service.current_version.version if service.current_version else None,
              'scan_date': execution.scanned_at.isoformat() if execution else None}
    if variant not in {'current_service', 'cats_remediated'}:
        blockers.append('Unsupported release variant.')
    if execution is None:
        blockers.append('A retained scan for the exact current service version is required.')
        return result
    if execution.scan_scope == 'image':
        review_notes.append('Evidence covers the selected image scan only; whole-service configuration and deployment coverage have not been established.')
    payload = json.loads(json.dumps(execution.raw_payload or {}))
    if not execution.complete:
        blockers.append('The selected current-version scan is incomplete.')
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
        review_notes.append('Retained render warnings require Cyber review.')
    files = dict(payload.get('helm_source_files') or payload.get('source_files') or {})
    values = list(payload.get('helm_values_files') or [])
    resources = raw.get('rendered_resources') or payload.get('rendered_resources') or []
    rendered = yaml.safe_dump_all(resources, sort_keys=False) if resources else ''
    image_rows = list(raw.get('images') or raw.get('container_images') or [])
    image_rows.extend({'image': row['image'], 'digest': row.get('image_digest')}
        for row in payload.get('findings', []) if row.get('image'))
    candidate_path = None
    record = None
    if variant == 'cats_remediated':
        record = db.get(RemediationExecution, remediation_id) if remediation_id else None
        result['remediation'] = record
        if not record or record.service_id != service.id or record.source_execution_id != execution.id or record.source_version_id != service.current_version_id:
            blockers.append('Candidate must belong to the exact current service scan and version.')
        else:
            if record.remediation_status != 'complete' or record.verification_status != 'verified':
                review_notes.append(f'Candidate remediation: {record.remediation_status}; deployment verification: {record.verification_status}.')
            scans = record.scan_results or {}
            if any((scans.get(key) or {}).get('status') != 'PASS' for key in ('configuration', 'vulnerabilities')):
                review_notes.append('Candidate scan checks did not all pass. Review retained findings and scan coverage.')
            if (record.workflow_inputs or {}).get('excluded_charts') or (record.workflow_inputs or {}).get('validation_skipped'):
                review_notes.append('Candidate has excluded charts or skipped validation; review the retained remediation scope.')
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
                        review_notes.append('Candidate deployment inventory is unavailable; deployability has not been established.')
                    for name, item in (deployment.get('files') or {}).items():
                        if name not in names:
                            raise ValueError('Candidate deployment file is missing')
                        with archive.open(name) as stream:
                            digest = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
                        if digest != item.get('sha256') or archive.getinfo(name).file_size != item.get('bytes'):
                            raise ValueError('Candidate deployment file digest mismatch')
                    if deployment and not deployment.get('files'):
                        raise ValueError('Candidate deployment file inventory is missing')
                    files = {name[10:]: archive.read(name) for name in names if name.startswith('candidate/') and not name.endswith('/')}
                    values = list(manifest.get('values_files') or [])
                    rendered = archive.read('scans/rendered-after.yaml').decode('utf-8') if 'scans/rendered-after.yaml' in names else ''
                    config_scan = json.loads(archive.read('scans/trivy-config-after.json')) if 'scans/trivy-config-after.json' in names else None
                    if config_scan is not None and not isinstance(config_scan, dict):
                        raise ValueError('Candidate configuration scan evidence is invalid')
                    replacements = {}
                    for item in manifest.get('images') or []:
                        if not item.get('remediated'):
                            raise ValueError('Candidate contains an unresolved image')
                        replacement = {'image': item['remediated'], 'digest': item.get('remediated_digest')}
                        if item.get('archive_path'):
                            name = safe_path(item['archive_path'])
                            if name not in names:
                                raise ValueError('Candidate image archive is missing')
                            with archive.open(name) as stream:
                                actual = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
                            if actual != 'sha256:' + str(item.get('artifact_sha256') or '').removeprefix('sha256:'):
                                raise ValueError('Candidate image archive digest mismatch')
                            replacement.update(archive_path=name, archive_digest=actual)
                        replacements[item.get('original')] = replacement
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
    helm_required = bool(values or any(PurePosixPath(name).name == 'Chart.yaml' for name in files) or (not candidate_path and (raw.get('charts') or raw.get('helm_charts')))
                         or payload.get('helm_charts') or payload.get('chart_inputs'))
    if helm_required and not files:
        blockers.append('Complete retained Helm chart sources are required for approved publication.')
    if helm_required and not rendered.strip():
        review_notes.append('Rendered deployment evidence is unavailable.')
    for name in values:
        if name not in files:
            blockers.append('Missing retained scan values file: ' + str(name))
    charts = []
    try:
        charts = _charts(files)
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
            if isinstance(item, dict) and item.get('archive_path'):
                identities[reference] = {'kind': 'image', 'reference': reference,
                    'digest': item['archive_digest'], 'archive_path': item['archive_path']}
                continue
            # Old scans sometimes stored the tag itself in image_digest. It is
            # not an immutable identity; retain that limitation for Cyber review.
            if not digest or digest == reference:
                if '@' not in str(reference):
                    from .cyber_release_publication import image_source
                    image_source(reference)  # Validate syntax without registry access.
                    identities.setdefault(reference, {'kind': 'image', 'reference': reference,
                        'digest': None, 'resolve_at_publication': True})
                    continue
            pinned, digest = _identity(reference, digest)
            if reference in identities and identities[reference]['digest'] and identities[reference]['digest'] != digest:
                raise ValueError('Conflicting retained image digests: ' + reference)
            identities[reference] = {'kind': 'image', 'reference': pinned, 'digest': digest}
        except ValueError as exc:
            blockers.append(str(exc))
    try:
        for reference in workload_images(rendered):
            if reference not in identities:
                if '@' in reference:
                    pinned, digest = _identity(reference)
                    identities[reference] = {'kind': 'image', 'reference': pinned, 'digest': digest}
                else:
                    from .cyber_release_publication import image_source
                    image_source(reference)
                    identities[reference] = {'kind': 'image', 'reference': reference, 'digest': None, 'resolve_at_publication': True}
    except (ValueError, yaml.YAMLError) as exc:
        blockers.append('Rendered image reference is invalid: ' + str(exc))
    if record and candidate_path:
        overview = normalize_overview({'source': 'CATS Remediated candidate', 'images': image_rows,
            'charts': [{'name': item['name'], 'version': item['version']} for item in charts]}, digest_resolver=None)
    for reference, item in identities.items():
        if item.get('resolve_at_publication'):
            review_notes.append('Image identity was not retained for ' + reference + '. Its tag will be resolved at publication and may differ from the scanned image.')
    if not identities and not charts:
        blockers.append('No complete retained image or chart inventory is available.')
    if not charts:
        review_notes.append('No Helm charts were supplied for this release.')
    configuration_available = (result.get('candidate_config_scan') is not None if record else
        bool(payload.get('policy_findings') or payload.get('configuration_scan') or payload.get('config_scan')))
    if not configuration_available:
        review_notes.append('No configuration findings or scan-completion record was retained. Configuration coverage is not established.')
    result['review_notes'] = list(dict.fromkeys(review_notes))
    inventory = {}
    for source, item in identities.items():
        artifact = inventory.setdefault(item['reference'], {**item, 'source_references': []})
        artifact['source_references'].append(source)
    # Findings repeat an image's identity once per CVE; report each problem once.
    blockers[:] = dict.fromkeys(blockers)
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


def _finding_identifiers(findings):
    """Identifiers from the retained pipeline, Grype and Trivy evidence formats."""
    rows = list(findings.get('vulnerabilities') or [])
    for scan in (findings.get('vulnerability_scans') or {}).values():
        if not isinstance(scan, dict):
            continue
        rows.extend(scan.get('matches') or [])
        for target in scan.get('Results') or []:
            if isinstance(target, dict):
                rows.extend(target.get('Vulnerabilities') or [])
    for row in rows:
        if isinstance(row, dict):
            yield row.get('cve') or row.get('finding') or row.get('VulnerabilityID') or (row.get('vulnerability') or {}).get('id') or ''


def _service_context(service, readiness):
    """Small, frozen review context; never borrow baseline topology for a candidate."""
    from collections import Counter
    from .architecture import build_architecture_graph, _resource_list
    from .compose_architecture import compose_services

    if readiness['remediation']:
        payload = {'service_overview': readiness['overview'],
                   'rendered_resources': [row for row in yaml.safe_load_all(readiness['rendered'])
                                          if isinstance(row, dict)]}
    else:
        payload = readiness['payload']
    resources = _resource_list(payload)
    compose = compose_services(payload)
    kinds = {item['kind'] for item in readiness['artifacts']}
    deployment_types = []
    if compose:
        deployment_types.append('Docker Compose')
    if 'chart' in kinds:
        deployment_types.append('Helm')
    elif resources:
        deployment_types.append('Kubernetes manifests')
    if not deployment_types and 'image' in kinds:
        deployment_types.append('Container images')
    architecture = None
    if resources or compose:
        graph = build_architecture_graph(payload, layouts=False)
        architecture = {
            'components': dict(sorted(Counter(node['kind'] for node in graph['nodes']).items())),
            'relationships': len(graph['relationships']),
            'unresolved': len(graph['unresolved']),
            'incomplete': graph['incomplete'],
            'basis': 'Declared configuration; runtime reachability is not verified',
        }
    return {'description': str(service.description or '').strip()[:600],
            'owner': str(service.owner or '').strip()[:240],
            'deployment_types': deployment_types, 'architecture': architecture}


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
        'evidence_scope': 'remediation-candidate' if record else f'current-{execution.scan_scope}-scan',
        'review_notes': readiness['review_notes'],
        'service_context': _service_context(service, readiness),
        'findings': {'summary': record.after_snapshot, 'configuration': readiness['candidate_config_scan'],
                     'vulnerability_scans': readiness['candidate_vulnerability_scans']} if record else {'vulnerabilities': readiness['payload'].get('findings', []), 'configuration': readiness['payload'].get('policy_findings', [])},
        'mitigations': [_row(row) for row in db.scalars(select(PoamEntry).where(PoamEntry.service_id == service.id))],
        'exceptions': exceptions, 'remediation': _row(record) if record else None, 'artifacts': []}
    snapshot['risk_intelligence'] = review_intelligence_snapshot(
        _finding_identifiers(snapshot['findings']), datetime.now(timezone.utc).isoformat())
    snapshot = json.loads(_json(snapshot))
    snapshot['source_payload_digest'] = payload_digest(readiness['payload'])
    for index, item in enumerate(readiness['artifacts']):
        artifact = {key: value for key, value in item.items() if key != 'sources'}
        if item['kind'] == 'chart':
            path = folder / f'chart-{index}.tgz'
            _package_chart(item, path)
            artifact.update(path=str(path.resolve()), digest=file_digest(path))
        if item.get('archive_path'):
            path = folder / f'image-{index}.tar'
            with ZipFile(readiness['candidate_path']) as archive, archive.open(item['archive_path']) as source, path.open('wb') as output:
                shutil.copyfileobj(source, output)
            if file_digest(path) != item['digest']:
                raise ValueError('Candidate image archive changed while freezing')
            artifact.update(path=str(path.resolve()), format='docker-archive')
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
            archive.write(folder / 'candidate.zip', 'candidate/candidate.zip')
            archive.writestr('candidate/configuration-scan.json', _json(readiness['candidate_config_scan']))
        if record:
            from openpyxl import Workbook
            workbook = Workbook()
            workbook.remove(workbook.active)
            for name, content in [('Candidate findings', snapshot['findings']), ('Candidate scans', record.scan_results), ('Mitigations', snapshot['mitigations']), ('Exceptions', snapshot['exceptions'])]:
                sheet = workbook.create_sheet(name)
                sheet.append(['Evidence scope', 'Record'])
                entries = content if isinstance(content, list) else [content]
                for entry in entries:
                    sheet.append(['CATS Remediated candidate' if name.startswith('Candidate') else 'Service context at approval', _json(entry)])
            stream = io.BytesIO()
            workbook.save(stream)
            workbook.close()
            archive.writestr('candidate/evidence.xlsx', stream.getvalue())
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
