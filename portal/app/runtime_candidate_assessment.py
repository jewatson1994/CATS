"""Join immutable runtime inventory to local, service-bound scanner receipts."""
from datetime import timedelta
from itertools import chain
import logging
import secrets
import shutil
import tarfile
from types import SimpleNamespace

from fastapi import HTTPException
from sqlalchemy import or_, select
import yaml

from . import cyber_approval_evidence as approvals
from .artifact_catalog import GlobalArtifact, ServiceArtifactAssignment
from .artifact_submissions import ProjectArtifactSubmission
from .database import SessionLocal
from .deployment_bundle import file_digest
from .discovery_helm_network import CHART_LAYER
from .execution_summaries import payload_digest
from .models import Execution, Service, ServiceVersion
from .pipeline_scan_dispatch import active_owner_id, prepare_scan
from . import runtime_discovery_charts as discovery_charts
from .proposal_scans import freshness_deadline
from .release_validity import utc
from .runtime_candidates import RuntimeReleaseCandidate, checksum, conflicting_tag_repository, require_current, trusted_scan_reference
from .runtime_image_manifests import IMAGE_TYPES, INDEX_BLOCKER, check_scanned_platform, known_index_digests
from .runtime_models import now
from .scan_coordination import ScanJob, TERMINAL


def chart_key(chart):
    return 'chart:' + checksum([chart['name'], chart['version'], chart['digest']])


def _assets(inventory):
    for image in inventory['images']:
        yield image['reference'], image
    charts = {chart_key(item): item for item in inventory['charts']}
    yield from sorted(charts.items())


def _bound(db, job, service):
    return (job and job.service_key == service.service_key and job.payload.get('ingest_service_db_id') == service.id
            and bool(job.payload.get('pipeline_owning_group_id'))
            and job.payload['pipeline_owning_group_id'] == active_owner_id(db, service.id))


def _project_job(db, job, service):
    if not _bound(db, job, service):
        return False
    submission = db.get(ProjectArtifactSubmission, job.id)
    return bool(submission and submission.service_id == service.id
                and submission.credential_id == job.payload.get('project_credential_id')
                and submission.kind == job.payload.get('pipeline_input_kind'))


def _archive(job, digest):
    from . import main
    path = main.PUBLIC_JOB_ROOT / job.id / 'retained-chart.tgz'
    if (not approvals.DIGEST.fullmatch(digest or '') or not path.is_file() or path.is_symlink()
            or path.parent.is_symlink() or file_digest(path) != digest):
        raise ValueError('The original Helm chart archive is unavailable or its checksum differs.')
    return path


def _origin(db, job, service):
    if not job.payload.get('runtime_candidate_artifact'):
        return _project_job(db, job, service)
    if not _bound(db, job, service):
        return False
    kind = job.payload.get('pipeline_input_kind')
    policy = job.payload.get('credential_policy')
    if policy == 'service':
        # The broker scopes mounted pull credentials by hostname. Only a single
        # exact configured image can request them; chart/CI sources cannot.
        target = trusted_scan_reference(db, service.id, job.payload['runtime_candidate_artifact'])
        return bool(kind == 'image' and target and job.payload.get('image_list') == target
                    and not any(job.payload.get(k) for k in ('chart_url', 'chart_names', 'archive_names',
                        'compose_enabled', 'definition_component', 'definition_components', 'runtime_project_source',
                        'runtime_discovery_source')))
    if policy != 'public':
        return False
    original_id = job.payload.get('runtime_project_source')
    discovery = job.payload.get('runtime_discovery_source')
    if discovery:
        if (kind != 'helm-chart' or original_id or not isinstance(discovery, dict)
                or not all(discovery.get(k) for k in ('confirmation_id', 'name', 'version', 'digest'))
                or discovery['digest'] != job.payload.get('chart_archive_digest')
                or chart_key(discovery) != job.payload['runtime_candidate_artifact']
                or any(job.payload.get(k) for k in ('image_list', 'chart_url', 'compose_enabled', 'definition_component',
                                                     'definition_components'))):
            return False
        verified = next(discovery_charts.confirmed_charts(db, service, discovery, discovery['confirmation_id']), None)
        return bool(verified and verified[0] == discovery)
    if original_id:
        original = db.get(ScanJob, original_id)
        if not _project_job(db, original, service) or original.payload['pipeline_input_kind'] != kind:
            return False
        if kind == 'helm-chart':
            digest = job.payload.get('chart_archive_digest')
            return bool(digest and original.payload.get('chart_archive_digest') == digest)
        return kind == 'image' and job.payload['image_list'] == original.payload.get('image_list')
    return (kind == 'image'
            and trusted_scan_reference(db, service.id, job.payload['runtime_candidate_artifact']) == job.payload.get('image_list'))


def _pinned(value, digest=None):
    pinned, _ = approvals._identity(value, digest)
    from .runtime_policy import _actual_identity
    identity = _actual_identity({'image_id': pinned})
    if not identity:
        raise ValueError('Unqualified image identity in retained scan.')
    host, path, digest = identity
    return f'{host}/{path}@{digest}'


def _image_inventory(raw):
    overview = raw.get('service_overview') or {}
    images = overview.get('images') or overview.get('container_images') or []
    aliases = {}
    for image in images:
        ref = (image.get('image') or image.get('reference') or image.get('name')) if isinstance(image, dict) else image
        digest = (image.get('digest') or image.get('image_digest')) if isinstance(image, dict) else None
        pin = _pinned(ref, digest)
        if ref in aliases and aliases[ref] != pin:
            raise ValueError('Conflicting image digests in retained scan.')
        aliases[ref] = aliases[pin] = pin
    for item in [*raw.get('findings', []), *raw.get('sbom_components', []), *raw.get('evidence_documents', []),
                 *raw.get('evidence_unavailable', []), *raw.get('sbom_images', [])]:
        ref = item.get('image') if isinstance(item, dict) else item
        digest = item.get('image_digest') if isinstance(item, dict) else None
        if not ref:
            continue
        pin = aliases.get(ref) if not digest and ref in aliases else _pinned(ref, digest)
        if ref in aliases and aliases[ref] != pin:
            raise ValueError('An evidence document identifies a different image.')
        aliases[ref] = aliases[pin] = pin
    return aliases


def _receipt(db, service, asset, job):
    if not job or not _origin(db, job, service):
        raise ValueError('A service-bound scanner receipt is required.')
    if job.status != 'complete' or job.payload.get('ingested') is not True:
        raise ValueError('Scanner job ' + job.status + '.')
    execution = db.get(Execution, job.payload.get('pipeline_execution_id')) if job.payload.get('pipeline_execution_id') else None
    scope = 'distribution' if job.payload.get('runtime_candidate_artifact') else 'evidence'
    if (not execution or execution.service_id != service.id or execution.execution_key != 'public:' + job.id
            or execution.scan_scope != scope or not execution.complete or not execution.service_version
            or execution.service_version.version != job.service_version):
        raise ValueError('Scanner execution does not match its job, service and version.')
    raw = execution.raw_payload
    if (not raw or not execution.payload_digest or payload_digest(raw) != execution.payload_digest
            or raw.get('execution_id') != execution.execution_key or raw.get('scan_scope') != scope
            or (raw.get('service') or {}).get('id') != service.service_key
            or (raw.get('service') or {}).get('version') != job.service_version
            or raw.get('complete') is not True or raw.get('skipped_images') or raw.get('skipped_charts')):
        raise ValueError('Retained scan evidence failed integrity or completeness validation.')
    if utc(execution.scanned_at) > now() or freshness_deadline({'scanned_at': execution.scanned_at.isoformat()}) <= now():
        raise ValueError('The retained assessment has expired.')
    overview = raw.get('service_overview') or {}
    if overview.get('missing_evidence') or overview.get('evidence'):
        raise ValueError('The retained scan reports missing assessment evidence.')
    raw_docs = raw.get('evidence_documents') or []
    result = {'job_id': job.id, 'execution_id': execution.id, 'payload_digest': execution.payload_digest,
              'scan_date': utc(execution.scanned_at).isoformat(), 'kind': asset['kind'],
              'fixable_only': raw.get('fixable_only'), 'warnings': overview.get('warnings') or [],
              'sboms': [{k: item.get(k) for k in ('format', 'name', 'image', 'sha256', 'bytes')}
                        for item in raw_docs if item['category'] == 'sbom']}
    if asset['kind'] == 'image':
        observed = asset['reference']
        source = job.payload.get('image_list')
        if (job.payload.get('pipeline_input_kind') != 'image'
                or source not in {observed, trusted_scan_reference(db, service.id, observed)}
                or not source or set(_image_inventory(raw).values()) != {source}
                or raw.get('helm_source_files') or (raw.get('service_overview') or {}).get('charts')):
            raise ValueError('Scanner evidence does not cover exactly the observed immutable image.')
        if not raw.get('sbom_components') or not result['sboms'] or not any(item['category'] == 'scanner' for item in raw_docs):
            raise ValueError('Original scanner output and SBOM evidence are required for this image.')
        check_scanned_platform(raw, asset['digest'])
        result.update(reference=observed, scan_reference=source, digest=asset['digest'])
    else:
        digest = asset.get('digest')
        if (not approvals.DIGEST.fullmatch(digest or '') or job.payload.get('pipeline_input_kind') != 'helm-chart'
                or job.payload.get('chart_archive_digest') != digest):
            raise ValueError('The deployed chart must match its service-scoped original archive by digest.')
        archive = _archive(job, digest)
        try:
            charts = approvals._charts(raw.get('helm_source_files') or {}, original_archive=archive)
        except (tarfile.TarError, yaml.YAMLError) as exc:
            raise ValueError('The original Helm chart or its vendored dependencies could not be validated.') from exc
        if [(c['name'], c['version']) for c in charts] != [(asset['name'], asset['version'])]:
            raise ValueError('Retained chart name and version differ from the observed Helm chart.')
        from .discovery_distributions import _source
        dependencies = [{**dep, 'repository': _source(dep.get('repository'))} for dep in charts[0]['dependencies']]
        result.update(name=asset['name'], version=asset['version'], digest=digest,
                      source_root=charts[0]['source_root'], dependencies=dependencies)
        if job.payload.get('runtime_discovery_source'):
            result['discovery'] = job.payload['runtime_discovery_source']
        else:
            confirmed = next(discovery_charts.confirmed_charts(db, service, asset), None)
            if confirmed:
                result['discovery'] = confirmed[0]
    return execution, result


def _possible_jobs(db, service, asset):
    query = select(ScanJob).where(ScanJob.service_key == service.service_key)
    if asset['kind'] == 'chart':
        if not approvals.DIGEST.fullmatch(asset.get('digest') or ''):
            return []
        query = query.where(ScanJob.payload['chart_archive_digest'].as_string() == asset['digest'])
    else:
        ref = asset['reference']
        pins = {ref, trusted_scan_reference(db, service.id, ref)} - {None}
        query = query.where(ScanJob.payload['pipeline_input_kind'].as_string() == 'image',
                            ScanJob.payload['image_list'].as_string().in_(pins))
    return db.scalars(query.order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).limit(64))


def claim_allowed(db, job):
    ref = job.payload['runtime_candidate_artifact']
    service = db.get(Service, job.payload['ingest_service_db_id'])
    from .service_ownership import active_service_predicate
    if (not service or not db.scalar(select(Service.id).where(Service.id == service.id, active_service_predicate()))
            or not _origin(db, job, service)):
        return False
    from .runtime_applications import in_scope
    from .runtime_models import RuntimeEnvironment
    for row in db.scalars(select(RuntimeReleaseCandidate).where(RuntimeReleaseCandidate.current.is_(True),
        RuntimeReleaseCandidate.service_id == service.id, RuntimeReleaseCandidate.status.in_(('draft', 'returned')),
        RuntimeReleaseCandidate.jobs[ref].as_string() == job.id)):
        env = db.get(RuntimeEnvironment, row.environment_id)
        if (env and env.kind == 'kubernetes' and env.cluster_role in ('development', 'validation')
                and env.cluster_role == row.inventory['source']['role']
                and in_scope(env, service.id)):
            return True
    return False


def _connect(db, candidate, service, key, asset, admission):
    """Reuse a valid receipt first. Failed assessments are retried after a cooldown."""
    assigned = (candidate.jobs or {}).get(key)
    current = db.get(ScanJob, assigned) if assigned else None
    original = None
    retained_discovery = None
    for job in _possible_jobs(db, service, asset):
        if not _origin(db, job, service):
            continue
        if original is None and not job.payload.get('runtime_candidate_artifact'):
            original = job
        if job.status not in TERMINAL:
            if job.payload.get('runtime_candidate_artifact') and job.payload['runtime_candidate_artifact'] != key:
                continue
            return job.id
        try:
            _receipt(db, service, asset, job)
            return job.id
        except (ValueError, OSError):
            pass
        if retained_discovery is None and job.payload.get('runtime_discovery_source'):
            try:
                retained_discovery = (_archive(job, asset['digest']), job.payload['runtime_discovery_source'])
            except (ValueError, OSError):
                pass
    if not admission[0]:
        return assigned
    if current and current.status in TERMINAL:
        failed_at = utc(current.finished_at or current.created_at)
        if now() < failed_at + timedelta(minutes=30):
            return assigned
    source, ref, mapped = None, None, None
    discoveries, discovery_evidence = None, None
    if asset['kind'] == 'image':
        mapped = trusted_scan_reference(db, service.id, asset['reference'])
        ref = mapped
        if not ref and original and original.payload['image_list'] == asset['reference']:
            ref = original.payload['image_list']
        if not ref:
            return assigned
    else:
        if original:
            try:
                source = _archive(original, asset['digest'])
            except (ValueError, OSError):
                pass
        if not source and retained_discovery:
            source, discovery_evidence = retained_discovery
        if not source:
            discoveries = discovery_charts.confirmed_charts(db, service, asset)
            first = next(discoveries, None)
            if first is None:
                return assigned or (original.id if original else None)
            discoveries = chain((first,), discoveries)
    from . import main
    job_id = secrets.token_hex(16)
    folder = main.PUBLIC_JOB_ROOT / job_id
    folder.mkdir(parents=True, exist_ok=False)
    try:
        connection = db.connection()
        if connection.dialect.name == 'sqlite' and not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql('BEGIN')
        with db.begin_nested():
            if source:
                shutil.copyfile(source, folder / 'submission-input')
            elif discoveries:
                for discovery in discoveries:
                    try:
                        discovery_charts.copy_upload(discovery, folder / 'submission-input')
                    except (OSError, ValueError):
                        continue
                    discovery_evidence = discovery[0]
                    break
                if not discovery_evidence:
                    raise ValueError('The confirmed chart uploads have expired or failed authentication.')
            is_chart = asset['kind'] == 'chart'
            job = prepare_scan(db, service, job_id, folder, kind='helm-chart' if is_chart else 'image',
                               reference=ref, filename='chart.tgz' if is_chart else None, version=candidate.proposed_version)
            job.payload = {**job.payload, 'runtime_candidate_artifact': key}
            if mapped:
                job.payload = {**job.payload, 'credential_policy': 'service'}
            elif discovery_evidence:
                discovery_charts.check_chart_package(folder, asset['name'])
                job.payload = {**job.payload, 'runtime_discovery_source': discovery_evidence}
            elif source or (original and original.payload['image_list'] == ref):
                job.payload = {**job.payload, 'runtime_project_source': original.id}
            if is_chart:
                _archive(job, asset['digest'])
                job.payload = {**job.payload, 'chart_archive_digest': asset['digest']}
            db.flush()
    except (HTTPException, ValueError, OSError) as exc:
        shutil.rmtree(folder, ignore_errors=True)
        if isinstance(exc, HTTPException) and exc.status_code in (429, 507):
            admission[0] = 0
        return assigned
    from .auth import record_audit
    record_audit(db, None, 'runtime.candidate.scan_queued', 'runtime_candidate', candidate.id,
                 service_id=service.id, job_id=job.id, reference=ref or asset['digest'])
    admission[0] -= 1
    return job.id


def _read(db, candidate, service):
    from .runtime_registry_resolution import resolution_blockers
    sources, assessments = [], []
    blockers = [*candidate.inventory['blockers'], *resolution_blockers(candidate)]
    for app in candidate.inventory['applications']:
        for item in app['components']:
            conflict = conflicting_tag_repository(item)
            if conflict and conflict not in blockers:
                blockers.append(conflict)
    indexes = known_index_digests(db, service.id, candidate.inventory)
    pending = False
    for key, asset in _assets(candidate.inventory):
        job_id = (candidate.jobs or {}).get(key)
        job = db.get(ScanJob, job_id, populate_existing=True) if job_id else None
        name = asset.get('reference') or f"{asset.get('name') or 'Unknown chart'} {asset.get('version') or ''}".strip()
        if asset['kind'] == 'image' and asset['digest'] in indexes:
            blockers.append(name + ': ' + INDEX_BLOCKER)
            assessments.append({**asset, 'job_id': job_id, 'status': 'unavailable', 'reason': INDEX_BLOCKER})
            continue
        try:
            if not job:
                if asset['kind'] == 'chart':
                    raise ValueError('Supply the observed archive digest and its matching project CI chart archive or confirmed Discovery chart upload.')
                if not trusted_scan_reference(db, service.id, name):
                    raise ValueError('Supply an exact project CI scan or configure a service-owned registry mapping.')
                pending = True
                raise ValueError('Waiting for scanner admission and a service-bound receipt.')
            execution, receipt = _receipt(db, service, asset, job)
        except (ValueError, OSError) as exc:
            pending |= bool(job and job.status not in TERMINAL)
            blockers.append(name + ': ' + str(exc))
            assessments.append({**asset, 'job_id': job_id, 'status': job.status if job else 'unavailable', 'reason': str(exc)})
        else:
            receipt['status'] = 'complete'
            sources.append((execution, receipt))
            assessments.append(receipt)
    return sources, assessments, blockers, pending


def _aggregate(db, candidate, service, sources):
    """Materialize exact source executions for the existing approval freezer without changing active posture."""
    from .schemas import ExecutionPayload
    key = aggregate_execution_key(candidate.id, (receipt for _, receipt in sources))
    existing = db.scalar(select(Execution).where(Execution.execution_key == key))
    if existing:
        return existing
    images = {r['scan_reference'] for _, r in sources if r['kind'] == 'image'}
    chart_inputs = [e for e, r in sources if r['kind'] == 'chart']
    observed = min(utc(execution.scanned_at) for execution, _ in sources)
    raw = {'execution_id': key, 'scanned_at': observed.isoformat(), 'complete': True, 'scan_scope': 'distribution',
           'fixable_only': any(r['fixable_only'] is not False for _, r in sources),
           'service': {'id': service.service_key, 'name': service.name, 'version': candidate.proposed_version},
           'artifact_type': 'helm' if chart_inputs else 'image', 'service_overview': {'images': [
               {'image': pin, 'digest': pin.split('@')[1]} for pin in sorted(images)], 'source': 'Runtime release candidate'},
           'sbom_images': sorted(images), 'sbom_components': [], 'findings': [], 'policy_findings': [],
           'evidence_documents': [], 'evidence_unavailable': [], 'helm_source_files': {}, 'helm_values_files': []}
    resources = []
    for e, receipt in sources:
        payload = e.raw_payload
        if (len(raw['sbom_components']) + len(payload.get('sbom_components', [])) > 50000
                or len(raw['evidence_documents']) + len(payload.get('evidence_documents', [])) > 2048):
            raise ValueError('Combined assessment exceeds the existing evidence retention limits.')
        if receipt['kind'] == 'chart':
            if not set(_image_inventory(payload).values()) <= images:
                raise ValueError('Retained chart scan contains image identities outside the running inventory.')
            prefix = f'chart-{e.id}/'
            raw['helm_source_files'].update({prefix + name: content for name, content in payload['helm_source_files'].items()})
            raw['helm_values_files'].extend(prefix + name for name in payload.get('helm_values_files', []))
            raw['policy_findings'].extend(payload.get('policy_findings', []))
            overview = payload.get('service_overview') or {}
            resources.extend(overview.get('rendered_resources') or [])
        else:
            for field in ('sbom_components', 'findings'):
                raw[field].extend({**item, 'image': receipt['scan_reference'], 'image_digest': receipt['digest']}
                                  for item in payload.get(field) or [])
            raw['policy_findings'].extend(payload.get('policy_findings') or [])
        for field in ('evidence_documents', 'evidence_unavailable'):
            for doc in payload.get(field) or []:
                # Prefix execution IDs so equal file names from different artifacts cannot collide.
                name = str(e.id) + '-' + doc['name']
                raw[field].append({**doc, 'name': name if len(name) <= 240 else checksum(name) + '-' + name[-170:]})
    raw['service_overview']['rendered_resources'] = resources
    raw = ExecutionPayload.model_validate(raw).model_dump(mode='json')
    version = db.scalar(select(ServiceVersion).where(ServiceVersion.service_id == service.id,
                         ServiceVersion.version == candidate.proposed_version))
    if version is None:
        version = ServiceVersion(service_id=service.id, version=candidate.proposed_version)
        db.add(version)
        db.flush()
    row = Execution(execution_key=key, service_id=service.id, service_version_id=version.id,
        scanned_at=observed, complete=True, scan_scope='distribution', raw_payload=raw, payload_digest=payload_digest(raw))
    db.add(row)
    db.flush()
    return row


def _intelligence(db, service, sources, captured):
    from .container_intelligence import evaluate_container_batch, observation_identity, valid_epss
    from .native_vex_models import VexDispositionPolicy
    from .packaged_risk_intelligence import overlay_packaged_kev, overlay_packaged_epss
    from .policy_data import review_intelligence_snapshot
    from .risk_profiles import DEFAULT_POLICY, resolve_policy, score_observation, validate_policy
    from .risk_worker import _catalog_current
    from .vex_intelligence import _item_cves
    policy_row, assignment = resolve_policy(db, service.id)
    policy = validate_policy(policy_row.configuration if policy_row else DEFAULT_POLICY)
    findings, items = [], []
    for execution, receipt in sources:
        if receipt['kind'] != 'image':
            continue
        for f in execution.raw_payload.get('findings', []):
            identity = observation_identity(SimpleNamespace(evidence=f.get('evidence') or {},
                installed_version=f.get('installed_version'), image_digest=receipt['digest']))
            identity.update(observed_at=receipt['scan_date'], evidence_valid_until=freshness_deadline(
                {'scanned_at': receipt['scan_date']}).isoformat())
            items.append(dict(cve=f['cve'], identity=identity, context=identity['context'], aliases=identity['aliases']))
            findings.append(dict(cve=f['cve'], severity=f.get('severity'), image=receipt['reference'],
                                 package=f.get('package'), installed_version=f.get('installed_version'),
                                 fixed_version=f.get('fixed_version')))
    instant = now()
    cves = sorted({cve for item in items for cve in _item_cves(item)})
    signals = review_intelligence_snapshot(cves, captured)
    signals = overlay_packaged_epss(db, overlay_packaged_kev(db, signals, instant), instant)
    fresh, _ = _catalog_current(signals, instant, policy)
    native = db.get(VexDispositionPolicy, 1)
    results = []
    for start in range(0, len(items), 250):
        results.extend(evaluate_container_batch(db, items[start:start+250], instant))
    for row, item, vex in zip(findings, items, results):
        intel = [signals['findings'].get(cve, {}) for cve in _item_cves(item)]
        kev = (True if any(entry.get('kev') is True for entry in intel) else False
               if all(entry.get('kev') is False for entry in intel) else None)
        epss = max((entry['epss'] for entry in intel if valid_epss(entry.get('epss'))), default=None)
        vex = {key: vex[key] for key in ('status', 'decision', 'reasons', 'statements', 'valid_until', 'conflict', 'stale') if key in vex}
        score = score_observation(policy, severity=row['severity'], epss=epss, kev=kev, fixable=bool(row['fixed_version']),
            vex=vex, native_vex_excluded=False if native and native.enabled else None,
            intelligence_current=fresh and not item['identity']['alias_overflow'] and
            all(valid_epss(entry.get('epss')) and isinstance(entry.get('kev'), bool) for entry in intel))
        row.update(vex=vex, kev=kev, epss=epss, score=score['score'], band=score['band'],
                   uncertain=score['uncertain'], risk_reasons=score['reasons'])
    return findings, {'policy': assignment, 'policy_version_id': policy_row.id if policy_row else None,
            'catalogs': {k: signals[k] for k in ('epss', 'kev')}, 'intelligence_current': fresh,
            'maximum_score': max((f['score'] for f in findings), default=None),
            'uncertain_findings': sum(f['uncertain'] for f in findings),
            'bands': {band: sum(f['band'] == band for f in findings) for band in ('critical', 'high', 'medium', 'low')}}


def _comparison(db, service, evidence, complete):
    from .cyber_approvals import CyberApproval, digest
    from .release_revisions import active_revision
    active = active_revision(db, service.id)
    approval = db.get(CyberApproval, active.approval_id) if active else None
    if (not approval or approval.service_id != service.id
            or not approval.snapshot or digest(approval.snapshot) != approval.snapshot_digest):
        return {'baseline_available': False, 'reason': 'No verified active release is available for comparison.'}
    baseline = approval.snapshot

    def index(artifacts):
        result = {}
        for artifact in artifacts:
            if artifact.get('kind') == 'image':
                name = artifact.get('reference', '').split('@')[0]
                if ':' in name.rsplit('/', 1)[-1]:
                    name = name.rsplit(':', 1)[0]
            elif artifact.get('kind') == 'chart':
                name = artifact.get('name') or ''
            else:
                continue
            result.setdefault((artifact['kind'], name), set()).add((artifact.get('version') or '', artifact.get('digest') or ''))
        return result

    def describe_asset(key, values):
        return {'kind': key[0], 'name': key[1], 'artifacts': [
            {'version': version or None, 'digest': digest or None} for version, digest in sorted(values)]}

    prior = baseline.get('runtime_evidence') or {}
    old = index([*prior['images'], *prior['charts']] if prior.get('images') else baseline.get('artifacts', []))
    new = index([*evidence['images'], *evidence['charts']])
    before = {row.get('cve') for row in (baseline.get('findings') or {}).get('vulnerabilities', []) if row.get('cve')}
    after = {row['cve'] for row in evidence['findings']}
    comparable = complete and isinstance((baseline.get('findings') or {}).get('vulnerabilities'), list)
    old_risk = prior.get('risk', {}).get('maximum_score')
    new_risk = evidence['risk']['maximum_score']
    def posture(findings, signals):
        severities = {}
        exploited, unknown = set(), set()
        for finding in findings:
            severity = (finding.get('severity') or 'unknown').lower()
            severities[severity] = severities.get(severity, 0) + 1
            cve = finding.get('cve')
            kev = (signals.get(cve) or {}).get('kev') if signals is not None else finding.get('kev')
            if cve and kev is True:
                exploited.add(cve)
            elif cve and kev is None:
                unknown.add(cve)
        return {'severity_counts': severities, 'known_exploited_cves': sorted(exploited), 'kev_unknown_count': len(unknown)}

    previous_findings = (baseline.get('findings') or {}).get('vulnerabilities')
    previous_signals = (baseline.get('risk_intelligence') or {}).get('findings') or {}
    previous_posture = (posture(prior['findings'], None) if 'findings' in prior else
                        posture(previous_findings, previous_signals) if isinstance(previous_findings, list) else None)
    inventory_complete = not evidence.get('inventory_blockers')
    return {'baseline_available': True, 'revision_id': active.id, 'approval_id': approval.id,
            'version': baseline.get('version'), 'added': [describe_asset(k, new[k]) for k in sorted(new.keys()-old.keys())],
            'inventory_complete': inventory_complete,
            'removed': [describe_asset(k, old[k]) for k in sorted(old.keys()-new.keys())] if inventory_complete else None,
            'updated': [{'kind': k[0], 'name': k[1], 'before': describe_asset(k, old[k])['artifacts'],
                         'after': describe_asset(k, new[k])['artifacts']} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]],
            'vulnerabilities_comparable': comparable, 'new_vulnerabilities': sorted(after-before) if comparable else None,
            'resolved_vulnerabilities': sorted(before-after) if comparable else None,
            'risk': {'before': old_risk, 'after': new_risk, 'before_posture': previous_posture,
                     'after_posture': posture(evidence['findings'], None) if complete else None,
                     'delta': round(new_risk-old_risk, 2)
                     if comparable and old_risk is not None and new_risk is not None else None}}


def aggregate_execution_key(candidate_id, receipts):
    return f'runtime-candidate:{candidate_id}:' + checksum([(r['job_id'], r['payload_digest']) for r in receipts])


def _include_catalog_matches(db, service_id, sources):
    """Annotate verified receipts with existing digest matches visible to this service."""
    if not sources:
        return
    digests = {receipt['digest'] for _, receipt in sources}
    identities = {}
    query = select(GlobalArtifact.id, GlobalArtifact.digest, GlobalArtifact.media_type,
                   GlobalArtifact.platform, ServiceArtifactAssignment.role).join(
        ServiceArtifactAssignment, ServiceArtifactAssignment.artifact_id == GlobalArtifact.id
    ).where(ServiceArtifactAssignment.service_id == service_id, GlobalArtifact.digest.in_(digests)
    ).order_by(GlobalArtifact.id, ServiceArtifactAssignment.role)
    for artifact_id, digest, media, platform, role in db.execute(query):
        by_artifact = identities.setdefault(digest, {})
        match = by_artifact.setdefault(artifact_id, {
            'artifact_id': artifact_id, 'media_type': media, 'platform': platform, 'roles': []})
        match['roles'].append(role)
    for _, receipt in sources:
        media_types = IMAGE_TYPES if receipt['kind'] == 'image' else (CHART_LAYER,)
        receipt['catalog_matches'] = [match for match in identities.get(receipt['digest'], {}).values()
                                      if match['media_type'] in (*media_types, 'application/octet-stream')]


def assess(db, row, service):
    from . import main
    sources, receipts, blockers, pending = _read(db, row, service)
    _include_catalog_matches(db, service.id, sources)
    execution = db.get(Execution, row.execution_id, populate_existing=True) if row.execution_id else None
    if (not execution or execution.execution_key != aggregate_execution_key(row.id, (receipt for _, receipt in sources))
            or execution.service_id != row.service_id or execution.scan_scope != 'distribution'
            or not execution.complete or not execution.raw_payload or not execution.payload_digest
            or payload_digest(execution.raw_payload) != execution.payload_digest):
        execution = None
    # Never fall back to current service evidence for an unavailable candidate execution.
    # The ordinary scanner retains editable text while packaged vendored dependencies are binary.
    # _receipt checked those dependencies against the digest-verified original with the same release validator.
    verified_charts = [dict(kind='chart', name=r['name'], version=r['version'],
                            source_root=f"chart-{e.id}/{r['source_root']}", dependencies=r['dependencies'])
                       for e, r in sources if r['kind'] == 'chart']
    review = (approvals.readiness(db, service, _proposal_execution=execution, _proposal_charts=verified_charts) if execution else
        dict(ready=False, blockers=[], execution=None, remediation=None, artifacts=[], overview={}, variant='current_service',
             review_notes=[], scan_date=None))
    if row.assessment_error:
        blockers.append(row.assessment_error)
    elif not blockers and not execution:
        blockers.append('The scanner coordinator is preparing the combined assessment.')
        pending = True
    if execution:
        expected = {r['scan_reference'] for _, r in sources if r['kind'] == 'image'}
        actual = {a['reference'] for a in review['artifacts'] if a['kind'] == 'image'}
        if expected != actual or any(not a.get('digest') for a in review['artifacts'] if a['kind'] == 'image'):
            blockers.append('The retained release artifacts differ from the immutable scanner inputs.')
        charts = {(r['name'], r['version']): r for _, r in sources if r['kind'] == 'chart'}
        selected = [a for a in review['artifacts'] if a['kind'] == 'chart']
        if sorted((a['name'], a['version']) for a in selected) != sorted(charts):
            blockers.append('Retained chart sources differ from the candidate chart inventory.')
        for chart in selected:
            receipt = charts.get((chart['name'], chart['version']))
            if receipt:
                chart.update(runtime_archive_path=str(main.PUBLIC_JOB_ROOT / receipt['job_id'] / 'retained-chart.tgz'),
                             runtime_archive_digest=receipt['digest'])
    blockers = list(dict.fromkeys([*blockers, *review['blockers']]))
    if not row.current:
        blockers.append('This inventory revision has been superseded.')
    captured = max((r['scan_date'] for _, r in sources), default=utc(row.created_at).isoformat())
    findings, risk = _intelligence(db, service, sources, captured)
    status = 'ready' if not blockers else 'scanning' if pending else 'blocked'
    evidence = {**row.inventory, 'candidate_id': row.id, 'revision': row.version, 'fingerprint': row.fingerprint,
                'proposed_version': row.proposed_version, 'assessments': receipts, 'findings': findings,
                'risk': risk, 'assessment_status': status, 'ready': not blockers, 'blockers': blockers,
                'inventory_blockers': list(row.inventory['blockers'])}
    evidence['comparison'] = _comparison(db, service, evidence, not blockers)
    review.update(ready=not blockers, blockers=blockers, version=row.proposed_version,
                  runtime_candidate_id=row.id, runtime_evidence=evidence)
    return review


def process(db, candidate, admission=None):
    """Refresh even without new reports; reserve a bounded number of worker inputs per pass."""
    from .auth import record_audit
    service = db.get(Service, candidate.service_id, with_for_update=True, populate_existing=True)
    row = require_current(db, candidate, service)
    if row.status not in ('draft', 'returned'):
        return assess(db, row, service)
    admission = [4] if admission is None else admission
    links = {}
    indexes = known_index_digests(db, service.id, row.inventory)
    for key, asset in _assets(row.inventory):
        job_id = ((row.jobs or {}).get(key) if asset['kind'] == 'image' and asset['digest'] in indexes
                  else _connect(db, row, service, key, asset, admission))
        if job_id:
            links[key] = job_id
    row.jobs = links
    db.flush()
    sources, _, blockers, _ = _read(db, row, service)
    if sources and not blockers:
        try:
            row.execution_id = _aggregate(db, row, service, sources).id
        except (ValueError, OSError) as exc:
            # A composition failure (e.g. mismatched chart children or size limits)
            # is retained on the draft and visible even when the cluster is offline.
            row.assessment_error = str(exc)[:500]
        else:
            row.assessment_error = None
    else:
        row.assessment_error = None
    result = assess(db, row, service)
    state = result['runtime_evidence']['assessment_status']
    if row.assessment_status != state:
        record_audit(db, None, 'runtime.candidate.assessment_changed', 'runtime_candidate', row.id,
                     service_id=row.service_id, previous=row.assessment_status, status=state)
    row.assessment_status, row.assessed_at = state, now()
    return result


def dispatch_pending(session_factory=SessionLocal):
    from .operating_mode import is_replica
    from .runtime_registry_resolution import resolve_requests
    if is_replica():
        return
    due = now() - timedelta(seconds=55)
    with session_factory() as db:
        ids = list(db.scalars(select(RuntimeReleaseCandidate.id).where(RuntimeReleaseCandidate.current.is_(True),
            RuntimeReleaseCandidate.status.in_(('draft', 'returned')),
            or_(RuntimeReleaseCandidate.assessed_at.is_(None), RuntimeReleaseCandidate.assessed_at < due))
            .order_by(RuntimeReleaseCandidate.assessed_at.asc().nullsfirst(), RuntimeReleaseCandidate.id).limit(20)))
    admission = [8]
    lookups = [4]
    if ids:
        start = int(now().timestamp() // 60) % len(ids)
        ids = ids[start:] + ids[:start]
    for candidate_id in ids:
        try:
            candidate_id = resolve_requests(session_factory, candidate_id, lookups)
        except (ValueError, OSError):
            # The original unresolved request stays visible until a future pass succeeds.
            pass
        with session_factory() as db:
            row = db.get(RuntimeReleaseCandidate, candidate_id)
            if not row or not row.current or row.status not in ('draft', 'returned'):
                continue
            try:
                process(db, row, admission)
                db.commit()
            except Exception:
                db.rollback()
                logging.getLogger(__name__).exception('Runtime candidate %s assessment failed', candidate_id)
                row = db.get(RuntimeReleaseCandidate, candidate_id, with_for_update=True)
                if row and row.current and row.status in ('draft', 'returned'):
                    row.assessed_at = now()
                    row.assessment_status = 'blocked'
                    row.assessment_error = 'Assessment could not finish. The coordinator will retry.'
                    db.commit()
