"""Immutable, service-scoped release selections from confirmed Discovery evidence."""
from collections import defaultdict
from pathlib import PureWindowsPath
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .auth import AuthContext, record_audit, require_user
from .cyber_approvals import _permission, _service, digest
from .database import get_db
from .discovery_models import DiscoveryConfirmation, DiscoveryDistribution, confirmed_inventories, service_distributions
from .discovery_routes import body
from .scan_coordination import DistributionScanInProgress

router = APIRouter(prefix='/api/services')


def _source(reference):
    """Only retain portable, credential-free source identifiers in release records."""
    if not isinstance(reference, str) or not reference or PureWindowsPath(reference).drive:
        return ''
    try:
        source = urlsplit(reference)
        if (source.username is not None or source.password is not None or source.query or source.fragment
                or source.scheme not in ('', 'https', 'http', 'oci') or reference.startswith(('/', '\\'))):
            return ''
    except ValueError:
        return ''
    return reference


def _enabled_chart_paths(charts, selected):
    """Return selected charts reachable from an independent selected component."""
    children = defaultdict(list)
    pending = []
    for chart in charts:
        if chart['id'] not in selected:
            continue
        if not chart['parent_chart_ids']:
            pending.append(chart['id'])
        for parent in chart['parent_chart_ids']:
            children[parent].append(chart['id'])
    reachable = set()
    while pending:
        current = pending.pop()
        if current not in reachable:
            reachable.add(current)
            pending.extend(children[current])
    return reachable


def _catalog(inventory, roots):
    options = {row['id']: row for row in inventory.get('configurable_components', [])
               if row['root_id'] in roots and row.get('technology') == 'helm'}
    charts = {}
    for root in inventory.get('roots', []):
        identity = root['id']
        if identity not in roots or root.get('technology') != 'helm':
            continue
        # Flux also records chart source directories as roots. Only top-level
        # Helm render targets can be independently included in a distribution.
        if identity not in options and not root.get('chart_name'):
            continue
        option = options.get(identity, {})
        charts[identity] = dict(id=identity, root_id=identity,
            label=root.get('chart_name') or option.get('label') or root['path'],
            source_path=_source(option.get('path') or root['path']), reference='', version=root.get('chart_version', ''),
            content_digest=root.get('chart_sha256') or '', digest_kind=root.get('chart_digest_kind', ''),
            state=root.get('state') or ('rendered' if root.get('completeness') == 'complete' else 'unresolved'),
            default_enabled=True, dependencies=[])
    dependencies = {}
    scoped_nodes = {node['id']: node for node in inventory.get('nodes', []) if node['root_id'] in roots}
    for node in scoped_nodes.values():
        if node.get('kind') not in ('ChartReference', 'HelmRelease', 'HelmDependency'):
            continue
        evidence = next(iter(node.get('provenance', [])), {})
        option = options.get(node['id'], {})
        record = dict(id=node['id'], root_id=node['root_id'], label=node['name'],
            source_path=_source(evidence.get('path') or option.get('path', '')), reference=_source(evidence.get('reference', '')),
            version=evidence.get('version', ''), content_digest=evidence.get('chart_sha256') or '',
            digest_kind=evidence.get('chart_digest_kind', ''), state=node.get('state', 'unresolved'),
            default_enabled=evidence.get('enabled') is not False, dependencies=[])
        if node['kind'] == 'HelmDependency':
            record.update(selection_scope='parent', condition=evidence.get('condition'), tags=evidence.get('tags', []),
                          enabled=evidence.get('enabled'), declared_version=evidence.get('declared_version', ''))
            dependencies[node['id']] = record
        else:
            charts[node['id']] = record
    owners = charts | dependencies
    parents = defaultdict(set)
    for edge in inventory.get('edges', []):
        if edge['kind'] != 'declares':
            continue
        parent, child = edge['source'], edge['target']
        if parent in owners and child in dependencies:
            owners[parent]['dependencies'].append(dependencies[child])
        if parent in scoped_nodes and child in scoped_nodes:
            parents[child].add(parent)
    for chart in charts.values():
        # Product roots group independently selectable services. Only nested
        # catalog declarations and Flux releases govern another chart.
        nearest = set()
        seen = set()
        pending = list(parents[chart['id']])
        while pending:
            parent = pending.pop()
            if parent in seen or parent in roots:
                continue
            seen.add(parent)
            if parent in charts:
                nearest.add(parent)
            else:
                pending.extend(parents[parent])
        chart['parent_chart_ids'] = sorted(nearest)
        chart['declared_enabled'] = chart['default_enabled']
    ordered = [charts[key] for key in sorted(charts)]
    defaults = _enabled_chart_paths(ordered, {chart['id'] for chart in ordered if chart['declared_enabled']})
    for chart in ordered:
        chart['default_enabled'] = chart['id'] in defaults
    return ordered


def _selection(service_id, name, confirmation, item, enabled_ids):
    inventory = item.inventory
    roots = set(confirmation.root_ids)
    charts = _catalog(inventory, roots)
    known = {chart['id'] for chart in charts}
    if not isinstance(enabled_ids, list) or any(not isinstance(key, str) for key in enabled_ids):
        raise HTTPException(422, 'Supply the list of included chart IDs')
    enabled = set(enabled_ids)
    if not enabled <= known or len(enabled) != len(enabled_ids):
        raise HTTPException(422, 'Chart selections must be distinct IDs in the confirmed inventory')
    reachable = _enabled_chart_paths(charts, enabled)
    for chart in charts:
        if chart['id'] in enabled and chart['id'] not in reachable:
            raise HTTPException(422, f"Select an owning chart before including {chart['label']}")
        if chart['id'] in enabled and chart['state'] != 'rendered':
            raise HTTPException(422, f"Resolve and rediscover the selected chart {chart['label']} before saving")
        if chart['id'] in enabled and (not chart['version'] or not re.fullmatch('[0-9a-f]{64}', chart['content_digest'])):
            raise HTTPException(409, f"Run Discovery again to capture the version and content digest of {chart['label']}")

    # Historic standalone Flux releases had no ownership edges. Their workload
    # rows cannot safely be attributed to an included or excluded chart.
    if any(c.get('technology') == 'helm' and c.get('root_id') in roots and c['id'] not in known
           for c in inventory.get('configurable_components', [])):
        raise HTTPException(409, 'Run Discovery again to record chart ownership for this inventory')
    disabled = known - enabled
    nodes = {n['id']: n['root_id'] for n in inventory.get('nodes', []) if n['root_id'] in roots}
    children = defaultdict(set)
    owned = set()
    for edge in inventory.get('edges', []):
        parent, child = edge['source'], edge['target']
        if edge['kind'] == 'declares' and child in nodes and (parent in nodes or parent in roots):
            children[parent].add(child)
            owned.add(child)
    for child, root in nodes.items():
        if child not in owned:
            children[root].add(child)
    pending = list((roots - disabled) | enabled)
    included = set()
    while pending:
        current = pending.pop()
        if current not in included and current not in disabled:
            included.add(current)
            pending.extend(children[current])
    dependency_evidence = {n['id']: next(iter(n.get('provenance', [])), {}) for n in inventory.get('nodes', [])
                           if n['id'] in included and n.get('kind') == 'HelmDependency'}
    for node in inventory.get('nodes', []):
        if node['id'] not in dependency_evidence:
            continue
        evidence = dependency_evidence[node['id']]
        if node.get('state') != 'resolved' or not evidence.get('version') or not re.fullmatch('[0-9a-f]{64}', evidence.get('chart_sha256') or ''):
            raise HTTPException(409, f"Resolve and rediscover the Helm dependency {node['name']} before saving")
    diagnostics = inventory.get('diagnostics', [])
    if inventory.get('completeness') != 'complete' and not diagnostics:
        raise HTTPException(409, 'Run Discovery again to identify which components have incomplete evidence')
    for diagnostic in diagnostics:
        owner, root = diagnostic.get('component_id'), diagnostic.get('root_id')
        if diagnostic.get('blocking') is False or (root and root not in roots):
            continue
        if owner in nodes or owner in roots:
            if owner not in included:
                continue
        elif root and root not in included:
            continue
        # An acquired native dependency can be explicitly off in its parent's
        # rendered values. Its dormant workloads are outside this release.
        if (diagnostic.get('code') == 'helm_dependency_images_not_verified'
                and dependency_evidence.get(owner, {}).get('enabled') is False):
            continue
        raise HTTPException(409, f"Resolve Discovery diagnostic {diagnostic.get('code', 'incomplete evidence')} before saving")
    occurrences = []
    excluded_in_roots = {c['root_id'] for c in charts if c['id'] in disabled}
    for row in inventory.get('images', []):
        root = row['root_id']
        if root not in roots:
            continue
        owner = row.get('component_id')
        if owner not in nodes and owner not in roots:
            if root in excluded_in_roots and root not in disabled:
                raise HTTPException(409, 'Run Discovery again to record image ownership for this inventory')
            owner = root
        if owner in included:
            occurrences.append(row)
    return dict(service_id=service_id, name=name, confirmation_id=confirmation.id, inventory_id=item.id,
                source_hash=item.source_hash, content_hash=item.content_hash, root_ids=sorted(roots),
                enabled_chart_ids=sorted(enabled), disabled_chart_ids=sorted(disabled), charts=charts,
                images=sorted({row['reference'] for row in occurrences}), image_occurrences=occurrences,
                selection_completeness='complete', discovery_completeness=inventory.get('completeness'),
                acknowledge_partial=confirmation.acknowledge_partial)


def _view(row):
    return {k: v for k, v in row.selection.items() if k != 'image_occurrences'} | {
        'id': row.id, 'selection_digest': row.selection_digest, 'created_at': row.created_at}


@router.get('/{key}/distributions')
def distributions(key: str, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    service = _service(db, auth, key)
    confirmed = db.execute(confirmed_inventories(service.id).order_by(DiscoveryConfirmation.created_at.desc())).all()
    confirmations = [dict(id=c.id, inventory_id=i.id, created_at=c.created_at,
                          charts=_catalog(i.inventory, set(c.root_ids))) for c, i in confirmed]
    rows = db.scalars(select(DiscoveryDistribution).where(DiscoveryDistribution.service_id == service.id,
        DiscoveryDistribution.confirmation_id.in_([c.id for c, _ in confirmed]))
        .order_by(DiscoveryDistribution.created_at.desc()))
    return dict(confirmations=confirmations, distributions=[_view(row) for row in rows],
                can_manage=auth.has('service.edit', service.id), can_scan=auth.has('scan.ingest', service.id))


@router.post('/{key}/distributions')
async def create_distribution(key: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    service = _service(db, auth, key)
    _permission(auth, 'service.edit', service.id)
    # A confirmed inventory can contain thousands of distinct chart IDs.
    data = await body(request, auth, max_bytes=1024 * 1024)
    if set(data) - {'name', 'confirmation_id', 'enabled_chart_ids', 'csrf_token'}:
        raise HTTPException(422, 'Unsupported distribution configuration')
    name = data.get('name')
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120 or not name.strip().isprintable():
        raise HTTPException(422, 'Enter a distribution name of up to 120 characters')
    identity = data.get('confirmation_id')
    if not isinstance(identity, str):
        raise HTTPException(422, 'Select a confirmed inventory')
    confirmed = db.execute(confirmed_inventories(service.id).where(DiscoveryConfirmation.id == identity)).first()
    if not confirmed:
        raise HTTPException(404, 'Confirmed inventory not found for this service')
    confirmation, item = confirmed
    selection = _selection(service.id, name.strip(), confirmation, item, data.get('enabled_chart_ids'))
    checksum = digest(selection)
    candidate_id = checksum.removeprefix('sha256:')[:32]
    row = db.get(DiscoveryDistribution, candidate_id)
    if row and row.selection_digest != checksum:
        raise HTTPException(409, 'This selection conflicts with an existing distribution identifier')
    if not row:
        row = DiscoveryDistribution(id=candidate_id, service_id=service.id, confirmation_id=confirmation.id,
                                    name=name.strip(), selection=selection, selection_digest=checksum)
        db.add(row)
        record_audit(db, auth, 'discovery.distribution.created', 'service', service.id,
                     distribution_id=candidate_id, selection_digest=checksum)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            row = db.get(DiscoveryDistribution, candidate_id)
            if not row or row.selection_digest != checksum:
                raise
    return {'distribution': _view(row)}


@router.post('/{key}/distributions/{distribution_id}/scan')
async def scan_distribution(key: str, distribution_id: str, request: Request,
                            auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    from . import main
    service = _service(db, auth, key)
    _permission(auth, 'scan.ingest', service.id)
    await body(request, auth)
    row = db.scalar(service_distributions(service.id).where(DiscoveryDistribution.id == distribution_id))
    if not row:
        raise HTTPException(404, 'Distribution not found for this service')
    selection = row.selection
    if digest(selection) != row.selection_digest:
        raise HTTPException(409, 'Saved distribution failed its integrity check')
    if not selection['images']:
        raise HTTPException(422, 'This distribution contains no resolved images to scan')
    configuration = main.get_global_configuration(db)
    try:
        scan_id = await main._prepare_public_scan(
            '\n'.join(selection['images']), ingest_service_id=service.service_key,
            ingest_service_version='distribution-' + row.id, ingest_scope='distribution', owner_user_id=auth.user.id,
            trusted_ca_certificates=main.parse_json(configuration.get('trusted_ca_certificates'), []),
            definition_context=row.scan_context())
    except DistributionScanInProgress as active:
        return {'job_id': active.job_id, 'url': '/scan?job_id=' + active.job_id}
    record_audit(db, auth, 'discovery.distribution.scan_queued', 'service', service.id,
                 distribution_id=row.id, scan_job_id=scan_id)
    db.commit()
    return {'job_id': scan_id, 'url': '/scan?job_id=' + scan_id}
