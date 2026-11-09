from types import SimpleNamespace
from copy import deepcopy

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.discovery_models import DiscoveryConfirmation, DiscoveryDistributionScan, DiscoveryInventory
from app.discovery_distributions import _catalog, _selection
from app.durable_jobs import DurableJob
from app.models import Group, Service, ServiceGroup
from app.scan_coordination import ScanJob
from test_discovery_routes import api, post, scoped_auth, stub_packaged_intelligence_startup


@pytest.fixture
def candidate(api):
    client, db, current = api
    current['auth'] = scoped_auth(db.get(Group, 1), ('service.view', 'service.edit', 'scan.ingest'))
    roots = ['product', 'mandatory', 'unconfirmed']
    graph = dict(completeness='partial', roots=[dict(id=root, technology='kubernetes') for root in roots],
                 nodes=[], edges=[], images=[], diagnostics=[dict(code='catalog_chart_unresolved',
                 root_id='product', component_id='missing', blocking=True)])
    for chart, state, source_enabled in [('one', 'rendered', True), ('two', 'rendered', False), ('missing', 'unresolved', False)]:
        graph['nodes'].append(dict(id=chart, root_id='product', kind='ChartReference', name=chart, state=state,
            provenance=[dict(path='values.yaml', enabled=source_enabled, reference='oci://registry.test/' + chart,
                             version='1.2.3', chart_sha256='a' * 64, chart_digest_kind='archive')]))
        graph['edges'].append(dict(kind='declares', source='product', target=chart))
    graph['nodes'].append(dict(id='dependency', root_id='product', kind='HelmDependency', name='cache',
        state='resolved', provenance=[dict(path='Chart.yaml', enabled=True, condition='cache.enabled',
        version='2.1', chart_sha256='c'*64, chart_digest_kind='tree')]))
    graph['edges'].append(dict(kind='declares', source='two', target='dependency'))
    for node, root, image, owners in [
        ('shared', 'product', 'shared:1', ['one', 'two']), ('a', 'product', 'a:1', ['one']),
        ('b', 'product', 'b:1', ['two']), ('also-shared', 'product', 'shared:1', ['one']),
        ('plain', 'mandatory', 'plain:1', []), ('outside', 'unconfirmed', 'outside:1', [])]:
        graph['nodes'].append(dict(id=node, root_id=root, kind='Pod', name=node))
        graph['images'].append(dict(reference=image, component_id=node, root_id=root))
        graph['edges'].extend(dict(kind='declares', source=owner, target=node) for owner in owners)
    job = DurableJob(id='source', kind='discovery', status='completed', payload={'group_id': 1}, result={})
    db.add(job)
    db.flush()
    db.add(DiscoveryInventory(id='inventory', job_id='source', group_id=1, source_hash='a'*64, content_hash='b'*64,
                              inventory=graph))
    db.flush()
    db.add(DiscoveryConfirmation(id='confirmed', inventory_id='inventory', service_id=1, confirmed_by=7,
                                 root_ids=roots[:2], acknowledge_partial=True))
    db.commit()
    return client, db, current


BASE = '/api/services/one/distributions'


def save(client, enabled, name='Release', **extra):
    return client.post(BASE, json=dict(name=name, confirmation_id='confirmed', enabled_chart_ids=enabled,
                       csrf_token='csrf') | extra)


def test_library_roots_are_evidence_not_selectable_deployments():
    graph = dict(completeness='complete', roots=[
        dict(id='application', technology='helm', chart_name='app', chart_version='1.0.0',
             chart_sha256='a' * 64, chart_digest_kind='tree', path='app', state='rendered'),
        dict(id='library', technology='helm', chart_name='common', chart_version='1.0.0',
             chart_sha256='b' * 64, chart_digest_kind='tree', path='common', state='library', chart_type='library'),
    ], nodes=[], edges=[], images=[dict(reference='app:1', root_id='application', component_id='application')],
       diagnostics=[dict(code='helm_library_chart', root_id='library', blocking=False)])
    confirmation = SimpleNamespace(id='confirmed', root_ids=['application', 'library'], acknowledge_partial=False)
    item = SimpleNamespace(id='inventory', inventory=graph, source_hash='source', content_hash='content')
    assert [chart['id'] for chart in _catalog(graph, set(confirmation.root_ids))] == ['application']
    selection = _selection(1, 'Release', confirmation, item, ['application'])
    assert selection['images'] == ['app:1']
    assert selection['enabled_chart_ids'] == ['application'] and selection['disabled_chart_ids'] == []
    with pytest.raises(HTTPException, match='distinct IDs'):
        _selection(1, 'Release', confirmation, item, ['application', 'library'])


def test_two_immutable_distributions_from_same_confirmation(candidate):
    client, db, _ = candidate
    options = client.get(BASE).json()
    assert options['can_manage'] and options['can_scan']
    assert {chart['id']: chart['default_enabled'] for chart in options['confirmations'][0]['charts']} == {
        'one': True, 'two': False, 'missing': False}
    response = save(client, ['two'])
    assert response.status_code == 200, response.text
    subset = response.json()['distribution']
    assert subset['images'] == ['b:1', 'plain:1', 'shared:1']
    assert subset['enabled_chart_ids'] == ['two'] and subset['disabled_chart_ids'] == ['missing', 'one']
    chart = next(c for c in subset['charts'] if c['id'] == 'two')
    assert chart['version'] == '1.2.3' and chart['content_digest'] == 'a'*64
    assert chart['reference'] == 'oci://registry.test/two'
    assert chart['dependencies'][0]['condition'] == 'cache.enabled'
    assert save(client, ['two']).json()['distribution']['id'] == subset['id']
    assert save(client, ['one']).json()['distribution']['images'] == ['a:1', 'plain:1', 'shared:1']
    assert len(client.get(BASE).json()['distributions']) == 2
    assert save(client, ['missing']).status_code == 422
    assert save(client, ['other']).status_code == 422
    assert save(client, ['two', 'two']).status_code == 422
    assert save(client, ['two'], images=['injected:1']).status_code == 422
    assert save(client, []).json()['distribution']['images'] == ['plain:1']
    with pytest.raises(DBAPIError, match='immutable'):
        db.execute(text("UPDATE discovery_distributions SET name='other' WHERE id=:id"), {'id': subset['id']})
    db.rollback()


def test_service_and_group_permissions_and_csrf(candidate):
    client, db, current = candidate
    saved = save(client, []).json()['distribution']
    assert client.post(BASE, json={'csrf_token': 'bad'}).status_code == 403
    assert client.get('/api/services/two/distributions').status_code == 404
    current['auth'] = scoped_auth(db.get(Group, 1), ('service.view',))
    assert client.get(BASE).json()['can_manage'] is False
    assert save(client, []).status_code == 403
    assert client.post(BASE+'/'+saved['id']+'/scan', json={'csrf_token':'csrf'}).status_code == 403
    current['auth'] = scoped_auth(db.get(Group, 2), ('service.view', 'service.edit', 'scan.ingest'))
    assert client.get(BASE).status_code == 404
    assert client.get('/api/services/two/distributions').json()['confirmations'] == []
    assert client.post('/api/services/two/distributions', json=dict(csrf_token='csrf', name='Copy',
        confirmation_id='confirmed', enabled_chart_ids=[])).status_code == 404


def test_shared_nested_release_needs_one_selected_owner(candidate):
    _, db, _ = candidate
    original = db.get(DiscoveryInventory, 'inventory')
    item = SimpleNamespace(id=original.id, source_hash=original.source_hash, content_hash=original.content_hash,
                           inventory=deepcopy(original.inventory))
    confirmation = db.get(DiscoveryConfirmation, 'confirmed')
    graph = item.inventory
    child = dict(graph['nodes'][0], id='nested', name='nested', kind='HelmRelease')
    graph['nodes'].append(child)
    # Both chart owners declare the same intermediate workload. A separate
    # root declaration and a reference edge must not override their ownership.
    graph['edges'].extend([dict(source='shared', target='nested', kind='declares'),
                           dict(source='product', target='nested', kind='declares'),
                           dict(source='missing', target='nested', kind='uses_source')])
    graph['images'].append(dict(reference='nested:1', component_id='nested', root_id='product'))
    for parent in ('one', 'two'):
        selection = _selection(1, 'Shared', confirmation, item, [parent, 'nested'])
        chart = next(c for c in selection['charts'] if c['id'] == 'nested')
        assert chart['parent_chart_ids'] == ['one', 'two'] and chart['default_enabled']
        assert 'nested:1' in selection['images']
    with pytest.raises(HTTPException, match='Select an owning chart'):
        _selection(1, 'Orphan', confirmation, item, ['nested'])
    assert 'nested:1' not in _selection(1, 'No charts', confirmation, item, [])['images']


def test_rehomed_service_cannot_review_or_scan_prior_group_distribution(candidate):
    from app.cyber_approval_evidence import _distribution_assessment
    client, db, current = candidate
    saved = save(client, ['two']).json()['distribution']
    service = db.get(Service, 1)
    assert _distribution_assessment(db, service, saved['id'], [])[0]['id'] == saved['id']
    db.delete(db.get(ServiceGroup, (1, 1)))
    db.flush()
    db.add(ServiceGroup(service_id=1, group_id=2))
    db.commit()
    current['auth'] = scoped_auth(db.get(Group, 2), ('service.view', 'service.edit', 'scan.ingest'))
    listing = client.get(BASE).json()
    assert listing['distributions'] == listing['confirmations'] == []
    assert client.post(BASE+'/'+saved['id']+'/scan', json={'csrf_token': 'csrf'}).status_code == 404
    blockers = []
    assert _distribution_assessment(db, service, saved['id'], blockers) == (None, None)
    assert 'unavailable' in blockers[0]


def test_only_verified_enabled_chart_and_dependency_sources_can_be_saved(candidate):
    _, db, _ = candidate
    original = db.get(DiscoveryInventory, 'inventory')
    confirmation = db.get(DiscoveryConfirmation, 'confirmed')
    item = SimpleNamespace(id=original.id, source_hash=original.source_hash, content_hash=original.content_hash,
                           inventory=deepcopy(original.inventory))
    chart = next(n for n in item.inventory['nodes'] if n['id'] == 'two')
    evidence = chart['provenance'][0]
    evidence['chart_sha256'] = ''
    with pytest.raises(HTTPException, match='version and content digest'):
        _selection(1, 'Release', confirmation, item, ['two'])
    evidence.update(chart_sha256='1'*64, reference='https://me:secret@example.test/chart')
    dependency = next(n for n in item.inventory['nodes'] if n['id'] == 'dependency')
    dependency['provenance'][0]['enabled'] = False
    issue = dict(root_id='product', component_id='dependency', blocking=True, code='helm_dependency_images_not_verified')
    item.inventory['diagnostics'].append(issue)
    selected = _selection(1, 'Release', confirmation, item, ['two'])
    assert selected['selection_completeness'] == 'complete' and selected['discovery_completeness'] == 'partial'
    assert not next(c['reference'] for c in selected['charts'] if c['id'] == 'two')
    dependency['provenance'][0]['enabled'] = None
    with pytest.raises(HTTPException, match='helm_dependency_images_not_verified'):
        _selection(1, 'Release', confirmation, item, ['two'])
    dependency['state'] = 'unresolved'
    with pytest.raises(HTTPException, match='Resolve and rediscover the Helm dependency'):
        _selection(1, 'Release', confirmation, item, ['two'])
    assert _selection(1, 'Release', confirmation, item, ['one'])['images'] == ['a:1', 'plain:1', 'shared:1']
    issue.update(code='unresolved_image_reference', component_id='shared')
    with pytest.raises(HTTPException, match='unresolved_image_reference'):
        _selection(1, 'Release', confirmation, item, ['one'])


def test_distribution_scan_uses_frozen_occurrences_recovers_and_can_be_reassessed(candidate, monkeypatch):
    client, db, _ = candidate
    import app
    from app import scan_coordination
    monkeypatch.setattr(scan_coordination, 'SessionLocal', lambda: Session(db.get_bind()))
    calls = []
    async def prepare(images, **kwargs):
        scan_id = 'scan' + str(len(calls))
        scan_coordination.DurableJobs()[scan_id] = dict(status='queued', image_list=images, **kwargs)
        calls.append((images, kwargs))
        return scan_id
    monkeypatch.setattr(app, 'main', SimpleNamespace(_prepare_public_scan=prepare, get_global_configuration=lambda db: {},
                        parse_json=lambda raw, default: default), raising=False)
    subset = save(client, ['two']).json()['distribution']
    path = BASE + '/' + subset['id'] + '/scan'
    def start():
        result = client.post(path, json={'csrf_token': 'csrf'})
        assert result.status_code == 200, result.text
        return result.json()['job_id']
    assert start() == start() == 'scan0'
    images, kwargs = calls[0]
    assert images.splitlines() == subset['images'] and kwargs['ingest_scope'] == 'distribution'
    context = kwargs['definition_context']
    assert context['distribution_id'] == subset['id'] and context['selection_digest'] == subset['selection_digest']
    assert context['discovery_inventory_id'] == 'inventory' and context['discovery_confirmation_id'] == 'confirmed'
    assert [r['component_id'] for r in context['discovery_images']] == ['shared', 'b', 'plain']
    with pytest.raises(HTTPException, match='does not match'):
        scan_coordination.DurableJobs()['forged'] = {**kwargs, 'status': 'queued', 'image_list': images,
            'definition_context': {**context, 'discovery_images': []}}
    db.get(ScanJob, 'scan0').status = 'complete'
    db.commit()
    assert start() == 'scan1'
    assert len(db.scalars(select(DiscoveryDistributionScan)).all()) == 2
    # A legacy full-inventory scan must never recover one of the subset scans.
    result = post(client, '/source/scan', {'confirmation_id': 'confirmed'})
    assert result.status_code == 200 and result.json()['job_id'] == 'scan2'
    assert calls[-1][1]['ingest_scope'] == 'service'
