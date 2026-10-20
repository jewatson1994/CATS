"""CSAF must retain vendor/product constraints before exact applicability."""
import copy
import json
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.vex_intelligence import _parse, _matches, configure_source, ingest_document, evaluate, _VERIFIED

PURL = 'pkg:rpm/redhat/openssl@3.0.7-1.el9?arch=x86_64'
CPE = 'cpe:/o:redhat:enterprise_linux:9'
NAMESPACE = 'https://www.redhat.com'
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


def product(pid, **helper):
    return {'product_id': pid, 'name': pid, 'product_identification_helper': helper}


def document():
    return {'document': {'category': 'csaf_vex', 'csaf_version': '2.0',
            'publisher': {'namespace': NAMESPACE},
            'tracking': {'id': 'CVE-2026-12345', 'version': '1', 'current_release_date': NOW.isoformat()}},
            'product_tree': {'full_product_names': [product('component', purl=PURL), product('os', cpe=CPE)],
                'relationships': [{'category': 'default_component_of', 'product_reference': 'component',
                    'relates_to_product_reference': 'os', 'full_product_name': product('combination')}]},
            'vulnerabilities': [{'cve': 'CVE-2026-12345', 'product_status': {'fixed': ['combination']}}]}


def parse(value):
    return _parse(json.dumps(value).encode())[-1]


def context():
    return {'purl': PURL, 'csaf_product_context': {'publisher': NAMESPACE, 'products': [{'cpe': CPE}]}}


def test_realistic_relationship_requires_exact_vendor_product_context():
    rows = parse(document())
    assert len(rows) == 1
    identity = rows[0][1]
    assert identity['product_id'] == PURL
    assert identity['csaf_product_id'] == 'combination'
    assert _matches(identity, context())
    for bad in ({'purl': PURL}, {**context(), 'csaf_product_context': {'publisher': NAMESPACE, 'products': [{'cpe': CPE.replace(':9', ':8')}]}},
                {**context(), 'csaf_product_context': {'publisher': 'https://other.example', 'products': [{'cpe': CPE}]}},
                {**context(), 'purl': PURL.replace('/redhat/', '/suse/')}, {**context(), 'version': 'different'},
                {**context(), 'csaf_product_context': CPE}):
        assert not _matches(identity, bad)


def test_conflicting_product_statuses_stay_in_their_separate_contexts():
    value = document()
    value['product_tree']['full_product_names'].append(product('os8', cpe=CPE.replace(':9', ':8')))
    relation = copy.deepcopy(value['product_tree']['relationships'][0])
    relation['relates_to_product_reference'] = 'os8'
    relation['full_product_name']['product_id'] = 'combination8'
    value['product_tree']['relationships'].append(relation)
    value['vulnerabilities'][0]['product_status']['known_affected'] = ['combination8']
    rows = parse(value)
    assert [row[2] for row in rows if _matches(row[1], context())] == ['fixed']


@pytest.mark.parametrize('mutation', ['missing_parent', 'unnamed_scope', 'missing_publisher', 'contradictory_helper', 'unsupported_relation'])
def test_unresolvable_relationship_never_falls_back_to_component_purl(mutation):
    value = document()
    if mutation == 'missing_parent':
        value['product_tree']['full_product_names'].pop()
    elif mutation == 'unnamed_scope':
        value['product_tree']['full_product_names'][1]['product_identification_helper'] = {}
    elif mutation == 'missing_publisher':
        value['document'].pop('publisher')
    elif mutation == 'contradictory_helper':
        value['product_tree']['relationships'][0]['full_product_name']['product_identification_helper'] = {'purl': PURL.replace('@3.0.7', '@4.0.0')}
    else:
        value['product_tree']['relationships'][0]['category'] = 'unknown'
    assert parse(value) == []


def test_versionless_vendor_assertion_is_stored_but_cannot_apply_to_installed_version():
    value = document()
    purl = 'pkg:rpm/redhat/openssl?arch=x86_64'
    value['product_tree']['full_product_names'][0]['product_identification_helper']['purl'] = purl
    identity = parse(value)[0][1]
    assert not _matches(identity, {**context(), 'purl': purl, 'version': '3.0.7-1.el9'})


def test_duplicate_ids_and_relationship_cycles_reject_document():
    value = document()
    value['product_tree']['full_product_names'].append(product('component'))
    with pytest.raises(ValueError, match='Duplicate CSAF'):
        parse(value)
    value = document()
    value['product_tree']['relationships'][0]['product_reference'] = 'combination'
    with pytest.raises(ValueError, match='Cyclic'):
        parse(value)


def test_nested_relationship_retains_all_context_layers():
    value = document()
    module = 'pkg:rpm/redhat/module@1?arch=x86_64'
    value['product_tree']['full_product_names'].append(product('module', purl=module))
    value['product_tree']['relationships'].append({'category': 'default_component_of', 'product_reference': 'module',
        'relates_to_product_reference': 'os', 'full_product_name': product('module-os')})
    value['product_tree']['relationships'][0]['relates_to_product_reference'] = 'module-os'
    identity = parse(value)[0][1]
    assert identity['csaf_product_context']['products'] == [{'cpe': CPE}, {'purl': module}]
    assert not _matches(identity, context())


def test_branch_ancestor_scope_is_not_flattened():
    value = document()
    value['product_tree'] = {'branches': [{'category': 'product_name', 'name': 'OS', 'product': product('os', cpe=CPE),
        'branches': [{'category': 'product_version', 'name': 'Component', 'product': product('component', purl=PURL)}]}]}
    value['vulnerabilities'][0]['product_status']['fixed'] = ['component']
    identity = parse(value)[0][1]
    assert not _matches(identity, {'purl': PURL})
    assert _matches(identity, context())


def test_database_batch_candidate_retains_scope_and_original_document():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        source = configure_source(db, 'Red Hat test', trusted=True, trust_reason='Synthetic test authority',
            allowed_hosts=['security.access.redhat.com'], authoritative_prefixes=['pkg:rpm/redhat/'])
        raw = json.dumps(document()).encode()
        loaded = ingest_document(db, source.id, raw, verification='tls', _proof=_VERIFIED,
            source_url='https://security.access.redhat.com/test.json')
        assert loaded.raw_text.encode() == raw
        assert evaluate(db, 'CVE-2026-12345', context(), NOW)['status'] == 'fixed'
        assert evaluate(db, 'CVE-2026-12345', {'purl': PURL}, NOW)['status'] == 'no_vex'
    engine.dispose()
