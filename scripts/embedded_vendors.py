"""Bounded, replayable acquisition of licensed SUSE CSAF VEX documents.

The callback owns authenticated acquisition and the immutable input lock. This
module never retrieves data at runtime and does not infer package equivalence.
"""
import collections
import csv
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor

BASE = 'https://ftp.suse.com/pub/projects/security/csaf-vex/'
LICENSE_URL = 'https://creativecommons.org/licenses/by/4.0/legalcode.txt'
LICENSE_SHA256 = '9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411'
LICENSE_NOTICE = 'CSAF 2.0 data is provided by SUSE under the Creative Commons License 4.0 with Attribution (CC-BY-4.0).'
PATH_PATTERN = re.compile(r'20\d{2}/cve-\d{4}-\d{4,}\.json\Z')
TIME_PATTERN = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_ACQUIRED_BYTES = 2 * 1024 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate SUSE JSON key')
        result[key] = value
    return result


def bounded_text(path):
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('SUSE index exceeds byte bound')
    return path.read_text(encoding='utf-8')


def select_paths(index_text, changes_text, directories, max_documents):
    """Cross-check both official indexes against live directories, deterministically."""
    if type(max_documents) is not int or not 1 <= max_documents <= 10000:
        raise ValueError('SUSE document limit must be between 1 and 10000')
    paths = set(index_text.splitlines())
    if len(paths) > 200000 or any(not PATH_PATTERN.fullmatch(path) for path in paths):
        raise ValueError('Invalid or oversized SUSE VEX index')
    existing = set()
    for year, text in directories.items():
        if not re.fullmatch(r'20\d{2}', year):
            raise ValueError('Invalid SUSE directory year')
        existing.update(year + '/' + name for name in re.findall(r'href="(cve-\d{4}-\d{4,}\.json)"', text))
    updates = {}
    changes_count = 0
    for row in csv.reader(changes_text.splitlines()):
        changes_count += 1
        if changes_count > 400000 or len(row) != 2 or not PATH_PATTERN.fullmatch(row[0]) or not TIME_PATTERN.fullmatch(row[1]):
            raise ValueError('Invalid or oversized SUSE change index')
        path, modified = row
        if path in paths and path in existing:
            updates[path] = max(modified, updates.get(path, ''))
    selected = sorted(updates, key=lambda path: (updates[path], path), reverse=True)[:max_documents]
    if not selected:
        raise ValueError('SUSE selection contains no available indexed documents')
    return selected, dict(index_documents=len(paths), directory_documents=len(existing), change_index_entries=changes_count,
                          eligible_documents=len(updates), selected_documents=len(selected),
                          index_missing_from_directories=len(paths - existing),
                          not_selected_document_limit=max(0, len(updates) - len(selected)))


def prepare_vendor_sources(acquire, *, max_documents=2048, max_canonical_bytes=1024*1024, workers=4):
    """Return (source metadata, state); copy state['license_files'] into the release.

    acquire(name, url) returns (Path, provenance). Replaying the same locked
    inputs makes the same selection; network access belongs solely to acquire.
    """
    if type(max_canonical_bytes) is not int or type(workers) is not int or not 1024 <= max_canonical_bytes <= 4*1024*1024 or not 1 <= workers <= 4:
        raise ValueError('Invalid SUSE selection bounds')
    index, index_meta = acquire('suse-vex-index.txt', BASE + 'index.txt')
    changes, changes_meta = acquire('suse-vex-changes.csv', BASE + 'changes.csv')
    license_path, license_meta = acquire('LICENSE-suse.txt', LICENSE_URL)
    if license_path.stat().st_size > MAX_INPUT_BYTES or hashlib.sha256(license_path.read_bytes()).hexdigest() != LICENSE_SHA256:
        raise ValueError('SUSE CC-BY-4.0 license changed; review required')
    index_text = bounded_text(index)
    # Validate paths before they may influence URLs or local acquisition names.
    paths = index_text.splitlines()
    if len(paths) > 200000 or any(not PATH_PATTERN.fullmatch(path) for path in paths):
        raise ValueError('Invalid or oversized SUSE VEX index')
    years = sorted({path.split('/')[0] for path in paths})
    if len(years) > 30:
        raise ValueError('Too many SUSE VEX directories')
    directories, directory_meta = {}, {}
    for year in years:
        path, meta = acquire('suse-vex-directory-' + year + '.html', BASE + year + '/')
        directories[year], directory_meta[year] = bounded_text(path), meta
    selected, metrics = select_paths(index_text, bounded_text(changes), directories, max_documents)
    def get(relative):
        path, meta = acquire('suse-vex-' + relative.replace('/', '-'), BASE + relative)
        return path, meta
    # Unique cache names and per-input metadata are safe for the builder callback.
    documents, acquired_bytes = [], 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for offset in range(0, len(selected), workers):
            batch = list(executor.map(get, selected[offset:offset + workers]))
            acquired_bytes += sum(path.stat().st_size for path, _ in batch)
            if acquired_bytes > MAX_ACQUIRED_BYTES:
                raise ValueError('SUSE acquired document cohort exceeds byte bound')
            documents.extend(batch)
    metrics.update(acquired_document_bytes=acquired_bytes, max_documents=max_documents,
                   max_canonical_document_bytes=max_canonical_bytes,
                   policy='Newest modified indexed documents present in the publisher directories; complete documents only, no statement truncation')
    provenance = dict(index=index_meta, changes=changes_meta, directories=directory_meta, license=license_meta)
    source = dict(id='suse-vex', name='SUSE CSAF VEX', url=BASE, acquired_at=index_meta['acquired_at'],
                  allowed_hosts=['ftp.suse.com'], authoritative_prefixes=['pkg:rpm/suse/'], trusted=True,
                  max_age_days=30, license='CC-BY-4.0', attribution='SUSE Product Security Team',
                  provenance=provenance, counts={}, category='vex', selection=metrics,
                  coverage='Bounded complete SUSE CVE CSAF VEX documents; exact product and relationship identities')
    advisory = dict(source, id='suse-advisories', name='SUSE CSAF product recommendations',
                    authoritative_prefixes=[], trusted=False, category='advisory', counts={},
                    coverage='Explicit recommended product identities from the selected SUSE documents; not VEX fixed assertions')
    return [source, advisory], dict(documents=documents, license_files={'LICENSE-suse.txt': license_path},
                                   max_canonical_bytes=max_canonical_bytes, metrics=metrics)


def licensed_document(data):
    document = data.get('document', {})
    notices = [note.get('text') for note in document.get('notes', []) if note.get('category') == 'legal_disclaimer']
    publisher = document.get('publisher', {})
    return (document.get('category') == 'csaf_vex' and document.get('csaf_version') == '2.0'
            and publisher.get('category') == 'vendor' and publisher.get('namespace') == 'https://www.suse.com/'
            and notices == [LICENSE_NOTICE])


def emit_vendor_records(state, emit, parse, exclusions):
    """Emit original VEX and separate product-scoped recommended advisories."""
    from app.csaf_identity import csaf_products
    from app.vex_intelligence import _identity
    metrics = state['metrics']
    counts = collections.Counter()
    for path, meta in state['documents']:
        if path.stat().st_size > MAX_INPUT_BYTES:
            exclusions['suse_input_document_size_limit'] += 1
            continue
        try:
            data = json.loads(path.read_bytes(), object_pairs_hook=strict_object)
            raw = canonical(data)
            if not licensed_document(data):
                exclusions['suse_unreviewed_document_license_or_authority'] += 1
                continue
            if len(raw) > state['max_canonical_bytes']:
                exclusions['suse_canonical_size_above_limit'] += 1
                continue
            parsed = parse(raw)
        except (ValueError, KeyError, TypeError, AttributeError):
            exclusions['suse_invalid_document'] += 1
            continue
        rows = parsed[-1]
        emit(dict(source='suse-vex', kind='vex', url=meta['url'], acquired_at=meta['acquired_at'], raw=data))
        counts.update(documents=1, canonical_bytes=len(raw), normalized_statements=len(rows),
                      versioned_purl_statements=sum(bool(row[1].get('purl') and row[1].get('version')) for row in rows),
                      product_context_statements=sum(bool(row[1].get('csaf_product_context')) for row in rows),
                      documents_with_supported_status=bool(rows))
        for row in rows:
            counts['status_' + row[2]] += 1
            if row[1].get('version'):
                counts['versioned_status_' + row[2]] += 1
        products = csaf_products(data.get('product_tree', {}), data['document'].get('publisher', {}), _identity)
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', '')
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
                exclusions['suse_non_cve_recommendation'] += 1
                continue
            # Recommendations carry no safety/exemption assertion. Keep every
            # qualifier and relationship context from the publisher's identity.
            identities = {canonical(products[pid]): products[pid] for pid in vuln.get('product_status', {}).get('recommended', [])
                          if pid in products and products[pid].get('purl', '').startswith('pkg:rpm/suse/')}
            if identities:
                emit(dict(source='suse-advisories', kind='advisory', record_id=data['document']['tracking']['id'], cve=cve,
                          product=None, data=dict(status='recommended', affected_identities=[identities[k] for k in sorted(identities)], raw=data),
                          url=meta['url'], acquired_at=meta['acquired_at']))
                counts.update(advisory_records=1, recommended_product_identities=len(identities))
    metrics.update(dict(counts))
    metrics['excluded'] = {key: value for key, value in exclusions.items() if key.startswith('suse_')}
    return metrics
