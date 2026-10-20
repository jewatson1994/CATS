"""Reproducible, whole-document Red Hat CSAF/VEX release acquisition.

The legacy per-CVE feed is the published archive that fits the release acquisition
bound. The separately published binary-expanded vex-feed archive is not substituted.
"""
import collections
import hashlib
import json
import re
import tarfile

BASE_URL = 'https://security.access.redhat.com/data/csaf/v2/vex/'
LICENSE_URL = 'https://access.redhat.com/security/data'
CC_URL = 'https://creativecommons.org/licenses/by/4.0/legalcode.txt'
LICENSE_SHA256 = {
    'LICENSE-redhat.html': 'a1fd756f9ebd470a2e197bf43357f28c67a4970e6953791716bbd53558e8bda5',
    'LICENSE-redhat-CC-BY-4.0.txt': '9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411',
}
LEGAL_NOTICE = ('This content is licensed under the Creative Commons Attribution 4.0 International License '
    '(https://creativecommons.org/licenses/by/4.0/). If you distribute this content, or a modified version '
    'of it, you must provide attribution to Red Hat Inc. and provide a link to the original.')
MAX_CANONICAL_BYTES = 262144
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024


def _sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare_sources(acquire):
    index, index_meta = acquire('redhat-archive-latest.txt', BASE_URL + 'archive_latest.txt')
    filename = index.read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'csaf_vex_\d{4}-\d{2}-\d{2}\.tar\.zst', filename):
        raise ValueError('Unexpected Red Hat archive locator')
    archive, archive_meta = acquire('redhat-vex.tar.zst', BASE_URL + filename)
    checksum, checksum_meta = acquire('redhat-vex.sha256', BASE_URL + filename + '.sha256')
    fields = checksum.read_text(encoding='utf-8').strip().split()
    if len(fields) != 2 or fields[1] != filename or fields[0] != _sha(archive):
        raise ValueError('Red Hat archive publisher checksum mismatch')
    license_files, license_meta = {}, {}
    for name, url in (('LICENSE-redhat.html', LICENSE_URL), ('LICENSE-redhat-CC-BY-4.0.txt', CC_URL)):
        path, meta = acquire(name, url)
        if _sha(path) != LICENSE_SHA256[name]:
            raise ValueError('Upstream license changed; review required: ' + name)
        license_files[name], license_meta[name] = path, meta
    source = dict(id='redhat-vex', name='Red Hat CSAF VEX', url=BASE_URL, acquired_at=archive_meta['acquired_at'],
        allowed_hosts=['security.access.redhat.com'], authoritative_prefixes=['pkg:rpm/redhat/'],
        trusted=True, max_age_days=30, license='CC-BY-4.0', attribution='Red Hat, Inc.', counts={}, category='vex',
        coverage='Whole per-CVE documents from the original Red Hat VEX archive within the canonical size bound',
        provenance={'archive': archive_meta, 'publisher_checksum': checksum_meta, 'locator': index_meta, 'license_evidence': license_meta},
        license_files=list(license_files), license_evidence_url=LICENSE_URL,
        trust_reason='Official Red Hat archive acquired over HTTPS with publisher checksum; Red Hat RPM namespace only and exact CSAF product context required')
    state = {'archive': archive, 'archive_meta': archive_meta, 'source': source, 'license_files': license_files,
             'max_canonical_bytes': MAX_CANONICAL_BYTES}
    return [source], state


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def emit_records(state, emit, parse, exclusions):
    import zstandard
    from embedded_tar import bounded_tar_open
    metrics = collections.Counter()
    cohorts = {str(cap): collections.Counter() for cap in (65536, 262144, 1048576, 4194304)}
    max_bytes = state['max_canonical_bytes']
    if not 1 <= max_bytes <= 4 * 1024 * 1024:
        raise ValueError('Invalid Red Hat canonical document bound')
    products, cves = set(), set()
    with state['archive'].open('rb') as compressed, zstandard.ZstdDecompressor(max_window_size=128 * 1024 * 1024).stream_reader(compressed) as stream, bounded_tar_open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            metrics.update(archive_members=1, archive_uncompressed_bytes=member.size)
            if metrics['archive_members'] > 200000 or metrics['archive_uncompressed_bytes'] > MAX_ARCHIVE_BYTES:
                raise ValueError('Red Hat archive exceeds decompression bound')
            if not member.isfile():
                exclusions['redhat_non_regular_member'] += 1
                continue
            metrics.update(archive_documents=1)
            if not re.fullmatch(r'\d{4}/cve-\d{4}-\d{4,}\.json', member.name):
                exclusions['redhat_non_cve_member'] += 1
                continue
            if member.size > MAX_MEMBER_BYTES:
                exclusions['redhat_member_above_safety_bound'] += 1
                continue
            raw = archive.extractfile(member).read(MAX_MEMBER_BYTES + 1)
            if len(raw) != member.size:
                raise ValueError('Truncated Red Hat archive member')
            try:
                data = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
                canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
                if not isinstance(data, dict):
                    raise ValueError('Not an object')
            except (ValueError, TypeError, RecursionError):
                exclusions['redhat_invalid_json'] += 1
                continue
            for cap, cohort in cohorts.items():
                if len(canonical) <= int(cap):
                    cohort.update(documents=1, canonical_bytes=len(canonical))
            if len(canonical) > max_bytes:
                exclusions['redhat_canonical_size_above_limit'] += 1
                continue
            doc = data.get('document', {})
            if not any(note.get('category') == 'legal_disclaimer' and note.get('text') == LEGAL_NOTICE for note in doc.get('notes', [])):
                raise ValueError('Red Hat document redistribution notice changed: ' + member.name)
            if doc.get('publisher', {}).get('namespace') != 'https://www.redhat.com':
                exclusions['redhat_unexpected_publisher'] += 1
                continue
            try:
                parsed = parse(canonical)
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
                exclusions['redhat_invalid_' + type(error).__name__ + ':' + str(error)[:100]] += 1
                continue
            rows = parsed[-1]
            versioned = sum(bool(row[1].get('purl') and row[1].get('version')) for row in rows)
            contextual = sum(bool(row[1].get('csaf_product_context')) for row in rows)
            metrics.update(retained_documents=1, canonical_bytes=len(canonical), normalized_statements=len(rows),
                versioned_purl_statements=versioned, documents_with_versioned_purls=bool(versioned), contextual_statements=contextual,
                documents_without_normalized_statements=not rows)
            products.update(row[1]['product_id'] for row in rows)
            cves.update(row[0] for row in rows)
            emit(dict(source='redhat-vex', kind='vex', url=BASE_URL + member.name,
                acquired_at=state['archive_meta']['acquired_at'], raw=data, upstream_sha256=hashlib.sha256(raw).hexdigest()))
    result = dict(metrics, unique_product_identities=len(products), unique_cves=len(cves),
        measured_size_cohorts={cap: dict(cohort) for cap, cohort in cohorts.items()}, max_canonical_document_bytes=max_bytes,
        policy='Complete original per-CVE documents; no statement truncation; exact versioned PURL and CSAF product context required for applicability',
        excluded={key: value for key, value in exclusions.items() if key.startswith('redhat_')})
    state['source']['selection'] = result
    return result
