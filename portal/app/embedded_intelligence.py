"""Offline, signed distribution loader. Uses the existing VEX ingestion engine."""
import base64
import gzip
import hashlib
import json
import logging
import time
import re
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit
from sqlalchemy import select, text, func, Table, Column, Integer, String, MetaData, literal_column, JSON
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .intelligence_models import IntelligenceRecord, IntelligencePackageInstall, IntelligencePackageState, IntelligencePackageCatalog, IntelligencePackageMember
from .vex_models import VexSource, VexDocument, VexStatement, utcnow
from .vex_intelligence import configure_source, ingest_document, _VERIFIED, _time, _aware, _pairs

PACKAGE_DIR = Path(__file__).with_name('embedded_intelligence_data')
PINNED_KEY = PACKAGE_DIR / 'release-key.pem'
from .embedded_payload import payload_paths, PayloadReader

MAX_COMPRESSED = 2 * 1024 * 1024 * 1024
MAX_UNCOMPRESSED = 8 * 1024 * 1024 * 1024
MAX_LINE = 8 * 1024 * 1024
KINDS = {'advisory', 'vulnerability', 'exploitation', 'risk_enrichment'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def _decode(raw):
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))

def _manifest(directory, key_path):
    if (directory / 'manifest.json').stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Manifest exceeds size limit')
    raw = (directory / 'manifest.json').read_bytes()
    manifest = _decode(raw)
    if canonical(manifest) != raw:
        raise ValueError('Manifest must be canonical JSON')
    key = serialization.load_pem_public_key(Path(key_path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Ed25519 release key required')
    key.verify(base64.b64decode((directory / 'manifest.sig').read_bytes(), validate=True), raw)
    if manifest.get('schema') != 'cats-embedded-intelligence/v1':
        raise ValueError('Unsupported intelligence package schema')
    if type(manifest.get('sequence')) is not int or manifest['sequence'] < 0:
        raise ValueError('Invalid sequence')
    if not isinstance(manifest.get('version'), str) or not re.fullmatch(r'[a-zA-Z0-9:._-]{1,128}', manifest['version']):
        raise ValueError('Invalid version')
    if _time(manifest['built_at']) > utcnow():
        raise ValueError('Package build timestamp is in the future')
    for field, limit in [('payload_bytes', MAX_COMPRESSED), ('uncompressed_bytes', MAX_UNCOMPRESSED)]:
        if type(manifest.get(field)) is not int or not 0 < manifest[field] <= limit:
            raise ValueError('Invalid ' + field)
    paths = payload_paths(directory, manifest)
    if sum(path.stat().st_size for path in paths) != manifest['payload_bytes']:
        raise ValueError('Payload size mismatch')
    with PayloadReader(paths, manifest) as payload:
        reader = _HashingReader(payload, manifest['payload_bytes'])
        while reader.read(1024 * 1024):
            pass
        if reader.size != manifest['payload_bytes'] or reader.digest.hexdigest() != manifest.get('payload_sha256'):
            raise ValueError('Payload digest mismatch')
    sources = manifest.get('sources')
    if not isinstance(sources, list) or len(sources) > 1000 or len({s['id'] for s in sources}) != len(sources) or len({s['name'] for s in sources}) != len(sources):
        raise ValueError('Invalid package sources')
    return manifest

def _lock(db):
    if db.get_bind().dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(719303016241)'))
    elif db.get_bind().dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))

def _state(db, status, error=None):
    state = db.get(IntelligencePackageState, 1)
    if state is None:
        state = IntelligencePackageState(id=1)
        db.add(state)
    state.status, state.last_error, state.updated_at = status, error, utcnow()

def _url(url, metadata):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in metadata['allowed_hosts'] or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Evidence URL is outside signed HTTPS source scope')

class _HashingReader:
    def __init__(self, stream, limit):
        if type(limit) is not int or limit <= 0:
            raise ValueError('Invalid compressed payload byte bound')
        self.stream, self.digest, self.size = stream, hashlib.sha256(), 0
        self.limit, self.eof = limit, False

    def read(self, size=-1):
        if size < 0:
            raise ValueError('Unbounded compressed payload read')
        if size == 0 or self.eof:
            return b''
        remaining = self.limit - self.size
        block = self.stream.read(min(size, remaining, 1024 * 1024) if remaining else 1)
        if len(block) > remaining:
            raise ValueError('Payload changed: compressed payload exceeds signed size')
        if not block:
            if remaining:
                raise ValueError('Payload changed: compressed payload is shorter than signed size')
            self.eof = True
        self.digest.update(block)
        self.size += len(block)
        return block


@contextmanager
def _authenticated_payload(directory, manifest):
    # Authenticate exactly the compressed bytes consumed by this transaction,
    # including when the distribution file changes after preflight verification.
    with PayloadReader(payload_paths(directory, manifest), manifest) as compressed:
        reader = _HashingReader(compressed, manifest['payload_bytes'])
        with gzip.GzipFile(fileobj=reader, mode='rb') as payload:
            yield payload
        if reader.size != manifest['payload_bytes'] or reader.digest.hexdigest() != manifest['payload_sha256']:
            raise ValueError('Payload changed during import')


def _materialize_enrichment_catalogs(db, install):
    """One-time transactional projection of authenticated payload membership.

    Existing installations are backfilled only after the signed package is
    reverified at startup. Assessments never read this large historical manifest.
    """
    existing = set(db.scalars(select(IntelligencePackageCatalog.source_key).where(
        IntelligencePackageCatalog.install_id == install.id)))
    kinds = {'cisa-kev': ('exploitation', 'exploitation_sha256s'),
             'first-epss': ('risk_enrichment', 'risk_enrichment_sha256s')}
    for meta in install.manifest.get('sources', []):
        key = meta.get('id')
        if key not in kinds or key in existing:
            continue
        kind, field = kinds[key]
        hashes = sorted(set(meta.get(field, [])))
        source_id = db.scalar(select(VexSource.id).where(VexSource.name == meta['name']))
        if source_id is None:
            raise ValueError('Authenticated enrichment source is missing')
        catalog = IntelligencePackageCatalog(install_id=install.id, source_id=source_id,
            source_key=key, kind=kind, record_count=len(hashes), metadata_json={
                name: value for name, value in meta.items()
                if name not in ('exploitation_sha256s', 'risk_enrichment_sha256s')})
        db.add(catalog)
        db.flush()
        for start in range(0, len(hashes), 400):
            batch = hashes[start:start + 400]
            records = db.execute(select(IntelligenceRecord.id, IntelligenceRecord.sha256).where(
                IntelligenceRecord.source_id == source_id, IntelligenceRecord.kind == kind,
                IntelligenceRecord.sha256.in_(batch))).all()
            if {sha for _, sha in records} != set(batch):
                raise ValueError('Authenticated enrichment membership is incomplete')
            db.execute(IntelligencePackageMember.__table__.insert(), [
                {'catalog_id': catalog.id, 'record_id': record_id} for record_id, _ in records])


def _advisory_sources(sources):
    return {meta['id'] for meta in sources if meta.get('category') == 'advisory'
            or (meta.get('counts') or {}).get('advisory', 0) > 0}


def _materialize_advisory_catalogs(db, install_id, directory, manifest, expected):
    """Project signed advisory membership without loading history or retaining hashes.

    Stream the authenticated payload once when catalogs are absent. Deduplicated
    records can originate in older installations, so package_version is never used
    as evidence of membership. Temporary rows and all inserts share the install
    transaction; a changed payload or missing record rolls the projection back.
    """
    existing = set(db.scalars(select(IntelligencePackageCatalog.source_key).where(
        IntelligencePackageCatalog.install_id == install_id)))
    missing = expected - existing
    if not missing:
        return
    metadata = {meta['id']: meta for meta in manifest['sources'] if meta['id'] in missing}
    sources = {}
    for key, meta in metadata.items():
        source_id = db.scalar(select(VexSource.id).where(VexSource.name == meta['name']))
        if source_id is None:
            raise ValueError('Authenticated advisory source is missing')
        sources[key] = source_id
    if set(sources) != missing:
        raise ValueError('Advisory source is absent from signed manifest')
    membership = Table('cats_intelligence_advisory_members', MetaData(),
        Column('source_key', String(200), primary_key=True),
        Column('record_id', Integer, primary_key=True), prefixes=['TEMPORARY'])
    membership.create(db.connection())
    pending = defaultdict(set)
    pending_count = 0

    def flush():
        for key, hashes in pending.items():
            records = db.execute(select(IntelligenceRecord.id, IntelligenceRecord.sha256).where(
                IntelligenceRecord.source_id == sources[key], IntelligenceRecord.kind == 'advisory',
                IntelligenceRecord.sha256.in_(hashes))).all()
            if {sha for _, sha in records} != hashes:
                raise ValueError('Authenticated advisory membership is incomplete')
            ids = [record_id for record_id, _ in records]
            retained = set(db.scalars(select(membership.c.record_id).where(
                membership.c.source_key == key, membership.c.record_id.in_(ids))))
            new_rows = [{'source_key': key, 'record_id': record_id}
                        for record_id in ids if record_id not in retained]
            if new_rows:
                db.execute(membership.insert(), new_rows)
        pending.clear()

    total = 0
    last_progress = time.monotonic()
    with _authenticated_payload(directory, manifest) as payload:
        while True:
            line = payload.readline(MAX_LINE + 1)
            if not line:
                break
            total += len(line)
            if time.monotonic() - last_progress >= 60:
                logging.getLogger(__name__).info(
                    'Intelligence catalog pass read %d of %d payload bytes; transaction not yet committed',
                    total, manifest['uncompressed_bytes'])
                last_progress = time.monotonic()
            if len(line) > MAX_LINE or total > manifest['uncompressed_bytes']:
                raise ValueError('Uncompressed payload exceeds bound')
            entry = _decode(line)
            if not isinstance(entry, dict):
                raise ValueError('Invalid intelligence entry')
            if entry.get('kind') != 'advisory' or entry.get('source') not in missing:
                continue
            pending[entry['source']].add(hashlib.sha256(canonical(entry)).hexdigest())
            pending_count += 1
            if pending_count >= 400:
                flush()
                pending_count = 0
    if total != manifest['uncompressed_bytes']:
        raise ValueError('Uncompressed payload size mismatch')
    flush()
    for key, meta in metadata.items():
        count = db.scalar(select(func.count()).select_from(membership).where(membership.c.source_key == key))
        catalog = IntelligencePackageCatalog(install_id=install_id, source_id=sources[key],
            source_key=key, kind='advisory', record_count=count, metadata_json={
                name: value for name, value in meta.items()
                if name not in ('exploitation_sha256s', 'risk_enrichment_sha256s')})
        db.add(catalog)
        db.flush()
        db.execute(IntelligencePackageMember.__table__.insert().from_select(
            ['catalog_id', 'record_id'], select(catalog.id, membership.c.record_id)
            .where(membership.c.source_key == key)))
    membership.drop(db.connection())


def _import(db, directory, manifest):
    sources = {}
    for meta in manifest['sources']:
        if _time(meta['acquired_at']) > _time(manifest['built_at']):
            raise ValueError('Source acquisition timestamp exceeds build time')
        _url(meta['url'], meta)
        source = db.scalar(select(VexSource).where(VexSource.name == meta['name']))
        if source is None:
            supplemental = meta.get('category') != 'vex' and not meta['authoritative_prefixes']
            source = configure_source(db, meta['name'], allowed_hosts=meta['allowed_hosts'], trusted=False if supplemental else meta['trusted'],
                max_age_days=meta['max_age_days'], authoritative_prefixes=meta['authoritative_prefixes'],
                trust_reason=meta.get('trust_reason') or 'Authority and acquisition provenance in signed embedded distribution')
            if supplemental:
                # Supplemental catalog trust grants no VEX product authority: the
                # existing evaluator requires a nonempty matching PURL scope.
                source.trusted = meta['trusted']
        sources[meta['id']] = (source, meta)
    counts, source_counts = Counter(), defaultdict(Counter)
    pending = []
    import_docs = Table('cats_intelligence_import_docs', MetaData(),
        Column('document_id', Integer, nullable=False, index=True), Column('source_key', String(200), nullable=False),
        prefixes=['TEMPORARY'])
    import_docs.create(db.connection())
    document_batch = []
    def flush_documents():
        if document_batch:
            db.execute(import_docs.insert(), document_batch)
            document_batch.clear()
    exploitation_hashes = defaultdict(set)
    risk_enrichment_hashes = defaultdict(set)
    def flush():
        if not pending:
            return
        dialect = db.get_bind().dialect.name
        if dialect in ('postgresql', 'sqlite'):
            if dialect == 'postgresql':
                from sqlalchemy.dialects.postgresql import insert
            else:
                from sqlalchemy.dialects.sqlite import insert
            # Use the unique index directly. A hash-only preflight lookup can
            # repeatedly scan the growing table before import statistics exist.
            statement = insert(IntelligenceRecord.__table__).on_conflict_do_nothing(
                index_elements=['source_id', 'sha256'])
            db.execute(statement, pending)
            pending.clear()
            return
        # Bounded bulk deduplication and insertion: no SQL per supplemental record.
        hashes = {row['sha256'] for row in pending}
        existing = set(db.execute(select(IntelligenceRecord.source_id, IntelligenceRecord.sha256).where(IntelligenceRecord.sha256.in_(hashes))).all())
        unique = {}
        for row in pending:
            key = (row['source_id'], row['sha256'])
            if key not in existing:
                unique[key] = row
        if unique:
            db.execute(IntelligenceRecord.__table__.insert(), list(unique.values()))
        pending.clear()
    total = 0
    last_progress = time.monotonic()
    with _authenticated_payload(directory, manifest) as payload:
        while True:
            line = payload.readline(MAX_LINE + 1)
            if not line:
                break
            total += len(line)
            if time.monotonic() - last_progress >= 60:
                logging.getLogger(__name__).info(
                    'Intelligence import read %d of %d payload bytes; transaction not yet committed',
                    total, manifest['uncompressed_bytes'])
                last_progress = time.monotonic()
            if len(line) > MAX_LINE or total > manifest['uncompressed_bytes']:
                raise ValueError('Uncompressed payload exceeds bound')
            entry = _decode(line)
            source, meta = sources[entry['source']]
            acquired = _time(entry.get('acquired_at', meta['acquired_at']))
            if acquired > _time(manifest['built_at']):
                raise ValueError('Acquisition timestamp exceeds build time')
            _url(entry['url'], meta)
            kind = entry['kind']
            if kind == 'vex':
                enabled = source.enabled
                try:
                    source.enabled = True
                    doc = ingest_document(db, source.id, canonical(entry['raw']), verification='tls', source_url=entry['url'], retrieved_at=acquired, _proof=_VERIFIED)
                    document_batch.append(dict(document_id=doc.id, source_key=entry['source']))
                    if len(document_batch) >= 500:
                        flush_documents()
                    source.last_success = acquired
                finally:
                    source.enabled = enabled
            elif kind in KINDS:
                if not re.fullmatch(r'CVE-\d{4}-\d{4,}', entry['cve']) or not isinstance(entry['data'], dict) or not isinstance(entry['record_id'], str):
                    raise ValueError('Invalid supplemental intelligence record')
                product = entry.get('product')
                if product is not None and not isinstance(product, str):
                    raise ValueError('Invalid supplemental product')
                pending.append(dict(source_id=source.id, kind=kind, record_id=entry['record_id'], cve=entry['cve'], product=product,
                    data=entry['data'], sha256=hashlib.sha256(canonical(entry)).hexdigest(), acquired_at=acquired,
                    source_url=entry['url'], package_version=manifest['version']))
                if kind == 'exploitation':
                    exploitation_hashes[entry['source']].add(pending[-1]['sha256'])
                if kind == 'risk_enrichment' and entry['source'] == 'first-epss':
                    risk_enrichment_hashes[entry['source']].add(pending[-1]['sha256'])
                if len(pending) >= 500:
                    flush()
            else:
                raise ValueError('Unknown intelligence kind')
            counts[kind] += 1
            source_counts[entry['source']][kind] += 1
    if total != manifest['uncompressed_bytes']:
        raise ValueError('Uncompressed payload size mismatch')
    flush()
    flush_documents()
    for source_key in sources:
        ids = select(import_docs.c.document_id).where(import_docs.c.source_key == source_key).distinct()
        documents = db.scalar(select(func.count()).select_from(ids.subquery()))
        if not documents:
            continue
        statements, products = db.execute(select(func.count(), func.count(func.distinct(VexStatement.product_id)))
            .where(VexStatement.document_id.in_(ids))).one()
        source_counts[source_key].update(vex_documents=documents, vex_statements=statements, vex_products=products)
        counts.update(vex_documents=documents, vex_statements=statements, vex_products=products)
    import_docs.drop(db.connection())
    counts['sources'] = len(sources)
    counts['records'] = sum(counts[kind] for kind in KINDS)
    stored = dict(manifest)
    stored['_signed_manifest_sha256'] = hashlib.sha256(canonical(manifest)).hexdigest()
    stored['sources'] = [dict(meta, counts=dict(source_counts[meta['id']]), exploitation_sha256s=sorted(exploitation_hashes[meta['id']]), risk_enrichment_sha256s=sorted(risk_enrichment_hashes[meta['id']])) for meta in manifest['sources']]
    install = IntelligencePackageInstall(version=manifest['version'], sequence=manifest['sequence'], manifest=stored, counts=dict(counts))
    db.add(install)
    db.flush()
    _materialize_enrichment_catalogs(db, install)
    _materialize_advisory_catalogs(db, install.id, directory, manifest, _advisory_sources(stored['sources']))
    _state(db, 'installed')

def install_package(session_factory, package_dir=None, *, key_path=None):
    """Install atomically; the dedicated importer checks the returned failure status.

    Legacy single-database deployments still invoke this during startup.
    """
    directory = Path(package_dir) if package_dir is not None else PACKAGE_DIR
    try:
        manifest = _manifest(directory, key_path or PINNED_KEY)
        with session_factory() as db:
            _lock(db)
            current = db.execute(select(IntelligencePackageInstall.id, IntelligencePackageInstall.version,
                IntelligencePackageInstall.sequence, IntelligencePackageInstall.manifest['_signed_manifest_sha256']
                .as_string().label('signed_manifest_sha256'),
                _status_sources_projection(db.get_bind().dialect.name)).order_by(
                    IntelligencePackageInstall.sequence.desc()).limit(1)).first()
            if current:
                if manifest['sequence'] < current.sequence:
                    db.rollback()
                    return 'older_skipped'
                if manifest['sequence'] == current.sequence:
                    if manifest['version'] != current.version or hashlib.sha256(canonical(manifest)).hexdigest() != current.signed_manifest_sha256:
                        raise ValueError('Conflicting package at installed sequence')
                    expected = {meta['id'] for meta in manifest['sources'] if meta['id'] in ('cisa-kev', 'first-epss')}
                    projected = set(db.scalars(select(IntelligencePackageCatalog.source_key).where(
                        IntelligencePackageCatalog.install_id == current.id)))
                    if expected - projected:
                        _materialize_enrichment_catalogs(db, db.get(IntelligencePackageInstall, current.id))
                    _materialize_advisory_catalogs(db, current.id, directory, manifest, _advisory_sources(current.sources))
                    _state(db, 'installed')
                    db.commit()
                    return 'unchanged'
            _import(db, directory, manifest)
            db.commit()
        return 'installed'
    except Exception as exc:
        logging.getLogger(__name__).warning('Embedded intelligence package rejected: %s', exc)
        try:
            with session_factory() as db:
                _lock(db)
                _state(db, 'failed', (type(exc).__name__ + ': ' + str(exc))[:1000])
                db.commit()
        except Exception:
            logging.getLogger(__name__).exception('Could not persist intelligence installation failure')
        return 'failed'

def _status_sources_projection(dialect):
    # Keep arbitrary public source metadata while removing the large immutable
    # membership lists inside the database, before JSON decoding in Python.
    if dialect == 'postgresql':
        expression = """(SELECT COALESCE(jsonb_agg(
            entry.value::jsonb - 'exploitation_sha256s' - 'risk_enrichment_sha256s'
            ORDER BY entry.ordinal), '[]'::jsonb)
            FROM json_array_elements(intelligence_package_installs.manifest -> 'sources')
            WITH ORDINALITY AS entry(value, ordinal))"""
    elif dialect == 'sqlite':
        expression = """(SELECT json_group_array(json(public_meta)) FROM
            (SELECT json_remove(value, '$.exploitation_sha256s', '$.risk_enrichment_sha256s') AS public_meta
             FROM json_each(intelligence_package_installs.manifest, '$.sources') ORDER BY CAST(key AS INTEGER)))"""
    else:
        raise ValueError('Unsupported intelligence status database dialect')
    return literal_column(expression, type_=JSON).label('sources')


def package_status(db):
    current = db.execute(select(IntelligencePackageInstall.version, IntelligencePackageInstall.sequence,
        IntelligencePackageInstall.installed_at, IntelligencePackageInstall.counts,
        IntelligencePackageInstall.manifest['built_at'].as_string().label('built_at'),
        IntelligencePackageInstall.manifest['exclusions'].label('exclusions'),
        _status_sources_projection(db.get_bind(clause=select(IntelligencePackageInstall)).dialect.name))
        .order_by(IntelligencePackageInstall.sequence.desc()).limit(1)).first()
    state = db.get(IntelligencePackageState, 1)
    result = dict(status=state.status if state else 'not_installed', version=None, sequence=None, built_at=None, installed_at=None,
                  last_error=state.last_error if state else None, counts={}, sources=[], exclusions=[], history=[])
    if current is None:
        return result
    sources = {s.name: s for s in db.scalars(select(VexSource))}
    for meta in current.sources:
        source = sources.get(meta['name'])
        health = 'unknown' if source is None else 'future_dated' if _time(meta['acquired_at']) > utcnow() else 'disabled' if source and not source.enabled else 'untrusted' if source and not source.trusted else 'empty' if not sum(meta.get('counts', {}).values()) else 'stale' if utcnow() >= _time(meta['acquired_at']) + timedelta(days=source.max_age_days if source else meta['max_age_days']) else 'loaded'
        public_meta = {key: value for key, value in meta.items() if key not in ('exploitation_sha256s','risk_enrichment_sha256s')}
        result['sources'].append(dict(public_meta, max_age_days=source.max_age_days if source else meta['max_age_days'], expires_at=(_time(meta['acquired_at']) + timedelta(days=source.max_age_days if source else meta['max_age_days'])).isoformat(), health=health, trusted=source.trusted if source else False, enabled=source.enabled if source else False))
    result.update(version=current.version, sequence=current.sequence, built_at=current.built_at, installed_at=_aware(current.installed_at).isoformat(), counts=current.counts, exclusions=current.exclusions or [])
    # History needs no manifest; each retained manifest can contain a full EPSS membership list.
    history = db.execute(select(IntelligencePackageInstall.version, IntelligencePackageInstall.sequence,
        IntelligencePackageInstall.installed_at, IntelligencePackageInstall.counts)
        .order_by(IntelligencePackageInstall.sequence.desc()).limit(20))
    result['history'] = [dict(version=i.version, sequence=i.sequence, installed_at=_aware(i.installed_at).isoformat(), counts=i.counts) for i in history]
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Verify the embedded distribution without database or network access')
    parser.add_argument('--verify', action='store_true', required=True)
    args = parser.parse_args()
    try:
        verified = _manifest(PACKAGE_DIR, PINNED_KEY)
    except Exception as exc:
        parser.exit(1, 'Embedded intelligence verification failed: ' + type(exc).__name__ + ': ' + str(exc) + '\n')
    print('Verified embedded intelligence ' + verified['version'])
