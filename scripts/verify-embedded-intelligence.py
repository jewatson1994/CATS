"""Benchmark the real signed distribution in a disposable database, never fixtures.

DATABASE_URL=sqlite:////tmp/embedded-acceptance.sqlite python scripts/verify-embedded-intelligence.py --report /tmp/report.json
No tables are dropped. PostgreSQL requires an explicitly loopback database URL.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
from time import perf_counter
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'portal'))



def package_name(purl):
    """Parse (ecosystem, namespace, name), excluding version/qualifiers/subpath.

    Only a final-component @ separates the version. A namespace such as
    npm/@scope stays intact; escaped path components are decoded separately.
    This does not assert equality between distinct package ecosystems.
    """
    if not isinstance(purl, str) or not purl.startswith('pkg:'):
        return None
    path = purl[4:].split('#', 1)[0].split('?', 1)[0]
    parts = path.split('/')
    if len(parts) < 2 or not parts[0] or not parts[-1]:
        return None
    name = parts[-1].rsplit('@', 1)[0]
    if not name:
        return None
    return (parts[0].lower(), tuple(unquote(part) for part in parts[1:-1]), unquote(name))


def aware(value):
    value = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def wrong_scope(identity):
    """Change a required distribution/product context while retaining the PURL."""
    from copy import deepcopy
    context = deepcopy(identity)
    if 'csaf_product_context' in context:
        context['csaf_product_context'] = {'publisher': context['csaf_product_context']['publisher'],
                                           'products': [{'cpe': 'cpe:/o:acceptance:wrong_product:0'}]}
        return context, 'same exact PURL and version, different containing product CPE'
    if 'distro' in context:
        context['distro'] = 'acceptance-wrong-distribution'
        return context, 'same exact PURL and version, contradictory distribution context'
    raise ValueError('Expected a source-scoped identity with distro or CSAF product context')


def freshness_identity_coverage(db, sources, now):
    """Count eligible retained rows without resolving observed applicability.

    Stream only candidate document verification metadata, then aggregate indexed
    statement batches in SQL. Never load raw documents or statement identities.
    """
    from sqlalchemy import select, func, case, or_
    from app.vex_models import VexDocument, VexStatement
    from app.vex_intelligence import _verification_current
    versioned = (VexStatement.product_id.like('pkg:%') & VexStatement.identity['version'].as_string().is_not(None)
                 & (VexStatement.identity['version'].as_string() != ''))
    contextual = VexStatement.identity['csaf_product_context'].as_string().is_not(None)
    distributed = VexStatement.identity['distro'].as_string().is_not(None)
    result = {}
    for source in sources:
        counts = {'fresh_verified_documents': 0, 'freshness_identity_eligible_statements': 0,
                  'freshness_identity_eligible_statuses': {},
                  'freshness_identity_eligible_csaf_context_statements': 0,
                  'freshness_identity_eligible_distro_statements': 0}
        result[source.id] = counts
        if not source.enabled or not source.trusted or not source.authoritative_prefixes:
            continue
        authority = or_(*(VexStatement.product_id.startswith(prefix, autoescape=True)
                          for prefix in source.authoritative_prefixes))
        def aggregate(document_ids):
            for status, total, contexts, distros in db.execute(select(VexStatement.status, func.count(),
                    func.sum(case((contextual, 1), else_=0)), func.sum(case((distributed, 1), else_=0)))
                    .where(VexStatement.document_id.in_(document_ids), versioned, authority)
                    .group_by(VexStatement.status)):
                counts['freshness_identity_eligible_statements'] += total
                counts['freshness_identity_eligible_csaf_context_statements'] += int(contexts or 0)
                counts['freshness_identity_eligible_distro_statements'] += int(distros or 0)
                statuses = counts['freshness_identity_eligible_statuses']
                statuses[status] = statuses.get(status, 0) + total
        candidates = select(VexDocument.id, VexDocument.verification, VexDocument.verification_key,
                            VexDocument.source_url).where(VexDocument.source_id == source.id,
                VexDocument.withdrawn.is_(False), VexDocument.issued_at <= now,
                VexDocument.issued_at > now - timedelta(days=source.max_age_days))
        batch = []
        for document in db.execute(candidates.execution_options(yield_per=400)):
            if not _verification_current(document, source):
                continue
            counts['fresh_verified_documents'] += 1
            batch.append(document.id)
            if len(batch) == 400:
                aggregate(batch)
                batch.clear()
        if batch:
            aggregate(batch)
    return result


def database_coverage(db, now=None):
    """Exact aggregate scans; no samples, estimates or full raw-document loads."""
    from sqlalchemy import select, func, case
    from app.vex_models import VexSource, VexDocument, VexStatement
    from app.intelligence_models import IntelligenceRecord
    started = perf_counter()
    now = aware(now or datetime.now(timezone.utc))
    source_rows = list(db.scalars(select(VexSource)))
    sources = {source.id: {'name': source.name, 'enabled': source.enabled, 'trusted': source.trusted,
                           'max_age_days': source.max_age_days, 'documents': 0, 'statements': 0,
                           'supplemental_records': 0, 'statuses': {}, 'versioned_statuses': {}, 'categories': {}}
               for source in source_rows}
    for source_id, total, first, last in db.execute(select(VexDocument.source_id, func.count(),
            func.min(VexDocument.issued_at), func.max(VexDocument.issued_at)).group_by(VexDocument.source_id)):
        sources[source_id].update(documents=total, earliest_document_issued_at=aware(first).isoformat(),
                                 latest_document_issued_at=aware(last).isoformat())
    versioned = (VexStatement.product_id.like('pkg:%') & VexStatement.identity['version'].as_string().is_not(None)
                 & (VexStatement.identity['version'].as_string() != ''))
    contextual = VexStatement.identity['csaf_product_context'].as_string().is_not(None)
    distributed = VexStatement.identity['distro'].as_string().is_not(None)
    aggregates = [func.count(), func.count(func.distinct(VexStatement.cve)),
                  func.count(func.distinct(VexStatement.product_id)),
                  func.sum(case((versioned, 1), else_=0)),
                  func.sum(case((versioned & contextual, 1), else_=0)),
                  func.sum(case((versioned & distributed, 1), else_=0))]
    fields = ('statements', 'unique_statement_cves', 'unique_statement_product_ids', 'versioned_purl_statements',
              'versioned_csaf_context_statements', 'versioned_distro_statements')
    for row in db.execute(select(VexDocument.source_id, *aggregates).join(VexStatement,
            VexStatement.document_id == VexDocument.id).group_by(VexDocument.source_id)):
        sources[row[0]].update(zip(fields, (int(value or 0) for value in row[1:])))
    for source_id, status, total, versioned_total in db.execute(select(VexDocument.source_id, VexStatement.status, func.count(), func.sum(case((versioned, 1), else_=0)))
            .join(VexStatement, VexStatement.document_id == VexDocument.id)
            .group_by(VexDocument.source_id, VexStatement.status)):
        sources[source_id]['statuses'][status] = total
        sources[source_id]['versioned_statuses'][status] = int(versioned_total or 0)
    freshness_started = perf_counter()
    freshness = freshness_identity_coverage(db, source_rows, now)
    freshness_seconds = perf_counter() - freshness_started
    for source_id, counts in freshness.items():
        sources[source_id].update(counts)
    pairs = select(VexDocument.source_id, VexStatement.cve, VexStatement.product_id).join(VexStatement,
        VexStatement.document_id == VexDocument.id).distinct().subquery()
    for source_id, total in db.execute(select(pairs.c.source_id, func.count()).group_by(pairs.c.source_id)):
        sources[source_id]['unique_cve_product_pairs'] = total
    for row in db.execute(select(IntelligenceRecord.source_id, IntelligenceRecord.kind, func.count(),
            func.count(func.distinct(IntelligenceRecord.cve)), func.count(func.distinct(IntelligenceRecord.product)))
            .group_by(IntelligenceRecord.source_id, IntelligenceRecord.kind)):
        sources[row[0]]['categories'][row[1]] = {'records': row[2], 'unique_cves': row[3], 'unique_product_ids': row[4]}
        sources[row[0]]['supplemental_records'] += row[2]
    source_cves = select(VexDocument.source_id, VexStatement.cve).join(VexStatement, VexStatement.document_id == VexDocument.id).union(select(IntelligenceRecord.source_id, IntelligenceRecord.cve)).subquery()
    for source_id, total in db.execute(select(source_cves.c.source_id, func.count()).group_by(source_cves.c.source_id)):
        sources[source_id]['unique_cves_across_all_categories'] = total
    all_cves = select(VexStatement.cve).union(select(IntelligenceRecord.cve)).subquery()
    all_products = select(VexStatement.product_id.label('product')).union(
        select(IntelligenceRecord.product.label('product')).where(IntelligenceRecord.product.is_not(None))).subquery()
    global_pairs = select(VexStatement.cve, VexStatement.product_id).distinct().subquery()
    overall = {
        'documents': sum(source['documents'] for source in sources.values()),
        'statements': sum(source['statements'] for source in sources.values()),
        'supplemental_records': sum(source['supplemental_records'] for source in sources.values()),
        'unique_cves_across_all_categories': db.scalar(select(func.count()).select_from(all_cves)),
        'unique_product_ids_across_all_categories': db.scalar(select(func.count()).select_from(all_products)),
        'unique_vex_cve_product_pairs': db.scalar(select(func.count()).select_from(global_pairs)),
        'unique_vex_cves': db.scalar(select(func.count(func.distinct(VexStatement.cve)))),
        'unique_vex_product_ids': db.scalar(select(func.count(func.distinct(VexStatement.product_id)))),
        'statuses': dict(sum((Counter(source['statuses']) for source in sources.values()), Counter())),
        'versioned_statuses': dict(sum((Counter(source['versioned_statuses']) for source in sources.values()), Counter()))}
    overall['freshness_identity_eligible_statuses'] = dict(sum(
        (Counter(source['freshness_identity_eligible_statuses']) for source in sources.values()), Counter()))
    for field in ('fresh_verified_documents', 'freshness_identity_eligible_statements',
                  'freshness_identity_eligible_csaf_context_statements', 'freshness_identity_eligible_distro_statements'):
        overall[field] = sum(source[field] for source in sources.values())
    for field in fields[3:]:
        overall[field] = sum(source.get(field, 0) for source in sources.values())
    # Stream only DISTINCT source/PURL strings. Raw JSON and the 20M+ statement
    # rows never enter Python. Package names are decoded as structured parts.
    package_sets = {source_id: set() for source_id in sources}
    unparsed = Counter()
    products = select(VexDocument.source_id, VexStatement.product_id.label('product')).join(VexStatement,
        VexStatement.document_id == VexDocument.id).union(select(IntelligenceRecord.source_id,
        IntelligenceRecord.product.label('product')).where(IntelligenceRecord.product.is_not(None)))
    for source_id, product in db.execute(products.execution_options(yield_per=1000)):
        name = package_name(product)
        if name is not None:
            package_sets[source_id].add(name)
        else:
            unparsed[source_id] += 1
    for source_id, source in sources.items():
        source['unique_package_names'] = len(package_sets[source_id])
        source['non_purl_product_ids'] = unparsed[source_id]
    overall['unique_package_names'] = len(set().union(*package_sets.values()))
    return {'scope': 'All immutable rows currently stored in this database, including historical revisions; not a claim of current package membership or applicability.',
            'definitions': {
                'unique_cve_product_pairs': 'Distinct CVE + exact product_id; repeated CVE/USN applicability rows collapse, but differing required CSAF contexts share a pair.',
                'unique_package_names': 'Distinct parsed (PURL type, decoded namespace components, decoded name); excludes version, qualifiers and subpath. Supplemental embedded JSON package names without a normalized product PURL are not counted.',
                'versioned_purl_statements': 'Rows with a PURL and explicit nonempty version. These require an exact observed identity and any distro/CSAF product context; this count is not fresh applicable matches.',
                'freshness_identity_eligible_statements': 'Retained versioned-PURL rows with currently enabled/trusted source authority, current TLS host or signature-key verification, nonwithdrawn document, and original issued_at <= as_of < issued_at + source max_age_days. Historical revisions may overlap. These are row preconditions, NOT unique resolved applicability or conflict-free matches; an exact observed identity and any required distro/CSAF context remain necessary.',
                'freshness_identity_eligible_csaf_context_statements': 'Eligible rows whose normalized identity requires exact resolved CSAF containing-product context. Unresolved CSAF products were excluded by normalization; this is not evidence that the scanned package supplied that context.',
                'fresh_matches': 'Measured separately by real scoped lookup examples at current time; source-as-of diagnostics are explicitly historical.'},
            'freshness_as_of': now.isoformat(), 'freshness_scan_seconds': freshness_seconds,
            'totals': overall, 'by_source': list(sources.values()), 'seconds': perf_counter() - started}


FRESH_EXAMPLE_DOCUMENT_LIMIT = 128
EXAMPLE_STATEMENT_LIMIT = 32


def scoped_lookup_examples(db, manifest, now):
    from sqlalchemy import select, or_
    from app.vex_models import VexSource, VexDocument, VexStatement
    from app.vex_intelligence import evaluate, _verification_current
    examples = {}
    seeds = {'redhat-vex': 'CVE-1999-0710', 'suse-vex': 'CVE-2015-4588'}

    def usable_assertion(result, statement):
        return result['status'] == statement.status and any(
            item['id'] == statement.id and item['reason'] is None for item in result['statements'])

    for source_key in ('ubuntu-vex', 'redhat-vex', 'suse-vex'):
        meta = next((value for value in manifest['sources'] if value['id'] == source_key), None)
        if meta is None:
            raise RuntimeError('Required vendor source absent from package: ' + source_key)
        source = db.scalar(select(VexSource).where(VexSource.name == meta['name']))
        if source is None:
            raise RuntimeError('Required vendor source not installed: ' + source_key)
        if not source.enabled or not source.trusted or not source.authoritative_prefixes:
            raise RuntimeError('Required vendor source lacks active trusted authority: ' + source_key)
        authority = or_(*(VexStatement.product_id.startswith(prefix, autoescape=True)
                          for prefix in source.authoritative_prefixes))
        query = select(VexStatement, VexDocument.id, VexDocument.issued_at, VexDocument.source_url,
                       VexDocument.document_key, VexDocument.sha256).join(VexDocument,
                       VexStatement.document_id == VexDocument.id).where(VexDocument.source_id == source.id,
                       VexDocument.issued_at <= now, authority,
                       VexStatement.product_id.like('pkg:%'), VexStatement.identity['version'].as_string().is_not(None),
                       VexStatement.identity['version'].as_string() != '')
        scope = 'distro' if source_key == 'ubuntu-vex' else 'csaf_product_context'
        query = query.where(VexStatement.identity[scope].as_string().is_not(None))
        selected = None
        selection_started = perf_counter()
        selection = {'mode': None, 'fresh_document_limit': FRESH_EXAMPLE_DOCUMENT_LIMIT,
                     'fresh_statement_evaluation_limit': EXAMPLE_STATEMENT_LIMIT,
                     'fresh_documents_examined': 0, 'fresh_statements_evaluated': 0,
                     'fallback_statement_limit_per_pass': EXAMPLE_STATEMENT_LIMIT,
                     'scope': 'Bounded example search, not an exhaustive claim that fresh matches are present or absent.'}
        # Bound documents before querying identities, avoiding a sort across all
        # vendor statements. Current verification uses the production predicate.
        documents = select(VexDocument.id, VexDocument.verification, VexDocument.verification_key,
                           VexDocument.source_url).where(VexDocument.source_id == source.id,
            VexDocument.withdrawn.is_(False), VexDocument.issued_at <= now,
            VexDocument.issued_at > now - timedelta(days=source.max_age_days)).order_by(
                VexDocument.issued_at.desc(), VexDocument.id.desc()).limit(FRESH_EXAMPLE_DOCUMENT_LIMIT)
        for document in db.execute(documents):
            selection['fresh_documents_examined'] += 1
            if not _verification_current(document, source):
                continue
            remaining = EXAMPLE_STATEMENT_LIMIT - selection['fresh_statements_evaluated']
            if not remaining:
                break
            candidates = query.where(VexDocument.id == document.id).order_by(VexStatement.id).limit(remaining)
            for row in db.execute(candidates):
                statement, document_id, issued_at, source_url, document_key, sha = row
                context = dict(statement.identity, purl=statement.product_id)
                selection['fresh_statements_evaluated'] += 1
                current = evaluate(db, statement.cve, context, as_of=now)
                if usable_assertion(current, statement):
                    as_of = aware(issued_at)
                    historical = evaluate(db, statement.cve, context, as_of=as_of)
                    selected = (*row[:2], as_of, source_url, document_key, sha, context, historical)
                    selection['mode'] = 'current_fresh'
                    break
            if selected or selection['fresh_statements_evaluated'] == EXAMPLE_STATEMENT_LIMIT:
                break
        if not selected:
            for seeded in (True, False):
                if seeded and source_key not in seeds:
                    continue
                candidate_query = query.where(VexStatement.cve == seeds[source_key]) if seeded else query
                # Explicit historical fallback still proves exact identity and
                # original publication-time trust; it makes no current claim.
                for row in db.execute(candidate_query.limit(EXAMPLE_STATEMENT_LIMIT)):
                    statement, document_id, issued_at, source_url, document_key, sha = row
                    context = dict(statement.identity, purl=statement.product_id)
                    as_of = aware(issued_at)
                    historical = evaluate(db, statement.cve, context, as_of=as_of)
                    if usable_assertion(historical, statement):
                        selected = (*row[:2], as_of, source_url, document_key, sha, context, historical)
                        selection['mode'] = 'historical_seed_fallback' if seeded else 'historical_sample_fallback'
                        break
                if selected:
                    break
        if not selected:
            raise RuntimeError('No trusted versioned context-scoped real example resolved within search bounds: ' + source_key)
        statement, document_id, as_of, source_url, document_key, sha, context, historical = selected
        selection_seconds = perf_counter() - selection_started
        started = perf_counter()
        current = evaluate(db, statement.cve, context, as_of=now)
        current_seconds = perf_counter() - started
        selection['selected_statement_current_usable'] = usable_assertion(current, statement)
        mismatched, mismatch_description = wrong_scope(context)
        started = perf_counter()
        wrong_now = evaluate(db, statement.cve, mismatched, as_of=now)
        wrong_as_of = evaluate(db, statement.cve, mismatched, as_of=as_of)
        mismatch_seconds = perf_counter() - started
        wrong_product = dict(context, purl=statement.product_id + '-acceptance-mismatch',
                             product_id=statement.product_id + '-acceptance-mismatch')
        wrong_purl = evaluate(db, statement.cve, wrong_product, as_of=as_of)
        if any(value['status'] != 'no_vex' for value in (wrong_now, wrong_as_of, wrong_purl)):
            raise RuntimeError('Wrong product context received VEX applicability: ' + source_key)
        examples[source_key] = {
            'cve': statement.cve, 'identity': context, 'source': source.name, 'source_url': source_url,
            'document_id': document_id, 'document_key': document_key, 'document_sha256': sha,
            'document_issued_at': as_of.isoformat(), 'source_acquired_at': meta['acquired_at'],
            'max_age_days': source.max_age_days, 'now': now.isoformat(), 'current': current,
            'current_fresh_match': any(item['source_id'] == source.id and item['reason'] is None for item in current['statements']),
            'selection': selection,
            'source_as_of': {'as_of': as_of.isoformat(), 'purpose': 'Historical diagnostic at the actual statement publication time; no production freshness or trust configuration changed.', 'result': historical},
            'wrong_context': {'description': mismatch_description, 'identity': mismatched,
                              'current': wrong_now, 'source_as_of': wrong_as_of},
            'wrong_purl': wrong_purl,
            'seconds': {'candidate_selection_and_source_as_of': selection_seconds, 'current_exact': current_seconds,
                        'wrong_context_current_and_source_as_of': mismatch_seconds}}
    return examples


def postgres_storage_and_plan(db, example):
    from sqlalchemy import text, select, bindparam
    from app.vex_models import VexSource, VexDocument, VexStatement
    tables = ('vex_sources', 'vex_documents', 'vex_statements', 'intelligence_records', 'intelligence_package_installs',
              'intelligence_package_catalogs', 'intelligence_package_members')
    sizes = db.execute(text("""SELECT t.relname AS table_name, pg_relation_size(t.oid) AS table_bytes,
        pg_indexes_size(t.oid) AS indexes_bytes, pg_total_relation_size(t.oid) AS total_bytes
        FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname=current_schema() AND t.relname IN :tables ORDER BY t.relname""").bindparams(
            bindparam('tables', expanding=True)), {'tables': tables}).mappings().all()
    indexes = db.execute(text("""SELECT t.relname AS table_name, i.relname AS index_name,
        pg_relation_size(i.oid) AS bytes, pg_get_indexdef(i.oid) AS definition
        FROM pg_index x JOIN pg_class t ON t.oid=x.indrelid JOIN pg_class i ON i.oid=x.indexrelid
        JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname=current_schema() AND t.relname IN :tables ORDER BY t.relname,i.relname""").bindparams(
            bindparam('tables', expanding=True)), {'tables': tables}).mappings().all()
    from sqlalchemy.orm import defer
    import app.vex_intelligence as vex_runtime
    candidate_limit = getattr(vex_runtime, "MAX_EVALUATION_CANDIDATES", 10000)
    query = select(VexStatement, VexDocument, VexSource).options(
        defer(VexDocument.raw_text, raiseload=True)).join(VexDocument,
        VexDocument.id == VexStatement.document_id).join(VexSource, VexSource.id == VexDocument.source_id).where(
        VexStatement.cve.in_([example['cve']]), VexStatement.product_id.in_([example['identity']['purl']])).limit(candidate_limit + 1)
    compiled = str(query.compile(dialect=db.bind.dialect, compile_kwargs={'literal_binds': True}))
    plan = db.scalar(text('EXPLAIN (FORMAT JSON, ANALYZE FALSE) ' + compiled))
    return {'tables': [dict(row) for row in sizes], 'indexes': [dict(row) for row in indexes],
            'representative_lookup_plan': {'source': example['source'], 'cve': example['cve'],
                'product_id': example['identity']['purl'], 'analyze': False, 'plan': plan},
            'note': 'Planner estimates are not measured row counts. Exact timed lookup and full-database counts are reported separately; indexes are reported as installed.'}


def enrichment_examples(db, install, now):
    from sqlalchemy import select
    from app.intelligence_models import IntelligenceRecord
    from app.vex_models import VexSource
    from app.packaged_risk_intelligence import overlay_packaged_kev, overlay_packaged_epss
    results = {}
    for name, kind, membership, overlay in (('cisa-kev', 'exploitation', 'exploitation_sha256s', overlay_packaged_kev),
            ('first-epss', 'risk_enrichment', 'risk_enrichment_sha256s', overlay_packaged_epss)):
        meta = next(value for value in install.manifest['sources'] if value['id'] == name)
        hashes = meta.get(membership, [])
        if not hashes:
            raise RuntimeError('Missing authenticated current enrichment membership: ' + name)
        source = db.scalar(select(VexSource).where(VexSource.name == meta['name']))
        query = select(IntelligenceRecord).where(IntelligenceRecord.source_id == source.id,
            IntelligenceRecord.kind == kind, IntelligenceRecord.sha256.in_(hashes[:128]))
        if name == 'first-epss':
            query = query.where(IntelligenceRecord.data['epss'].as_float() > 0)
        record = db.scalar(query.limit(1))
        if record is None:
            raise RuntimeError('No positive current package enrichment record found: ' + name)
        unknown_cve = 'CVE-1900-0000'
        if db.scalar(select(IntelligenceRecord.id).where(IntelligenceRecord.source_id == source.id,
                IntelligenceRecord.cve == unknown_cve).limit(1)) is not None:
            raise RuntimeError('Unknown control unexpectedly exists in real corpus')
        snapshot = {'findings': {record.cve: {'kev': None, 'epss': None}, unknown_cve: {'kev': None, 'epss': None}},
                    'kev': {'state': 'MISSING'}, 'epss': {'state': 'MISSING'}}
        started = perf_counter()
        current = overlay(db, snapshot, now)
        elapsed = perf_counter() - started
        reference = aware(meta.get('score_date', meta['acquired_at']))
        # At acquisition, both publication and acquisition have actually occurred.
        as_of = max(reference, aware(meta['acquired_at']))
        started = perf_counter()
        historical = overlay(db, snapshot, as_of)
        historical_seconds = perf_counter() - started
        field = 'kev' if name == 'cisa-kev' else 'epss'
        expected = True if field == 'kev' else record.data['epss']
        if historical['findings'][record.cve].get(field) != expected or historical['findings'][unknown_cve].get(field) is not None:
            raise RuntimeError('Real enrichment source-as-of positive or unknown control failed: ' + name)
        fresh = as_of <= now < reference + timedelta(days=source.max_age_days)
        if fresh and (current['findings'][record.cve].get(field) != expected or current['findings'][unknown_cve].get(field) is not None):
            raise RuntimeError('Fresh real enrichment current overlay failed: ' + name)
        results[field + '_overlay'] = {
            'cve': record.cve, 'source_url': record.source_url, 'sha256': record.sha256,
            'source_acquired_at': meta['acquired_at'], 'publication_at': reference.isoformat(),
            'max_age_days': source.max_age_days, 'current_fresh': fresh, 'now': now.isoformat(),
            'expected_positive_value': expected, 'positive': current['findings'][record.cve],
            'catalog': current[field], 'unknown_control': unknown_cve,
            'unknown_preserved': current['findings'][unknown_cve].get(field) is None,
            'seconds': elapsed, 'source_as_of': {'as_of': as_of.isoformat(), 'seconds': historical_seconds,
                'positive': historical['findings'][record.cve], 'unknown': historical['findings'][unknown_cve],
                'catalog': historical[field], 'purpose': 'Historical diagnostic at acquired publication; no production configuration changed.'}}
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--package-dir', type=Path)
    parser.add_argument('--key-path', type=Path)
    parser.add_argument('--already-installed', action='store_true', help='Inspect an imported normal-image database; skip only the first import, still measure repeat import')
    parser.add_argument('--upgrade-signing-key', type=Path, help='Optional external release key for a temporary same-payload/newer-sequence acceptance package')
    args = parser.parse_args()
    if not os.environ.get('DATABASE_URL'):
        parser.error('DATABASE_URL must explicitly select a disposable database')
    from sqlalchemy.engine import make_url
    url = make_url(os.environ['DATABASE_URL'])
    if url.get_backend_name() not in ('sqlite', 'postgresql'):
        parser.error('Only SQLite or explicitly loopback PostgreSQL are supported')
    allowed_port = None
    if url.get_backend_name() == 'postgresql':
        try:
            loopback = ipaddress.ip_address(url.host).is_loopback
        except (ValueError, TypeError):
            loopback = url.host == 'localhost'
        if not loopback:
            parser.error('PostgreSQL database must be loopback')
        allowed_port = url.port or 5432
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex
    blocked = []
    def guard(address):
        try:
            allowed = allowed_port is not None and ipaddress.ip_address(address[0]).is_loopback and address[1] == allowed_port
        except (ValueError, TypeError, IndexError):
            allowed = False
        if not allowed:
            blocked.append(str(address))
            raise RuntimeError('Offline acceptance blocked outbound socket: ' + str(address))
    def connect(sock, address):
        guard(address)
        return original_connect(sock, address)
    def connect_ex(sock, address):
        guard(address)
        return original_connect_ex(sock, address)
    socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
    from sqlalchemy import create_engine, event, select, func, text
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import models, risk_models
    from app.intelligence_models import IntelligenceRecord, IntelligencePackageInstall
    from app.vex_models import VexDocument, VexStatement
    from app.embedded_intelligence import install_package, package_status, PACKAGE_DIR, canonical
    from app.risk_profiles import score_observation, validate_policy
    engine = create_engine(os.environ['DATABASE_URL'])
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    queries = Counter()
    phase = ['install']
    progress_at = [perf_counter()]
    def sql_count(*unused):
        queries[phase[0]] += 1
        current = perf_counter()
        if current - progress_at[0] >= 20:
            print(json.dumps({'progress':phase[0], 'sql_statements':queries[phase[0]]}), flush=True)
            progress_at[0] = current
    event.listen(engine, 'before_cursor_execute', sql_count)
    report = {'started_at':datetime.now(timezone.utc).isoformat(), 'database_backend':engine.dialect.name,
              'corpus':'shipped signed distribution', 'network_policy':'blocked except explicitly loopback database', 'blocked_connections':blocked}
    try:
        with factory() as db:
            report['preexisting_install_count'] = db.scalar(select(func.count(IntelligencePackageInstall.id)))
        start = perf_counter()
        outcome = 'already_installed' if args.already_installed else install_package(factory, args.package_dir, key_path=args.key_path)
        report['install'] = {'outcome':outcome, 'seconds':perf_counter()-start}
        with factory() as db:
            status = package_status(db)
        if outcome not in ('installed', 'unchanged', 'already_installed') or not status.get('version'):
            raise RuntimeError(status.get('last_error') or outcome)
        report['package'] = status
        phase[0] = 'repeat'
        start = perf_counter()
        outcome = install_package(factory, args.package_dir, key_path=args.key_path)
        report['repeat'] = {'outcome':outcome, 'seconds':perf_counter()-start}
        if outcome != 'unchanged':
            raise RuntimeError('Repeated import did not skip')
        if args.upgrade_signing_key:
            import base64
            import shutil
            import tempfile
            from cryptography.hazmat.primitives import serialization
            directory = args.package_dir or PACKAGE_DIR
            manifest = json.loads((directory / 'manifest.json').read_bytes())
            manifest['sequence'] += 1
            signed_bytes = canonical(manifest)
            key = serialization.load_pem_private_key(args.upgrade_signing_key.read_bytes(), password=None)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='embedded-upgrade-', dir=args.report.parent) as temp:
                upgrade = Path(temp)
                from app.embedded_payload import payload_paths
                for part in payload_paths(directory, manifest):
                    shutil.copyfile(part, upgrade / part.name)
                (upgrade / 'manifest.json').write_bytes(signed_bytes)
                (upgrade / 'manifest.sig').write_bytes(base64.b64encode(key.sign(signed_bytes)))
                with factory() as db:
                    before = {model.__tablename__:db.scalar(select(func.count(model.id))) for model in (VexDocument,VexStatement,IntelligenceRecord)}
                phase[0] = 'upgrade'
                start = perf_counter()
                result = install_package(factory, upgrade, key_path=args.key_path)
                report['upgrade'] = {'outcome':result, 'seconds':perf_counter()-start, 'sequence':manifest['sequence'], 'kind':'Same real payload, temporary signed newer-sequence manifest; original release files unchanged'}
                if result != 'installed':
                    with factory() as db:
                        raise RuntimeError('Upgrade failed: ' + str(package_status(db).get('last_error')))
                phase[0] = 'downgrade'
                start = perf_counter()
                result = install_package(factory, args.package_dir, key_path=args.key_path)
                report['downgrade'] = {'outcome':result, 'seconds':perf_counter()-start}
                if result != 'older_skipped':
                    raise RuntimeError('Older signed package was not skipped')
                with factory() as db:
                    after = {model.__tablename__:db.scalar(select(func.count(model.id))) for model in (VexDocument,VexStatement,IntelligenceRecord)}
                if before != after:
                    raise RuntimeError('Same-payload upgrade duplicated immutable evidence')
                report['upgrade']['revision_counts_unchanged'] = True
        with factory() as db:
            phase[0] = 'full_database_counts'
            now = datetime.now(timezone.utc)
            report['coverage'] = database_coverage(db, now)
            report['database_counts'] = {name: report['coverage']['totals'][name]
                for name in ('documents', 'statements', 'supplemental_records')}
            install = db.scalar(select(IntelligencePackageInstall).order_by(IntelligencePackageInstall.sequence.desc()).limit(1))
            phase[0] = 'scoped_lookup'
            report['lookup_examples'] = scoped_lookup_examples(db, install.manifest, now)
            example = report['lookup_examples']['ubuntu-vex']
            report['lookup'] = {'cve': example['cve'], 'identity': example['identity'],
                'exact': example['current'], 'mismatch': example['wrong_context']['current'],
                'seconds': example['seconds']['current_exact'], 'as_of': now.isoformat()}
            inputs = {'severity': 'high', 'epss': None, 'kev': False, 'intelligence_current': False}
            report['score_scenario'] = {'description': 'Declared conservative scenario inputs with actual current-time Ubuntu VEX; not corpus CVSS/EPSS values.',
                'inputs': inputs, 'result': score_observation(validate_policy({}), vex=example['current'], **inputs)}
            phase[0] = 'enrichment_lookup'
            report.update(enrichment_examples(db, install, now))
            phase[0] = 'storage_and_plan'
            if engine.dialect.name == 'sqlite':
                report['database_bytes'] = db.scalar(text('PRAGMA page_count')) * db.scalar(text('PRAGMA page_size'))
            else:
                report['database_bytes'] = db.scalar(text('SELECT pg_database_size(current_database())'))
                report['postgresql'] = postgres_storage_and_plan(db, example)
        if blocked:
            raise RuntimeError('Runtime attempted prohibited outbound connections')
        report['passed'] = True
    except Exception as exc:
        report['passed'] = False
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        report['sql_statements'] = dict(queries)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, default=str), encoding='utf-8')
        engine.dispose()
        socket.socket.connect, socket.socket.connect_ex = original_connect, original_connect_ex
    print(json.dumps({'passed':report['passed'], 'report':str(args.report), 'install':report.get('install'), 'repeat':report.get('repeat'), 'counts':report.get('database_counts'), 'error':report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
