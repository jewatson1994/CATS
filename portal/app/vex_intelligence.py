"""Bounded VEX ingestion and exact identity applicability. Never mutates findings."""
import hashlib
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit, unquote, parse_qsl
from sqlalchemy import select
from .vex_models import VexSource, VexDocument, VexStatement, VexIngestionAudit, utcnow

MAX_BYTES = 4 * 1024 * 1024
MAX_STATEMENTS = 10000
MAX_EVALUATION_CANDIDATES = 10000
_VERIFIED = object()
STATUSES = {'affected', 'not_affected', 'fixed', 'under_investigation'}

def _time(value):
    result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return result.astimezone(timezone.utc)

def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

def _json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Document exceeds byte limit')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Invalid JSON number')))
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid bounded JSON document') from exc
    if not isinstance(data, dict):
        raise ValueError('Document must be an object')
    return data

def configure_source(db, name, allowed_hosts=None, trusted=False, max_age_days=30, public_key=None, trust_reason=None, authoritative_prefixes=None, enabled=True):
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 200:
        raise ValueError('Source name is required (maximum 200 characters)')
    name = name.strip()
    if type(trusted) is not bool or type(enabled) is not bool:
        raise ValueError('Trusted and enabled must be booleans')
    if type(max_age_days) is not int or not 1 <= max_age_days <= 3650:
        raise ValueError('Invalid maximum age')
    for label, values in (('Authority scopes', authoritative_prefixes), ('Allowed hosts', allowed_hosts)):
        if values is not None and (not isinstance(values, list) or len(values) > 100 or any(not isinstance(v, str) or not v or len(v) > 1500 for v in values)):
            raise ValueError(label + ' must be a bounded list of nonempty strings')
    scopes = sorted(set(authoritative_prefixes or []))
    if trust_reason is not None and (not isinstance(trust_reason, str) or len(trust_reason) > 10000):
        raise ValueError('Invalid trust rationale')
    if trusted and (not trust_reason or not trust_reason.strip() or not scopes):
        raise ValueError('Trusted sources require an authority scope and trust rationale')
    if any(not re.fullmatch(r'pkg:[a-z][a-z0-9.+-]*/[^?#\s]*[/@]', p) or '%' in p for p in scopes):
        raise ValueError('Authority scopes must be package URL prefixes ending / or @')
    hosts = sorted(set(allowed_hosts or []))
    if any(len(h) > 253 or h != h.lower() or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', h) for h in hosts):
        raise ValueError('Use exact lowercase DNS hostnames')
    if public_key is not None:
        if not isinstance(public_key, str) or len(public_key) > 10000:
            raise ValueError('Invalid public key')
        if not public_key.strip():
            public_key = None
        else:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            try:
                key = serialization.load_pem_public_key(public_key.encode('ascii'))
            except (ValueError, TypeError, UnicodeError) as exc:
                raise ValueError('Valid Ed25519 public key required') from exc
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError('Ed25519 public key required')
    source = db.scalar(select(VexSource).where(VexSource.name == name))
    if source is None:
        source = VexSource(name=name)
        db.add(source)
    source.allowed_hosts, source.trusted, source.enabled = hosts, trusted, enabled
    source.max_age_days, source.public_key = max_age_days, public_key
    source.trust_reason, source.authoritative_prefixes = trust_reason, scopes
    db.flush()
    return source


def list_sources(db):
    from sqlalchemy import func
    issued = dict(db.execute(select(VexDocument.source_id, func.max(VexDocument.issued_at)).group_by(VexDocument.source_id)).all())
    now = utcnow()
    def health(source):
        date = issued.get(source.id)
        return ('disabled' if not source.enabled else 'untrusted' if not source.trusted else 'empty' if not date else 'future_dated' if _aware(date) > now else 'stale' if now >= _aware(date) + timedelta(days=source.max_age_days) else 'loaded')
    return [{'id': s.id, 'name': s.name, 'trusted': s.trusted, 'enabled': s.enabled,
             'allowed_hosts': s.allowed_hosts, 'max_age_days': s.max_age_days,
             'authoritative_prefixes': s.authoritative_prefixes, 'trust_reason': s.trust_reason,
             'last_success': s.last_success.isoformat() if s.last_success else None,
             'last_error': s.last_error, 'has_pinned_key': bool(s.public_key), 'health': health(s),
             'latest_issued_at': _aware(issued[s.id]).isoformat() if issued.get(s.id) else None}
            for s in db.scalars(select(VexSource).order_by(VexSource.id))]

def _identity(product):
    if not isinstance(product, dict):
        raise ValueError('Product must be an object')
    pid = product.get('@id') or product.get('id')
    if not isinstance(pid, str) or not pid or len(pid.encode("utf-8")) > 1500:
        raise ValueError('Product identity required')
    identity = {'product_id': pid}
    if pid.startswith('pkg:'):
        identity['purl'] = pid
        main = pid.split('?', 1)[0].split('#', 1)[0]
        if '@' in main:
            identity['version'] = unquote(main.rsplit('@', 1)[1])
        qualifiers = dict(parse_qsl(urlsplit(pid).query))
        for key in ('distro', 'digest'):
            if key in qualifiers:
                identity[key] = qualifiers[key]
    for key in ('version', 'distro', 'digest'):
        if key in product:
            if not isinstance(product[key], str) or not product[key].strip():
                raise ValueError('Product identity fields must be nonempty strings')
            if key in identity and identity[key] != product[key]:
                raise ValueError('Contradictory product identity')
            identity[key] = str(product[key])
    return identity

def _parse(raw):
    data = _json(raw)
    rows = []
    if data.get('@context') in ('https://openvex.dev/ns/v0.2.0', 'https://openvex.dev/ns/v0.2.0/'):
        fmt = 'openvex'
        key, version, issued = data['@id'], str(data['version']), _time(data['timestamp'])
        statements = data['statements']
        if not isinstance(statements, list) or len(statements) > MAX_STATEMENTS:
            raise ValueError('Invalid statement count')
        for statement in statements:
            from .ubuntu_vex import statement_cves
            cves = statement_cves(data, statement)
            status = statement['status']
            if status == 'not_affected' and not any(isinstance(statement.get(k), str) and statement[k].strip() for k in ('justification', 'impact_statement')):
                raise ValueError('not_affected requires justification or impact statement')
            products = statement['products']
            if not isinstance(products, list) or len(rows) + len(cves) * len(products) > MAX_STATEMENTS:
                raise ValueError('Invalid normalized statement count')
            for product in products:
                identity = _identity(product)
                for cve in cves:
                    rows.append((cve, identity, status, statement.get('justification'),
                                 statement.get('impact_statement'), statement.get('action_statement')))
    elif data.get('document', {}).get('category') == 'csaf_vex' and data['document'].get('csaf_version') == '2.0':
        fmt = 'csaf'
        track = data['document']['tracking']
        key, version, issued = track['id'], str(track['version']), _time(track['current_release_date'])
        from .csaf_identity import csaf_products
        products = csaf_products(data.get('product_tree', {}), data['document'].get('publisher', {}), _identity)
        mapping = {'known_affected': 'affected', 'known_not_affected': 'not_affected', 'fixed': 'fixed', 'under_investigation': 'under_investigation'}
        for vulnerability in data.get('vulnerabilities', []):
            for vendor_status, ids in vulnerability.get('product_status', {}).items():
                if vendor_status not in mapping:
                    continue
                for pid in ids:
                    if pid in products:
                        notes = '\n'.join(str(n.get('text', '')) for n in vulnerability.get('notes', []))
                        rows.append((vulnerability.get('cve'), products[pid], mapping[vendor_status], None, notes, None))
    else:
        raise ValueError('Unsupported VEX format/version')
    if not isinstance(key, str) or not key or len(key) > 2000 or not version or len(version) > 100 or len(rows) > MAX_STATEMENTS:
        raise ValueError('Invalid document identity or statement count')
    for cve, identity, status, *notes in rows:
        if any(note is not None and (not isinstance(note, str) or len(note) > 100000) for note in notes):
            raise ValueError('VEX statements require bounded text evidence')
        if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve) or status not in STATUSES:
            raise ValueError('Invalid CVE or VEX status')
    return data, fmt, key, version, issued, rows

def ingest_document(db, source_id, raw, *, verification='unverified', source_url=None, retrieved_at=None, _proof=None):
    source = db.get(VexSource, source_id)
    if source is None or not source.enabled:
        raise ValueError('Unknown or disabled source')
    if verification != 'unverified' and _proof is not _VERIFIED:
        raise ValueError('Verification requires authenticated retrieval or pinned signature')
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Invalid document bytes or byte limit exceeded')
    digest = hashlib.sha256(raw).hexdigest()
    existing = db.scalar(select(VexDocument).where(VexDocument.source_id == source_id, VexDocument.sha256 == digest))
    if existing:
        db.add(VexIngestionAudit(source_id=source_id, outcome='duplicate', detail=digest))
        return existing
    try:
        data, fmt, key, version, issued, rows = _parse(raw)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        source.last_error = 'Rejected invalid VEX document'
        db.add(VexIngestionAudit(source_id=source_id, outcome='rejected', detail=str(exc)[:500]))
        raise ValueError('Invalid VEX document: ' + str(exc)) from exc
    doc = VexDocument(source_id=source_id, sha256=digest, raw_text=raw.decode('utf-8'), format=fmt,
                      document_key=key, version=version, issued_at=issued, retrieved_at=retrieved_at or utcnow(),
                      source_url=source_url, verification=verification,
                      verification_key=hashlib.sha256((source.public_key or '').encode()).hexdigest() if verification == 'signature' else None, withdrawn=data.get('withdrawn') is True)
    db.add(doc)
    db.flush()
    # Bulk insertion keeps full vendor corpora bounded without changing normalization.
    for start in range(0, len(rows), 1000):
        db.execute(VexStatement.__table__.insert(), [
            dict(document_id=doc.id, cve=cve, product_id=identity['product_id'], identity=identity,
                 status=status, justification=justification, impact=impact, action=action)
            for cve, identity, status, justification, impact, action in rows[start:start + 1000]])
    source.last_success, source.last_error = retrieved_at or utcnow(), None
    db.add(VexIngestionAudit(source_id=source_id, outcome='ingested', detail=digest))
    db.flush()
    return doc

def _matches(identity, context):
    if identity.get('csaf_product_context') is not None and context.get('csaf_product_context') != identity['csaf_product_context']:
        return False
    pid = context.get('purl') or context.get('product_id')
    if not pid or pid != identity['product_id']:
        return False
    # A versionless package/name cannot establish version-specific applicability.
    observed_version = context.get('version')
    if not observed_version:
        main = pid.split('?', 1)[0].split('#', 1)[0]
        observed_version = unquote(main.rsplit('@', 1)[1]) if '@' in main else None
    if not identity.get('version') or not observed_version or str(observed_version) != identity['version']:
        return False
    for key in ('distro', 'digest'):
        if (context.get(key) or identity.get(key)) and str(context.get(key, '')) != str(identity.get(key, '')):
            return False
    return True

# Batch entry points share bounded evidence queries; single evaluation delegates here.
def _verification_current(doc, source):
    if doc.verification == 'signature':
        return bool(source.public_key) and doc.verification_key == hashlib.sha256(source.public_key.encode()).hexdigest()
    if doc.verification == 'tls':
        return bool(doc.source_url) and urlsplit(doc.source_url).hostname in source.allowed_hosts
    return False


def _identity_rejection(identity, context):
    reasons = []
    required = identity.get('csaf_product_context')
    if required is not None and context.get('csaf_product_context') != required:
        reasons.append('missing_product_context' if not context.get('csaf_product_context') else 'product_context_mismatch')
    pid = context.get('purl') or context.get('product_id')
    if pid != identity.get('product_id'):
        reasons.append('product_identity_mismatch' if pid else 'missing_package_identity')
    if not identity.get('version') or not context.get('version'):
        reasons.append('missing_package_version')
    elif str(context['version']) != identity['version']:
        reasons.append('version_mismatch')
    for key in ('distro', 'digest'):
        if str(context.get(key, '')) != str(identity.get(key, '')):
            reasons.append(key + '_mismatch')
    return reasons


def _publisher_matches(scope, doc, source, product):
    """Derived vendor spellings are only applicable to that publisher's evidence."""
    if not scope:
        return True
    namespace = scope.get('namespace')
    if namespace and not product.startswith('pkg:deb/' + namespace + '/'):
        return False
    publisher = scope.get('publisher')
    if publisher is None:
        return True
    parsed = urlsplit(doc.source_url or '')
    host = parsed.hostname
    if parsed.scheme != 'https' or parsed.username or parsed.password or host not in (source.allowed_hosts or []):
        return False
    if publisher == 'canonical':
        return (host == 'security-metadata.canonical.com' or
                host == 'github.com' and bool(re.fullmatch(
                    r'/canonical/ubuntu-security-notices/blob/[^/]+/vex/cve/[^/]+/CVE-\d{4}-\d{4,}\.json', parsed.path)) or
                host == 'raw.githubusercontent.com' and bool(re.fullmatch(
                    r'/canonical/ubuntu-security-notices/[^/]+/vex/cve/[^/]+/CVE-\d{4}-\d{4,}\.json', parsed.path)))
    return False


def _evaluate_records(records, latest, context, now, diagnostics=False, publisher_scope=None):
    matches, valid, rejected = [], [], []
    for statement, doc, source in records:
        reason = None
        if not _publisher_matches(publisher_scope, doc, source, statement.product_id):
            reason = 'derived_publisher_scope_mismatch'
        elif not _matches(statement.identity, context):
            reason = ', '.join(_identity_rejection(statement.identity, context)) or 'identity_mismatch'
        elif _aware(doc.issued_at) > now:
            reason = 'future_dated'
        elif _aware(doc.issued_at) != latest.get((doc.source_id, doc.document_key)):
            reason = 'superseded_revision'
        if reason:
            if diagnostics and len(rejected) < 20:
                rejected.append({'id': statement.id, 'document_id': doc.id, 'source_id': source.id,
                                 'source': source.name, 'identity': statement.identity, 'status': statement.status,
                                 'cve': statement.cve, 'accepted': False, 'reason': reason})
            continue
        reason = ('withdrawn' if doc.withdrawn else 'unverified' if not source.enabled or not source.trusted or not any(statement.product_id.startswith(p) for p in (source.authoritative_prefixes or [])) or not _verification_current(doc, source) else
                  'stale' if now >= _aware(doc.issued_at) + timedelta(days=source.max_age_days) else None)
        item = {'id': statement.id, 'document_id': doc.id, 'source_id': source.id, 'source': source.name,
                'status': statement.status, 'identity': statement.identity, 'verification': doc.verification,
                'sha256': doc.sha256, 'reason': reason, 'justification': statement.justification,
                'impact_statement': statement.impact, 'action_statement': statement.action,
                'valid_until': (_aware(doc.issued_at) + timedelta(days=source.max_age_days)).isoformat()}
        if diagnostics:
            item.update(accepted=reason is None, cve=statement.cve)
        matches.append(item)
        if reason is None:
            valid.append(item)
    statuses = {s['status'] for s in valid}
    status = 'conflicting' if len(statuses) > 1 else next(iter(statuses)) if statuses else next((r for r in ('withdrawn', 'stale', 'unverified') if any(s['reason'] == r for s in matches)), 'no_vex')
    # A stale/withdrawn assessment from a previously authoritative source is
    # uncertainty, not corroboration for an otherwise safe conclusion.
    if status in ('not_affected', 'fixed') and any(s['reason'] in ('stale', 'withdrawn') for s in matches):
        status = 'under_investigation'
    result = {'status': status, 'statements': matches,
            'valid_until': min((s['valid_until'] for s in valid), default=None),
            'reasons': sorted({s['reason'] for s in matches if s['reason']}) or ([status] if status in ('no_vex', 'conflicting') else [])}
    if diagnostics:
        result.update(rejected_candidates=rejected, exact_candidate_count=len(records),
                      rejected_candidates_truncated=len(rejected) == 20)
    return result


def _item_cves(item):
    # Scanner-supplied aliases only; package names never establish a CVE alias.
    aliases = item.get('aliases')
    aliases = aliases if isinstance(aliases, list) else []
    return sorted({value.upper() for value in [item['cve'], *aliases[:8]]
                   if isinstance(value, str) and re.fullmatch(r'CVE-\d{4}-\d{4,}', value, re.I)}) or [item['cve']]


def _merge_identity_results(parts, cves, diagnostics):
    """A relationship adds evidence; it never selects the safest of competing facts."""
    statements = [s for part in parts for s in part['statements']]
    accepted = [s for s in statements if s['reason'] is None]
    statuses = {s['status'] for s in accepted}
    status = ('conflicting' if len(statuses) > 1 else next(iter(statuses)) if statuses else
              next((r for r in ('withdrawn', 'stale', 'unverified')
                    if any(s['reason'] == r for s in statements)), 'no_vex'))
    reasons = {r for part in parts for r in part['reasons'] if r != 'no_vex'}
    if status == 'conflicting':
        reasons.add('identity_evidence_conflict')
        direct = {s['status'] for s in accepted if s['identity_kind'] == 'exact_observed'}
        derived = {s['status'] for s in accepted if s['identity_kind'] == 'authoritative_resolved'}
        if direct and derived and len(direct | derived) > 1:
            reasons.add('direct_derived_conflict')
    if status in ('not_affected', 'fixed'):
        if any(s['reason'] in ('stale', 'withdrawn', 'stale_mapping') for s in statements) or 'stale_mapping' in reasons:
            status = 'under_investigation'
        elif any(not any(s['cve'] == cve and s['status'] == status for s in accepted) for cve in cves):
            status = 'under_investigation'
            reasons.add('incomplete_alias_applicability')
    if status == 'no_vex' and 'stale_mapping' in reasons:
        status = 'under_investigation'
    result = {'status': status, 'statements': statements,
              'valid_until': min((p['valid_until'] for p in parts if p['valid_until']), default=None),
              'reasons': sorted(reasons) or (['no_vex'] if status == 'no_vex' else [])}
    if diagnostics:
        rejected = [s for part in parts for s in part.get('rejected_candidates', [])]
        result.update(exact_candidate_count=sum(p.get('exact_candidate_count', 0) for p in parts),
                      direct_candidate_count=parts[0].get('exact_candidate_count', 0),
                      resolved_candidate_count=sum(p.get('exact_candidate_count', 0) for p in parts[1:]),
                      direct_applicable_count=sum(s['identity_kind'] == 'exact_observed' for s in accepted),
                      resolved_applicable_count=sum(s['identity_kind'] == 'authoritative_resolved' for s in accepted),
                      rejected_candidates=rejected[:20],
                      rejected_candidates_truncated=len(rejected) > 20 or any(p.get('rejected_candidates_truncated') for p in parts))
    return result


def evaluate_batch(db, items, as_of=None, *, diagnostics=False, identity_candidates=None):
    """Exact indexed lookup; additional contexts are supplied only by the server resolver."""
    from sqlalchemy import tuple_, func
    if len(items) > 1000:
        raise ValueError('Evaluate at most 1000 items per batch')
    if identity_candidates is not None and len(identity_candidates) != len(items):
        raise ValueError('Identity candidate batches must align')
    now = _aware(as_of or utcnow())
    candidates, limits = [], []
    for index, item in enumerate(items):
        direct = {'kind': 'exact_observed', 'context': item.get('context', item)}
        extra = identity_candidates[index] if identity_candidates is not None else []
        extra = [c for c in extra if c.get('eligible') and c.get('kind') == 'authoritative_resolved']
        limited = len(extra) > 8
        known = {json.dumps(direct['context'], sort_keys=True)}
        contexts = [direct]
        for candidate in extra[:8]:
            key = json.dumps(candidate['context'], sort_keys=True)
            if key not in known:
                contexts.append(candidate)
                known.add(key)
        candidates.append(contexts)
        limits.append(limited)
    from sqlalchemy.orm import defer
    identities = sorted({(cve, product) for item, contexts in zip(items, candidates)
                         for cve in _item_cves(item) for candidate in contexts
                         if (product := candidate['context'].get('purl') or candidate['context'].get('product_id'))})
    records = []
    # Bound parameters as well as materialized records. No per-observation queries
    # or corpus-wide product enumeration, including positive high-fanout matches.
    for start in range(0, len(identities), 1000):
        records.extend(db.execute(select(VexStatement, VexDocument, VexSource)
            .options(defer(VexDocument.raw_text, raiseload=True))
            .join(VexDocument, VexDocument.id == VexStatement.document_id)
            .join(VexSource, VexSource.id == VexDocument.source_id)
            .where(tuple_(VexStatement.cve, VexStatement.product_id).in_(identities[start:start + 1000]))
            .limit(MAX_EVALUATION_CANDIDATES + 1 - len(records))).all())
        if len(records) > MAX_EVALUATION_CANDIDATES:
            return [{'status': 'under_investigation', 'statements': [], 'valid_until': None,
                     'reasons': ['candidate_limit']} for _ in items]
    keys = sorted({(d.source_id, d.document_key) for _, d, _ in records})
    latest = {}
    for start in range(0, len(keys), 400):
        for source_id, document_key, issued in db.execute(select(VexDocument.source_id, VexDocument.document_key, func.max(VexDocument.issued_at)).where(tuple_(VexDocument.source_id, VexDocument.document_key).in_(keys[start:start + 400]), VexDocument.issued_at <= now).group_by(VexDocument.source_id, VexDocument.document_key)):
            latest[(source_id, document_key)] = _aware(issued)
    by_pair = {}
    for row in records:
        by_pair.setdefault((row[0].cve, row[0].product_id), []).append(row)
    results = []
    for item, contexts, limited in zip(items, candidates, limits):
        cves = _item_cves(item)
        parts = []
        for candidate in contexts:
            context = candidate['context']
            pid = context.get('purl') or context.get('product_id')
            rows = [row for cve in cves for row in by_pair.get((cve, pid), [])]
            part = _evaluate_records(rows, latest, context, now, True, candidate.get('publisher_scope'))
            for statement in [*part['statements'], *part['rejected_candidates']]:
                statement.update(identity_kind=candidate['kind'], matched_product_id=pid,
                                 relationship=candidate.get('relationship'))
            if candidate.get('valid_until'):
                try:
                    expiry = _time(candidate['valid_until'])
                except (ValueError, TypeError):
                    expiry = now
                if expiry <= now:
                    for statement in part['statements']:
                        statement.update(accepted=False, reason='stale_mapping')
                    part.update(status='under_investigation', valid_until=None, reasons=['stale_mapping'])
                elif part['valid_until']:
                    part['valid_until'] = min(_time(part['valid_until']), expiry).isoformat()
            parts.append(part)
        result = _merge_identity_results(parts, cves, diagnostics)
        if limited:
            result['status'] = 'under_investigation'
            result['reasons'].append('identity_candidate_limit')
        if isinstance(item.get('aliases'), list) and len(item['aliases']) > 8 and result['status'] in ('not_affected', 'fixed'):
            result['status'] = 'under_investigation'
            result['reasons'].append('alias_limit')
        results.append(result)
    return results


def evaluate(db, cve, context, as_of=None):
    return evaluate_batch(db, [{'cve': cve, 'context': context}], as_of)[0]


def intelligence_token(db):
    from sqlalchemy import func
    sources = [{**s, 'last_success': None, 'last_error': None} for s in list_sources(db)]
    # Append-only revisions and every authority/config field contribute to invalidation.
    docs = db.execute(select(func.count(VexDocument.id), func.max(VexDocument.id))).one()
    keys = [(s.id, s.public_key) for s in db.scalars(select(VexSource).order_by(VexSource.id))]
    return hashlib.sha256(json.dumps([sources, list(docs), keys], sort_keys=True, default=str).encode()).hexdigest()



def sync_source_document(db, source_id, url):
    """Explicit HTTPS sync, DNS pinned per request, no proxies or redirects."""
    import ssl
    import time
    import urllib3
    source = db.get(VexSource, source_id)
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 32 for c in url):
        raise ValueError('URL outside pinned HTTPS source scope')
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError('URL outside pinned HTTPS source scope') from exc
    if source is None or not source.enabled or parsed.scheme != 'https' or parsed.hostname not in source.allowed_hosts or parsed.username or parsed.password or port not in (None, 443) or parsed.fragment:
        raise ValueError('URL outside pinned HTTPS source scope')
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError('Source resolves to nonpublic address')
    headers = {'Host': parsed.hostname, 'Accept-Encoding': 'identity'}
    previous = (source.etags or {}).get(url, {})
    if previous.get('etag'):
        headers['If-None-Match'] = previous['etag']
    if previous.get('modified'):
        headers['If-Modified-Since'] = previous['modified']
    # Connect to the checked address while validating the original hostname.
    pool = urllib3.HTTPSConnectionPool(addresses[0][4][0], port=443,
              ssl_context=ssl.create_default_context(), assert_hostname=parsed.hostname,
              server_hostname=parsed.hostname, timeout=urllib3.Timeout(connect=5, read=10), retries=False)
    response = None
    try:
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        response = pool.urlopen('GET', path, headers=headers, redirect=False, preload_content=False, decode_content=False)
        if response.status == 304:
            source.last_success, source.last_error = utcnow(), None
            return {'status': 'not_modified'}
        if response.status != 200:
            raise ValueError('Source returned HTTP ' + str(response.status))
        if response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise ValueError('Compressed source responses are unsupported')
        raw, deadline = bytearray(), time.monotonic() + 30
        while True:
            chunk = response.read(65536, decode_content=False)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_BYTES or time.monotonic() > deadline:
                raise ValueError('Source exceeds byte/time limit')
        doc = ingest_document(db, source_id, bytes(raw), verification='tls', source_url=url, _proof=_VERIFIED)
        source.etags = {**(source.etags or {}), url: {'etag': response.headers.get('ETag'), 'modified': response.headers.get('Last-Modified')}}
        return {'status': 'ingested', 'document_id': doc.id}
    except Exception:
        source.last_error = 'Source retrieval failed'
        db.add(VexIngestionAudit(source_id=source_id, outcome='fetch_failed', detail=url))
        raise
    finally:
        if response is not None:
            response.close()
        pool.close()
