"""Bounded offline container evidence diagnostics; never alters scanner findings."""
from collections import defaultdict
from datetime import timedelta
import re
import math
from urllib.parse import unquote, parse_qsl
from sqlalchemy import select, union_all, literal, case, func, cast, Text, LargeBinary
from .risk_profiles import aware
from .vex_intelligence import _identity, _item_cves, evaluate_batch
from .vex_models import VexStatement, VexSource
from .intelligence_models import (IntelligenceRecord, IntelligencePackageInstall,
    IntelligencePackageCatalog, IntelligencePackageMember)

MAX_ADVISORY_CANDIDATES = 2000
MAX_ADVISORY_SCOPE_BYTES = 65536
ECOSYSTEMS = {'pypi': 'PyPI', 'maven': 'Maven', 'npm': 'npm', 'golang': 'Go',
              'nuget': 'NuGet', 'cargo': 'crates.io'}


def package_identity(purl):
    """Parse without rewriting vendor, version, architecture or distribution."""
    if not isinstance(purl, str) or len(purl.encode('utf-8')) > 1500:
        raise ValueError('missing_or_invalid_purl')
    if re.search(r'\s|%(?![0-9a-fA-F]{2})', purl):
        raise ValueError('malformed_purl')
    match = re.fullmatch(r'pkg:([a-z][a-z0-9.+-]*)/([^?#]+)(?:\?([^#]+))?(?:#(.+))?', purl)
    if not match:
        raise ValueError('malformed_purl')
    kind, path, query, subpath = match.groups()
    name, sep, version = path.rpartition('@')
    if not sep or not name or not version:
        raise ValueError('missing_package_version')
    qualifiers = parse_qsl(query or '', keep_blank_values=True, errors='strict', strict_parsing=True)
    if len(dict(qualifiers)) != len(qualifiers) or any(not k or not v for k, v in qualifiers):
        raise ValueError('ambiguous_purl_qualifiers')
    if any(not re.fullmatch(r'[a-z][a-z0-9._-]*', k) or any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in v) for k, v in qualifiers):
        raise ValueError('malformed_purl_qualifiers')
    if subpath is not None:
        subpath = unquote(subpath, errors='strict')
        if any(part in ('', '.', '..') for part in subpath.split('/')) or any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in subpath):
            raise ValueError('malformed_purl_subpath')
    decoded = unquote(name, errors='strict')
    decoded_version = unquote(version, errors='strict')
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in decoded + decoded_version):
        raise ValueError('malformed_purl')
    if any(part in ('', '.', '..') for part in decoded.split('/')):
        raise ValueError('malformed_purl')
    return {'type': kind, 'name': decoded, 'version': decoded_version,
            'qualifiers': dict(qualifiers), 'subpath': subpath}



def _scanner_version(parsed, raw_purl, installed, evidence):
    """Recognize proven scanner representations without changing package identity."""
    if not isinstance(installed, str):
        return installed, None
    version = parsed['version']
    if parsed['type'] == 'rpm':
        epoch_version = re.fullmatch(r'([0-9]+):(.+)', installed)
        if (epoch_version and epoch_version[1] == parsed['qualifiers'].get('epoch')
                and epoch_version[2] == version):
            return version, {'kind': 'rpm_epoch_qualifier', 'raw': installed,
                             'version': version, 'epoch': epoch_version[1]}
    if parsed['type'] == 'golang' and parsed['name'] == 'stdlib' and installed == 'go' + version:
        # Syft/Grype represent the Go runtime as go1.x, but its PURL as 1.x.
        # Require the same raw artifact tuple; unrelated module versions are not aliases.
        for key in ('scanner_artifact', 'sbom_artifact'):
            artifact = evidence.get(key)
            if (isinstance(artifact, dict) and artifact.get('type') == 'go-module'
                    and artifact.get('name') == 'stdlib' and artifact.get('purl') == raw_purl
                    and artifact.get('version') == installed):
                return version, {'kind': 'go_stdlib_prefix', 'raw': installed,
                                 'version': version, 'evidence': key}
    return installed, None


def observation_identity(observation):
    evidence = observation.evidence if isinstance(observation.evidence, dict) else {}
    raw = evidence.get('purl') or evidence.get('package_url')
    aliases = evidence.get('aliases')
    aliases = aliases if isinstance(aliases, list) else []
    alias_count = evidence.get('alias_count')
    alias_count = max(len(aliases), alias_count) if type(alias_count) is int and alias_count >= 0 else len(aliases)
    result = {'raw_purl': raw, 'scanner_distro': evidence.get('scanner_distro'),
              'scanner_artifact': evidence.get('scanner_artifact'),
              'scanner_source': evidence.get('scanner_source'),
              'scanner_descriptor': evidence.get('scanner_descriptor'),
              'sbom_descriptor': evidence.get('sbom_descriptor'), 'sbom_schema': evidence.get('sbom_schema'),
              'observed_at': evidence.get('observed_at'),
              'evidence_valid_until': evidence.get('evidence_valid_until'),
              'aliases': [v for v in aliases[:8] if isinstance(v, str)],
              'alias_count': alias_count,
              'alias_overflow': alias_count > 8 or evidence.get('aliases_truncated') is True,
              'sbom_artifact': evidence.get('sbom_artifact'), 'sbom_distro': evidence.get('sbom_distro'),
              'sbom_source': evidence.get('sbom_source'), 'image_provenance': evidence.get('image_provenance'),
              'image_digest': observation.image_digest, 'raw_installed_version': observation.installed_version,
              'version_normalization': None, 'context': {}, 'reasons': []}
    try:
        parsed = package_identity(raw)
        product = {'@id': raw}
        version, normalization = _scanner_version(parsed, raw, observation.installed_version, evidence)
        result['version_normalization'] = normalization
        digest = observation.image_digest if parsed['type'] == 'oci' else evidence.get('package_digest')
        for key, value in (('version', version), ('digest', digest), ('distro', evidence.get('distro'))):
            if value is not None:
                product[key] = value
        context = _identity(product)
        supplied = evidence.get('csaf_product_context')
        # Only an explicit publisher-scoped machine identity is carried forward.
        # Generic distro metadata and OCI labels are never promoted to enterprise scope.
        if supplied is not None:
            if (not isinstance(supplied, dict) or not isinstance(supplied.get('publisher'), str)
                or not supplied['publisher'] or not isinstance(supplied.get('products'), list)
                or not 0 < len(supplied['products']) <= 32
                or any(not isinstance(p, dict) or not p or set(p) - {'cpe', 'purl'}
                       or any(not isinstance(v, str) or len(v) > 1500 for v in p.values())
                       for p in supplied['products'])):
                raise ValueError('invalid_product_context')
            context['csaf_product_context'] = supplied
        result.update(context=context, package=parsed)
    except (ValueError, TypeError, UnicodeError) as exc:
        result['reasons'] = [str(exc)]
    return result


def _presence_samples(db, cves):
    """One indexed LIMIT 1 probe per input CVE, in bounded SQL batches.

    This intentionally does not count or enumerate every product for a common CVE.
    The retained sample proves presence, never that all other identities reject.
    """
    found = {}
    cves = sorted(set(cves))
    for start in range(0, len(cves), 200):
        wanted = union_all(*(select(literal(cve).label('cve')) for cve in cves[start:start + 200])).subquery('wanted_cves')
        first = select(VexStatement.id).where(VexStatement.cve == wanted.c.cve).limit(1).correlate(wanted).scalar_subquery()
        query = select(wanted.c.cve, VexStatement.id, VexStatement.product_id, VexStatement.document_id).select_from(wanted).outerjoin(VexStatement, VexStatement.id == first)
        for cve, sid, product, document in db.execute(query):
            found[cve] = {'id': sid, 'product_id': product, 'document_id': document} if sid else None
    return found


def evaluate_container_batch(db, items, now):
    from .package_identity_resolution import resolve_package_identity
    resolutions = []
    for item in items:
        identity = item.get('identity', {'context': item.get('context', {})})
        # Recompute from retained observation evidence. Never accept a caller's
        # precomputed candidates as authority, and avoid recursively copying a
        # previous resolution when an item is evaluated more than once.
        observed = {key: value for key, value in identity.items() if key != 'resolution'}
        resolution = resolve_package_identity(observed, now=now)
        identity['resolution'] = resolution
        resolutions.append(resolution)
    results = evaluate_batch(db, items, now, diagnostics=True,
                             identity_candidates=[r['candidates'] for r in resolutions])
    absent_exact = [item for item, result in zip(items, results) if result.get('exact_candidate_count') == 0]
    samples = _presence_samples(db, [cve for item in absent_exact for cve in _item_cves(item)])
    for item, result, resolution in zip(items, results, resolutions):
        result['resolved_identity_count'] = sum(c.get('eligible') is True and c['kind'] == 'authoritative_resolved' for c in resolution['candidates'])
        result['resolution_outcome'] = resolution['outcome']
        identities = item.get('identity', {})
        result['lookup_cves'] = _item_cves(item)
        if 'candidate_limit' in result.get('reasons', []):
            result['cve_present'] = None
        elif result.get('exact_candidate_count'):
            result['cve_present'] = True
        else:
            sample = next((samples[cve] for cve in _item_cves(item) if samples.get(cve)), None)
            result['cve_present'] = bool(sample)
            if sample:
                result.setdefault('rejected_candidates', []).append({**sample, 'accepted': False,
                    'identity': {'product_id': sample['product_id']},
                    'reason': 'different_product_identity_sample' if sample['product_id'] != item.get('context', {}).get('product_id') else 'cve_presence_sample', 'sample_only': True})
        reasons = list(result.get('reasons', []))
        if identities.get('alias_overflow'):
            reasons.append('alias_limit')
            if result['cve_present'] is False:
                result['cve_present'] = None
            if result['status'] in ('not_affected', 'fixed'):
                result['status'] = 'under_investigation'
        if identities.get('reasons'):
            reasons.extend(identities['reasons'])
        reasons.extend(resolution.get('reasons', []))
        # Failed source relationships cannot invalidate an independently complete
        # direct match. Disagreement on the observed installed tuple itself is
        # different: e.g. an arm64 DB record cannot corroborate an amd64 target.
        # Keep that uncertainty visible even when the PURL alone matches VEX.
        observed_tuple_conflicts = {
            'installed_record_observation_mismatch', 'installed_binary_metadata_conflict',
            'observed_version_conflict', 'binary_epoch_conflict', 'distribution_namespace_conflict',
            'distribution_release_conflict', 'distribution_purl_conflict',
            'distribution_codename_conflict', 'distribution_codename_release_conflict',
        }
        observed_conflict = (resolution['outcome'] == 'conflicting_authoritative_metadata'
                             and bool(observed_tuple_conflicts.intersection(resolution.get('reasons', []))))
        resolution_uncertain = (resolution['outcome'] in ('stale_mapping', 'conflicting_authoritative_metadata')
                                or 'identity_candidate_limit' in resolution.get('reasons', []))
        direct_complete = all(any(statement.get('identity_kind') == 'exact_observed'
                and statement.get('reason') is None and statement.get('cve') == cve
                and statement.get('status') == result['status'] for statement in result.get('statements', []))
            for cve in result['lookup_cves'])
        if result['status'] in ('not_affected', 'fixed') and (observed_conflict or resolution_uncertain and not direct_complete):
            result['status'] = 'under_investigation'
            reasons.append('identity_resolution_uncertain')
        if result.get('exact_candidate_count') == 0 and result['cve_present'] is not None:
            reasons.append('cve_present_without_exact_product' if result['cve_present'] else 'cve_absent_from_vex')
        result['reasons'] = list(dict.fromkeys(reasons))
        missing = identities.get('reasons') or any('missing_' in r.get('reason', '') for r in result.get('rejected_candidates', []))
        result['applicability_state'] = 'missing_context' if missing and result['status'] == 'no_vex' else result['status']
    return results


def _package_name(kind, name):
    if kind == 'pypi':
        return re.sub(r'[-_.]+', '-', name).lower()
    return name.replace('/', ':', 1) if kind == 'maven' else name


def advisory_batch(db, items, now):
    """Link package-scoped OSV/SecDB references, without inferring VEX status.

    Version ranges are retained for reviewer inspection, not reimplemented as a
    second scanner. No advisory can establish Not Affected or reduce a score.
    Only members of the current authenticated package are considered.
    """
    cves = sorted({cve for item in items for cve in _item_cves(item)})
    latest = select(IntelligencePackageInstall.id).order_by(IntelligencePackageInstall.sequence.desc()).limit(1).scalar_subquery()
    rows = []
    scopes = {key: IntelligenceRecord.data[key] for key in ('affected', 'package', 'release', 'withdrawn')}
    byte_length = (lambda value: func.octet_length(cast(value, Text))) if db.bind.dialect.name == 'postgresql' else (lambda value: func.length(cast(cast(value, Text), LargeBinary)))
    scope_size = sum(func.coalesce(byte_length(value), 0) for value in scopes.values())
    scope_bounded = scope_size <= MAX_ADVISORY_SCOPE_BYTES
    for start in range(0, len(cves), 400):
        remaining = MAX_ADVISORY_CANDIDATES + 1 - len(rows)
        if remaining <= 0:
            break
        # Project only package applicability fields, never complete advisory documents.
        rows.extend(db.execute(select(IntelligenceRecord.id, IntelligenceRecord.cve,
            IntelligenceRecord.record_id, IntelligenceRecord.source_url, IntelligenceRecord.kind,
            *(case((scope_bounded, value), else_=None).label(key) for key, value in scopes.items()),
            scope_bounded.label('scope_bounded'),
            VexSource.name, VexSource.enabled, VexSource.trusted, VexSource.max_age_days,
            IntelligencePackageCatalog.metadata_json)
            .join(IntelligencePackageMember, IntelligencePackageMember.record_id == IntelligenceRecord.id)
            .join(IntelligencePackageCatalog, IntelligencePackageCatalog.id == IntelligencePackageMember.catalog_id)
            .join(VexSource, VexSource.id == IntelligenceRecord.source_id)
            .where(IntelligencePackageCatalog.install_id == latest,
                   IntelligenceRecord.kind == 'advisory', IntelligenceRecord.cve.in_(cves[start:start + 400]))
            .limit(remaining)).mappings())
    if len(rows) > MAX_ADVISORY_CANDIDATES:
        return [{'records': [], 'reasons': ['advisory_candidate_limit'], 'truncated': True, 'valid_until': None} for _ in items]
    by_cve = defaultdict(list)
    for row in rows:
        by_cve[row['cve']].append(row)
    results = []
    for item in items:
        identity = item.get('identity', {})
        package = identity.get('package') or {}
        kind, observed_name = package.get('type'), package.get('name', '')
        records, reasons, seen = [], [], set()
        valid_until = None
        for cve in _item_cves(item):
            for row in by_cve[cve]:
                if row['id'] in seen:
                    continue
                seen.add(row['id'])
                if not row['scope_bounded']:
                    reasons.append('advisory_scope_limit')
                    continue
                matched, version_basis = False, None
                if kind in ECOSYSTEMS:
                    affected = row['affected'] if isinstance(row['affected'], list) else []
                    for entry in affected[:1000]:
                        if not isinstance(entry, dict) or not isinstance(entry.get('package'), dict):
                            continue
                        pkg = entry['package']
                        if not isinstance(pkg.get('name'), str):
                            continue
                        if pkg.get('ecosystem') != ECOSYSTEMS[kind] or _package_name(kind, str(pkg.get('name', ''))) != _package_name(kind, observed_name):
                            continue
                        versions = entry.get('versions')
                        versions = versions if isinstance(versions, list) and all(isinstance(v, str) for v in versions) else []
                        ranges = entry.get('ranges')
                        ranges = ranges if isinstance(ranges, list) and all(isinstance(r, dict) for r in ranges) else []
                        if package.get('version') in versions:
                            matched, version_basis = True, 'explicit_version_list'
                        elif ranges:
                            matched, version_basis = True, 'package_reference_ranges_not_evaluated'
                        else:
                            reasons.append('advisory_version_not_listed')
                elif kind == 'apk' and observed_name.startswith('alpine/'):
                    matched = (row['package'] == observed_name.split('/', 1)[1]
                               and row['release'] == package.get('qualifiers', {}).get('distro'))
                    version_basis = 'package_reference_secdb_fix_not_evaluated'
                if not matched:
                    continue
                meta = row['metadata_json'] or {}
                try:
                    acquired = aware(meta['acquired_at'])
                    expires = acquired + timedelta(days=row['max_age_days'])
                    current = acquired <= now < expires
                except (KeyError, TypeError, ValueError, OverflowError):
                    current = False
                reason = ('withdrawn' if row['withdrawn'] else 'untrusted_or_disabled' if not row['enabled'] or not row['trusted'] else 'stale' if not current else None)
                if reason is None:
                    valid_until = min(valid_until, expires) if valid_until else expires
                records.append({'id': row['id'], 'source': row['name'], 'external_id': row['record_id'],
                    'kind': 'advisory', 'source_url': row['source_url'], 'cve': cve,
                    'match_reason': version_basis, 'reason': reason, 'current': reason is None,
                    'applicability': 'advisory_reference_only', 'package': package,
                    'version_ranges_evaluated': False})
        if kind not in ECOSYSTEMS and kind != 'apk':
            reasons.append('unsupported_advisory_ecosystem')
        results.append({'has_current': any(r['current'] for r in records),
                        'has_stale': any(r['reason'] == 'stale' for r in records), 'records': records[:20], 'reasons': sorted(set(reasons)),
                        'truncated': len(records) > 20, 'candidate_count': len(records),
                        'valid_until': valid_until.isoformat() if valid_until else None})
    return results


def valid_epss(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1


COVERAGE_KEYS = ('authoritative_vex', 'applicable_vex', 'advisory_only', 'kev', 'epss',
                 'no_intelligence', 'unresolved_identity', 'stale_or_conflicting', 'cve_absent', 'identity_rejected',
                 'direct_vex_candidates', 'resolved_vex_candidates', 'resolved_identity',
                 'direct_applicable_vex', 'resolved_applicable_vex')


def coverage_report(details, now):
    """Union flags per finding, then separately per image. Never sum source hits."""
    service, images = {}, {}
    for finding in details:
        fid = finding['finding_id']
        all_flags = set()
        for observation in finding['observations']:
            vex, advisory = observation.get('vex', {}), observation.get('advisory', {})
            flags = set()
            if vex.get('exact_candidate_count', 0): flags.add('authoritative_vex')
            if vex.get('direct_candidate_count', 0): flags.add('direct_vex_candidates')
            if vex.get('resolved_candidate_count', 0): flags.add('resolved_vex_candidates')
            if vex.get('resolved_identity_count', 0): flags.add('resolved_identity')
            if vex.get('direct_applicable_count', 0): flags.add('direct_applicable_vex')
            if vex.get('resolved_applicable_count', 0): flags.add('resolved_applicable_vex')
            if any(s.get('accepted') for s in vex.get('statements', [])): flags.add('applicable_vex')
            if advisory.get('has_current', any(r.get('current') for r in advisory.get('records', []))) and 'applicable_vex' not in flags: flags.add('advisory_only')
            if observation.get('kev') is True: flags.add('kev')
            if valid_epss(observation.get('epss')): flags.add('epss')
            if (vex.get('applicability_state') == 'missing_context' or not observation.get('observation_id')
                or vex.get('resolution_outcome') in ('insufficient_identity_evidence', 'conflicting_authoritative_metadata', 'stale_mapping', 'no_verified_relationship')):
                flags.add('unresolved_identity')
            if vex.get('resolution_outcome') in ('stale_mapping', 'conflicting_authoritative_metadata') or vex.get('status') in ('stale', 'conflicting', 'withdrawn') or any(s.get('reason') in ('stale', 'withdrawn') for s in vex.get('statements', [])) or advisory.get('has_stale', any(r.get('reason') == 'stale' for r in advisory.get('records', []))): flags.add('stale_or_conflicting')
            if vex.get('cve_present') is False: flags.add('cve_absent')
            if any(any(reason in candidate.get('reason', '') for reason in ('identity', 'version', 'distro', 'digest', 'product_context', 'package_')) for candidate in vex.get('rejected_candidates', [])): flags.add('identity_rejected')
            all_flags |= flags
            key = (observation.get('image'), observation.get('image_digest'))
            images.setdefault(key, {}).setdefault(fid, set()).update(flags)
        service[fid] = all_flags
    def summary(values):
        counts = {key: 0 for key in COVERAGE_KEYS}
        for flags in values.values():
            if 'applicable_vex' in flags:
                flags = flags - {'advisory_only'}
            if not flags & {'applicable_vex', 'advisory_only', 'kev', 'epss'}:
                flags = flags | {'no_intelligence'}
            for flag in flags: counts[flag] += 1
        return {'total_findings': len(values), 'counts': counts}
    return {'denominator': 'unique_findings', 'as_of': now.isoformat(), **summary(service),
            'definitions': {'authoritative_vex': 'Exact CVE/PURL candidate; trust, freshness and product context may still reject it.',
                'direct_vex_candidates': 'Exact candidates for the original observed identity.',
                'resolved_vex_candidates': 'Exact candidates for an independently verified derived identity; not yet proof of applicability.',
                'resolved_identity': 'At least one eligible derived package identity, regardless of VEX coverage.',
                'direct_applicable_vex': 'At least one applicable statement for the original observed identity.',
                'resolved_applicable_vex': 'At least one applicable statement through a verified relationship. Conflicts remain unresolved.',
                'applicable_vex': 'At least one trusted current statement with exact identity and required product context. Conflicts remain unresolved.',
                'no_intelligence': 'No current applicable VEX, current advisory reference, affirmative KEV or available EPSS.',
                'identity_rejected': 'An exact candidate failed identity requirements, or an explicitly labelled different-product sample proves CVE presence. Date/revision rejections alone do not count.',
                'denominator': 'Distinct active finding IDs, unioned across observations and sources. Image denominators use distinct finding IDs in that image; image totals overlap.'},
            'images': [{'image': key[0], 'image_digest': key[1], **summary(values)} for key, values in images.items()]}
