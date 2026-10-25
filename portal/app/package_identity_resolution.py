"""Offline, bounded identities proven by the observed installed package database.

A source field is evidence, not permission to guess another distribution, version,
architecture, repository pocket, RPM epoch, or enterprise product. This module
never queries a feed and never mutates scanner evidence. Callers must still check
VEX publisher authority, product context, freshness, status conflicts and limits.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import re
from urllib.parse import parse_qsl, quote, unquote

RESOLVER_VERSION = 'cats-package-identity/v2'
MAX_CANDIDATES = 8
MAX_ARTIFACT_BYTES = 65536
OUTCOMES = frozenset({
    'exact_observed_identity', 'authoritatively_resolved_identity',
    'multiple_valid_candidate_identities', 'insufficient_identity_evidence',
    'conflicting_authoritative_metadata', 'unsupported_ecosystem',
    'stale_mapping', 'no_verified_relationship',
})
DEBIAN_SOURCE_SPEC = 'https://www.debian.org/doc/debian-policy/ch-controlfields.html#source'
SYFT_DPKG_SPEC = 'https://github.com/anchore/syft/blob/v1.31.0/syft/pkg/cataloger/debian/parse_dpkg_db.go'
CANONICAL_VEX_SPEC = 'https://github.com/canonical/ubuntu-security-notices/tree/main/vex'
# Contradiction checks only: these stable release facts never fill a missing
# codename. Other releases still require their own observed OS metadata.
UBUNTU_RELEASE_CHECKS = {
    '22.04': ('jammy', 'https://releases.ubuntu.com/22.04/'),
    '24.04': ('noble', 'https://ubuntu.com/blog/ubuntu-desktop-24-04-noble-numbat-deep-dive'),
}


class _EvidenceError(ValueError):
    def __init__(self, reason, outcome='insufficient_identity_evidence'):
        super().__init__(reason)
        self.outcome = outcome


def _text(value, limit=1500):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value))


def _time(value):
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    else:
        raise ValueError('invalid_timestamp')
    if result.tzinfo is None:
        raise ValueError('invalid_timestamp')
    return result.astimezone(timezone.utc)


def _parse(purl):
    if not _text(purl) or re.search(r'%(?![0-9a-fA-F]{2})', purl):
        raise _EvidenceError('missing_or_invalid_observed_purl')
    match = re.fullmatch(r'pkg:([a-z][a-z0-9.+-]*)/([^?#]+)(?:\?([^#]+))?', purl)
    if not match or '@' not in match[2]:
        raise _EvidenceError('missing_or_invalid_observed_purl')
    path, version = match[2].rsplit('@', 1)
    parts = [unquote(part, errors='strict') for part in path.split('/')]
    version = unquote(version, errors='strict')
    pairs = parse_qsl(match[3] or '', keep_blank_values=True, strict_parsing=True,
                      errors='strict', max_num_fields=32)
    if (any(not _text(p) or p in ('.', '..') or '/' in p for p in parts)
            or not _text(version) or len(dict(pairs)) != len(pairs)
            or any(not re.fullmatch(r'[a-z][a-z0-9._-]*', k) or not _text(v) for k, v in pairs)):
        raise _EvidenceError('invalid_observed_identity')
    return {'type': match[1], 'namespace': '/'.join(parts[:-1]), 'name': parts[-1],
            'version': version, 'qualifiers': dict(pairs)}


def _chain(relation, source, path, observed, details):
    return {'relation': relation, 'source': source, 'evidence_path': path,
            'source_version': deepcopy(observed.get('sbom_descriptor') or observed.get('scanner_descriptor')),
            'observed_at': observed.get('observed_at'), 'details': deepcopy(details)}


def _artifact_record(observed, parsed, artifact):
    try:
        encoded_size = len(json.dumps(artifact, ensure_ascii=True))
    except (TypeError, ValueError, RecursionError):
        raise _EvidenceError('invalid_installed_metadata')
    if encoded_size > MAX_ARTIFACT_BYTES:
        raise _EvidenceError('installed_metadata_limit')
    metadata_type = artifact.get('metadataType')
    if metadata_type not in ('dpkg-db-entry', 'rpm-db-entry'):
        return None
    expected = 'dpkg-db-cataloger' if parsed['type'] == 'deb' else 'rpm-db-cataloger'
    expected_type = 'dpkg-db-entry' if parsed['type'] == 'deb' else 'rpm-db-entry'
    if artifact.get('foundBy') != expected or metadata_type != expected_type:
        raise _EvidenceError('unverified_package_database_cataloger')
    locations = artifact.get('locations')
    if not isinstance(locations, list) or len(locations) > 32:
        raise _EvidenceError('missing_installed_database_location')
    allowed = ({'/var/lib/dpkg/status'} if parsed['type'] == 'deb' else
               {'/var/lib/rpm/Packages', '/var/lib/rpm/rpmdb.sqlite',
                '/usr/lib/sysimage/rpm/Packages', '/usr/lib/sysimage/rpm/Packages.db',
                '/usr/lib/sysimage/rpm/rpmdb.sqlite'})
    if not any(isinstance(location, dict) and
               isinstance(location.get('path') or location.get('realPath'), str)
               and (location.get('path') or location.get('realPath')) in allowed
               and (location.get('annotations', {}).get('evidence') == 'primary'
                    if isinstance(location.get('annotations'), dict) else False)
               for location in locations):
        raise _EvidenceError('missing_installed_database_location')
    bindings = (
        (artifact.get('purl'), observed['context'].get('purl', observed['context'].get('product_id'))),
        (artifact.get('name'), parsed['name']), (artifact.get('type'), parsed['type']),
        (artifact.get('version'), observed.get('raw_installed_version')),
    )
    # Absence is not a contradiction. Check every present binding before
    # returning an incomplete-record error, so another explicit mismatch wins.
    if any(_text(actual) and _text(expected) and actual != expected for actual, expected in bindings):
        raise _EvidenceError('installed_record_observation_mismatch', 'conflicting_authoritative_metadata')
    errors = []
    if any(not _text(actual) or not _text(expected) for actual, expected in bindings):
        errors.append(_EvidenceError('incomplete_installed_record_identity'))
    metadata = artifact.get('metadata')
    if not isinstance(metadata, dict):
        raise _EvidenceError('missing_installed_package_metadata')
    return metadata, errors


def _artifact_records(observed, parsed):
    records, errors = [], []
    # An incomplete first record cannot hide a contradiction in another verified
    # installed record. Retain validation errors until both sources are checked.
    for key in ('sbom_artifact', 'scanner_artifact'):
        artifact = observed.get(key)
        if not isinstance(artifact, dict):
            continue
        try:
            record = _artifact_record(observed, parsed, artifact)
            if record is not None:
                metadata, record_errors = record
                records.append((key, artifact, metadata))
                errors.extend(record_errors)
        except _EvidenceError as exc:
            errors.append(exc)
        except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
            errors.append(_EvidenceError('invalid_installed_metadata'))
    if not records and not errors:
        errors.append(_EvidenceError('missing_verified_installed_database_record'))
    return records, errors


def _binary_record_errors(parsed, records):
    errors = []
    for _, _, metadata in records:
        if parsed['type'] == 'deb':
            fields = ((metadata.get('package'), parsed['name']),
                      (metadata.get('version'), parsed['version']))
        else:
            # RPM version and release are independently present header fields.
            # Missing either one must not conceal a contradiction in the other.
            parts = parsed['version'].rsplit('-', 1)
            version, release = parts if len(parts) == 2 else (None, None)
            fields = ((metadata.get('name'), parsed['name']),
                      (metadata.get('version'), version), (metadata.get('release'), release))
        fields += ((metadata.get('architecture'), parsed['qualifiers'].get('arch')),)
        if any(_text(actual) and _text(expected) and actual != expected for actual, expected in fields):
            errors.append(_EvidenceError('installed_binary_metadata_conflict', 'conflicting_authoritative_metadata'))
        if any(not _text(actual) or not _text(expected) for actual, expected in fields):
            errors.append(_EvidenceError('incomplete_installed_binary_metadata'))
        if parsed['type'] == 'rpm':
            epoch = metadata.get('epoch')
            if 'epoch' not in metadata:
                errors.append(_EvidenceError('incomplete_rpm_epoch'))
            elif epoch is not None and (type(epoch) is not int or epoch < 0):
                errors.append(_EvidenceError('invalid_rpm_epoch'))
            elif (parsed['qualifiers'].get('epoch') is not None
                    and str(epoch if epoch is not None else 0) != parsed['qualifiers']['epoch']):
                errors.append(_EvidenceError('binary_epoch_conflict', 'conflicting_authoritative_metadata'))
    return errors


def _distro(observed, parsed):
    namespace = parsed['namespace']
    records, errors = [], []
    for key in ('sbom_distro', 'scanner_distro'):
        value = observed.get(key)
        if not isinstance(value, dict):
            continue
        identity = value.get('id') or value.get('name')
        version = value.get('versionID') or value.get('version')
        codename = value.get('versionCodename') or value.get('codename')
        if _text(identity, 200) and identity != namespace:
            errors.append(_EvidenceError('distribution_namespace_conflict', 'conflicting_authoritative_metadata'))
        if identity not in ('ubuntu', 'debian'):
            if not _text(identity, 200):
                errors.append(_EvidenceError('missing_distribution_release'))
            continue
        if not _text(version, 200):
            errors.append(_EvidenceError('missing_distribution_release'))
            version = None
        if codename and (not _text(codename, 200) or not re.fullmatch(r'[a-z][a-z0-9-]*', codename)):
            errors.append(_EvidenceError('invalid_distribution_codename'))
            codename = None
        # Keep every independently valid field. An absent version cannot hide
        # another record's release or this record's explicit codename conflict.
        records.append((key, identity, version, codename or None))
    if not records:
        raise next((error for error in errors if error.outcome == 'conflicting_authoritative_metadata'),
                   errors[0] if errors else _EvidenceError('missing_distribution_release'))
    versions = {(identity, version) for _, identity, version, _ in records if version is not None}
    if len(versions) > 1:
        errors.append(_EvidenceError('distribution_release_conflict', 'conflicting_authoritative_metadata'))
    codes = {code for _, _, _, code in records if code is not None}
    if len(codes) > 1:
        errors.append(_EvidenceError('distribution_codename_conflict', 'conflicting_authoritative_metadata'))
    _, identity, version, _ = next((record for record in records if record[2] is not None), records[0])
    codename = next(iter(codes), None)
    # Only spellings supplied by installed OS records are related. ESM pockets,
    # revisions and other releases are never enumerated. Missing spelling is
    # incomplete evidence, not a disagreement with a complete direct identity.
    qualifier = parsed['qualifiers'].get('distro')
    release_spellings = {identity + '-' + version for identity, version in versions}
    if qualifier not in codes | release_spellings:
        release_spelling = bool(qualifier and qualifier.startswith(identity + '-'))
        if qualifier and ((release_spelling and versions) or (not release_spelling and codes)):
            errors.append(_EvidenceError('distribution_purl_conflict', 'conflicting_authoritative_metadata'))
        else:
            errors.append(_EvidenceError('missing_distribution_codename'))
    for record_identity, record_version in versions:
        if record_identity != 'ubuntu':
            continue
        for record_code in codes:
            release_check = UBUNTU_RELEASE_CHECKS.get(record_version)
            if ((release_check and record_code != release_check[0])
                    or any(code == record_code and release != record_version
                           for release, (code, _) in UBUNTU_RELEASE_CHECKS.items())):
                errors.append(_EvidenceError('distribution_codename_release_conflict', 'conflicting_authoritative_metadata'))
    if namespace == 'ubuntu' and not codename:
        errors.append(_EvidenceError('missing_distribution_codename'))
    if errors:
        raise next((error for error in errors if error.outcome == 'conflicting_authoritative_metadata'), errors[0])
    release_check = UBUNTU_RELEASE_CHECKS.get(version) if namespace == 'ubuntu' else None
    return (codename if namespace == 'ubuntu' else qualifier), _chain(
        'installed_distribution_release', 'scanner_os_release', records[0][0], observed,
        {'id': identity, 'version': version, 'codename': codename, 'observed_distro': qualifier,
         'release_consistency_reference': release_check[1] if release_check else None})


def _purl(namespace, name, version, architecture, distro):
    # Canonical publishes the literal Debian version, including epoch colon.
    return ('pkg:deb/' + namespace + '/' + quote(name, safe='.+-') + '@'
            + quote(version, safe=':+.-~') + '?arch=' + quote(architecture, safe='')
            + '&distro=' + quote(distro, safe='/.-'))


def _deb_candidates(observed, parsed, records):
    if parsed['namespace'] not in ('ubuntu', 'debian'):
        raise _EvidenceError('unsupported_distribution_namespace', 'unsupported_ecosystem')
    if set(parsed['qualifiers']) - {'arch', 'distro', 'upstream'}:
        raise _EvidenceError('unsupported_purl_qualifier_scope', 'no_verified_relationship')
    distro, distro_chain = _distro(observed, parsed)
    tuples, chains = set(), []
    for path, artifact, metadata in records:
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', str(metadata.get('architecture', ''))):
            raise _EvidenceError('missing_installed_package_architecture')
        # Syft preserves the parsed Debian Source name and optional version as
        # separate fields; an omitted version means the binary Version, per
        # Debian Policy 5.6.1. Both parser fields must actually be present.
        if 'source' not in metadata or 'sourceVersion' not in metadata:
            raise _EvidenceError('incomplete_debian_source_fields')
        source = metadata['source']
        source_version = metadata['sourceVersion']
        if not isinstance(source, str) or not isinstance(source_version, str):
            raise _EvidenceError('invalid_debian_source_fields')
        if source_version and not source:
            raise _EvidenceError('source_version_without_source_name', 'conflicting_authoritative_metadata')
        source, source_version = source or parsed['name'], source_version or metadata['version']
        if (not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', source)
                or not re.fullmatch(r'(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*', source_version)):
            raise _EvidenceError('invalid_debian_source_identity')
        # Syft emits either Source or Source@SourceVersion. Verify the whole
        # supplied tuple before dropping this redundant relationship qualifier.
        if parsed['qualifiers'].get('upstream', source) not in {source, source + '@' + source_version}:
            raise _EvidenceError('upstream_source_conflict', 'conflicting_authoritative_metadata')
        tuples.add((source, source_version))
        chains.append(_chain('installed_binary_to_source', DEBIAN_SOURCE_SPEC, path + '.metadata', observed,
            {'binary_name': metadata['package'], 'binary_version': metadata['version'],
             'binary_architecture': metadata['architecture'], 'source_name': source,
             'source_version': source_version, 'source_version_defaulted': not metadata['sourceVersion'],
             'source_name_defaulted': not metadata['source'], 'metadata_type': artifact['metadataType'],
             'cataloger': artifact['foundBy'], 'parser_reference': SYFT_DPKG_SPEC,
             'image_digest': observed.get('image_digest')}))
    if len(tuples) != 1:
        raise _EvidenceError('source_relationship_conflict', 'conflicting_authoritative_metadata')
    source, source_version = next(iter(tuples))
    namespace, original = parsed['namespace'], observed['context']
    scope = {'namespace': namespace, 'publisher': 'canonical' if namespace == 'ubuntu' else None}
    candidates = []
    for name, version, arch, relation in (
            (parsed['name'], parsed['version'], parsed['qualifiers']['arch'], 'binary_vendor_identity'),
            (source, source_version, 'source', 'installed_binary_to_source')):
        product_id = _purl(namespace, name, version, arch, distro)
        if product_id == (original.get('purl') or original.get('product_id')):
            continue
        provenance = [*chains, distro_chain, _chain('vendor_purl_representation',
            CANONICAL_VEX_SPEC if namespace == 'ubuntu' else DEBIAN_SOURCE_SPEC,
            'context.purl', observed, {'product_id': product_id, 'relationship': relation})]
        candidates.append({'kind': 'authoritative_resolved', 'context': {
            'product_id': product_id, 'purl': product_id, 'version': version, 'distro': distro},
            'relationship': relation, 'eligible': True, 'publisher_scope': scope,
            'provenance_chain': provenance, 'valid_until': observed.get('evidence_valid_until')})
    return candidates, chains


def _rpm_relationships(observed, parsed, records):
    relationships, source_values = [], set()
    for path, artifact, metadata in records:
        epoch = metadata.get('epoch')
        source_rpm = metadata.get('sourceRpm')
        match = re.fullmatch(r'(.+)-([^-]+)-([^-]+)\.(?:src|nosrc)\.rpm', source_rpm) if _text(source_rpm, 700) else None
        if not match:
            raise _EvidenceError('missing_valid_source_rpm')
        source_values.add(source_rpm)
        relationships.append(_chain('installed_binary_to_source_rpm', 'rpm_installed_header', path + '.metadata.sourceRpm', observed,
            {'source_rpm': source_rpm, 'source_name': match[1], 'source_version': match[2],
             'source_release': match[3], 'source_epoch': None, 'binary_epoch': epoch,
             'binary_architecture': metadata['architecture'], 'modularity': metadata.get('modularityLabel'),
             'vendor': metadata.get('vendor'), 'image_digest': observed.get('image_digest')}))
    if len(source_values) != 1:
        raise _EvidenceError('source_relationship_conflict', 'conflicting_authoritative_metadata')
    return relationships


def resolve_package_identity(observed, *, now=None, max_candidates=MAX_CANDIDATES):
    """Return original identity plus bounded, independently proven candidates.

    Input is ``container_intelligence.observation_identity``'s result. Optional
    observed_at/evidence_valid_until describe the authenticated scan lifetime.
    Installed metadata on an immutable image establishes a static relationship;
    callers retain their normal scan and VEX freshness checks. No trusted boolean
    or asserted vendor product supplied in scanner evidence creates a mapping.
    """
    if not isinstance(observed, dict):
        raise ValueError('Observed identity must be an object')
    if type(max_candidates) is not int or not 1 <= max_candidates <= MAX_CANDIDATES:
        raise ValueError('Invalid identity candidate limit')
    result = {'resolver_version': RESOLVER_VERSION, 'observed_identity': deepcopy(observed),
              'outcome': 'exact_observed_identity', 'candidates': [], 'relationships': [],
              'reasons': [], 'valid_until': None}
    context = observed.get('context')
    if isinstance(context, dict) and (context.get('purl') or context.get('product_id')):
        result['candidates'].append({'kind': 'exact_observed', 'context': deepcopy(context),
            'eligible': True, 'publisher_scope': None, 'relationship': 'exact_observed_identity',
            'provenance_chain': [], 'valid_until': None})
    try:
        if not result['candidates']:
            raise _EvidenceError('missing_observed_identity')
        parsed = _parse(context.get('purl') or context.get('product_id'))
        if parsed['type'] not in ('deb', 'rpm'):
            raise _EvidenceError('unsupported_package_ecosystem', 'unsupported_ecosystem')
        records, validation_errors = _artifact_records(observed, parsed)
        validation_errors.extend(_binary_record_errors(parsed, records))
        if (context.get('version') != parsed['version']
                or (parsed['type'] == 'deb' and observed.get('raw_installed_version') != parsed['version'])
                or (context.get('distro') is not None and context['distro'] != parsed['qualifiers'].get('distro'))):
            validation_errors.append(_EvidenceError('observed_version_conflict', 'conflicting_authoritative_metadata'))
        if parsed['type'] == 'deb' and parsed['namespace'] in ('ubuntu', 'debian'):
            try:
                _distro(observed, parsed)
            except _EvidenceError as exc:
                validation_errors.append(exc)
            except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
                validation_errors.append(_EvidenceError('invalid_identity_metadata'))
        # Contradictions in the observed binary are independent of whether a
        # source relationship is complete, current, or transferable. Check every
        # verified record before any source-only failure can preserve a direct VEX match.
        conflict = next((error for error in validation_errors
                         if error.outcome == 'conflicting_authoritative_metadata'), None)
        if conflict is not None:
            raise conflict
        current = _time(now) if now is not None else datetime.now(timezone.utc)
        if observed.get('observed_at') is not None and _time(observed['observed_at']) > current:
            raise _EvidenceError('future_dated_package_evidence', 'stale_mapping')
        if observed.get('evidence_valid_until') is not None:
            expiry = _time(observed['evidence_valid_until'])
            if expiry <= current:
                raise _EvidenceError('expired_package_evidence', 'stale_mapping')
            result['valid_until'] = expiry.isoformat()
        digest = observed.get('image_digest')
        if not isinstance(digest, str) or not re.fullmatch(r'(?:[^\s@]+@)?sha256:[a-f0-9]{64}', digest):
            raise _EvidenceError('missing_immutable_image_binding')
        if context.get('digest'):
            raise _EvidenceError('package_digest_scope_not_transferable', 'no_verified_relationship')
        if validation_errors:
            raise validation_errors[0]
        if parsed['type'] == 'rpm':
            result['relationships'] = _rpm_relationships(observed, parsed, records)
            raise _EvidenceError('source_rpm_epoch_and_vendor_product_context_unverified', 'no_verified_relationship')
        derived, result['relationships'] = _deb_candidates(observed, parsed, records)
        if len(derived) + len(result['candidates']) > max_candidates:
            raise _EvidenceError('identity_candidate_limit', 'insufficient_identity_evidence')
        result['candidates'].extend(derived)
        result['outcome'] = ('multiple_valid_candidate_identities' if len(derived) > 1 else
                             'authoritatively_resolved_identity' if derived else 'exact_observed_identity')
    except _EvidenceError as exc:
        result['outcome'], result['reasons'] = exc.outcome, [str(exc)]
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        result['outcome'], result['reasons'] = 'insufficient_identity_evidence', ['invalid_identity_metadata']
    return result
