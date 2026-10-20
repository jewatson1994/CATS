"""Installed metadata permits exact relationships, never guessed product scope."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from app.package_identity_resolution import OUTCOMES, resolve_package_identity

NOW = datetime(2026, 10, 20, 8, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]
DIGEST = 'sha256:' + 'a' * 64


def deb_identity(*, name='libssl3', version='3.0.2-0ubuntu1.26', source='openssl',
                 source_version='', namespace='ubuntu', arch='amd64'):
    release, codename = ('22.04', 'jammy') if namespace == 'ubuntu' else ('12', 'bookworm')
    purl = (f'pkg:deb/{namespace}/{name}@{version}?arch={arch}&distro={namespace}-{release}'
            + (f'&upstream={source}' if source and source != name else ''))
    return {'context': {'product_id': purl, 'purl': purl, 'version': version,
                        'distro': namespace + '-' + release},
        'raw_purl': purl, 'raw_installed_version': version, 'image_digest': DIGEST,
        'observed_at': NOW.isoformat(), 'evidence_valid_until': (NOW + timedelta(days=1)).isoformat(),
        'sbom_descriptor': {'name': 'syft', 'version': '1.31.0'},
        'sbom_distro': {'id': namespace, 'versionID': release, 'versionCodename': codename},
        'scanner_distro': {'name': namespace, 'version': release},
        'sbom_artifact': {'id': 'observed-1', 'name': name, 'version': version, 'type': 'deb',
            'purl': purl, 'foundBy': 'dpkg-db-cataloger', 'metadataType': 'dpkg-db-entry',
            'locations': [{'path': '/var/lib/dpkg/status', 'annotations': {'evidence': 'primary'}}],
            'metadata': {'package': name, 'version': version, 'architecture': arch,
                         'source': source, 'sourceVersion': source_version}}}


def derived(result):
    return [c for c in result['candidates'] if c['kind'] == 'authoritative_resolved']


def test_retained_ubuntu_metadata_resolves_binary_and_source_with_provenance():
    capture = json.loads((ROOT / 'docs/evidence/container-vex-scans/ubuntu.json').read_text())
    row = next(r for r in capture['findings'] if r['package'] == 'libssl3')
    identity = deb_identity()
    # The tuple/source fields are retained real scanner evidence. Cataloger,
    # metadataType and location above model the documented raw Syft projection.
    identity['sbom_artifact']['metadata'] = deepcopy(row['evidence']['sbom_artifact']['metadata'])
    identity['image_digest'] = capture['image_digest']
    before = deepcopy(identity)
    result = resolve_package_identity(identity, now=NOW)
    assert identity == before and result['observed_identity'] == before
    assert result['outcome'] == 'multiple_valid_candidate_identities'
    candidates = derived(result)
    assert [c['context']['purl'] for c in candidates] == [
        'pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.26?arch=amd64&distro=jammy',
        'pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.26?arch=source&distro=jammy']
    assert all(c['eligible'] and c['publisher_scope']['publisher'] == 'canonical' for c in candidates)
    source = candidates[1]['provenance_chain'][0]
    assert source['details']['source_version_defaulted'] is True
    assert source['source_version'] == {'name': 'syft', 'version': '1.31.0'}
    assert source['observed_at'] == NOW.isoformat()
    assert source['details']['image_digest'] == capture['image_digest']
    assert result['valid_until'] == (NOW + timedelta(days=1)).isoformat()
    candidates[0]['context']['purl'] = 'mutated'
    assert identity == before


def test_debian_source_rebuild_version_is_not_binary_version_or_ubuntu_namespace():
    result = resolve_package_identity(deb_identity(name='bash', namespace='debian',
        version='5.2.15-2+b7', source='bash', source_version='5.2.15-2'), now=NOW)
    source = next(c for c in derived(result) if c['relationship'] == 'installed_binary_to_source')
    assert source['context']['purl'] == 'pkg:deb/debian/bash@5.2.15-2?arch=source&distro=debian-12'
    assert all('/ubuntu/' not in c['context']['purl'] for c in result['candidates'])
    assert source['context']['version'] == '5.2.15-2'
    assert source['publisher_scope'] == {'namespace': 'debian', 'publisher': None}


@pytest.mark.parametrize('name', ['bash', 'bsdutils'])
def test_retained_debian_explicit_source_version_qualifier_is_verified(name):
    capture = json.loads((ROOT / 'docs/evidence/container-vex-scans/debian-12-9.json').read_text())
    artifact = next(row for row in capture['components'] if row['name'] == name)
    identity = deb_identity(name=name, namespace='debian', version=artifact['version'])
    identity['sbom_artifact'].update(deepcopy(artifact))
    identity['context'].update(purl=artifact['purl'], product_id=artifact['purl'])
    identity['raw_purl'] = artifact['purl']
    identity['image_digest'] = capture['image_digest']
    result = resolve_package_identity(identity, now=NOW)
    source = next(c for c in derived(result) if c['relationship'] == 'installed_binary_to_source')
    metadata = artifact['metadata']
    assert source['context']['purl'] == (f"pkg:deb/debian/{metadata['source']}@"
        f"{metadata['sourceVersion']}?arch=source&distro=debian-12")
    # A different upstream version cannot authorize the otherwise valid source.
    identity['context']['purl'] = artifact['purl'] + '-conflict'
    identity['context']['product_id'] = identity['context']['purl']
    identity['sbom_artifact']['purl'] = identity['context']['purl']
    conflict = resolve_package_identity(identity, now=NOW)
    assert conflict['outcome'] == 'conflicting_authoritative_metadata'
    assert conflict['reasons'] == ['upstream_source_conflict']
    assert not derived(conflict)


def test_source_epoch_is_explicit_and_can_differ_from_binary_epoch():
    result = resolve_package_identity(deb_identity(name='bsdutils', version='1:2.37.2-4ubuntu3.5',
        source='util-linux', source_version='2.37.2-4ubuntu3.5'), now=NOW)
    assert {c['context']['purl'] for c in derived(result)} == {
        'pkg:deb/ubuntu/bsdutils@1:2.37.2-4ubuntu3.5?arch=amd64&distro=jammy',
        'pkg:deb/ubuntu/util-linux@2.37.2-4ubuntu3.5?arch=source&distro=jammy'}


def test_empty_source_name_and_version_have_documented_debian_defaults():
    result = resolve_package_identity(deb_identity(name='adduser', version='3.118ubuntu5', source=''), now=NOW)
    source = derived(result)[1]
    assert source['context']['purl'] == 'pkg:deb/ubuntu/adduser@3.118ubuntu5?arch=source&distro=jammy'
    assert source['provenance_chain'][0]['details']['source_name_defaulted']


@pytest.mark.parametrize('mutation,reason,outcome', [
    (lambda x: x['sbom_artifact'].pop('metadataType'), 'missing_verified_installed_database_record', 'insufficient_identity_evidence'),
    (lambda x: x['sbom_artifact'].pop('foundBy'), 'unverified_package_database_cataloger', 'insufficient_identity_evidence'),
    (lambda x: x['sbom_artifact'].update(locations=[]), 'missing_installed_database_location', 'insufficient_identity_evidence'),
    (lambda x: x['sbom_artifact']['metadata'].pop('sourceVersion'), 'incomplete_debian_source_fields', 'insufficient_identity_evidence'),
    (lambda x: x['sbom_artifact']['metadata'].update(sourceVersion=None), 'invalid_debian_source_fields', 'insufficient_identity_evidence'),
    (lambda x: x['sbom_artifact']['metadata'].update(architecture='arm64'), 'installed_binary_metadata_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['sbom_artifact']['metadata'].update(source='other-source'), 'upstream_source_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['sbom_artifact']['metadata'].update(version='3.0.2-0ubuntu1.25'), 'installed_binary_metadata_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['sbom_artifact'].update(name='other'), 'installed_record_observation_mismatch', 'conflicting_authoritative_metadata'),
    (lambda x: x['sbom_distro'].update(id='debian'), 'distribution_namespace_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['scanner_distro'].update(name='alpine'), 'distribution_namespace_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['scanner_distro'].update(version='24.04'), 'distribution_release_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['sbom_distro'].update(versionCodename='noble'), 'distribution_codename_release_conflict', 'conflicting_authoritative_metadata'),
    (lambda x: x['sbom_distro'].pop('versionCodename'), 'missing_distribution_codename', 'insufficient_identity_evidence'),
    (lambda x: x.update(image_digest='mutable:tag'), 'missing_immutable_image_binding', 'insufficient_identity_evidence'),
    (lambda x: x.update(evidence_valid_until=NOW.isoformat()), 'expired_package_evidence', 'stale_mapping'),
    (lambda x: x.update(observed_at=(NOW + timedelta(minutes=1)).isoformat()), 'future_dated_package_evidence', 'stale_mapping'),
])
def test_unverified_conflicting_or_stale_metadata_cannot_remove_original_exact_candidate(mutation, reason, outcome):
    identity = deb_identity()
    exact = deepcopy(identity['context'])
    mutation(identity)
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == outcome
    assert result['reasons'] == [reason]
    assert len(result['candidates']) == 1
    assert result['candidates'][0]['context'] == exact
    assert result['candidates'][0]['kind'] == 'exact_observed'


def test_duplicate_authoritative_records_must_agree_on_source_version():
    identity = deb_identity()
    identity['scanner_artifact'] = deepcopy(identity['sbom_artifact'])
    identity['scanner_artifact']['metadata']['sourceVersion'] = '3.0.2-0ubuntu1.25'
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == ['source_relationship_conflict']
    assert not derived(result)


def test_unknown_pocket_qualifier_is_not_silently_dropped():
    identity = deb_identity()
    purl = identity['raw_purl'] + '&repository=esm-infra'
    identity['context'].update(purl=purl, product_id=purl)
    identity['sbom_artifact']['purl'] = purl
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'no_verified_relationship'
    assert result['reasons'] == ['unsupported_purl_qualifier_scope']
    assert not derived(result)


def test_no_other_architecture_or_esm_pocket_is_invented():
    identity = deb_identity(arch='all')
    result = resolve_package_identity(identity, now=NOW)
    assert all('?arch=all&' in c['context']['purl'] or '?arch=source&' in c['context']['purl'] for c in derived(result))
    assert all('esm-' not in c['context']['purl'] for c in derived(result))


def test_caller_asserted_vendor_context_does_not_become_derived_product_scope():
    identity = deb_identity()
    identity['context']['csaf_product_context'] = {'publisher': 'vendor', 'products': [{'cpe': 'cpe:invented'}]}
    result = resolve_package_identity(identity, now=NOW)
    assert all('csaf_product_context' not in c['context'] for c in derived(result))
    assert result['candidates'][0]['context']['csaf_product_context'] == identity['context']['csaf_product_context']


def test_candidate_overflow_keeps_original_and_suppresses_all_derived():
    result = resolve_package_identity(deb_identity(), now=NOW, max_candidates=2)
    assert result['reasons'] == ['identity_candidate_limit']
    assert len(result['candidates']) == 1


def test_missing_purl_and_unsupported_ecosystems_are_explicit():
    assert resolve_package_identity({})['outcome'] == 'insufficient_identity_evidence'
    identity = {'context': {'purl': 'pkg:apk/alpine/musl@1.2.5-r0', 'version': '1.2.5-r0'}}
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'unsupported_ecosystem' and len(result['candidates']) == 1
    assert len(OUTCOMES) == 8


@pytest.mark.parametrize('namespace,name,version,release,epoch,source_rpm,distro', [
    ('redhat', 'openssl-libs', '3.2.2', '6.el9_5.1', 1, 'openssl-3.2.2-6.el9_5.1.src.rpm', 'rhel-9.6'),
    ('suse', 'libopenssl3', '3.1.4', '150600.5.3.1', 0, 'openssl-3-3.1.4-150600.5.3.1.src.rpm', 'sles-15.6'),
])
def test_source_rpm_never_inherits_binary_epoch_or_enterprise_context(namespace, name, version, release, epoch, source_rpm, distro):
    binary_version = version + '-' + release
    purl = f'pkg:rpm/{namespace}/{name}@{binary_version}?arch=x86_64&distro={distro}&epoch={epoch}'
    identity = {'context': {'purl': purl, 'version': binary_version, 'distro': distro},
        'raw_installed_version': str(epoch) + ':' + binary_version, 'image_digest': DIGEST,
        'sbom_artifact': {'name': name, 'version': str(epoch) + ':' + binary_version,
            'type': 'rpm', 'purl': purl, 'foundBy': 'rpm-db-cataloger', 'metadataType': 'rpm-db-entry',
            'locations': [{'path': '/var/lib/rpm/rpmdb.sqlite', 'annotations': {'evidence': 'primary'}}],
            'metadata': {'name': name, 'version': version, 'release': release, 'epoch': epoch,
                'architecture': 'x86_64', 'sourceRpm': source_rpm, 'vendor': namespace}}}
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'no_verified_relationship' and not derived(result)
    assert result['relationships'][0]['details']['source_epoch'] is None
    assert result['relationships'][0]['details']['binary_epoch'] == epoch
    assert result['reasons'] == ['source_rpm_epoch_and_vendor_product_context_unverified']


def test_oversized_installed_metadata_is_not_silently_truncated_into_identity():
    identity = deb_identity()
    identity['sbom_artifact']['metadata']['extra'] = 'x' * 65536
    result = resolve_package_identity(identity, now=NOW)
    assert not derived(result)
    assert result['outcome'] == 'insufficient_identity_evidence'


@pytest.mark.parametrize('mode', ['missing_record', 'missing_source', 'stale', 'package_digest'])
def test_distribution_contradiction_precedes_unusable_source_mapping(mode):
    identity = deb_identity()
    identity['scanner_distro']['version'] = '24.04'
    if mode == 'missing_record':
        del identity['sbom_artifact']['metadataType']
    elif mode == 'missing_source':
        del identity['sbom_artifact']['metadata']['sourceVersion']
    elif mode == 'stale':
        identity['evidence_valid_until'] = NOW.isoformat()
    else:
        identity['context']['digest'] = 'sha256:' + 'b' * 64
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == ['distribution_release_conflict']
    assert not derived(result)


@pytest.mark.parametrize('conflict,reason', [
    ({'architecture': 'aarch64'}, 'installed_binary_metadata_conflict'),
    ({'epoch': 2}, 'binary_epoch_conflict'),
])
def test_source_rpm_failure_cannot_hide_second_installed_binary_conflict(conflict, reason):
    product = 'pkg:rpm/redhat/acl@2.3.1-4.el9?arch=x86_64&distro=rhel-9&epoch=0'
    identity = {'context': {'purl': product, 'version': '2.3.1-4.el9', 'distro': 'rhel-9'},
        'raw_installed_version': '2.3.1-4.el9', 'image_digest': DIGEST,
        'sbom_artifact': {'name': 'acl', 'version': '2.3.1-4.el9', 'type': 'rpm', 'purl': product,
            'foundBy': 'rpm-db-cataloger', 'metadataType': 'rpm-db-entry',
            'locations': [{'path': '/var/lib/rpm/rpmdb.sqlite', 'annotations': {'evidence': 'primary'}}],
            'metadata': {'name': 'acl', 'version': '2.3.1', 'release': '4.el9', 'epoch': 0,
                         'architecture': 'x86_64', 'sourceRpm': ''}}}
    identity['scanner_artifact'] = deepcopy(identity['sbom_artifact'])
    identity['scanner_artifact']['metadata'].update(conflict)
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == [reason]
    assert not derived(result)


@pytest.mark.parametrize('bad_record', [
    None, False, 1, 1.5, 'ubuntu', [], ['ubuntu'],
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': None},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': False},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': True},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': 0},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': 1.5},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': ''},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': 'invalid codename'},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': []},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': ['jammy']},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': {}},
    {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': {'bad': 'shape'}},
])
@pytest.mark.parametrize('bad_key,other_key', [
    ('sbom_distro', 'scanner_distro'), ('scanner_distro', 'sbom_distro')])
def test_malformed_distro_cannot_hide_independent_release_contradiction(bad_record, bad_key, other_key):
    identity = deb_identity()
    identity[bad_key] = deepcopy(bad_record)
    identity[other_key] = {'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': 'noble'}
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == ['distribution_codename_release_conflict']
    assert not derived(result)


@pytest.mark.parametrize('field', ['id', 'versionID'])
@pytest.mark.parametrize('bad_value', [None, False, True, 0, 1, 1.5, '', [], ['ubuntu'], {}, {'bad': 'shape'}])
def test_invalid_distro_identity_types_do_not_hide_sibling_contradiction(field, bad_value):
    identity = deb_identity()
    identity['sbom_distro'][field] = bad_value
    identity['scanner_distro'] = {'name': 'ubuntu', 'version': '22.04', 'codename': 'noble'}
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'][0] in {'distribution_namespace_conflict', 'distribution_codename_release_conflict', 'distribution_codename_conflict'}
    assert not derived(result)


@pytest.mark.parametrize('bad_location', [
    {'path': ['bad-shape'], 'annotations': {'evidence': 'primary'}},
    {'realPath': {'bad': 'shape'}, 'annotations': {'evidence': 'primary'}},
    {'path': '/var/lib/dpkg/status', 'annotations': []}, None, 'invalid'])
@pytest.mark.parametrize('position', [0, 1])
def test_malformed_extra_location_cannot_hide_present_binary_conflict(bad_location, position):
    identity = deb_identity()
    identity['sbom_artifact']['locations'].insert(position, bad_location)
    identity['sbom_artifact']['metadata']['architecture'] = 'arm64'
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == ['installed_binary_metadata_conflict']
    assert not derived(result)


@pytest.mark.parametrize('field', ['package', 'version', 'architecture'])
@pytest.mark.parametrize('missing', [None, '', [], {}])
def test_incomplete_binary_fields_are_not_confirmed_contradictions(field, missing):
    identity = deb_identity()
    identity['sbom_artifact']['metadata'][field] = missing
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'insufficient_identity_evidence'
    assert result['reasons'] == ['incomplete_installed_binary_metadata']
    assert not derived(result)


@pytest.mark.parametrize('section,field', [
    ('metadata', 'package'), ('metadata', 'version'), ('wrapper', 'name'),
    ('wrapper', 'version'), ('wrapper', 'purl')])
def test_missing_record_field_cannot_hide_other_present_binary_contradiction(section, field):
    identity = deb_identity()
    target = identity['sbom_artifact']['metadata'] if section == 'metadata' else identity['sbom_artifact']
    target.pop(field)
    identity['sbom_artifact']['metadata']['architecture'] = 'arm64'
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == ['installed_binary_metadata_conflict']
    assert not derived(result)


@pytest.mark.parametrize('first,second', [
    ({'id': 'ubuntu'}, {'id': 'alpine'}),
    ({'id': []}, {'id': 'debian', 'versionID': None}),
    ({'id': 'ubuntu', 'versionID': None, 'versionCodename': 'noble'},
     {'id': 'ubuntu', 'versionID': '22.04'}),
    ({'id': 'ubuntu', 'versionID': '22.04', 'versionCodename': None},
     {'id': 'ubuntu', 'versionID': '24.04', 'versionCodename': []}),
])
@pytest.mark.parametrize('reverse', [False, True])
def test_partial_distro_records_keep_independent_conflicting_fields(first, second, reverse):
    identity = deb_identity()
    identity['sbom_distro'], identity['scanner_distro'] = (second, first) if reverse else (first, second)
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert not derived(result)


@pytest.mark.parametrize('epoch_present,epoch,expected', [
    (False, None, 'incomplete_rpm_epoch'),
    (True, None, 'binary_epoch_conflict'),
    (True, 0, 'binary_epoch_conflict'),
    (True, 1, 'source_rpm_epoch_and_vendor_product_context_unverified'),
])
def test_rpm_omitted_epoch_is_incomplete_but_explicit_null_declares_no_epoch(epoch_present, epoch, expected):
    purl = 'pkg:rpm/redhat/acl@2.3.1-4.el9?arch=x86_64&distro=rhel-9&epoch=1'
    identity = {'context': {'purl': purl, 'version': '2.3.1-4.el9', 'distro': 'rhel-9'},
        'raw_installed_version': '1:2.3.1-4.el9', 'image_digest': DIGEST,
        'sbom_artifact': {'name': 'acl', 'version': '1:2.3.1-4.el9', 'type': 'rpm', 'purl': purl,
            'foundBy': 'rpm-db-cataloger', 'metadataType': 'rpm-db-entry',
            'locations': [{'path': '/var/lib/rpm/rpmdb.sqlite', 'annotations': {'evidence': 'primary'}}],
            'metadata': {'name': 'acl', 'version': '2.3.1', 'release': '4.el9',
                         'architecture': 'x86_64', 'sourceRpm': 'acl-2.3.1-4.el9.src.rpm'}}}
    if epoch_present:
        identity['sbom_artifact']['metadata']['epoch'] = epoch
    result = resolve_package_identity(identity, now=NOW)
    assert result['reasons'] == [expected]
    assert not derived(result)


@pytest.mark.parametrize('missing_field,conflict_field,conflict_value', [
    ('release', 'version', '2.3.2'), ('version', 'release', '5.el9')])
def test_partial_rpm_tuple_cannot_hide_other_present_field_conflict(missing_field, conflict_field, conflict_value):
    purl = 'pkg:rpm/redhat/acl@2.3.1-4.el9?arch=x86_64&distro=rhel-9&epoch=0'
    metadata = {'name': 'acl', 'version': '2.3.1', 'release': '4.el9', 'epoch': 0,
                'architecture': 'x86_64', 'sourceRpm': 'acl-2.3.1-4.el9.src.rpm'}
    metadata.pop(missing_field)
    metadata[conflict_field] = conflict_value
    identity = {'context': {'purl': purl, 'version': '2.3.1-4.el9', 'distro': 'rhel-9'},
        'raw_installed_version': '2.3.1-4.el9', 'image_digest': DIGEST,
        'sbom_artifact': {'name': 'acl', 'version': '2.3.1-4.el9', 'type': 'rpm', 'purl': purl,
            'foundBy': 'rpm-db-cataloger', 'metadataType': 'rpm-db-entry',
            'locations': [{'path': '/var/lib/rpm/rpmdb.sqlite', 'annotations': {'evidence': 'primary'}}],
            'metadata': metadata}}
    result = resolve_package_identity(identity, now=NOW)
    assert result['outcome'] == 'conflicting_authoritative_metadata'
    assert result['reasons'] == ['installed_binary_metadata_conflict']
    assert not derived(result)
