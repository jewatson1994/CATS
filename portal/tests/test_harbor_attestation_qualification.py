"""Preserved signed claims must retain their original source registry identity."""
import base64
import json

import pytest

from app import oci_attestations
from harbor_attestation_qualification import PURPOSE, scope, verified_statement


SOURCE = 'source.example/qualification/attestation/fixtures/application@sha256:' + 'a' * 64
EVIDENCE = {'qualification.json': 'sha256:' + 'b' * 64}


def envelope(*, subject=None, predicate=None, predicate_type=None):
    statement = {'_type': 'https://in-toto.io/Statement/v0.1',
                 'subject': [{'name': SOURCE.rsplit('@', 1)[0], 'digest': subject or {'sha256': 'a' * 64}}],
                 'predicateType': predicate_type or oci_attestations.PREDICATE_TYPES[PURPOSE],
                 'predicate': predicate or oci_attestations._predicate(SOURCE, PURPOSE, EVIDENCE)}
    return json.dumps({'payloadType': 'application/vnd.in-toto+json',
                       'payload': base64.b64encode(json.dumps(statement).encode()).decode()})


def test_native_verified_output_keeps_original_source_subject_after_relocation():
    predicate = oci_attestations._predicate(SOURCE, PURPOSE, EVIDENCE)
    statement = verified_statement(envelope(), SOURCE, predicate)
    assert statement['predicate']['subject'] == SOURCE
    assert statement['subject'][0]['digest'] == {'sha256': 'a' * 64}


@pytest.mark.parametrize('changes', [
    {'subject': {'sha256': 'c' * 64}},
    {'predicate_type': 'https://untrusted.example/predicate'},
    {'predicate': oci_attestations._predicate(SOURCE.replace('source.example', 'target.example'), PURPOSE, EVIDENCE)},
    {'predicate': oci_attestations._predicate(SOURCE, PURPOSE, {'qualification.json': 'sha256:' + 'c' * 64})},
])
def test_different_subject_predicate_or_evidence_cannot_qualify(changes):
    with pytest.raises(ValueError, match='No attestation binds'):
        verified_statement(envelope(**changes), SOURCE, oci_attestations._predicate(SOURCE, PURPOSE, EVIDENCE))


@pytest.mark.parametrize('namespace', ['qualification', 'approved/attestation', 'qualification/../approved',
                                      'qualification/attestation/*', 'qualification//attestation'])
def test_namespace_must_be_an_exact_qualification_subtree(namespace):
    with pytest.raises(AssertionError):
        scope('https://source.example', 'https://target.example', namespace)


def test_distinct_trusted_https_origins_are_required():
    assert scope('https://source.example', 'https://target.example', 'qualification/attestation') == (
        'source.example', 'target.example')
    for source, target in [('http://source.example', 'https://target.example'),
                           ('https://source.example', 'https://source.example'),
                           ('https://user:secret@source.example', 'https://target.example')]:
        with pytest.raises(AssertionError):
            scope(source, target, 'qualification/attestation')
