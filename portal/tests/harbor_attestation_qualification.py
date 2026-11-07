"""Opt-in native Cosign attestation preservation through actual Harbor replication.

Publish writes a new, explicitly scoped synthetic source repository only. An
independent Harbor controller must replicate that subtree; this helper never
copies objects between registries. Verify reads only the configured target,
checks every recorded graph byte, and invokes native Cosign with the retained
independent public key and explicit CA. The unchanged predicate must name the
original source reference, even though verification reads the target reference.

This qualifies Harbor transport, not approved-release attestation import/proxy
support. The image and attestation are synthetic qualification content.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

from harbor_graph_qualification import context, host, image_fixture, require, write_json


LABEL = 'SYNTHETIC Harbor native attestation preservation; not scanned or approved production content'
PURPOSE = 'release'


def scope(source, target, namespace):
    source_host, target_host = host(source), host(target)
    require(source_host != target_host, 'Source and target must differ')
    segment = r'[a-z0-9]+(?:[._-][a-z0-9]+)*'
    require(re.fullmatch('qualification/' + segment + r'(?:/' + segment + r')*', namespace),
            'Use a literal qualification/ subtree')
    return source_host, target_host


def recorded_graph(ctx, client, digest):
    graph = ctx.portable._Graph(ctx.env).graph(client, digest)
    return {key: graph[key] for key in ('descriptor', 'manifests', 'blobs')}


def tagged_graph(ctx, client, tag):
    _, _, raw = client.request('GET', client.api + '/manifests/' + tag)
    digest = ctx.oci._digest(raw)
    return recorded_graph(ctx, client, digest)


def verified_statement(output, source_reference, predicate):
    """Check native Cosign output without rewriting a signed source claim."""
    from app import oci_attestations
    oci_attestations._verified_statement(output, source_reference, PURPOSE, predicate)
    for line in output.splitlines():
        if not line.strip():
            continue
        envelope = json.loads(line)
        statement = json.loads(base64.b64decode(envelope['payload'], validate=True))
        if (statement.get('predicateType') == oci_attestations.PREDICATE_TYPES[PURPOSE]
                and statement.get('predicate') == predicate
                and statement.get('subject', [{}])[0].get('digest') == {
                    'sha256': source_reference.rsplit('@sha256:', 1)[1]}):
            require(statement['predicate']['subject'] == source_reference,
                    'Original source predicate subject changed')
            return statement
    raise AssertionError('No verified original source statement')


def publish(ctx, args):
    from app import oci_attestations
    source, target = scope(args.source, args.target, args.namespace)
    require(not (ctx.root / 'expected.json').exists(), 'Use a fresh workspace for publication')
    key = ctx.root / 'signer'
    require(not key.with_suffix('.key').exists(), 'Use a fresh signer workspace')
    subprocess.run(['cosign', 'generate-key-pair', '--output-key-prefix', str(key)],
                   env=dict(ctx.signing.clean_environment(ctx.env),
                            COSIGN_PASSWORD=ctx.private['signing_password']),
                   check=True, capture_output=True, timeout=120)
    key.with_suffix('.key').chmod(0o600)
    public, fingerprint = ctx.signing.public_key(key.with_suffix('.pub').read_bytes())
    material = ({'signing_enabled': True, 'signing_public_key': public,
                 'signing_fingerprint': fingerprint},
                {ctx.signing.SECRET_ENV[0]: base64.b64encode(key.with_suffix('.key').read_bytes()).decode(),
                 ctx.signing.SECRET_ENV[1]: ctx.private['signing_password']})
    image = image_fixture(ctx, source, args.namespace, 2601106)
    evidence = {'qualification.json': ctx.oci._digest(ctx.portable.canonical({'fixture': LABEL}))}
    receipt = oci_attestations.attest_and_verify(image['reference'], PURPOSE, evidence, material, ctx.env)
    _, repository, digest = ctx.oci._reference(image['reference'])
    client = ctx.oci._Client(source, repository, ctx.env, pull_only=True)
    tag = digest.replace(':', '-') + '.att'
    expected = {'format': 'cats-harbor-attestation-preservation-v1', 'fixture': LABEL,
                'source': 'https://' + source, 'target': 'https://' + target,
                'namespace': args.namespace, 'repository': repository,
                'source_reference': image['reference'],
                'target_reference': target + '/' + repository + '@' + digest,
                'subject_digest': digest, 'image_graph': recorded_graph(ctx, client, digest),
                'attestation_tag': tag, 'attestation_graph': tagged_graph(ctx, client, tag),
                'predicate': oci_attestations._predicate(image['reference'], PURPOSE, evidence),
                'predicate_type': oci_attestations.PREDICATE_TYPES[PURPOSE],
                'trusted_fingerprint': fingerprint, 'source_verification': receipt,
                'ca_sha256': hashlib.sha256(Path(ctx.env['SSL_CERT_FILE']).read_bytes()).hexdigest()}
    write_json(ctx.root / 'expected.json', expected)
    print('Synthetic source image and native signed attestation published and verified; Harbor replication is required.')


def verify(ctx, args):
    source, target = scope(args.source, args.target, args.namespace)
    expected = json.loads((ctx.root / 'expected.json').read_text(encoding='utf-8'))
    require(expected['fixture'] == LABEL and expected['source'] == 'https://' + source
            and expected['target'] == 'https://' + target and expected['namespace'] == args.namespace,
            'Retained fixture scope does not match explicit endpoints and namespace')
    repository, digest = expected['repository'], expected['subject_digest']
    require(repository == args.namespace + '/fixtures/application'
            and ctx.oci._DIGEST.fullmatch(digest), 'Invalid retained repository or digest')
    source_reference, target_reference = (registry + '/' + repository + '@' + digest for registry in (source, target))
    require(expected['source_reference'] == source_reference and expected['target_reference'] == target_reference,
            'Retained subject references changed')
    require(expected['attestation_tag'] == digest.replace(':', '-') + '.att', 'Attestation tag changed')
    require(expected['ca_sha256'] == hashlib.sha256(Path(ctx.env['SSL_CERT_FILE']).read_bytes()).hexdigest(),
            'Verification CA differs from the explicit publication trust')
    public = ctx.root / 'signer.pub'
    require(ctx.signing.public_key(public.read_bytes())[1] == expected['trusted_fingerprint'],
            'Independent public key fingerprint changed')
    client = ctx.oci._Client(target, repository, ctx.env, pull_only=True)
    image_graph = recorded_graph(ctx, client, digest)
    attestation_graph = tagged_graph(ctx, client, expected['attestation_tag'])
    require(image_graph == expected['image_graph'], 'Target subject graph differs from source')
    require(attestation_graph == expected['attestation_graph'], 'Target attestation graph differs from source')
    output = ctx.signing._command(['cosign', 'verify-attestation', '--key', str(public),
        '--type', expected['predicate_type'], '--insecure-ignore-tlog=true', '--offline', target_reference],
        ctx.signing.clean_environment(ctx.env)).stdout
    statement = verified_statement(output, source_reference, expected['predicate'])
    (ctx.root / 'target-cosign-verified.jsonl').write_text(output, encoding='utf-8')
    report = {'format': expected['format'], 'fixture': LABEL, 'status': 'passed',
              'checked_at': datetime.now(timezone.utc).isoformat(),
              'source_reference': source_reference, 'target_reference': target_reference,
              'subject_digest': digest, 'predicate_type': expected['predicate_type'],
              'original_source_predicate_subject': statement['predicate']['subject'],
              'predicate': statement['predicate'], 'statement_subjects': statement['subject'],
              'image_graph': image_graph, 'attestation_graph': attestation_graph,
              'equivalent_relationship': expected['attestation_tag'],
              'trusted_fingerprint': expected['trusted_fingerprint'], 'explicit_ca_sha256': expected['ca_sha256'],
              'native_cosign_verification': 'passed', 'transparency_log': False,
              'verification_registry': 'https://' + target,
              'verification_uses_source_registry': False,
              'scope': 'Native Harbor transport only; approved-release import and proxy support are separate.'}
    write_json(ctx.root / 'verification.json', report)
    print('Target native Cosign signature, original source predicate, subject digest and exact OCI graphs verified.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('publish', 'verify'))
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--source', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--ca', type=Path)
    parser.add_argument('--docker-config', type=Path)
    args = parser.parse_args()
    scope(args.source, args.target, args.namespace)
    ctx = context(args)
    {'publish': publish, 'verify': verify}[args.phase](ctx, args)


if __name__ == '__main__':
    main()
