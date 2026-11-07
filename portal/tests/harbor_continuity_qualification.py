"""Opt-in real Harbor/HTTP qualification of attestations and key continuity.

Uses explicitly labelled SYNTHETIC image/chart/evidence fixtures, real Cosign
keys, the production publisher/importer, and an independently deployed replica.
An external controller runs Harbor replication, disconnects the source, and
restarts the replica between phases. This driver never copies to the target
registry or writes the replica database. Credentials remain in --workspace.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib.parse import quote
from zipfile import ZipFile

import requests

from harbor_graph_qualification import (
    LABEL, context, credentials, evidence_fixture, host, image_fixture, inventory,
    require, write_json,
)
from nginx_workflow_integration import API, load
from nginx_replica_acceptance import (
    assert_disconnected, assert_override_admin_denied, assert_override_uses,
    create_exact_override, exact_override_payload, pull_graph, revoke_override,
)
from nginx_replica_workflow import configure_principal, local_cyber


def destination(ctx, args):
    from app.secrets import encrypt_secret
    username, password = credentials(ctx.env, host(args.source))
    public = dict(id='harbor-continuity', name=LABEL, endpoint=args.source, namespace=args.namespace)
    return public, dict(public, username=username, password=encrypt_secret(password),
                        ca_pem=Path(ctx.env['SSL_CERT_FILE']).read_text())


def publisher_db(ctx):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app import main  # register the complete production schema
    from app.database import Base
    engine = create_engine('sqlite:///' + str(ctx.root / 'publisher.sqlite'))
    Base.metadata.create_all(engine)
    return engine, Session(engine)


def publish(ctx, args):
    from sqlalchemy import select
    from app import release_key_rotation, release_validity
    from app.models import PortalSetting, Service
    from app.replica_models import ReleasePublicationSequence
    sequence = args.sequence
    require(sequence in (1, 2, 3, 4, 5), 'Use three key generations followed by two same-image approvals')
    expected = load(ctx.root, 'expected.json', dict(fixture=LABEL, service_key=args.service_key,
        namespace=args.namespace, receipts={}))
    require(str(sequence) not in expected['receipts'], 'Use a fresh sequence; retained publications are immutable')
    engine, db = publisher_db(ctx)
    with db:
        service = db.get(Service, 1)
        if not service:
            require(sequence == 1, 'Publish the original key first')
            service = Service(id=1, service_key=args.service_key, name='Synthetic key continuity qualification')
            db.add(service)
            db.flush()
            db.add(ReleasePublicationSequence(service_id=1, sequence=0))
        require(service.service_key == args.service_key, 'Publisher service identity changed')
        counter = db.get(ReleasePublicationSequence, 1)
        require(counter.sequence == sequence - 1, 'Publication sequence is not consecutive')
        key = ctx.root / ('signer-' + str(min(sequence, 3)))
        if not key.with_suffix('.key').exists():
            subprocess.run(['cosign', 'generate-key-pair', '--output-key-prefix', str(key)],
                env=dict(ctx.env, COSIGN_PASSWORD=ctx.private['signing_password']),
                check=True, capture_output=True, timeout=120)
            key.with_suffix('.key').chmod(0o600)
        current = ctx.signing.store_keys(key.with_suffix('.key').read_bytes(), key.with_suffix('.pub').read_bytes(),
                                        ctx.private['signing_password'], True)
        if sequence > 3:
            (ctx.root / ('signer-' + str(sequence) + '.pub')).write_bytes(key.with_suffix('.pub').read_bytes())
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == ctx.signing.SETTING))
        if setting:
            current = release_key_rotation.prepare_configuration(db, json.loads(setting.value), current)
            setting.value = json.dumps(current)
        else:
            setting = PortalSetting(key='image_signing', value=json.dumps(current))
            db.add(setting)
            expected['trusted_fingerprint'] = current['fingerprint']
        counter.sequence = sequence
        counter.previous_release_id = str(sequence)
        db.commit()
        folder = ctx.root / ('release-' + str(sequence))
        folder.mkdir(exist_ok=True)
        if sequence > 3:
            prior = load(ctx.root / 'release-3', 'approval.json')
            image = next(item for item in prior['snapshot']['artifacts'] if item['kind'] == 'image')
        else:
            image = image_fixture(ctx, host(args.source), args.namespace, sequence)
        evidence, chart = evidence_fixture(ctx, folder, args.service_key, sequence)
        public, target = destination(ctx, args)
        now = datetime.now(timezone.utc)
        validity = release_validity.new_validity(now)
        portable = dict(format=ctx.portable.FORMAT, kind='release', service_uuid=args.service_key,
            release_uuid=str(sequence), release_sequence=sequence,
            supersedes_release_uuid=str(sequence - 1) if sequence > 1 else None, revoked_at=None, **validity)
        snapshot = dict(service_id=1, service_key=args.service_key,
            evidence=dict(path=str(evidence), digest=ctx.publication.file_digest(evidence)),
            artifacts=[image, dict(kind='chart', name='application', path=str(chart),
                                  digest=ctx.publication.file_digest(chart))],
            destination=public, signing_fingerprint=current['fingerprint'],
            approval_validity=validity, portable_release=portable)
        approval = SimpleNamespace(id=sequence, release_key='synthetic-continuity-' + str(sequence),
            snapshot=snapshot, snapshot_digest=ctx.oci._digest(ctx.publication.canonical(snapshot)),
            status='approved', decided_by_id=1, decided_at=now, decision_rationale=LABEL, revoked_at=None)
        receipt = ctx.publication.publish(db, approval, target,
            lambda value: write_json(folder / 'publication.json', value))
        verified = ctx.portable.fetch_release(receipt['release']['reference'], ctx.env,
                                              [expected['trusted_fingerprint']])
        require(verified['complete'] and verified['verified'], 'Source verification failed')
        require(all(item.get('attestation') for item in receipt['artifacts']), 'Every artifact requires an attestation')
        expected['receipts'][str(sequence)] = inventory(ctx, receipt, host(args.target))
        expected['release_repository'] = ctx.oci._reference(receipt['release']['reference'])[1]
        write_json(ctx.root / 'expected.json', expected)
        write_json(folder / 'approval.json', dict(vars(approval), decided_at=now.isoformat()), private=True)
    engine.dispose()
    print(json.dumps(dict(published_sequence=sequence, signer=current['fingerprint'],
                          original_trust_pin=expected['trusted_fingerprint'])), flush=True)


def revoke(ctx, args):
    from app.replica_models import ReleasePublicationSequence
    expected = load(ctx.root, 'expected.json')
    require(set(expected['receipts']) == {'1', '2', '3', '4', '5'},
            'Complete both rotations and delayed same-image replication before revocation')
    value = load(ctx.root / 'release-1', 'approval.json')
    value['decided_at'] = datetime.fromisoformat(value['decided_at'])
    value['revoked_at'] = datetime.now(timezone.utc)
    value['revocation_reason'] = 'Withdraw original-key release using the second authenticated successor'
    approval = SimpleNamespace(**value)
    metadata = dict(approval.snapshot['portable_release'], kind='revocation', release_sequence=6,
        target_release_uuid='1', revoked_by_id=1, revoked_at=approval.revoked_at.isoformat(),
        reason=approval.revocation_reason)
    engine, db = publisher_db(ctx)
    with db:
        db.get(ReleasePublicationSequence, 1).sequence = 6
        db.commit()
        receipt = ctx.publication.publish_revocation(db, approval, destination(ctx, args)[1], metadata,
            lambda value: write_json(ctx.root / 'revocation-publication.json', value))
    engine.dispose()
    expected['receipts']['revocation'] = inventory(ctx, receipt, host(args.target))
    write_json(ctx.root / 'expected.json', expected)
    print('Original release revoked using the second successor key.', flush=True)


def api_context(ctx, args):
    stack = json.loads(args.replica_stack.read_text(encoding='utf-8-sig'))
    api = API(args.replica_url)
    api.session.verify = ctx.env['SSL_CERT_FILE']
    api.login(stack['replica_admin_username'], stack['replica_admin_new_password'])
    return api, load(ctx.root, 'replica-state.json', {}), load(ctx.root, 'report.json', {'fixture': LABEL})


def persist(ctx, state, report):
    write_json(ctx.root / 'replica-state.json', state, private=True)
    write_json(ctx.root / 'report.json', report)


def setup(ctx, args):
    api, state, report = api_context(ctx, args)
    expected = load(ctx.root, 'expected.json')
    username, password = credentials(ctx.env, host(args.target))
    name = 'Synthetic continuity qualification'
    upstream = next((u for u in api.get('/api/oci/upstreams') if u['name'] == name), None)
    if not upstream:
        upstream = api.post('/api/oci/upstreams', dict(name=name, endpoint=args.target,
            username=username, password=password, ca_pem=Path(ctx.env['SSL_CERT_FILE']).read_text(), enabled=True))
    source = next((s for s in api.get('/api/replica/sources')['sources'] if s['name'] == name), None)
    if not source:
        source = api.post('/api/replica/sources', dict(name=name, upstream_id=upstream['id'],
            repository=expected['release_repository'], trusted_publishers=[expected['trusted_fingerprint']],
            poll_seconds=86400, enabled=True))
    require(source['trusted_publishers'] == [expected['trusted_fingerprint']], 'Only original key may be pinned')
    state.update(upstream_id=upstream['id'], source_id=source['id'], service_key=expected['service_key'],
                 releases_repository=expected['release_repository'])
    report['setup'] = dict(source_id=source['id'], trusted_publishers=source['trusted_publishers'])
    persist(ctx, state, report)


def releases(api, state):
    return api.get('/api/replica/releases?service_key=' + quote(state['service_key'], safe=''))['releases']


def sync(ctx, args):
    api, state, report = api_context(ctx, args)
    expected = load(ctx.root, 'expected.json')
    queued = api.post('/api/replica/sync', {'source_id': state['source_id']})['jobs']
    require(len(queued) == 1, 'Exactly one source must be selected')
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        job = next(j for j in api.get('/api/replica/status')['jobs'] if j['id'] == queued[0]['id'])
        if job['status'] in {'failed', 'cancelled'}:
            raise AssertionError('Replica sync failed: ' + str(job.get('error')))
        if job['status'] == 'completed':
            require((job.get('result') or {}).get('failed', 0) == 0, 'Replica rejected a published release')
            break
        time.sleep(2)
    else:
        raise TimeoutError('Replica sync exceeded 15 minutes')
    rows = releases(api, state)
    require(len(rows) == args.sequence, 'Expected preserved release history without duplicate services')
    require(len({r['service_id'] for r in rows}) == 1, 'Rotation changed replica service identity')
    if 'service_id' in state:
        require(state['service_id'] == rows[0]['service_id'], 'Original service identity was replaced')
    state['service_id'] = rows[0]['service_id']
    require({r['publisher'] for r in rows} == {expected['trusted_fingerprint']}, 'Publisher anchor changed')
    source = next(s for s in api.get('/api/replica/sources')['sources'] if s['id'] == state['source_id'])
    require(source['trusted_publishers'] == [expected['trusted_fingerprint']], 'Replica trust pin was modified')
    report.setdefault('sync', []).append(dict(sequence=args.sequence, job_id=job['id'],
        result=job['result'], service_id=state['service_id'], releases=[dict(id=r['id'],
        source_release_id=r['source_release_id'], status=r['status'], publisher=r['publisher']) for r in rows]))
    configure_principal(api, ctx.root, state, report)
    persist(ctx, state, report)
    print(json.dumps(report['sync'][-1]), flush=True)


def machine(ctx, state):
    session = requests.Session()
    session.trust_env = False
    session.verify = ctx.env['SSL_CERT_FILE']
    session.auth = (state['machine']['name'], state['machine']['secret'])
    return session


def attestation_pull(ctx, args, session, release):
    from app.oci_attestations import verify_envelope
    verified = []
    for item in release['artifacts']:
        inventory = item['attestation']
        repository = item['proxy_repositories'][0]
        base = args.proxy_url + '/v2/' + repository
        # Digest access is deliberately first, before any tag request.
        graph = pull_graph(session, args.proxy_url, repository, inventory['digest'])
        response = session.get(base + '/manifests/' + inventory['tag'], timeout=60)
        require(response.status_code == 200 and ctx.oci._digest(response.content) == inventory['digest'],
                'Attestation tag did not resolve to this release immutable inventory')
        document = response.json()
        sequence = int(release['source_release_id'])
        public = (ctx.root / ('signer-' + str(sequence) + '.pub')).read_bytes()
        for layer in document['layers']:
            payload = session.get(base + '/blobs/' + layer['digest'], timeout=60)
            require(payload.status_code == 200, 'Proxy did not route the attestation envelope')
            require(ctx.oci._digest(payload.content) == layer['digest'], 'Envelope bytes changed')
            receipt = verify_envelope(payload.content, item['digest'], public,
                ctx.signing.public_key(public)[1], inventory['receipts'][0])
            require(receipt['subject'].startswith(host(args.source) + '/'), 'Relocated source claim was rewritten')
        refs = session.get(base + '/referrers/' + item['digest'], timeout=60)
        require(refs.status_code == 200 and inventory['digest'] in {d['digest'] for d in refs.json()['manifests']},
                'Referrer discovery omitted retained attestation')
        verified.append(dict(repository=repository, root=item['digest'], attestation=inventory['digest'],
                             graph=graph, original_subject_retained=True))
    return verified


def denied(ctx, args, session, release):
    codes = []
    for item in release['artifacts']:
        base = args.proxy_url + '/v2/' + item['proxy_repositories'][0]
        inventory = item['attestation']
        for path in ('/manifests/' + inventory['tag'], '/manifests/' + inventory['digest'],
                     '/referrers/' + item['digest']):
            response = session.get(base + path, timeout=60)
            require(response.status_code in (403, 404), 'Denied release exposed attestation or referrers')
            codes.append(response.status_code)
        # Empty OCI config blobs may be shared with active artifacts; only the
        # signed envelope blobs are unique and expected to be denied here.
        for digest in inventory['blobs']:
            if digest == ctx.oci._digest(b'{}'):
                continue
            response = session.get(base + '/blobs/' + digest, timeout=60)
            require(response.status_code in (403, 404), 'Warm cached envelope bypassed revocation')
            codes.append(response.status_code)
    return codes


def verify(ctx, args):
    api, state, report = api_context(ctx, args)
    rows = releases(api, state)
    selected = next(r for r in rows if r['source_release_id'] == str(args.sequence))
    require(selected['status'] == 'active', 'Latest release is not active')
    with machine(ctx, state) as session:
        if args.disconnected:
            report['disconnected'] = assert_disconnected(session, [args.source + '/v2/'])
        result = dict(images=[pull_graph(session, args.proxy_url, item['proxy_repositories'][0], item['digest'])
                              for item in selected['artifacts']],
                      attestations=attestation_pull(ctx, args, session, selected))
    report.setdefault('pulls', []).append(dict(sequence=args.sequence, disconnected=args.disconnected, **result))
    persist(ctx, state, report)
    print(f'Verified all artifacts and signed attestations for sequence {args.sequence}.', flush=True)


def override(ctx, args):
    api, state, report = api_context(ctx, args)
    original = next(r for r in releases(api, state) if r['source_release_id'] == '1')
    require(original['status'] == 'superseded', 'Original key release must be superseded')
    # Scope the override to each retained root; each remains independently audited.
    local = local_cyber(api, ctx.root, state, report)
    local.session.verify = ctx.env['SSL_CERT_FILE']
    grants = []
    with machine(ctx, state) as session:
        report['before_override_denied'] = denied(ctx, args, session, original)
        for item in original['artifacts']:
            payload = exact_override_payload(original['id'], item['digest'],
                mission_impact='Verify disconnected continuity for the original signed release.',
                justification='Synthetic attestation routing and key rotation qualification.',
                risk_acceptance='Local Cyber accepts superseded-release risk for this isolated qualification.')
            assert_override_admin_denied(api.session, api.base, api.csrf, state['service_key'], payload)
            grants.append(create_exact_override(local.session, local.base, local.csrf, state['service_key'], payload))
        report['override_pull'] = attestation_pull(ctx, args, session, original)
        report['override_uses'] = [assert_override_uses(local.session, local.base, state['service_key'], grant['id'],
            release_id=original['id'], digest=grant['digests'][0], principal_id=state['machine']['id']) for grant in grants]
        for grant in grants:
            revoke_override(local.session, local.base, local.csrf, state['service_key'], grant['id'],
                            'Completed disconnected attestation continuity qualification')
        report['after_override_revocation_denied'] = denied(ctx, args, session, original)
    report['overrides'] = [dict(id=g['id'], release_id=g['release_id'], digests=g['digests'],
                                expires_at=g['expires_at']) for g in grants]
    persist(ctx, state, report)
    print('Original-key attestations allowed by exact local overrides, then denied after revocation.', flush=True)


def verify_revocation(ctx, args):
    api, state, report = api_context(ctx, args)
    rows = releases(api, state)
    original = next(r for r in rows if r['source_release_id'] == '1')
    require(original['status'] == 'revoked', 'Current successor did not revoke original-key release')
    require(next(r for r in rows if r['source_release_id'] == str(args.sequence))['status'] == 'active',
            'Unrelated release changed')
    with machine(ctx, state) as session:
        report['successor_signed_revocation_denied'] = denied(ctx, args, session, original)
    report['successor_signed_revocation'] = True
    persist(ctx, state, report)


def verify_restart(ctx, args):
    api, state, report = api_context(ctx, args)
    expected = load(ctx.root, 'expected.json')
    rows = releases(api, state)
    retained = [dict(id=r['id'], source_release_id=r['source_release_id'],
                     status=r['status'], publisher=r['publisher']) for r in rows]
    require(retained == report['sync'][-1]['releases'], 'Restart changed retained identities or release state')
    source = next(s for s in api.get('/api/replica/sources')['sources'] if s['id'] == state['source_id'])
    require(source['trusted_publishers'] == [expected['trusted_fingerprint']], 'Restart changed original trust pin')
    local = local_cyber(api, ctx.root, state, report)
    grants = local.get('/api/services/' + quote(state['service_key'], safe='') + '/local-overrides')['overrides']
    audited = []
    for retained_grant in report['overrides']:
        grant = next(g for g in grants if g['id'] == retained_grant['id'])
        require(grant['status'] == 'revoked', 'Restart restored a revoked local exception')
        audited.append(assert_override_uses(local.session, local.base, state['service_key'], grant['id'],
            release_id=grant['release_id'], digest=grant['digests'][0], principal_id=state['machine']['id']))
    report['restart_persistence'] = dict(releases=retained, source_id=source['id'],
        original_pin=source['trusted_publishers'][0], revoked_override_ids=[g['override_id'] for g in audited],
        audit_retained=True)
    persist(ctx, state, report)
    print('Restart preserved publisher identity, release history, original trust pin and revoked override audit.')


def verify_retention(ctx, args):
    """Both repeated approvals must survive first replication after tag movement."""
    api, state, report = api_context(ctx, args)
    expected = load(ctx.root, 'expected.json')
    rows = releases(api, state)
    retained = []
    for sequence in (4, 5):
        verified = ctx.portable.fetch_release(expected['receipts'][str(sequence)]['target_reference'],
                                             ctx.env, [expected['trusted_fingerprint']])
        require(verified['complete'] and verified['verified'], 'Harbor lost an older attachment graph')
        retained.append(sequence)
    old = next(r for r in rows if r['source_release_id'] == '4')
    active = next(r for r in rows if r['source_release_id'] == '5')
    old_image = next(i for i in old['artifacts'] if i['kind'] == 'image')
    active_image = next(i for i in active['artifacts'] if i['kind'] == 'image')
    require(old_image['digest'] == active_image['digest'], 'Retention fixture must share the image root')
    require(old_image['attestation']['digest'] != active_image['attestation']['digest'],
            'Approval attestations must differ')
    with machine(ctx, state) as session:
        disconnected = assert_disconnected(session, [args.source + '/v2/'])
        base = args.proxy_url + '/v2/' + old_image['proxy_repositories'][0]
        response = session.get(base + '/manifests/' + old_image['attestation']['digest'], timeout=60)
        require(response.status_code in (403, 404), 'Active shared root exposed superseded attestation')
        refs = session.get(base + '/referrers/' + active_image['digest'], timeout=60)
        require(refs.status_code == 200, 'Active shared-root discovery failed')
        digests = {d['digest'] for d in refs.json()['manifests']}
        require(active_image['attestation']['digest'] in digests and
                old_image['attestation']['digest'] not in digests, 'Referrers mixed approval inventories')
    report['delayed_same_image_replication'] = dict(verified_sequences=retained,
        shared_image_digest=active_image['digest'], superseded_attestation_status=response.status_code,
        publisher_unavailable=disconnected)
    persist(ctx, state, report)


def bootstrap(ctx, args):
    from sqlalchemy import select
    from app import main
    from app.replica_authorization import trusted_release
    from app.replica_models import ReplicaPublisherTrust, ReplicaRelease, ReplicaServiceState
    from harbor_graph_qualification import active_state, import_release, ledger
    expected = load(ctx.root, 'expected.json')
    expected['target'] = args.target
    report = load(ctx.root, 'report.json')
    with requests.Session() as session:
        session.trust_env = False
        session.verify = ctx.env['SSL_CERT_FILE']
        disconnected = assert_disconnected(session, [args.source + '/v2/'])
    verified = ctx.portable.fetch_release(expected['receipts']['3']['target_reference'], ctx.env,
                                          [expected['trusted_fingerprint']])
    require(verified['complete'] and verified['verified'], 'Disconnected full-chain verification failed')
    engine, db, source = ledger(ctx, expected, 'direct-successor-bootstrap')
    with db:
        result = import_release(db, source, verified)
        state = db.scalar(select(ReplicaServiceState))
        release = db.scalar(select(ReplicaRelease))
        trust = db.scalar(select(ReplicaPublisherTrust))
        require(trust.generation == 2 and trust.publisher_root == expected['trusted_fingerprint'],
                'Fresh replica did not authenticate both transitions from the original root')
        require(trusted_release(db, release, state, datetime.now(timezone.utc)), 'Fresh successor is not authorized')
        report['direct_successor_bootstrap'] = dict(result=result, state=active_state(db),
            original_pin=expected['trusted_fingerprint'], actual_signer=release.key_fingerprint,
            generation=trust.generation, publisher_unavailable=disconnected)
    engine.dispose()
    write_json(ctx.root / 'report.json', report)
    print('Fresh isolated importer authenticated the second successor using only the original pin.', flush=True)


def offline(ctx, args):
    receipt = load(ctx.root / ('release-' + str(args.sequence)), 'publication.json')
    expected = load(ctx.root, 'expected.json')
    folder = ctx.root / ('offline-' + str(args.sequence))
    require(not folder.exists(), 'Offline check requires a fresh output directory')
    folder.mkdir()
    with ZipFile(receipt['bundle_path']) as archive:
        for member in archive.infolist():
            path = Path(member.filename)
            require(not path.is_absolute() and '..' not in path.parts, 'Unsafe generated bundle member')
        archive.extractall(folder)
    script = folder / 'verify-import.py'
    require(script.is_file(), 'Standalone import verifier is missing')
    result = subprocess.run([sys.executable, str(script), '--fingerprint', expected['trusted_fingerprint']],
                            env=ctx.env, capture_output=True, text=True, timeout=180)
    require(result.returncode == 0, 'Delivered standalone verifier rejected original pin: ' + result.stderr[-1500:])
    report = load(ctx.root, 'report.json')
    report['offline_original_pin'] = dict(sequence=args.sequence, signer=receipt['signing_fingerprint'],
        trusted_fingerprint=expected['trusted_fingerprint'], bundle_digest=receipt['bundle_digest'], verified=True)
    write_json(ctx.root / 'report.json', report)
    print('Standalone offline bundle verified using the original trust pin.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('publish', 'revoke', 'setup', 'sync', 'verify', 'override',
                                        'verify-revocation', 'verify-retention', 'verify-restart', 'bootstrap', 'offline'))
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--source', default='https://harbor-source.test:8443')
    parser.add_argument('--target', default='https://harbor-target.test:8443')
    parser.add_argument('--namespace', default='qualification/completion-20261107')
    parser.add_argument('--service-key', default='harbor-continuity-20261107')
    parser.add_argument('--sequence', type=int, default=1)
    parser.add_argument('--ca', type=Path)
    parser.add_argument('--docker-config', type=Path)
    parser.add_argument('--replica-stack', type=Path)
    parser.add_argument('--replica-url', default='https://final-replica.test:9443')
    parser.add_argument('--proxy-url', default='https://final-replica.test:9553')
    parser.add_argument('--disconnected', action='store_true')
    args = parser.parse_args()
    ctx = context(args)
    # Reused Local Cyber helper creates another API client; configure the same
    # explicitly selected local CA for it without disabling TLS validation.
    initializer = API.__init__
    def initialize(self, *values, **kwargs):
        initializer(self, *values, **kwargs)
        self.session.verify = ctx.env['SSL_CERT_FILE']
    API.__init__ = initialize
    globals()[args.phase.replace('-', '_')](ctx, args)


if __name__ == '__main__':
    main()
