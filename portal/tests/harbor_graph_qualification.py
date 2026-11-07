"""Opt-in qualification of actual Harbor replication with SYNTHETIC fixtures.

Run inside an explicitly configured verification environment with the application,
Cosign, SSL_CERT_FILE and DOCKER_CONFIG available. This companion publishes only
to the source. A separate operator/controller must run Harbor replication, stop
the source, and remove/restore target objects for the omission cases. Optional
quarantine/restore phases rename only a checked fixture blob in an explicitly
mounted disposable target volume. This companion never copies between registries
or accesses a live portal database. Import checks use the production importer
and isolated SQLite.
Stop registry writers before storage injection. A global blob may only be held
when every stored repository reference belongs to the selected fixture subtree.

  python harbor_graph_qualification.py publish --workspace /verification/graph
  # Run Harbor replication; stop the source registry independently.
  python harbor_graph_qualification.py verify --workspace /verification/graph
  # Remove the exact target object recorded in expected.json / omissions.
  python harbor_graph_qualification.py verify --workspace /verification/graph --case missing-child
  # Restore the injected storage object (or rerun Harbor replication), then retry.
  python harbor_graph_qualification.py verify --workspace /verification/graph --case recover --failed-case missing-child

The synthetic image layers, Helm chart, SBOM and scanner output exercise the OCI
graph and signed evidence protocol. They are not a real scan or Cyber decision.
Actual nginx approval, HTTP pull authorization and local overrides are separate
acceptance workflows. Reports contain no registry or signing credentials.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tarfile
from types import SimpleNamespace
from urllib.parse import urlsplit
from zipfile import ZipFile


LABEL = 'SYNTHETIC Harbor graph qualification; not scanned or approved production content'
OMISSIONS = ('missing-child', 'missing-layer', 'missing-evidence', 'missing-signature')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_json(path, value, *, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    with os.fdopen(os.open(path, flags, 0o600 if private else 0o644), 'w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
    if private:
        path.chmod(0o600)


def host(endpoint):
    value = urlsplit(endpoint)
    require(value.scheme == 'https' and value.hostname and not value.username and not value.password
            and value.path in ('', '/') and not value.query and not value.fragment,
            'Provide a credential-free HTTPS registry origin')
    return value.netloc


def context(args):
    from cryptography.fernet import Fernet
    from app import cyber_release_publication, portable_release, release_oci, signing
    root = args.workspace.resolve()
    root.mkdir(parents=True, exist_ok=True)
    private_path = root / 'private-state.json'
    if private_path.exists():
        private = json.loads(private_path.read_text(encoding='utf-8'))
    else:
        private = {'encryption_key': Fernet.generate_key().decode(), 'signing_password': secrets.token_urlsafe(32)}
        write_json(private_path, private, private=True)
    os.environ['CATS_CONFIG_ENCRYPTION_KEY'] = private['encryption_key']
    env = dict(os.environ)
    if args.ca:
        env['SSL_CERT_FILE'] = str(args.ca.resolve())
    if args.docker_config:
        env['DOCKER_CONFIG'] = str(args.docker_config.resolve())
    require(env.get('SSL_CERT_FILE') and Path(env['SSL_CERT_FILE']).is_file(), 'A trusted CA file is required')
    require(env.get('DOCKER_CONFIG') and (Path(env['DOCKER_CONFIG']) / 'config.json').is_file(),
            'An explicit Docker authentication configuration is required')
    return SimpleNamespace(root=root, private=private, env=env, oci=release_oci, portable=portable_release,
                           publication=cyber_release_publication, signing=signing)


def credentials(env, registry):
    config = json.loads((Path(env['DOCKER_CONFIG']) / 'config.json').read_text(encoding='utf-8'))
    for key in (registry, 'https://' + registry, 'https://' + registry + '/v1/'):
        entry = config.get('auths', {}).get(key, {})
        if entry.get('auth'):
            value = base64.b64decode(entry['auth'], validate=True).decode()
            require(':' in value and '\n' not in value and '\r' not in value, 'Invalid Docker credentials')
            return value.split(':', 1)
    raise ValueError('Source Docker configuration has no inline authentication for the exact registry host')


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(content), 0o644, 0
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def image_fixture(ctx, registry, namespace, sequence):
    client = ctx.oci._Client(registry, namespace + '/fixtures/application', ctx.env)
    children = []
    for architecture in ('amd64', 'arm64'):
        content = tar_bytes({'SYNTHETIC-QUALIFICATION.txt': f'{LABEL}\n{sequence}:linux/{architecture}\n'.encode()})
        layer = client.upload(content, 'application/vnd.oci.image.layer.v1.tar')
        config = client.upload(ctx.portable.canonical({'architecture': architecture, 'os': 'linux',
            'config': {'Labels': {'io.cats.fixture': LABEL}},
            'rootfs': {'type': 'layers', 'diff_ids': [layer['digest']]}}),
            'application/vnd.oci.image.config.v1+json')
        content = ctx.portable.canonical({'schemaVersion': 2, 'mediaType': ctx.oci.MANIFEST_TYPE,
                                         'config': config, 'layers': [layer]})
        digest = ctx.oci._digest(content)
        require(client.request('PUT', client.api + '/manifests/' + digest,
                               body=content, media_type=ctx.oci.MANIFEST_TYPE)[0] == 201, 'Image publication failed')
        children.append({'mediaType': ctx.oci.MANIFEST_TYPE, 'digest': digest, 'size': len(content),
                         'platform': {'os': 'linux', 'architecture': architecture}})
    content = ctx.portable.canonical({'schemaVersion': 2, 'mediaType': ctx.oci.INDEX_TYPE, 'manifests': children})
    digest = ctx.oci._digest(content)
    require(client.request('PUT', client.api + '/manifests/' + digest,
                           body=content, media_type=ctx.oci.INDEX_TYPE)[0] == 201, 'Index publication failed')
    return {'kind': 'image', 'reference': registry + '/' + client.repository + '@' + digest,
            'digest': digest}


def evidence_fixture(ctx, folder, service_key, sequence):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app import main, portable_release_capture
    from app.database import Base
    from app.models import Service
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key=service_key, name='Synthetic Harbor graph fixture',
                          description=f'{LABEL}; revision {sequence}')
        db.add(service)
        db.flush()
        state = portable_release_capture.capture(db, service, {})
    engine.dispose()
    evidence = folder / 'evidence.zip'
    with ZipFile(evidence, 'w') as archive:
        archive.writestr('replica-service.json', ctx.portable.canonical(state))
        archive.writestr('SYNTHETIC-QUALIFICATION.txt', LABEL)
        archive.writestr('sbom.json', ctx.portable.canonical({'fixture': LABEL, 'artifacts': [], 'revision': sequence}))
        archive.writestr('scanner-output.json', ctx.portable.canonical({'fixture': LABEL, 'findings': [], 'revision': sequence}))
    chart = folder / 'application.tgz'
    with tarfile.open(chart, 'w:gz') as archive:
        files = {'application/Chart.yaml': f'apiVersion: v2\nname: application\nversion: 1.0.{sequence}\ndescription: Synthetic Harbor qualification fixture\n'.encode(),
                 'application/README.md': LABEL.encode(),
                 'application/templates/fixture.yaml': b'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: synthetic-harbor-fixture\ndata:\n  fixture: synthetic\n'}
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), 0o644
            archive.addfile(entry, io.BytesIO(content))
    return evidence, chart


def manifest(ctx, registry, repository, digest):
    client = ctx.oci._Client(registry, repository, ctx.env, pull_only=True)
    _, _, content = client.request('GET', client.api + '/manifests/' + digest)
    require(ctx.oci._digest(content) == digest, 'Manifest bytes differ from the immutable digest')
    return json.loads(content)


def inventory(ctx, receipt, target):
    source, repository, digest = ctx.oci._reference(receipt['release']['reference'])
    result = {'source_reference': receipt['release']['reference'],
              'target_reference': target + '/' + repository + '@' + digest,
              'release': receipt['release'], 'manifest': receipt['manifest'], 'artifacts': receipt.get('artifacts', [])}
    document = manifest(ctx, source, repository, digest)
    result['release_objects'] = [{'repository': repository, 'kind': 'blob', **item}
                                 for item in [document['config'], *document['layers']]]
    if receipt.get('artifacts'):
        image = next(item for item in receipt['artifacts'] if item['kind'] == 'image')
        _, image_repo, image_digest = ctx.oci._reference(image['reference'])
        index = manifest(ctx, source, image_repo, image_digest)
        child = index['manifests'][0]
        child_document = manifest(ctx, source, image_repo, child['digest'])
        evidence = next(item for item in document['layers']
                        if item.get('annotations', {}).get('org.opencontainers.image.title') == 'evidence.zip')
        result['omissions'] = {
            'missing-child': {'repository': image_repo, 'kind': 'manifest', **child, 'parent_digest': image_digest},
            'missing-layer': {'repository': image_repo, 'kind': 'blob', **child_document['layers'][0], 'parent_digest': child['digest']},
            'missing-evidence': {'repository': repository, 'kind': 'blob', **evidence, 'parent_digest': digest},
            'missing-signature': {'repository': image_repo, 'kind': 'manifest',
                                  'digest': image['signature']['digest'], 'parent_digest': image_digest},
        }
        result['platforms'] = [item['platform'] for item in index['manifests']]
    return result


def publish(ctx, args):
    from app import release_validity
    from app.secrets import encrypt_secret
    require(not (ctx.root / 'expected.json').exists(), 'Publication already exists; use a fresh explicit workspace')
    source, target = host(args.source), host(args.target)
    require(source != target, 'Source and target must be different registries')
    key = ctx.root / 'signer'
    if not key.with_suffix('.key').exists():
        subprocess.run(['cosign', 'generate-key-pair', '--output-key-prefix', str(key)],
            env=dict(ctx.env, COSIGN_PASSWORD=ctx.private['signing_password']), check=True, capture_output=True, timeout=120)
        key.with_suffix('.key').chmod(0o600)
    settings = ctx.signing.store_keys(key.with_suffix('.key').read_bytes(), key.with_suffix('.pub').read_bytes(),
                                     ctx.private['signing_password'], True)
    db = SimpleNamespace(scalars=lambda query: [SimpleNamespace(key='image_signing', value=json.dumps(settings))])
    public_destination = {'id': 'harbor-qualification', 'name': 'Synthetic Harbor qualification',
                          'endpoint': 'https://' + source, 'namespace': args.namespace}
    username, password = credentials(ctx.env, source)
    destination = {**public_destination, 'username': username, 'password': encrypt_secret(password),
                   'ca_pem': Path(ctx.env['SSL_CERT_FILE']).read_text(encoding='utf-8')}
    expected = {'fixture': LABEL, 'source': 'https://' + source, 'target': 'https://' + target,
                'namespace': args.namespace, 'service_key': args.service_key,
                'trusted_fingerprint': settings['fingerprint'], 'receipts': {}}
    approvals = []
    for sequence, label in ((1, 'first'), (2, 'successor')):
        folder = ctx.root / label
        folder.mkdir(exist_ok=True)
        image = image_fixture(ctx, source, args.namespace, sequence)
        evidence, chart = evidence_fixture(ctx, folder, args.service_key, sequence)
        now = datetime.now(timezone.utc)
        validity = release_validity.new_validity(now)
        metadata = {'format': ctx.portable.FORMAT, 'kind': 'release', 'service_uuid': args.service_key,
            'release_uuid': str(sequence), 'release_sequence': sequence,
            'supersedes_release_uuid': '1' if sequence == 2 else None, 'revoked_at': None, **validity}
        snapshot = {'service_id': 1, 'service_key': args.service_key,
            'evidence': {'path': str(evidence), 'digest': ctx.publication.file_digest(evidence)},
            'artifacts': [image, {'kind': 'chart', 'name': 'application', 'path': str(chart),
                                 'digest': ctx.publication.file_digest(chart)}],
            'destination': public_destination, 'signing_fingerprint': settings['fingerprint'],
            'approval_validity': validity, 'portable_release': metadata}
        approval = SimpleNamespace(id=sequence, release_key=f'harbor-synthetic-{sequence}', snapshot=snapshot,
            snapshot_digest=ctx.oci._digest(ctx.publication.canonical(snapshot)), status='approved',
            decided_by_id=1, decided_at=now, decision_rationale=LABEL, revoked_at=None)
        receipt = ctx.publication.publish(db, approval, destination,
            lambda value, folder=folder: write_json(folder / 'publication.json', value))
        verified = ctx.portable.fetch_release(receipt['release']['reference'], ctx.env, [settings['fingerprint']])
        require(verified['verified'] and verified['complete'], 'Source fixture verification failed')
        expected['receipts'][label] = inventory(ctx, receipt, target)
        approvals.append(approval)
    successor = approvals[-1]
    successor.revoked_at = datetime.now(timezone.utc)
    successor.revocation_reason = 'Synthetic exact-release withdrawal for Harbor qualification'
    metadata = {**successor.snapshot['portable_release'], 'kind': 'revocation', 'release_sequence': 3,
        'target_release_uuid': '2', 'revoked_by_id': 1,
        'revoked_at': successor.revoked_at.isoformat(), 'reason': successor.revocation_reason}
    receipt = ctx.publication.publish_revocation(db, successor, destination, metadata,
        lambda value: write_json(ctx.root / 'revocation-publication.json', value))
    expected['receipts']['revocation'] = inventory(ctx, receipt, target)
    expected['omissions'] = expected['receipts']['successor']['omissions']
    expected['release_repository'] = ctx.oci._reference(receipt['release']['reference'])[1]
    write_json(ctx.root / 'expected.json', expected)
    print(json.dumps({'status': 'published', 'fixture': LABEL, 'receipts': list(expected['receipts']),
                      'expected': str(ctx.root / 'expected.json')}))


def fetch(ctx, expected, label):
    receipt = expected['receipts'][label]
    result = ctx.portable.fetch_release(receipt['target_reference'], ctx.env, [expected['trusted_fingerprint']])
    require(result['complete'] and result['verified'] and result['manifest'] == receipt['manifest'],
            'Target signed manifest differs from the published fixture')
    # The detached release-manifest signature is the production trust boundary.
    # Also retain coverage of the auxiliary Cosign signature transported beside
    # the release root, so this qualification accounts for that graph as well.
    signature = receipt['release'].get('signature')
    if signature:
        registry, repository, digest = ctx.oci._reference(receipt['target_reference'])
        client = ctx.oci._Client(registry, repository, ctx.env, pull_only=True)
        graph = ctx.portable._Graph(ctx.env).graph(client, signature['digest'])
        bound = False
        for layer in graph['document'].get('layers', []):
            detached = layer.get('annotations', {}).get('dev.cosignproject.cosign/signature')
            payload = graph['contents'].get(layer['digest'])
            if detached and payload and json.loads(payload).get('critical', {}).get('image', {}).get('docker-manifest-digest') == digest:
                ctx.portable._verify_blob(payload, detached.encode(), result['files']['release-public-key.pem'],
                                         expected['trusted_fingerprint'])
                bound = True
        require(bound, 'Auxiliary release signature graph does not bind the release root')
        result['auxiliary_release_signature'] = {'digest': signature['digest'],
            'manifests': graph['manifests'], 'blobs': graph['blobs'], 'verified': True}
    if label != 'revocation':
        require(ctx.oci._digest(result['evidence']) == receipt['manifest']['evidence']['digest'],
                'Signed archive digest differs from retained evidence bytes')
        require(sorted(item['kind'] for item in result['artifacts']) == ['chart', 'image'], 'Deployable inventory changed')
        image = next(item for item in result['artifacts'] if item['kind'] == 'image')
        require(len(image['manifests']) == 3 and image['media_type'] == ctx.oci.INDEX_TYPE, 'Multiarch graph is incomplete')
        registry, repository, digest = ctx.oci._reference(image['reference'])
        index = manifest(ctx, registry, repository, digest)
        require(sorted(item['platform']['architecture'] for item in index['manifests']) == ['amd64', 'arm64'],
                'Expected both Linux architectures')
        chart = next(item for item in result['artifacts'] if item['kind'] == 'chart')
        _, repository, digest = ctx.oci._reference(chart['reference'])
        chart_document = manifest(ctx, registry, repository, digest)
        require(chart_document['config']['mediaType'] == 'application/vnd.cncf.helm.config.v1+json'
                and chart_document['layers'][0]['mediaType'] == 'application/vnd.cncf.helm.chart.content.v1.tar+gzip',
                'Helm OCI media types changed')
    return result


def ledger(ctx, expected, name, *, existing=False):
    from sqlalchemy import create_engine, event, select
    from sqlalchemy.orm import Session
    from app.database import Base
    from app.models import User
    from app.oci_models import OCIUpstream
    from app.replica_models import ReplicaSource
    folder = ctx.root / 'isolated-imports' / name
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'state.sqlite'
    require(path.exists() if existing else not path.exists(),
            'Recovery requires an existing failed-case ledger; fresh checks require an unused case ledger')
    os.environ['CATS_REPLICA_STORAGE'] = str(folder / 'evidence')
    engine = create_engine('sqlite:///' + path.as_posix())
    @event.listens_for(engine, 'connect')
    def foreign_keys(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    source = db.scalar(select(ReplicaSource))
    if not existing:
        user = User(username='synthetic-importer', password_hash='!', display_name='Synthetic qualification importer')
        upstream = OCIUpstream(name='synthetic-harbor-target', endpoint=expected['target'])
        db.add_all([user, upstream])
        db.flush()
        source = ReplicaSource(name='synthetic-target-releases', upstream_id=upstream.id,
            repository=expected['release_repository'], trusted_publishers=[expected['trusted_fingerprint']], created_by_id=user.id)
        db.add(source)
        db.commit()
    require(source is not None, 'Isolated replica source is missing')
    return engine, db, source


def active_state(db):
    from sqlalchemy import select
    from app.replica_models import ReplicaRelease, ReplicaServiceState
    from app.replica_integrity import verify_record
    from app.release_validity import utc
    state = db.scalar(select(ReplicaServiceState).execution_options(populate_existing=True))
    require(state is not None, 'Replica service was not activated')
    release = db.get(ReplicaRelease, state.active_release_id, populate_existing=True)
    require(release is not None and verify_record(release), 'Retained active release failed its local integrity seal')
    return {'release_uuid': release.source_release_id, 'sequence': release.sequence, 'high_sequence': state.high_sequence,
            'approved_at': utc(release.approved_at).isoformat(),
            'expires_at': utc(release.expires_at).isoformat() if release.expires_at else None,
            'revoked_at': utc(release.revoked_at).isoformat() if release.revoked_at else None}


def import_release(db, source, verified):
    from app.replica_import import reconcile
    result = reconcile(db, source, verified)
    db.commit()
    return result


def expect_absent(ctx, expected, case):
    target = expected['omissions'][case]
    registry = host(expected['target'])
    client = ctx.oci._Client(registry, target['repository'], ctx.env, pull_only=True)
    # The containing graph must still be advertised; deleting its parent would
    # prove only a missing root, not an incomplete recursive graph.
    manifest(ctx, registry, target['repository'], target['parent_digest'])
    _, release_repo, release_digest = ctx.oci._reference(expected['receipts']['successor']['target_reference'])
    manifest(ctx, registry, release_repo, release_digest)
    try:
        status, headers, content = client.request(
            'GET', client.api + ('/manifests/' if target['kind'] == 'manifest' else '/blobs/') + target['digest'])
    except ctx.oci._RegistryError as error:
        require(error.status == 404, 'The omitted object must be absent (404), not denied or unreachable')
        return {**target, 'observed_http_status': 404}
    # Harbor's descriptor cache can retain the size of a removed storage blob.
    # Its GET then returns 200 with that Content-Length but no body. Record the
    # actual response, and require the production verifier to reject it below.
    if (target['kind'] == 'blob' and status == 200 and target.get('size', 0) > 0
            and not content and headers.get('Content-Length') == str(target['size'])):
        return {**target, 'observed_http_status': status, 'observed_body_bytes': 0,
                'observed_content_length': headers.get('Content-Length'),
                'empty_body_for_nonempty_blob': True}
    raise AssertionError('The object did not exhibit the required missing-content response')


def rejection_checks(ctx, expected, baseline):
    fingerprint = expected['trusted_fingerprint']
    wrong = 'sha256:' + ('0' if fingerprint[-1] != '0' else '1') * 64
    try:
        ctx.portable.fetch_release(expected['receipts']['first']['target_reference'], ctx.env, [wrong])
    except ValueError as error:
        require(str(error) == 'Release publisher is not independently trusted', 'Wrong-signer check failed for another reason')
    else:
        raise AssertionError('Untrusted publisher was accepted')
    modified = json.loads(baseline['files']['release-manifest.json'])
    modified['portable']['release_sequence'] += 100
    try:
        ctx.portable._verify_blob(ctx.portable.canonical(modified), baseline['files']['release-manifest.sig'],
                                 baseline['files']['release-public-key.pem'], fingerprint)
    except ValueError as error:
        require(str(error) == 'Portable release signature verification failed', 'Sequence tamper failed for another reason')
    else:
        raise AssertionError('Changed sequence retained a valid signature')
    return {'wrong_trust_pin_rejected': True, 'changed_sequence_signature_rejected': True,
            'tamper_scope': 'local mutation of actual fetched signed bytes; Harbor storage was not changed'}


def verify(ctx, args):
    from sqlalchemy import select
    from app.replica_models import ReplicaRelease
    from app.replica_integrity import verify_record
    expected = json.loads((ctx.root / 'expected.json').read_text(encoding='utf-8'))
    case = args.case
    require(case != 'recover' or args.failed_case in OMISSIONS, '--failed-case is required for recovery')
    if case == 'recover':
        failed_report = ctx.root / 'reports' / (args.failed_case + '.json')
        require(failed_report.is_file(), 'Recovery requires a previously passed omission check')
        prior = json.loads(failed_report.read_text(encoding='utf-8'))
        require(prior.get('status') == 'passed' and prior.get('case') == args.failed_case
                and prior.get('target') == expected['target'] and prior.get('fixture') == LABEL
                and prior.get('active_preserved') is True
                and (prior.get('omission', {}).get('observed_http_status') == 404
                     or prior.get('omission', {}).get('empty_body_for_nonempty_blob') is True),
                'The prior check did not prove the matching omission and active-state preservation')
    baseline = fetch(ctx, expected, 'first')
    report = {'fixture': LABEL, 'case': case, 'target': expected['target'], 'source_reads': 0,
              'scope': 'actual target OCI graph and production importer in isolated SQLite; HTTP authorization tested separately',
              'started_at': datetime.now(timezone.utc).isoformat()}
    if case == 'recover':
        report['failed_case'] = args.failed_case
    if case in ('wrong-signer', 'changed-sequence'):
        report.update(rejection_checks(ctx, expected, baseline))
    else:
        name = args.failed_case if case == 'recover' else case
        engine, db, source = ledger(ctx, expected, name, existing=case == 'recover')
        try:
            if case != 'recover':
                report['first_import'] = import_release(db, source, baseline)
            before = active_state(db)
            require(before['release_uuid'] == '1' and before['high_sequence'] == 1, 'Baseline must remain active')
            if case in OMISSIONS:
                report['omission'] = expect_absent(ctx, expected, case)
                try:
                    candidate = fetch(ctx, expected, 'successor')
                except ctx.oci._RegistryError as error:
                    require(error.status == 404, 'Incomplete graph failed for an unrelated registry error')
                    report['verification_rejected_http_status'] = error.status
                except ValueError as error:
                    require(report['omission'].get('empty_body_for_nonempty_blob') is True
                            and str(error) == 'Incomplete or corrupt replicated OCI content',
                            'Incomplete graph failed for an unrelated validation error')
                    report['verification_rejected_incomplete_content'] = True
                else:
                    raise AssertionError('Incomplete target graph was accepted: ' + candidate['reference'])
                db.rollback()
                require(active_state(db) == before, 'Incomplete candidate changed active replica state')
                report.update(active_preserved=True, active=before)
            else:
                successor = fetch(ctx, expected, 'successor')
                report['successor_import'] = import_release(db, source, successor)
                active = active_state(db)
                require(active['release_uuid'] == '2' and active['high_sequence'] == 2
                        and active['expires_at'] == successor['manifest']['approval']['expires_at'],
                        'Successor activation or original expiry changed')
                report['older_replay'] = import_release(db, source, baseline)
                require(report['older_replay']['status'] == 'unchanged' and active_state(db) == active,
                        'Older replay changed active release or extended validity')
                report['active_after_replay'] = active
                report['graphs'] = {label: [{'kind': item['kind'], 'reference': item['reference'],
                    'manifests': item['manifests'], 'blobs': item['blobs']} for item in result['artifacts']]
                    for label, result in (('first', baseline), ('successor', successor))}
                report['signed_evidence'] = {label: {'digest': ctx.oci._digest(result['evidence']),
                    'bytes': len(result['evidence']), 'detached_signature_verified': True,
                    'archive_files': sorted(ZipFile(io.BytesIO(result['evidence'])).namelist()),
                    'release_signature_graph': result.get('auxiliary_release_signature')}
                    for label, result in (('first', baseline), ('successor', successor))}
                if case == 'complete':
                    report.update(rejection_checks(ctx, expected, baseline))
                    found = set(ctx.portable.discover_release_references(host(expected['target']), expected['release_repository'], ctx.env))
                    require({row['target_reference'] for row in expected['receipts'].values()} <= found,
                            'Exact release-repository discovery omitted a signed event')
                    report['exact_repository_discoveries'] = sorted(found)
                    report['revocation_import'] = import_release(db, source, fetch(ctx, expected, 'revocation'))
                    final = active_state(db)
                    require(final['revoked_at'] is not None and final['high_sequence'] == 3, 'Exact successor revocation was not applied')
                    first = db.scalar(select(ReplicaRelease).where(ReplicaRelease.source_release_id == '1'))
                    require(first.revoked_at is None and verify_record(first), 'Revocation changed the unrelated first release')
                    report['post_revocation_replay'] = import_release(db, source, baseline)
                    require(active_state(db) == final, 'Replay bypassed publisher revocation')
                    report['final_active'] = final
                else:
                    report['recovered_after_content_restored'] = True
        finally:
            db.close()
            engine.dispose()
        # New engine/connection proves this state survives process-storage reopening.
        engine, db, _ = ledger(ctx, expected, name, existing=True)
        try:
            reopened = active_state(db)
            require(reopened == (report.get('final_active') or report.get('active_after_replay') or report['active']),
                    'Persisted replica state changed on database reopening')
            report['durable_state_reopened'] = reopened
        finally:
            db.close()
            engine.dispose()
    report.update(status='passed', completed_at=datetime.now(timezone.utc).isoformat())
    filename = case + ('-' + args.failed_case if case == 'recover' else '') + '.json'
    write_json(ctx.root / 'reports' / filename, report)
    print(json.dumps({'status': 'passed', 'case': case, 'report': str(ctx.root / 'reports' / filename)}))


def check_quarantine_scope(expected, confirmed_target, repository):
    namespace = expected['namespace']
    segment = r'[a-z0-9]+(?:[._-][a-z0-9]+)*'
    require(expected['fixture'] == LABEL
            and re.fullmatch(r'qualification(?:/' + segment + r')*', namespace)
            and confirmed_target == expected['target'] and expected['target'] != expected['source'],
            'Storage injection is restricted to the explicitly confirmed qualification target')
    require(repository.startswith(namespace + '/'),
            'Only objects in the exact retained qualification subtree may be quarantined')


def owned_blob_links(volume, namespace, digest):
    """Check layer, revision and tag links before touching globally shared bytes."""
    repositories = volume / 'docker/registry/v2/repositories'
    require(repositories.is_dir()
            and not any(path.is_symlink() for path in (repositories, *repositories.parents)),
            'Unsafe registry repository storage')
    owned = []
    # Inspect every link, including tag-current links whose path has no digest.
    # Refuse symlink trees rather than skipping potentially shared references.
    for path in repositories.rglob('*'):
        require(not path.is_symlink(), 'Unsafe registry repository storage')
        if path.name != 'link':
            continue
        require(path.is_file() and path.stat().st_size <= 256, 'Invalid registry repository link')
        if path.read_bytes().strip() != digest.encode('ascii'):
            continue
        relative = path.relative_to(repositories).as_posix()
        require(relative.startswith(namespace + '/'),
                'Fixture blob is shared outside the exact qualification subtree')
        owned.append(relative)
    require(owned, 'Fixture blob has no owned repository references')
    return owned


def quarantine(ctx, args):
    """Reversible failure injection only in explicitly mounted fixture storage."""
    expected = json.loads((ctx.root / 'expected.json').read_text(encoding='utf-8'))
    require(args.case in OMISSIONS and args.registry_root is not None,
            'Specify an omission case and the disposable target registry volume mount')
    target = expected['omissions'][args.case]
    check_quarantine_scope(expected, args.confirm_target, target['repository'])
    # Reuse the production parser to validate the digest before constructing paths.
    ctx.oci._reference(host(expected['target']) + '/' + target['repository'] + '@' + target['digest'])
    checksum = target['digest'].removeprefix('sha256:')
    volume = args.registry_root.resolve()
    data = volume / 'docker' / 'registry' / 'v2' / 'blobs' / 'sha256' / checksum[:2] / checksum / 'data'
    held = data.with_name('data.cats-qualification-' + args.case)
    require(data.resolve().is_relative_to(volume) and held.resolve().is_relative_to(volume)
            and not any(path.is_symlink() for path in (data, held, *data.parents)),
            'Unsafe registry storage path')
    report_path = ctx.root / 'injections' / (args.case + '.json')
    if args.phase == 'quarantine':
        require(data.is_file() and not held.exists(), 'Fixture content must exist and not already be quarantined')
        links = owned_blob_links(volume, expected['namespace'], target['digest'])
        baseline = fetch(ctx, expected, 'first')
        fetch(ctx, expected, 'successor')
        forbidden = {baseline['digest'], expected['receipts']['first']['release']['signature']['digest']}
        forbidden.update(item['digest'] for item in expected['receipts']['first']['release_objects'])
        for artifact in baseline['artifacts']:
            forbidden.update([artifact['digest'], artifact['signature']['digest'], *artifact['manifests'], *artifact['blobs']])
        require(target['digest'] not in forbidden, 'The omitted digest must not belong to the active baseline')
        content = data.read_bytes()
        require('sha256:' + hashlib.sha256(content).hexdigest() == target['digest'], 'Stored fixture bytes fail their hash')
        report = {'fixture': LABEL, 'target': expected['target'], 'case': args.case,
            'object': target, 'bytes': len(content), 'mechanism': 'same-directory reversible fixture blob rename',
            'owned_repository_link_count': len(links),
            'prepared_at': datetime.now(timezone.utc).isoformat(), 'quarantined_at': None, 'restored_at': None}
        # Persist ownership first so an interrupted injection still has enough
        # information for the explicit restore command to recover its file.
        write_json(report_path, report)
        data.rename(held)
        report['quarantined_at'] = datetime.now(timezone.utc).isoformat()
        write_json(report_path, report)
    else:
        require(held.is_file() and not data.exists() and report_path.is_file(), 'No exclusively quarantined fixture to restore')
        require('sha256:' + hashlib.sha256(held.read_bytes()).hexdigest() == target['digest'], 'Quarantined fixture bytes changed')
        report = json.loads(report_path.read_text(encoding='utf-8'))
        require(report['object'] == target and report['target'] == expected['target'], 'Quarantine ownership record changed')
        held.rename(data)
        report['restored_at'] = datetime.now(timezone.utc).isoformat()
        write_json(report_path, report)
    print(json.dumps({'status': args.phase, 'case': args.case, 'digest': target['digest']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('phase', choices=('publish', 'verify', 'quarantine', 'restore'))
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--source', default='https://harbor-source.test:8443')
    parser.add_argument('--target', default='https://harbor-target.test:8443')
    parser.add_argument('--namespace', default='qualification')
    parser.add_argument('--service-key', default='synthetic-harbor-graph')
    parser.add_argument('--ca', type=Path, help='Trusted CA bundle; otherwise SSL_CERT_FILE')
    parser.add_argument('--docker-config', type=Path, help='Directory containing config.json; otherwise DOCKER_CONFIG')
    parser.add_argument('--case', choices=('complete', *OMISSIONS, 'wrong-signer', 'changed-sequence', 'recover'), default='complete')
    parser.add_argument('--failed-case', choices=OMISSIONS)
    parser.add_argument('--registry-storage', '--registry-root', dest='registry_root', type=Path,
                        help='Explicit disposable target volume mount; quarantine/restore only')
    parser.add_argument('--confirm-target', help='Exact target HTTPS origin; quarantine/restore only')
    args = parser.parse_args()
    ctx = context(args)
    {'publish': publish, 'verify': verify, 'quarantine': quarantine, 'restore': quarantine}[args.phase](ctx, args)


if __name__ == '__main__':
    main()
