"""Opt-in real OCI corpus publisher for the 100-image / 23-replacement test.

Only the explicitly supplied SOURCE Harbor is written. Harbor's replication
jobservice, source outage, target omission and real replica HTTP checks are
controlled separately. The base is an immutable runnable Linux/amd64 image;
each variant adds a distinct real filesystem layer and executable configuration.
Assessment records are SYNTHESIZED test evidence, never actual scan results or
a production Cyber approval. Production capture, signing and verification are
used without substituting their results.

Run publish-first, replicate and verify baseline with harbor_inventory_http.py,
then publish-successor. Never publish successor before baseline is retained.
The runtime-images.tar output can be docker-loaded once, then each tag in
runtime-images.json executed with --network none to verify its marker output.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
from zipfile import ZipFile

from harbor_graph_qualification import context, credentials, host, require, tar_bytes


LABEL = 'SYNTHESIZED assessment evidence for real runnable OCI inventory qualification; not scanned or production-approved'
FIRST = tuple(range(100))
SUCCESSOR = tuple(range(23, 123))
IMAGE_TYPE = 'application/vnd.oci.image.manifest.v1+json'
CONFIG_TYPE = 'application/vnd.oci.image.config.v1+json'
LAYER_TYPE = 'application/vnd.oci.image.layer.v1.tar'


def write_json(path, value, *, private=False):
    """Replace a complete checkpoint atomically; never truncate its predecessor."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                prefix='.' + path.name + '-', delete=False) as stream:
            pending = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        pending.chmod(0o600 if private else 0o644)
        os.replace(pending, path)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


def bind_workspace(root, args):
    plan = {key: getattr(args, key) for key in ('source', 'target', 'namespace', 'service_key', 'base_image')}
    path = root / 'publication-plan.json'
    if path.exists():
        require(json.loads(path.read_text(encoding='utf-8')) == plan,
                'Workspace belongs to a different publication plan; use its original parameters')
    else:
        expected = root / 'expected.json'
        if expected.exists():
            previous = json.loads(expected.read_text(encoding='utf-8'))
            require(all(previous.get(key) == value for key, value in plan.items()),
                    'Existing publication belongs to a different workspace plan')
        else:
            require(not any((root / name).exists() for name in ('base.json', 'images.json', 'publisher-evidence.sqlite')),
                    'Unbound partial publication exists; use a fresh workspace')
        write_json(path, plan)
    return plan


def digest(content):
    return 'sha256:' + hashlib.sha256(content).hexdigest()


def marker(index):
    require(type(index) is int and 0 <= index < 123, 'Corpus index must be between 0 and 122')
    return f'cats-harbor-inventory-{index:03d}\n'.encode()


def variant(base, index):
    """Return deterministic real layer/config bytes without changing the base."""
    require(base.get('os') == 'linux' and base.get('architecture') == 'amd64',
            'The runtime corpus requires an immutable Linux/amd64 base')
    require(base.get('rootfs', {}).get('type') == 'layers'
            and isinstance(base['rootfs'].get('diff_ids'), list)
            and base['rootfs']['diff_ids'], 'Base image has no runnable filesystem layers')
    layer = tar_bytes({'qualification-id': marker(index)})
    config = deepcopy(base)
    config['rootfs']['diff_ids'].append(digest(layer))
    config.setdefault('history', []).append({'created': '2026-11-05T00:00:00Z',
        'created_by': 'CATS staging qualification marker layer', 'comment': LABEL})
    config.setdefault('config', {}).update(Entrypoint=['/bin/sh', '-c', 'cat /qualification-id'],
        Cmd=[], WorkingDir='/', User='0')
    config['config'].setdefault('Labels', {}).update({'io.cats.qualification': LABEL,
        'io.cats.qualification.index': str(index)})
    return config, layer


def retain(root, descriptor, content):
    require(digest(content) == descriptor['digest'] and len(content) == descriptor['size'],
            'OCI descriptor does not match its content')
    path = root / 'blobs' / 'sha256' / descriptor['digest'][7:]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == content, 'Retained corpus object has changed')
    else:
        path.write_bytes(content)
    return path


def prepare_base(ctx, args):
    path = ctx.root / 'base.json'
    layout = ctx.root / 'corpus-oci'
    if path.exists():
        value = json.loads(path.read_text(encoding='utf-8'))
        require(value['reference'] == args.base_image, 'Workspace already belongs to a different immutable base')
        return value
    registry, repository, identity = ctx.oci._reference(args.base_image)
    require(registry == host(args.source), 'The base must already be retained in the explicit source Harbor')
    source = ctx.oci._Client(registry, repository, ctx.env, pull_only=True)
    document, descriptor = source.manifest(identity)
    if 'manifests' in document:
        choices = [item for item in document['manifests']
                   if item.get('platform', {}).get('os') == 'linux'
                   and item.get('platform', {}).get('architecture') == 'amd64']
        require(len(choices) == 1, 'Base index must contain exactly one Linux/amd64 image')
        document, descriptor = source.manifest(choices[0]['digest'])
    require(document.get('layers') and document.get('config'), 'Base must be a nonempty image manifest')
    # An interrupted initial download cannot make the next attempt collide
    # with _Transport's deliberately fresh layout requirement.
    with tempfile.TemporaryDirectory(prefix='.base-download-', dir=ctx.root) as temporary:
        transport = ctx.publication._Transport(Path(temporary) / 'oci', ctx.env)
        transport.graph(source, descriptor['digest'])
        for blob_path in transport.blobs.iterdir():
            content = blob_path.read_bytes()
            retain(layout, {'digest': 'sha256:' + blob_path.name, 'size': len(content)}, content)
    config = json.loads((layout / 'blobs' / 'sha256' / document['config']['digest'][7:]).read_bytes())
    variant(config, 0)  # Validate the platform and filesystem before source writes.
    require(len(config['rootfs']['diff_ids']) == len(document['layers']), 'Base layer/diff-id count differs')
    value = {'reference': args.base_image, 'descriptor': descriptor, 'document': document, 'config': config}
    write_json(path, value)
    return value


def corpus(ctx, args, indices):
    base = prepare_base(ctx, args)
    layout = ctx.root / 'corpus-oci'
    path = ctx.root / 'images.json'
    images = json.loads(path.read_text(encoding='utf-8')) if path.exists() else []
    by_index = {item['index']: item for item in images}
    repository = args.namespace + '/inputs/corpus'
    client = ctx.oci._Client(host(args.source), repository, ctx.env)
    # One shared repository links the genuine base blobs once. Every root and
    # marker layer remains distinct; no fabricated digest stands in for bytes.
    for item in base['document']['layers']:
        content = (layout / 'blobs' / 'sha256' / item['digest'][7:]).read_bytes()
        actual = client.upload(content, item['mediaType'])
        require(all(actual[key] == item[key] for key in ('digest', 'size', 'mediaType')),
                'Base layer changed during source upload')
    for index in indices:
        if index in by_index:
            continue
        config, layer_bytes = variant(base['config'], index)
        layer = client.upload(layer_bytes, LAYER_TYPE)
        configuration = client.upload(ctx.portable.canonical(config), CONFIG_TYPE)
        retain(layout, layer, layer_bytes)
        retain(layout, configuration, ctx.portable.canonical(config))
        content = ctx.portable.canonical({'schemaVersion': 2, 'mediaType': IMAGE_TYPE,
            'config': configuration, 'layers': [*base['document']['layers'], layer]})
        descriptor = {'mediaType': IMAGE_TYPE, 'digest': digest(content), 'size': len(content)}
        retain(layout, descriptor, content)
        require(client.request('PUT', client.api + '/manifests/' + descriptor['digest'],
            body=content, media_type=IMAGE_TYPE)[0] == 201, 'Source rejected corpus image')
        name = f'image-{index:03d}'
        require(client.request('PUT', client.api + '/manifests/' + name,
            body=content, media_type=IMAGE_TYPE)[0] == 201, 'Source rejected corpus discovery tag')
        by_index[index] = {'index': index, 'name': name, 'kind': 'image',
            'reference': host(args.source) + '/' + repository + '@' + descriptor['digest'],
            'digest': descriptor['digest'], 'descriptor': descriptor,
            'config': configuration, 'marker_layer': layer,
            'expected_stdout': marker(index).decode()}
        write_json(path, sorted(by_index.values(), key=lambda item: item['index']))
        print(f'Prepared runnable corpus image {index + 1}/123', flush=True)
    images = sorted(by_index.values(), key=lambda item: item['index'])
    require(len({item['digest'] for item in images}) == len(images), 'Corpus roots must be distinct')
    write_json(layout / 'oci-layout', {'imageLayoutVersion': '1.0.0'})
    write_json(layout / 'index.json', {'schemaVersion': 2, 'manifests': [
        {**item['descriptor'], 'annotations': {'org.opencontainers.image.ref.name': item['name']}}
        for item in images]})
    return images


def capture(ctx, args, images, sequence, folder):
    """Persist one source service and history, then use the production capture."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session
    from app import main, models as m, portable_release_capture
    from app.database import Base
    engine = create_engine('sqlite:///' + (ctx.root / 'publisher-evidence.sqlite').as_posix())
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = db.scalar(select(m.Service).where(m.Service.service_key == args.service_key))
        if service is None:
            require(sequence == 1, 'The first service snapshot must be captured first')
            service = m.Service(service_key=args.service_key, name='Real OCI 100-image staging inventory',
                description=LABEL, assessment_status='assessed')
            db.add(service)
            db.add(m.User(username='synthesized-qualification-author', display_name=LABEL, password_hash='!'))
            db.flush()
        author = db.scalar(select(m.User).where(m.User.username == 'synthesized-qualification-author'))
        version = db.scalar(select(m.ServiceVersion).where(m.ServiceVersion.service_id == service.id,
            m.ServiceVersion.version == f'qualification-{sequence}'))
        selected = FIRST if sequence == 1 else SUCCESSOR
        inventory = [item['digest'] for item in images if item['index'] in selected]
        checkpoint = folder / 'capture.json'
        evidence = folder / 'evidence.zip'
        if version is not None:
            require(checkpoint.is_file() and evidence.is_file(), 'Committed capture checkpoint is missing')
            saved = json.loads(checkpoint.read_text(encoding='utf-8'))
            execution = db.scalar(select(m.Execution).where(m.Execution.service_version_id == version.id))
            require(execution is not None and saved == {'sequence': sequence, 'service_key': args.service_key,
                'service_id': service.id, 'execution_id': execution.id, 'author_id': author.id,
                'inventory': inventory, 'evidence_digest': digest(evidence.read_bytes())},
                'Committed capture checkpoint differs from its retained evidence or source identity')
            result = evidence, service.id, execution.id, author.id
            engine.dispose()
            return result
        version = m.ServiceVersion(service_id=service.id, version=f'qualification-{sequence}')
        db.add(version)
        db.flush()
        now = datetime.now(timezone.utc)
        existing = {item.image_digest: item for item in db.scalars(select(m.ServiceImage).where(
            m.ServiceImage.service_id == service.id))}
        by_index = {item['index']: item for item in images}
        for index in selected:
            item = by_index[index]
            if item['digest'] not in existing:
                old = existing[by_index[index - 100]['digest']] if index >= 100 else None
                if old:
                    old.lifecycle_status = 'replaced'
                    old.lifecycle_reason = LABEL
                db.add(m.ServiceImage(service_id=service.id, image_reference=item['reference'],
                    image_digest=item['digest'], replacement_of_id=old.id if old else None,
                    requested_by_id=author.id, approved_by_id=author.id, scan_status='completed',
                    last_scanned_at=now, lifecycle_reason=LABEL))
        key = f'{args.service_key}-synthesized-{sequence}'
        payload = {'execution_id': key, 'scanned_at': now.isoformat(), 'complete': True,
            'fixable_only': False, 'qualification_evidence': LABEL,
            'service': {'id': args.service_key, 'name': service.name, 'version': version.version},
            'images': [{'reference': by_index[index]['reference'], 'digest': by_index[index]['digest'],
                        'qualification_evidence': LABEL} for index in selected]}
        execution = m.Execution(execution_key=key, service_id=service.id, service_version_id=version.id,
            scanned_at=now, complete=True, raw_payload=payload)
        db.add(execution)
        db.add(m.AuditEvent(actor_user_id=author.id, action='qualification.synthesized_snapshot',
            target_type='service', target_id=str(service.id), detail={'label': LABEL, 'sequence': sequence}))
        db.flush()
        service.current_version_id = version.id
        # Read the persisted SQLite representations for both snapshots; its
        # DateTime columns discard timezone offsets on reload.
        db.flush()
        db.expire_all()
        state = portable_release_capture.capture(db, service, {'source_execution_id': execution.id,
            'qualification_evidence': LABEL})
        with ZipFile(evidence, 'w') as archive:
            archive.writestr('replica-service.json', ctx.portable.canonical(state))
            archive.writestr('QUALIFICATION-EVIDENCE.txt', LABEL)
            archive.writestr('synthesized-assessment.json', ctx.portable.canonical(payload))
        write_json(checkpoint, {'sequence': sequence, 'service_key': args.service_key,
            'service_id': service.id, 'execution_id': execution.id, 'author_id': author.id,
            'inventory': inventory, 'evidence_digest': digest(evidence.read_bytes())})
        db.commit()
        result = evidence, service.id, execution.id, author.id
    engine.dispose()
    return result


def runtime_archive(ctx, images):
    """Preserve native OCI bytes, with legacy Docker entries for older engines."""
    base = json.loads((ctx.root / 'base.json').read_text(encoding='utf-8'))
    layout = ctx.root / 'corpus-oci' / 'blobs' / 'sha256'
    path = ctx.root / 'runtime-images.tar'
    entries, runtime = [], []
    def add(archive, name, content):
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(content), 0o644, 0
        archive.addfile(info, io.BytesIO(content))
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
        # Containerd-backed Docker reports a manifest ID, while the classic
        # store reports a config ID. Native OCI entries preserve the signed
        # root instead of synthesizing a different Docker manifest wrapper.
        native = []
        retained = set()
        for image in images:
            manifest_bytes = (layout / image['digest'][7:]).read_bytes()
            require(digest(manifest_bytes) == image['digest'], 'Runtime OCI root has changed')
            manifest = json.loads(manifest_bytes)
            require(manifest['config']['digest'] == image['config']['digest'],
                    'Runtime OCI root refers to a different configuration')
            descriptor = {'mediaType': manifest['mediaType'], 'digest': image['digest'],
                'size': len(manifest_bytes)}
            tag = 'docker.io/library/cats-inventory-qualification:' + image['name']
            native.append({**descriptor, 'annotations': {'io.containerd.image.name': tag,
                'org.opencontainers.image.ref.name': tag}})
            for blob in [descriptor, manifest['config'], *manifest['layers']]:
                if blob['digest'] in retained:
                    continue
                content = (layout / blob['digest'][7:]).read_bytes()
                require(digest(content) == blob['digest'] and len(content) == blob['size'],
                        'Runtime OCI object differs from its signed descriptor')
                add(archive, 'blobs/sha256/' + blob['digest'][7:], content)
                retained.add(blob['digest'])
        add(archive, 'oci-layout', encoded({'imageLayoutVersion': '1.0.0'}))
        add(archive, 'index.json', encoded({'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': native}))
        layers = []
        for descriptor, diff_id in zip(base['document']['layers'], base['config']['rootfs']['diff_ids']):
            content = (layout / descriptor['digest'][7:]).read_bytes()
            if descriptor['mediaType'].endswith(('+gzip', '.gzip')):
                content = gzip.decompress(content)
            require(digest(content) == diff_id, 'Runtime base layer differs from its uncompressed diff ID')
            name = diff_id[7:] + '/layer.tar'
            add(archive, name, content)
            layers.append(name)
        for image in images:
            config_name = image['config']['digest'][7:] + '.json'
            layer_name = image['marker_layer']['digest'][7:] + '/layer.tar'
            add(archive, config_name, (layout / image['config']['digest'][7:]).read_bytes())
            add(archive, layer_name, (layout / image['marker_layer']['digest'][7:]).read_bytes())
            tag = 'cats-inventory-qualification:' + image['name']
            entries.append({'Config': config_name, 'RepoTags': [tag], 'Layers': [*layers, layer_name]})
            runtime.append({'index': image['index'], 'tag': tag, 'oci_digest': image['digest'],
                'config_digest': image['config']['digest'], 'expected_stdout': image['expected_stdout']})
        add(archive, 'manifest.json', encoded(entries))
    write_json(ctx.root / 'runtime-images.json', {'images': runtime, 'archive': str(path),
        'archive_digest': digest(path.read_bytes()), 'network': 'none', 'label': LABEL})


def runtime_identity(inspected, item):
    """Match exact content identity across classic and containerd Docker stores."""
    require(inspected in (item['oci_digest'], item['config_digest']),
        f"Loaded Docker identity {inspected} differs from published OCI root "
        f"{item['oci_digest']} and configuration {item['config_digest']}")
    return 'oci-manifest' if inspected == item['oci_digest'] else 'image-config'


def execute_runtime_image(item):
    inspected = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', item['tag']],
        check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    identity_kind = runtime_identity(inspected, item)
    # The tag may change after inspection. Run only the content ID whose
    # binding to the signed publication has already been checked.
    result = subprocess.run(['docker', 'run', '--pull', 'never', '--rm', '--network', 'none',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--memory', '64m', '--pids-limit', '32', inspected], capture_output=True, timeout=120)
    return {'index': item['index'], 'tag': item['tag'], 'oci_digest': item['oci_digest'],
        'config_digest': item['config_digest'], 'docker_image_id': inspected,
        'execution_image': inspected, 'docker_identity_kind': identity_kind,
        'exit_code': result.returncode, 'stdout': result.stdout.decode('utf-8', errors='replace'),
        'stderr': result.stderr.decode('utf-8', errors='replace')[:4000],
        'marker_matches': result.stdout == item['expected_stdout'].encode(),
        'passed': result.returncode == 0 and result.stdout == item['expected_stdout'].encode()}


def publish(ctx, args, sequence):
    from app import release_validity
    from app.secrets import encrypt_secret
    source, target = host(args.source), host(args.target)
    require(source != target, 'Source and target must be distinct HTTPS origins')
    bind_workspace(ctx.root, args)
    expected_path = ctx.root / 'expected.json'
    expected = json.loads(expected_path.read_text(encoding='utf-8')) if expected_path.exists() else None
    if expected:
        for key in ('source', 'target', 'namespace', 'service_key', 'base_image'):
            require(expected[key] == getattr(args, key), f'Workspace {key} does not match this invocation')
    require(sequence == 1 or expected and 'first' in expected['receipts'], 'Publish the first release before its successor')
    label = 'first' if sequence == 1 else 'successor'
    if expected and label in expected['receipts']:
        print(json.dumps({'status': 'already-published', 'release': label, 'expected': str(expected_path)}))
        return
    key = ctx.root / 'signer'
    if not key.with_suffix('.key').exists():
        subprocess.run(['cosign', 'generate-key-pair', '--output-key-prefix', str(key)],
            env=dict(ctx.env, COSIGN_PASSWORD=ctx.private['signing_password']), check=True,
            capture_output=True, timeout=120)
        key.with_suffix('.key').chmod(0o600)
    settings = ctx.signing.store_keys(key.with_suffix('.key').read_bytes(), key.with_suffix('.pub').read_bytes(),
        ctx.private['signing_password'], True)
    expected = expected or {'label': LABEL, 'source': args.source, 'target': args.target,
        'namespace': args.namespace, 'service_key': args.service_key, 'base_image': args.base_image,
        'trusted_fingerprint': settings['fingerprint'], 'first_indices': list(FIRST),
        'successor_indices': list(SUCCESSOR), 'receipts': {}}
    require(expected['trusted_fingerprint'] == settings['fingerprint'], 'Publisher signer changed')
    images = corpus(ctx, args, range(100 if sequence == 1 else 123))
    expected['images'] = images
    folder = ctx.root / label
    folder.mkdir(exist_ok=True)
    freeze = folder / 'frozen-approval.json'
    public_destination = {'id': 'harbor-inventory-qualification', 'name': LABEL,
        'endpoint': args.source, 'namespace': args.namespace}
    if freeze.exists():
        frozen = json.loads(freeze.read_text(encoding='utf-8'))
    else:
        evidence, service_id, execution_id, author_id = capture(ctx, args, images, sequence, folder)
        now = datetime.now(timezone.utc)
        validity = release_validity.new_validity(now)
        metadata = {'format': ctx.portable.FORMAT, 'kind': 'release', 'service_uuid': args.service_key,
            'release_uuid': str(sequence), 'release_sequence': sequence,
            'supersedes_release_uuid': '1' if sequence == 2 else None, 'revoked_at': None, **validity}
        selected = FIRST if sequence == 1 else SUCCESSOR
        snapshot = {'service_id': service_id, 'service_key': args.service_key,
            'source_execution_id': execution_id, 'qualification_evidence': LABEL,
            'evidence': {'path': str(evidence), 'digest': ctx.publication.file_digest(evidence)},
            'artifacts': [{key: item[key] for key in ('kind', 'name', 'reference', 'digest')}
                          for item in images if item['index'] in selected],
            'destination': public_destination, 'signing_fingerprint': settings['fingerprint'],
            'approval_validity': validity, 'portable_release': metadata}
        frozen = {'id': sequence, 'release_key': f'harbor-inventory-{sequence}', 'snapshot': snapshot,
            'snapshot_digest': digest(ctx.portable.canonical(snapshot)), 'status': 'approved',
            'decided_by_id': author_id, 'decided_at': now.isoformat(), 'decision_rationale': LABEL,
            'revoked_at': None}
        write_json(freeze, frozen)
    username, password = credentials(ctx.env, source)
    destination = {**public_destination, 'username': username, 'password': encrypt_secret(password),
        'ca_pem': Path(ctx.env['SSL_CERT_FILE']).read_text(encoding='utf-8')}
    db = SimpleNamespace(scalars=lambda query: [SimpleNamespace(key='image_signing', value=json.dumps(settings))])
    approval = SimpleNamespace(**{**frozen, 'decided_at': datetime.fromisoformat(frozen['decided_at'])})
    receipt = ctx.publication.publish(db, approval, destination,
        lambda value: write_json(folder / 'publication.json', value))
    verified = ctx.portable.fetch_release(receipt['release']['reference'], ctx.env, [settings['fingerprint']])
    require(verified['complete'] and verified['verified'] and len(verified['artifacts']) == 100,
        'Production source verification did not retain exactly 100 real image graphs')
    _, repository, identity = ctx.oci._reference(receipt['release']['reference'])
    receipt['target_reference'] = target + '/' + repository + '@' + identity
    expected['release_repository'] = repository
    expected['receipts'][label] = receipt
    if sequence == 2:
        image = next(item for item in images if item['index'] == 100)
        artifact = next(item for item in receipt['artifacts'] if item['digest'] == image['digest'])
        expected['omission'] = {'kind': 'blob', 'repository': ctx.oci._reference(artifact['reference'])[1],
            **image['marker_layer'], 'parent_digest': image['digest'], 'index': 100}
        runtime_archive(ctx, images)
    write_json(expected_path, expected)
    print(json.dumps({'status': 'published', 'release': label, 'image_count': 100,
        'label': LABEL, 'expected': str(expected_path)}), flush=True)


def verify_runtime(workspace):
    """Host-only bounded execution; no Harbor, signing or application imports."""
    root = workspace.resolve()
    expected = json.loads((root / 'runtime-images.json').read_text(encoding='utf-8'))
    archive = root / 'runtime-images.tar'
    checksum = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    identity = 'sha256:' + checksum.hexdigest()
    require(identity == expected['archive_digest'], 'Runtime archive has changed')
    images = expected['images']
    require(len(images) == 123 and {item['index'] for item in images} == set(range(123)),
            'Runtime proof requires the complete 123-image corpus')
    published = json.loads((root / 'expected.json').read_text(encoding='utf-8'))
    source_images = {item['index']: item for item in published['images']}
    require(len(published['images']) == len(source_images) == 123
            and set(source_images) == set(range(123)), 'Published corpus is incomplete')
    published_roots = {artifact['digest'] for label in ('first', 'successor')
                       for artifact in published['receipts'][label]['artifacts']}
    require(published_roots == {item['digest'] for item in source_images.values()},
            'Published receipts differ from the complete runtime corpus')
    for item in images:
        require(item['tag'] == f"cats-inventory-qualification:image-{item['index']:03d}"
                and item['expected_stdout'] == marker(item['index']).decode(),
                'Unexpected runtime image tag or marker')
        original = source_images[item['index']]
        require(item['oci_digest'] == original['digest']
                and item['config_digest'] == original['config']['digest'],
                'Runtime sidecar differs from the published image identity')
        manifest_bytes = (root / 'corpus-oci' / 'blobs' / 'sha256' / original['digest'][7:]).read_bytes()
        require(digest(manifest_bytes) == original['digest']
                and json.loads(manifest_bytes)['config']['digest'] == item['config_digest'],
                'Runtime configuration is not bound to the published OCI manifest')
    subprocess.run(['docker', 'load', '--input', str(archive)], check=True, capture_output=True, timeout=600)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(execute_runtime_image, images))
    report = {'archive_digest': identity, 'image_count': len(results),
        'passed': all(item['passed'] for item in results), 'network': 'none',
        'image_reference_policy': 'validated-immutable-id',
        'read_only': True, 'capabilities': [], 'no_new_privileges': True, 'images': results}
    write_json(root / 'runtime-verification.json', report)
    require(report['passed'], 'At least one actual image runtime failed; inspect runtime-verification.json')
    print(json.dumps({'runtime_images_passed': len(results), 'archive_digest': identity}), flush=True)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('phase', choices=('publish-first', 'publish-successor', 'export-runtime', 'verify-runtime'))
    result.add_argument('--workspace', required=True, type=Path)
    result.add_argument('--source', default='https://harbor-source.test:8443')
    result.add_argument('--target', default='https://harbor-target.test:8443')
    result.add_argument('--namespace', default='qualification/staging-inventory-20261105')
    result.add_argument('--service-key', default='harbor-inventory-qualification')
    result.add_argument('--base-image')
    result.add_argument('--ca', type=Path)
    result.add_argument('--docker-config', type=Path)
    return result


def main():
    args = parser().parse_args()
    if args.phase == 'verify-runtime':
        verify_runtime(args.workspace)
        return
    if args.phase == 'export-runtime':
        runtime_archive(SimpleNamespace(root=args.workspace),
            json.loads((args.workspace / 'images.json').read_text(encoding='utf-8')))
        return
    require(args.phase == 'export-runtime' or args.base_image, 'Publication requires an immutable --base-image')
    # Validate repository components before network writes.
    from nginx_replica_acceptance import _repository
    _repository(args.namespace)
    _repository(args.service_key)
    ctx = context(args)
    publish(ctx, args, 1 if args.phase == 'publish-first' else 2)


if __name__ == '__main__':
    main()
