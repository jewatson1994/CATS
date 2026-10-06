"""Versioned delivery bundles. Validation is entirely local and never resolves dependencies."""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

import yaml

MAX_FILES = 20000
MAX_BYTES = 20 * 1024**3
MAX_METADATA = 8 * 1024**2
CHUNK = 1024**2


def safe_path(value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("Unsafe bundle path")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value or any(p in ('.', '..') or p.endswith((' ', '.')) for p in path.parts)
            or '\\' in value or ':' in value or any(ord(c) < 32 for c in value)
            or any(p.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *('COM'+str(i) for i in range(1,10)), *('LPT'+str(i) for i in range(1,10))} for p in path.parts)):
        raise ValueError("Unsafe bundle path")
    return value


def file_digest(path):
    with Path(path).open('rb') as stream:
        return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate metadata key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON number")))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid bundle JSON') from exc


def _yaml(path):
    if path.stat().st_size > MAX_METADATA:
        raise ValueError('Chart metadata exceeds limit')
    value = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError('Invalid chart metadata')
    return value


def _untar(path, destination):
    """Stream regular files only; tar member names and expanded size are bounded."""
    seen, total = set(), 0
    with tarfile.open(path, 'r|*') as archive:
        for member in archive:
            name = safe_path(member.name.rstrip('/') if member.isdir() else member.name)
            if name.casefold() in seen or len(seen) >= MAX_FILES or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe tar member')
            seen.add(name.casefold())
            total += member.size
            if total > MAX_BYTES or member.size < 0:
                raise ValueError('Archive expanded size exceeds limit')
            target = destination / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, CHUNK)


def dependency_inventory(chart, *, strict=True, prefix=''):
    """Check recursively vendored exact versions, including packaged subcharts."""
    result = []
    def visit(root, location, depth):
        if depth > 30:
            raise ValueError('Helm dependency depth exceeds limit')
        metadata = _yaml(root / 'Chart.yaml')
        declarations = metadata.get('dependencies', []) or []
        if not isinstance(declarations, list):
            raise ValueError('Invalid Helm dependencies')
        lock = _yaml(root / 'Chart.lock') if (root / 'Chart.lock').is_file() else None
        locked = lock.get('dependencies', []) if lock else []
        if not isinstance(locked, list) or any(not isinstance(item, dict) for item in locked):
            raise ValueError('Invalid Helm lock dependencies')
        if lock and (not isinstance(locked, list) or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(lock.get('digest', '')))):
            raise ValueError('Invalid Helm lock provenance')
        candidates = []
        charts = root / 'charts'
        if charts.is_dir():
            for child in sorted(charts.iterdir()):
                if child.is_dir() and (child / 'Chart.yaml').is_file():
                    candidates.append((child, child.name, None))
                elif child.is_file() and child.name.endswith('.tgz'):
                    temporary = tempfile.TemporaryDirectory(prefix='cats-subchart-')
                    expanded = Path(temporary.name)
                    try:
                        _untar(child, expanded)
                        roots = [p.parent for p in expanded.glob('*/Chart.yaml')]
                        if len(roots) != 1:
                            raise ValueError('Ambiguous packaged Helm dependency')
                        candidates.append((roots[0], child.name, temporary))
                    except Exception:
                        temporary.cleanup()
                        raise
        try:
            used = set()
            for declaration in declarations:
                if not isinstance(declaration, dict) or not declaration.get('name') or not declaration.get('version'):
                    raise ValueError('Invalid Helm dependency declaration')
                name, constraint = declaration['name'], str(declaration['version'])
                matches_lock = [d for d in locked if d.get('name') == name and d.get('repository', '') == declaration.get('repository', '')]
                if lock and len(matches_lock) != 1:
                    raise ValueError('Helm lock does not match dependency declarations')
                version = str(matches_lock[0]['version']) if matches_lock else constraint
                if not re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', version):
                    raise ValueError('Dependency requires an exact locked version')
                if re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', constraint) and constraint != version:
                    raise ValueError('Dependency lock version mismatch')
                matching = [(i, item) for i, item in enumerate(candidates) if _yaml(item[0] / 'Chart.yaml').get('name') == name and str(_yaml(item[0] / 'Chart.yaml').get('version')) == version]
                if len(matching) != 1:
                    if not strict and not matching:
                        result.append({'name': name, 'version': version, 'repository': declaration.get('repository', ''), 'vendored': False, 'parent': location})
                        continue
                    raise ValueError('Missing or ambiguous vendored Helm dependency: ' + name)
                index, (child, filename, _) = matching[0]
                used.add(index)
                child_location = '/'.join(p for p in (location, 'charts', filename) if p)
                result.append({'name': name, 'version': version, 'repository': declaration.get('repository', ''), 'alias': declaration.get('alias'), 'file': child_location, 'parent': location, 'vendored': True,
                               'lockDigest': lock.get('digest') if lock else None})
                visit(child, child_location, depth + 1)
            if strict and len(used) != len(candidates):
                raise ValueError('Undeclared vendored Helm dependency')
            if lock and len(locked) != len(declarations):
                raise ValueError('Helm lock dependency mismatch')
        finally:
            for _, _, temporary in candidates:
                if temporary:
                    temporary.cleanup()
    visit(Path(chart), prefix, 0)
    return result


def workload_images(rendered):
    """Images in actual Kubernetes pod specs, including hooks and list documents."""
    images = set()
    active, visited = set(), [0]
    def collect(document):
        if not isinstance(document, dict):
            return
        visited[0] += 1
        if visited[0] > MAX_FILES or id(document) in active:
            raise ValueError('Recursive or oversized rendered workload inventory')
        kind = document.get('kind')
        if kind == 'List':
            active.add(id(document))
            for item in document.get('items', []):
                collect(item)
            active.remove(id(document))
            return
        spec = document.get('spec', {})
        if kind == 'CronJob':
            spec = spec.get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
        elif kind in {'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'ReplicationController', 'Job'}:
            spec = spec.get('template', {}).get('spec', {})
        elif kind != 'Pod':
            return
        for field in ('containers', 'initContainers', 'ephemeralContainers'):
            for container in spec.get(field, []) or []:
                reference = container.get('image')
                if not isinstance(reference, str) or not reference.strip() or any(c.isspace() for c in reference):
                    raise ValueError('Invalid rendered container image')
                images.add(reference)
    documents = yaml.safe_load_all(rendered) if isinstance(rendered, str) else rendered
    for document in documents:
        collect(document)
    return sorted(images)


def _layer_diff_digest(path):
    """DiffIDs hash uncompressed layer bytes, including for containerd Docker saves."""
    with Path(path).open('rb') as raw:
        compressed = raw.read(2) == b'\x1f\x8b'
        raw.seek(0)
        stream = gzip.GzipFile(fileobj=raw) if compressed else raw
        digest, size = hashlib.sha256(), 0
        try:
            for chunk in iter(lambda: stream.read(CHUNK), b''):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError('Image layer exceeds uncompressed size limit')
                digest.update(chunk)
        except (OSError, EOFError) as exc:
            raise ValueError('Invalid compressed image layer') from exc
        finally:
            if compressed:
                stream.close()
        return 'sha256:' + digest.hexdigest()


def _archive_contains_identity(root, expected, config_identity, layers):
    """Bind a containerd image ID to the already verified Docker-save contents."""
    index_path = root / 'index.json'
    if not index_path.is_file() or index_path.stat().st_size > MAX_METADATA:
        return False
    index = _json(index_path.read_bytes())
    def inspect(descriptor, depth=0):
        if not isinstance(descriptor, dict) or depth > 8:
            return False
        digest = descriptor.get('digest', '')
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            return False
        blob = root / 'blobs' / 'sha256' / digest[7:]
        if not blob.is_file():
            return False  # Other platforms can be omitted from Docker save.
        if blob.stat().st_size > MAX_METADATA or blob.stat().st_size != descriptor.get('size') or file_digest(blob) != digest:
            raise ValueError('Image archive manifest integrity mismatch')
        value = _json(blob.read_bytes())
        if not isinstance(value, dict):
            return False
        if 'manifests' in value:
            return any(inspect(child, depth + 1) for child in value['manifests'])
        config = value.get('config', {})
        if config.get('digest') != config_identity:
            return False
        config_blob = root / 'blobs' / 'sha256' / config_identity[7:]
        if not config_blob.is_file() or config_blob.stat().st_size != config.get('size'):
            return False
        descriptors = value.get('layers', [])
        if not isinstance(descriptors, list) or len(descriptors) != len(layers):
            return False
        for descriptor, layer in zip(descriptors, layers):
            path = root / layer
            if not isinstance(descriptor, dict) or descriptor.get('digest') != file_digest(path) or descriptor.get('size') != path.stat().st_size:
                raise ValueError('Image archive manifest layer integrity mismatch')
        return True
    return isinstance(index, dict) and any(
        isinstance(row, dict) and row.get('digest') == expected and inspect(row)
        for row in index.get('manifests', []))


def image_archive_identity(path, reference, expected_identity=None):
    """Docker-save config hashes are immutable content IDs, not registry manifest digests."""
    with tempfile.TemporaryDirectory(prefix='cats-image-') as temporary:
        root = Path(temporary)
        _untar(path, root)
        manifest_path = root / 'manifest.json'
        if not manifest_path.is_file() or manifest_path.stat().st_size > MAX_METADATA:
            raise ValueError('Unsupported image archive: Docker save manifest required')
        manifest = _json(manifest_path.read_bytes())
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError('Ambiguous image archive')
        item = manifest[0]
        if not isinstance(item, dict):
            raise ValueError('Invalid image archive manifest')
        config = root / safe_path(item.get('Config'))
        layers = item.get('Layers')
        if not isinstance(layers, list) or not all((root / safe_path(layer)).is_file() for layer in layers) or not config.is_file():
            raise ValueError('Incomplete image archive')
        if reference not in (item.get('RepoTags') or []):
            raise ValueError('Image archive does not contain rendered reference')
        identity = file_digest(config)
        if config.stat().st_size > MAX_METADATA:
            raise ValueError('Image configuration exceeds metadata limit')
        config_data = _json(config.read_bytes())
        if not isinstance(config_data, dict) or not isinstance(config_data.get('rootfs'), dict):
            raise ValueError('Invalid image configuration')
        diff_ids = config_data['rootfs'].get('diff_ids', [])
        if not isinstance(diff_ids, list):
            raise ValueError('Invalid image layer inventory')
        if len(diff_ids) != len(layers):
            raise ValueError('Image archive layer inventory mismatch')
        for layer, expected in zip(layers, diff_ids):
            if not hmac.compare_digest(_layer_diff_digest(root / layer), str(expected)):
                raise ValueError('Image archive layer integrity mismatch')
        if expected_identity is not None and expected_identity != identity:
            if not _archive_contains_identity(root, expected_identity, identity, layers):
                raise ValueError('Image archive identity mismatch')
            return expected_identity
        return identity


def _manifest(value):
    if not isinstance(value, dict) or value.get('schemaVersion') != '1.0' or value.get('validationType') not in {'helm-chart', 'standard-bundle', 'offline-bundle'}:
        raise ValueError('Unsupported delivery bundle schema')
    service, deployment = value.get('service'), value.get('deployment')
    if not isinstance(service, dict) or not all(isinstance(service.get(k), str) and service[k] for k in ('id', 'version')):
        raise ValueError('Bundle requires service version identity')
    if not isinstance(deployment, dict) or deployment.get('type') != 'helm':
        raise ValueError('Unsupported bundle deployment type')
    safe_path(deployment.get('chartPath'))
    values = deployment.get('valuesFiles')
    if not isinstance(values, list) or len(values) > 50 or any(not isinstance(p, str) for p in values) or len(set(values)) != len(values):
        raise ValueError('Invalid ordered Helm values files')
    for path in values:
        safe_path(path)
    files = value.get('files')
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise ValueError('Invalid bundle inventory')
    for name, metadata in files.items():
        safe_path(name)
        if name == 'manifest.json' or not isinstance(metadata, dict) or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(metadata.get('sha256', ''))) or type(metadata.get('bytes')) is not int or metadata['bytes'] < 0:
            raise ValueError('Invalid file integrity inventory')
    if deployment['chartPath'] + '/Chart.yaml' not in files or any(p not in files for p in values) or 'rendered.yaml' not in files:
        raise ValueError('Declared deployment files are missing')
    if not isinstance(value.get('images'), list) or not isinstance(value.get('helmDependencies'), list):
        raise ValueError('Invalid deployment inventory')
    return value


def validate_bundle(path, *, expected_type=None, expected_digest=None, destination=None):
    if expected_digest and not hmac.compare_digest(file_digest(path), expected_digest):
        raise ValueError('Bundle artifact integrity mismatch')
    with tempfile.TemporaryDirectory(prefix='cats-bundle-') as temporary:
        root = Path(temporary)
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES + 1 or sum(e.file_size for e in entries) > MAX_BYTES:
                raise ValueError('Bundle resource limit exceeded')
            names = set()
            for entry in entries:
                safe_path(entry.orig_filename)
                name = safe_path(entry.filename)
                mode = entry.external_attr >> 16
                if name.casefold() in names or entry.is_dir() or (stat.S_IFMT(mode) and not stat.S_ISREG(mode)) or entry.flag_bits & 1:
                    raise ValueError('Unsafe bundle member')
                names.add(name.casefold())
            if 'manifest.json' not in names or archive.getinfo('manifest.json').file_size > MAX_METADATA:
                raise ValueError('Bundle manifest is missing or oversized')
            manifest = _manifest(_json(archive.read('manifest.json')))
            if expected_type and manifest['validationType'] != expected_type:
                raise ValueError('Bundle validation type mismatch')
            if set(manifest['files']) | {'manifest.json'} != {e.filename for e in entries}:
                raise ValueError('Bundle inventory mismatch')
            for entry in entries:
                target = root / entry.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                count, digest = 0, hashlib.sha256()
                with archive.open(entry) as source, target.open('xb') as output:
                    while chunk := source.read(CHUNK):
                        count += len(chunk)
                        if count > entry.file_size:
                            raise ValueError('Bundle expanded size mismatch')
                        digest.update(chunk)
                        output.write(chunk)
                if entry.filename != 'manifest.json':
                    expected = manifest['files'][entry.filename]
                    if count != expected['bytes'] or not hmac.compare_digest('sha256:' + digest.hexdigest(), expected['sha256']):
                        raise ValueError('Bundle file integrity mismatch')
        offline = manifest['validationType'] == 'offline-bundle'
        dependencies = dependency_inventory(root / manifest['deployment']['chartPath'], strict=offline, prefix=manifest['deployment']['chartPath'])
        if dependencies != manifest['helmDependencies']:
            raise ValueError('Helm dependency provenance mismatch')
        if (root / 'rendered.yaml').stat().st_size > MAX_METADATA:
            raise ValueError('Rendered inventory exceeds metadata limit')
        required = workload_images((root / 'rendered.yaml').read_text(encoding='utf-8'))
        references = []
        for image in manifest['images']:
            if not isinstance(image, dict) or not isinstance(image.get('reference'), str) or not image['reference'] or image.get('reference') in references:
                raise ValueError('Invalid image inventory')
            references.append(image.get('reference'))
            archive_name = safe_path(image.get('file'))
            if archive_name not in manifest['files'] or image.get('identityType') != 'docker_config' or image_archive_identity(root / archive_name, image['reference']) != image.get('digest'):
                raise ValueError('Image archive identity mismatch')
        if not set(references).issubset(required) or (offline and set(references) != set(required)):
            raise ValueError('Required rendered images are not completely reconciled')
        if manifest.get('requiredImages') != required:
            raise ValueError('Rendered image inventory mismatch')
        if destination is not None:
            destination = Path(destination)
            if any(p.is_symlink() for p in [destination, *destination.parents]):
                raise ValueError('Unsafe extraction destination')
            if destination.exists() and any(destination.iterdir()):
                raise ValueError('Extraction destination must be empty')
            destination.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink():
                raise ValueError('Unsafe extraction destination')
            shutil.copytree(root, destination, dirs_exist_ok=True)
        return manifest


def build_bundle(output_path, *, bundle_type, service, source_files, chart_path, values_files=None,
                 rendered_manifests, image_archives=None, evidence=None, namespace='cats-validation', provenance=None):
    """Build final bytes once; callers retain this path and validate its digest before release."""
    if bundle_type not in {'helm-chart', 'standard-bundle', 'offline-bundle'}:
        raise ValueError('Unsupported bundle type')
    if Path(output_path).exists():
        raise ValueError('Bundle output already exists')
    with tempfile.TemporaryDirectory(prefix='cats-build-bundle-') as temporary:
        root = Path(temporary)
        for name, content in source_files.items():
            if name in {'manifest.json', 'rendered.yaml', 'evidence.json'}:
                raise ValueError('Reserved bundle file')
            target = root / safe_path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode() if isinstance(content, str) else content)
        (root / 'rendered.yaml').write_text(rendered_manifests, encoding='utf-8')
        images = []
        for image in image_archives or []:
            name = safe_path(image['archive_path'])
            if name in source_files or name in {'manifest.json', 'rendered.yaml', 'evidence.json'} or any(i['file'] == name for i in images):
                raise ValueError('Duplicate bundle file')
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(image['source_path'], target)
            identity = image_archive_identity(target, image['reference'])
            if image.get('digest') and image['digest'] != identity:
                raise ValueError('Supplied image identity mismatch')
            images.append({'reference': image['reference'], 'digest': identity, 'identityType': 'docker_config', 'file': name})
        if evidence is not None:
            (root / 'evidence.json').write_text(json.dumps(evidence, sort_keys=True), encoding='utf-8')
        files = {p.relative_to(root).as_posix(): {'bytes': p.stat().st_size, 'sha256': file_digest(p)} for p in sorted(root.rglob('*')) if p.is_file()}
        manifest = {'schemaVersion': '1.0', 'validationType': bundle_type, 'bundleType': {'offline-bundle': 'offline', 'standard-bundle': 'standard'}.get(bundle_type),
                    'service': service, 'deployment': {'type': 'helm', 'chartPath': chart_path, 'valuesFiles': values_files or [], 'namespace': namespace},
                    'files': files, 'images': images, 'requiredImages': workload_images(rendered_manifests),
                    'helmDependencies': dependency_inventory(root / chart_path, strict=bundle_type == 'offline-bundle', prefix=chart_path),
                    'evidence': {'path': 'evidence.json'} if evidence is not None else None, 'provenance': provenance or {}}
        _manifest(manifest)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with ZipFile(output_path, 'x', ZIP_DEFLATED, allowZip64=True) as archive:
                entries = {'manifest.json': json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()}
                for name in sorted([*files, 'manifest.json']):
                    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = ZIP_DEFLATED
                    info.external_attr = 0o100600 << 16
                    with archive.open(info, 'w', force_zip64=True) as target:
                        if name in entries:
                            target.write(entries[name])
                        else:
                            with (root / name).open('rb') as source:
                                shutil.copyfileobj(source, target, CHUNK)
            validate_bundle(output_path, expected_type=bundle_type)
        except Exception:
            if output_path.exists():
                output_path.unlink()
            raise
        return manifest


def build_helm_archive(output_path, source_files, values_files=None, *, chart_path=None, service=None):
    """Transport the exact prepared Helm chart and ordered values; this is not a delivery bundle."""
    if chart_path is None:
        roots = [str(PurePosixPath(name).parent) for name in source_files if name.endswith('/Chart.yaml') and 'charts' not in PurePosixPath(name).parts[:-1]]
        if 'Chart.yaml' in source_files:
            # Put root charts in a declared directory, preserving all external values paths.
            source_files = {'chart/' + name: value for name, value in source_files.items()}
            values_files = ['chart/' + name for name in values_files or []]
            roots = ['chart']
        if len(roots) != 1:
            raise ValueError('Prepared Helm deployment chart must be explicit')
        chart_path = roots[0]
    return build_bundle(output_path, bundle_type='helm-chart', service=service or {'id': 'prepared-chart', 'version': 'unspecified'},
                        source_files=source_files, chart_path=chart_path, values_files=values_files, rendered_manifests='')


def prepare_helm_archive(path, destination, expected_digest=None):
    manifest = validate_bundle(path, expected_type='helm-chart', expected_digest=expected_digest, destination=destination)
    return {'root_directory': str(Path(destination)), 'chart_directory': str(Path(destination) / manifest['deployment']['chartPath']),
            'values_files': [str(Path(destination) / name) for name in manifest['deployment']['valuesFiles']], 'manifest': manifest}
