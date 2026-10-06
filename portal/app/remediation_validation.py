"""Static gating and exact retained-candidate declarations for remediation only."""
from __future__ import annotations

import hashlib
from pathlib import Path
from . import deployment_bundle as bundles


def classify_static(validation):
    """Uncertainty is not a defect; concrete syntax, integrity and scope failures block."""
    checks = validation.get('checks', {})
    blockers, warnings = [], []
    informational = {'cats_policy', 'trivy_config_rescan', 'vulnerability_rescan'}
    for name in validation.get('required_checks', checks):
        check = checks.get(name, {'status': 'NOT RUN', 'detail': 'Evidence unavailable.'})
        status = check.get('status')
        if status == 'PASS':
            continue
        detail = str(check.get('detail') or '')
        uncertain = status in {'NOT RUN', 'WARNING_UNVERIFIED', 'UNAVAILABLE'}
        uncertain |= name in informational
        uncertain |= 'unavailable' in detail.lower() and name in {'helm_lint', 'helm_template', 'baseline_render'}
        outcome = 'WARNING_UNVERIFIED' if uncertain else 'BLOCKING'
        check['outcome'] = outcome
        (warnings if uncertain else blockers).append({'check': name, 'detail': detail})
    validation.update(status='BLOCKING' if blockers else 'WARNING_UNVERIFIED' if warnings else 'PASS',
                      blockers=blockers, warnings=warnings,
                      runtime_eligible=not blockers)
    return validation


def deployment_manifest(archive, *, candidate_dir, values_files, rendered, service, images):
    """Describe these ZIP bytes without resolving dependencies or rebuilding sources."""
    roots = sorted(path.parent for path in Path(candidate_dir).rglob('Chart.yaml')
                   if 'charts' not in path.relative_to(candidate_dir).parts[:-1])
    if len(roots) != 1 or not service:
        return None
    chart = roots[0]
    chart_path = 'candidate/' + chart.relative_to(candidate_dir).as_posix()
    chart_path = chart_path.removesuffix('/.')
    inventory = {}
    for entry in archive.infolist():
        if entry.filename == 'manifest.json':
            continue
        with archive.open(entry) as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        inventory[entry.filename] = {'bytes': entry.file_size, 'sha256': 'sha256:' + digest}
    embedded = []
    for image in images:
        name = f"images/{image.get('patch_job_id')}.tar"
        if name not in inventory or not image.get('candidate'):
            continue
        # Identity is checked again by the existing bundle adapter before deployment.
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory(prefix='cats-candidate-image-') as temporary:
            target = Path(temporary) / 'image.tar'
            with archive.open(name) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            identity = bundles.image_archive_identity(target, image['candidate'])
        embedded.append({'reference': image['candidate'], 'digest': identity,
                         'identityType': 'docker_config', 'file': name})
    return {'schemaVersion': '1.0', 'validationType': 'standard-bundle', 'bundleType': 'standard',
            'service': service, 'deployment': {'type': 'helm', 'chartPath': chart_path,
                'valuesFiles': ['candidate/' + path for path in values_files], 'namespace': 'cats-validation'},
            'files': inventory, 'images': embedded, 'requiredImages': bundles.workload_images(rendered),
            'helmDependencies': bundles.dependency_inventory(chart, strict=False, prefix=chart_path),
            'provenance': {'source': 'retained-remediation-candidate'}}


def validation_result(result, request):
    """Success needs artifact binding, actual Helm deployment and completed cleanup."""
    expected = {'request_id': request['request_id'], 'validation_type': request['validation_type'],
                'service': request['service'], 'artifact_digest': request['artifact']['digest']}
    if any(result.get(key) != value for key, value in expected.items()):
        raise ValueError('Candidate validation evidence binding mismatch')
    if result.get('status') == 'VERIFIED':
        helm = result.get('helm_result') or {}
        if (result.get('cleanup_status') != 'COMPLETE' or helm.get('install') != 'PASS'
                or helm.get('release_status') != 'DEPLOYED' or helm.get('execution_mode') != 'HELM'
                or helm.get('helm_release_verified') is not True):
            raise ValueError('Candidate verification requires Helm release and completed cleanup evidence')
    return {**expected, 'status': result.get('status'), 'cleanup_status': result.get('cleanup_status'),
            'validation_id': result.get('validation_id'), 'validator_id': result.get('validator_id'),
            'detail': result.get('reason'), 'result': result}
