"""Execute the actual validator's strict offline Kind/Helm health acceptance path."""
import json
from pathlib import Path
import sys
import uuid
from app.deployment_validation import ValidationArtifact, ValidationConfig, validate_artifact

base = Path(sys.argv[1])
pins = json.loads(Path(sys.argv[2]).read_text())
ref = json.loads((base / 'acquisition.json').read_text())['self_test_image_reference']
artifact = ValidationArtifact(source_files={p.relative_to(base / 'chart').as_posix():p.read_text()
    for p in (base / 'chart').rglob('*') if p.is_file()},
    image_archives={ref:str(base / 'images/self-test.tar')}, expected_images=[ref],
    offline=True, require_helm_lifecycle=True, job_id=uuid.uuid4().hex)
Path('/tmp/validator-qualification').mkdir(parents=True, exist_ok=True)
config = ValidationConfig(strict_sandbox_policy=True, allow_network_egress=False,
    require_local_images=True, workspace_root='/tmp/validator-qualification',
    kind_node_image=pins['node_image']['reference'], kind_node_archive=str(base / 'images/node.tar'),
    kind_binary=str(base / 'bin/kind'), kubectl_binary=str(base / 'bin/kubectl'),
    helm_binary=str(base / 'bin/helm'), total_timeout_seconds=1200,
    load_balancer_provider_enabled=False, ingress_controller_enabled=False)
result = validate_artifact(artifact, config=config)
(base / 'self-test-qualification.json').write_text(json.dumps(result,sort_keys=True,indent=2) + '\n')
helm = result.get('helm_result') or {}; offline = result.get('offline') or {}
if not (result.get('status') == 'VERIFIED' and result.get('cleanup_status') == 'COMPLETE'
        and offline.get('network_isolated') is True and offline.get('external_image_pulls') == 0
        and offline.get('external_chart_fetches') == 0 and helm.get('install') == 'PASS'
        and helm.get('release_status') == 'DEPLOYED'
        and helm.get('execution_mode') != 'PREFLIGHTED_MANIFEST_APPLY'):
    raise RuntimeError('Actual strict offline validator self-test qualification failed; inspect self-test-qualification.json')
