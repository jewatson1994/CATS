import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from app.ingress import (
    CONTROLLER_NAME,
    IngressNginxProvider,
    LABEL_KEY,
    PROVIDER_NAMESPACE,
    PROVIDER_VERSION,
    REQUIRED_IMAGES,
    bootstrap,
)


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _config(bundle_dir):
    return SimpleNamespace(
        ingress_bundle_dir=str(bundle_dir),
        kind_binary="kind",
        kubectl_binary="kubectl",
    )


def _manifest(*, host_network=False):
    controller, certgen = REQUIRED_IMAGES
    controller_digest = REQUIRED_IMAGES[controller]
    certgen_digest = REQUIRED_IMAGES[certgen]
    return f"""---
apiVersion: v1
kind: Namespace
metadata:
  name: ingress-nginx
---
apiVersion: v1
kind: Service
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
spec:
  type: LoadBalancer
  selector:
    app: controller
  ports:
  - name: http
    port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: {str(host_network).lower()}
      containers:
      - name: controller
        image: {controller}@{controller_digest}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: ingress-nginx-admission-create
  namespace: ingress-nginx
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: create
        image: {certgen}@{certgen_digest}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: ingress-nginx-admission-patch
  namespace: ingress-nginx
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: patch
        image: {certgen}@{certgen_digest}
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: nginx
spec:
  controller: k8s.io/ingress-nginx
"""


def _bundle(tmp_path: Path, *, host_network=False):
    bundle_dir = tmp_path / "ingress-bundle"
    bundle_dir.mkdir(parents=True)
    manifest = bundle_dir / "deploy.yaml"
    manifest.write_text(_manifest(host_network=host_network), encoding="utf-8")
    images = []
    archives = []
    for index, (name, digest) in enumerate(REQUIRED_IMAGES.items()):
        archive = bundle_dir / f"image-{index}.tar"
        archive.write_bytes(f"trusted archive {index}".encode())
        archives.append(archive)
        images.append({
            "name": name,
            "digest": digest,
            "archive": archive.name,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        })
    (bundle_dir / "bundle.json").write_text(json.dumps({
        "schema_version": 1,
        "provider": "ingress-nginx",
        "version": PROVIDER_VERSION,
        "manifest": {"path": manifest.name, "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()},
        "images": images,
    }), encoding="utf-8")
    return bundle_dir, archives


def _readiness_payload(*, endpoints=True, class_controller="k8s.io/ingress-nginx"):
    labels = {LABEL_KEY: "true"}
    return json.dumps({"items": [
        {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": CONTROLLER_NAME, "namespace": PROVIDER_NAMESPACE, "labels": labels, "generation": 2},
            "spec": {"replicas": 1},
            "status": {"observedGeneration": 2, "availableReplicas": 1, "updatedReplicas": 1},
        },
        {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": CONTROLLER_NAME, "namespace": PROVIDER_NAMESPACE, "labels": labels},
            "spec": {"type": "LoadBalancer"},
            "status": {"loadBalancer": {"ingress": [{"ip": "172.30.0.250"}]}},
        },
        {
            "apiVersion": "networking.k8s.io/v1", "kind": "IngressClass",
            "metadata": {"name": "nginx", "labels": labels},
            "spec": {"controller": class_controller},
        },
        {
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": "controller-abc", "namespace": PROVIDER_NAMESPACE,
                         "labels": {"kubernetes.io/service-name": CONTROLLER_NAME}},
            "endpoints": [{"conditions": {"ready": endpoints}}],
        },
    ]})


def _runner(calls, *, readiness=None, fail_token=None, timeout_token=None):
    def run(argv, cap, key=None, env=None):
        calls.append((list(argv), cap, dict(env or {})))
        if timeout_token and timeout_token in argv:
            raise TimeoutError("provider command timed out")
        if fail_token and fail_token in argv:
            return Result(1, stderr="controller unavailable")
        if argv[:3] == ["kubectl", "get", "deployment,service,ingressclass,endpointslice"]:
            return Result(stdout=readiness or _readiness_payload())
        return Result()
    return run


def test_missing_offline_bundle_fails_truthfully_without_commands(tmp_path):
    calls = []
    root = tmp_path / "run"
    root.mkdir()
    result = bootstrap(_config(tmp_path / "missing"), _runner(calls), root, root / "kubeconfig", "run-1",
                       {"KIND_CLUSTER_NAME": "cluster-1"}, 30)

    assert result["status"] == "FAILED"
    assert result["offline_asset_unavailable"] is True
    assert result["failure_kind"] == "OFFLINE_ASSET_UNAVAILABLE"
    assert "offline inventory is unavailable" in " ".join(result["warnings"])
    assert calls == []


def test_bootstrap_verifies_bundle_preloads_images_and_waits_for_readiness(tmp_path):
    bundle_dir, archives = _bundle(tmp_path)
    root = tmp_path / "run"
    root.mkdir()
    calls = []
    result = bootstrap(_config(bundle_dir), _runner(calls), root, root / "kubeconfig", "validation-run",
                       {"KIND_CLUSTER_NAME": "validation-cluster"}, 60)

    assert result["status"] == "AVAILABLE"
    assert result["controller_ready"] is True
    assert result["ingress_class_ready"] is True
    assert result["dependencies"] == ["metallb"]
    assert result["readiness"]["load_balancer_ready"] is True
    assert result["readiness"]["network_reachability_tested"] is False
    loads = [argv for argv, _, _ in calls if argv[:3] == ["kind", "load", "image-archive"]]
    assert {Path(argv[3]).name for argv in loads} == {item.name for item in archives}
    assert all(argv[argv.index("--name") + 1] == "validation-cluster" for argv in loads)
    assert all("pull" not in argv and argv[0] not in {"curl", "wget"} for argv, _, _ in calls)
    apply_index = next(index for index, (argv, _, _) in enumerate(calls) if argv[:2] == ["kubectl", "apply"])
    load_indexes = [index for index, (argv, _, _) in enumerate(calls) if argv[:3] == ["kind", "load", "image-archive"]]
    assert max(load_indexes) < apply_index
    assert any(argv[:3] == ["kubectl", "rollout", "status"] for argv, _, _ in calls)
    assert sum(1 for argv, _, _ in calls if argv[:3] == ["kubectl", "wait", "--for=condition=complete"]) == 2
    assert any(argv[:3] == ["kubectl", "apply", "--dry-run=server"] for argv, _, _ in calls)

    documents = list(yaml.safe_load_all((root / "cats-ingress-nginx.yaml").read_text(encoding="utf-8")))
    for document in documents:
        assert document["metadata"]["labels"][LABEL_KEY] == "true"
        template = (document.get("spec") or {}).get("template") or {}
        if template:
            assert template["metadata"]["labels"][LABEL_KEY] == "true"
            for container in (template.get("spec") or {}).get("containers", []):
                assert container["imagePullPolicy"] == "Never"
                assert "@sha256:" not in container["image"]
        if document.get("kind") == "Job":
            assert document["spec"]["ttlSecondsAfterFinished"] == 300


def test_bundle_hash_digest_and_security_boundary_fail_closed(tmp_path):
    bundle_dir, _ = _bundle(tmp_path / "hash")
    (bundle_dir / "deploy.yaml").write_text("tampered", encoding="utf-8")
    root = tmp_path / "run-hash"
    root.mkdir()
    result = bootstrap(_config(bundle_dir), _runner([]), root, root / "kubeconfig", "run",
                       {"KIND_CLUSTER_NAME": "cluster"}, 10)
    assert result["status"] == "FAILED"
    assert "manifest hash verification failed" in " ".join(result["warnings"])

    bundle_dir, _ = _bundle(tmp_path / "digest")
    inventory_path = bundle_dir / "bundle.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["images"][0]["digest"] = "sha256:" + "0" * 64
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    root = tmp_path / "run-digest"
    root.mkdir()
    result = bootstrap(_config(bundle_dir), _runner([]), root, root / "kubeconfig", "run",
                       {"KIND_CLUSTER_NAME": "cluster"}, 10)
    assert "does not match the pinned release" in " ".join(result["warnings"])

    bundle_dir, _ = _bundle(tmp_path / "security", host_network=True)
    root = tmp_path / "run-security"
    root.mkdir()
    result = bootstrap(_config(bundle_dir), _runner([]), root, root / "kubeconfig", "run",
                       {"KIND_CLUSTER_NAME": "cluster"}, 10)
    assert "security boundary: hostNetwork" in " ".join(result["warnings"])


def test_bootstrap_reports_controller_failure_and_timeout(tmp_path):
    bundle_dir, _ = _bundle(tmp_path)
    root = tmp_path / "failed"
    root.mkdir()
    failed = bootstrap(_config(bundle_dir), _runner([], fail_token="deployment/ingress-nginx-controller"),
                       root, root / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster"}, 30)
    assert failed["status"] == "FAILED"
    assert failed["failure_kind"] == "BOOTSTRAP_FAILED"

    root = tmp_path / "timeout"
    root.mkdir()
    timed_out = bootstrap(_config(bundle_dir), _runner([], timeout_token="job/ingress-nginx-admission-create"),
                          root, root / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster"}, 30)
    assert timed_out["status"] == "FAILED"
    assert timed_out["failure_kind"] == "BOOTSTRAP_TIMEOUT"


def test_collect_evidence_requires_controller_class_service_and_ready_endpoint(tmp_path):
    provider = IngressNginxProvider()
    healthy = provider.collect_evidence(_config(tmp_path), _runner([], readiness=_readiness_payload()),
                                        tmp_path / "kubeconfig", {}, 5)
    assert healthy["status"] == "AVAILABLE"
    assert healthy["load_balancer_ready"] is True
    assert healthy["network_reachability_tested"] is False

    no_endpoint = provider.collect_evidence(_config(tmp_path), _runner([], readiness=_readiness_payload(endpoints=False)),
                                            tmp_path / "kubeconfig", {}, 5)
    assert no_endpoint["status"] == "FAILED"
    assert no_endpoint["controller_endpoints_ready"] is False

    wrong_class = provider.collect_evidence(_config(tmp_path), _runner([], readiness=_readiness_payload(class_controller="other/controller")),
                                            tmp_path / "kubeconfig", {}, 5)
    assert wrong_class["status"] == "FAILED"
    assert wrong_class["ingress_class_ready"] is False


def test_cleanup_is_owned_by_disposable_kind_cluster():
    result = IngressNginxProvider().cleanup()
    assert result == {"status": "DEFERRED_TO_KIND_CLUSTER_DESTROY", "host_resources": [], "idempotent": True}
