import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from app.load_balancer import LABEL_KEY, MetalLBProvider, POOL_NAME, bootstrap


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _config(bundle_dir):
    return SimpleNamespace(
        load_balancer_bundle_dir=str(bundle_dir),
        docker_binary="docker",
        kind_binary="kind",
        kubectl_binary="kubectl",
    )


def _bundle(tmp_path: Path):
    controller = "quay.io/metallb/controller:v0.16.1"
    speaker = "quay.io/metallb/speaker:v0.16.1"
    manifest = f"""---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ipaddresspools.metallb.io
spec: {{}}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: l2advertisements.metallb.io
spec: {{}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: controller
  namespace: metallb-system
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: controller
        image: {controller}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: speaker
  namespace: metallb-system
spec:
  template:
    spec:
      containers:
      - name: speaker
        image: {speaker}
"""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir(parents=True)
    manifest_path = bundle_dir / "metallb-native.yaml"
    manifest_path.write_text(manifest, encoding="utf-8")
    archives = []
    images = []
    for name, content, digest in (
        (controller, b"verified controller archive", "sha256:" + "1" * 64),
        (speaker, b"verified speaker archive", "sha256:" + "2" * 64),
    ):
        archive = bundle_dir / ("controller.tar" if "controller" in name else "speaker.tar")
        archive.write_bytes(content)
        archives.append(archive)
        images.append({"name": name, "digest": digest, "archive": archive.name, "sha256": hashlib.sha256(content).hexdigest()})
    (bundle_dir / "bundle.json").write_text(json.dumps({
        "schema_version": 1,
        "provider": "metallb",
        "version": "0.16.1",
        "manifest": {"path": manifest_path.name, "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest()},
        "images": images,
    }), encoding="utf-8")
    return bundle_dir, archives


def _network_json(extra=None):
    containers = {"kind-node": {"IPv4Address": "172.30.0.2/24"}}
    containers.update(extra or {})
    return json.dumps([{"IPAM": {"Config": [{"Subnet": "172.30.0.0/24", "Gateway": "172.30.0.1"}]}, "Containers": containers}])


def _runner(calls, *, network_json=None, fail=None, timeout_on=None):
    def run(argv, cap, key=None, env=None):
        calls.append((list(argv), cap, dict(env or {})))
        if timeout_on and timeout_on in argv:
            raise TimeoutError("provider command timed out")
        if fail and fail in argv:
            return Result(1, "", "controller unavailable")
        if argv[:3] == ["docker", "network", "inspect"]:
            return Result(stdout=network_json or _network_json())
        return Result()
    return run


def test_bootstrap_verifies_offline_bundle_loads_images_and_orders_pool_after_ready(tmp_path):
    bundle_dir, archives = _bundle(tmp_path)
    root = tmp_path / "run"
    root.mkdir()
    calls = []
    result = bootstrap(_config(bundle_dir), _runner(calls), root, root / "kubeconfig", "cats-validation-run", {
        "KIND_CLUSTER_NAME": "cats-validation-run",
        "KIND_EXPERIMENTAL_DOCKER_NETWORK": "cats-validation-run-network",
    }, 30)

    assert result["status"] == "AVAILABLE"
    assert result["controller_ready"] is True
    assert result["duration_ms"] > 0
    assert result["address_pool"]["addresses"]
    assert result["bundle"]["manifest_sha256"]
    loads = [item[0] for item in calls if item[0][0:3] == ["kind", "load", "image-archive"]]
    assert {Path(item[3]).name for item in loads} == {archive.name for archive in archives}
    assert all("--name" in item and item[item.index("--name") + 1] == "cats-validation-run" for item in loads)
    assert all(item[0] != "curl" and "pull" not in item for item in calls)
    rollout_index = next(index for index, item in enumerate(calls) if item[0][:2] == ["kubectl", "rollout"])
    pool_index = next(index for index, item in enumerate(calls) if any("cats-metallb-pool.yaml" in part for part in item[0]))
    assert pool_index > rollout_index
    rendered = list(yaml_documents(root / "cats-metallb-native.yaml"))
    assert rendered
    for document in rendered:
        assert document["metadata"]["labels"][LABEL_KEY] == "true"
        template = (document.get("spec") or {}).get("template") or {}
        if template:
            assert template["metadata"]["labels"][LABEL_KEY] == "true"
            for container in (template.get("spec") or {}).get("containers", []):
                assert container["imagePullPolicy"] == "Never"


def yaml_documents(path):
    import yaml
    return yaml.safe_load_all(path.read_text(encoding="utf-8"))


def test_bootstrap_rejects_missing_or_corrupt_trusted_artifacts(tmp_path):
    bundle_dir, _ = _bundle(tmp_path)
    (bundle_dir / "metallb-native.yaml").write_text("tampered", encoding="utf-8")
    run_root = tmp_path / "run"
    run_root.mkdir()
    result = MetalLBProvider().bootstrap(_config(bundle_dir), _runner([]), run_root, tmp_path / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster", "KIND_EXPERIMENTAL_DOCKER_NETWORK": "network"}, 10)
    assert result["status"] == "FAILED"
    assert "hash verification" in " ".join(result["warnings"])
    assert not any("kind" in call[0] for call in [])

    bundle_dir, _ = _bundle(tmp_path / "other")
    (bundle_dir / "controller.tar").write_bytes(b"corrupt")
    calls = []
    run_root = tmp_path / "run2"
    run_root.mkdir()
    result = bootstrap(_config(bundle_dir), _runner(calls), run_root, tmp_path / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster", "KIND_EXPERIMENTAL_DOCKER_NETWORK": "network"}, 10)
    assert result["status"] == "FAILED"
    assert "archive hash verification" in " ".join(result["warnings"])
    assert calls == []


def test_bootstrap_reports_controller_failure_and_timeout_without_raising(tmp_path):
    bundle_dir, _ = _bundle(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    calls = []
    failed = bootstrap(_config(bundle_dir), _runner(calls, fail="deployment/controller"), run_root, tmp_path / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster", "KIND_EXPERIMENTAL_DOCKER_NETWORK": "network"}, 10)
    assert failed["status"] == "FAILED"
    assert failed["controller_ready"] is False
    assert any("controller" in warning for warning in failed["warnings"])
    assert any(stage["status"] == "FAIL" and "deployment_controller" in stage["name"] for stage in failed["stages"])

    calls = []
    timeout_root = tmp_path / "run2"
    timeout_root.mkdir()
    timed_out = bootstrap(_config(bundle_dir), _runner(calls, timeout_on="crd/ipaddresspools.metallb.io"), timeout_root, tmp_path / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster", "KIND_EXPERIMENTAL_DOCKER_NETWORK": "network"}, 10)
    assert timed_out["status"] == "FAILED"
    assert any("timed out" in warning for warning in timed_out["warnings"])


def test_network_pool_is_bounded_and_excludes_gateway_and_allocated_nodes(tmp_path):
    bundle_dir, _ = _bundle(tmp_path)
    run_root = tmp_path / "run"
    run_root.mkdir()
    allocated = {f"node-{index}": {"IPv4Address": f"172.30.0.{240 + index}/24"} for index in range(1, 8)}
    calls = []
    result = bootstrap(_config(bundle_dir), _runner(calls, network_json=_network_json(allocated)), run_root, tmp_path / "kubeconfig", "run", {"KIND_CLUSTER_NAME": "cluster", "KIND_EXPERIMENTAL_DOCKER_NETWORK": "network"}, 10)
    pool = result["address_pool"]
    assert result["status"] == "AVAILABLE"
    assert len(pool["addresses"]) <= 16
    assert "172.30.0.1" not in pool["addresses"] and "172.30.0.2" not in pool["addresses"]
    assert not set(pool["addresses"]) & {f"172.30.0.{240 + index}" for index in range(1, 8)}
    assert all(0 < int(address.rsplit(".", 1)[1]) < 255 for address in pool["addresses"])


def test_collect_evidence_requires_both_controller_speaker_pool_and_advertisement(tmp_path):
    provider = MetalLBProvider()
    config = _config(tmp_path)
    payload = {"items": [
        {"kind": "Deployment", "metadata": {"name": "controller", "labels": {LABEL_KEY: "true"}, "generation": 1}, "spec": {"replicas": 1}, "status": {"observedGeneration": 1, "availableReplicas": 1, "updatedReplicas": 1}},
        {"kind": "DaemonSet", "metadata": {"name": "speaker", "labels": {LABEL_KEY: "true"}, "generation": 1}, "spec": {}, "status": {"observedGeneration": 1, "desiredNumberScheduled": 1, "numberReady": 1, "updatedNumberScheduled": 1}},
        {"kind": "IPAddressPool", "metadata": {"name": POOL_NAME, "labels": {LABEL_KEY: "true"}}, "spec": {"addresses": ["172.30.0.250/32"]}},
        {"kind": "L2Advertisement", "metadata": {"name": "cats-validation-l2", "labels": {LABEL_KEY: "true"}}, "spec": {"ipAddressPools": [POOL_NAME]}},
        {"kind": "Deployment", "metadata": {"name": "untrusted", "labels": {}}, "spec": {}, "status": {}},
    ]}
    def healthy(*_args): return Result(stdout=json.dumps(payload))
    evidence = provider.collect_evidence(config, healthy, tmp_path / "kubeconfig", {}, 5)
    assert evidence["status"] == "AVAILABLE"
    assert evidence["controller_ready"] is True

    payload["items"][-3]["spec"]["addresses"] = []
    evidence = provider.collect_evidence(config, healthy, tmp_path / "kubeconfig", {}, 5)
    assert evidence["status"] == "FAILED"
    assert evidence["controller_ready"] is False


def test_cleanup_is_cluster_owned_and_concurrency_uses_run_identity():
    provider = MetalLBProvider()
    assert provider.cleanup()["status"] == "DEFERRED_TO_KIND_CLUSTER_DESTROY"
    assert provider.cleanup()["host_resources"] == []


def test_two_runs_load_into_only_their_own_clusters(tmp_path):
    bundle_dir, _ = _bundle(tmp_path)
    for identity in ("first-run", "second-run"):
        root = tmp_path / identity
        root.mkdir()
        calls = []
        result = bootstrap(_config(bundle_dir), _runner(calls), root, root / "kubeconfig", identity,
                           {"KIND_CLUSTER_NAME": identity, "KIND_EXPERIMENTAL_DOCKER_NETWORK": identity + "-network"}, 30)
        assert result["controller_ready"]
        for argv, _, env in calls:
            assert env["KIND_CLUSTER_NAME"] == identity
            if argv[:3] == ["kind", "load", "image-archive"]:
                assert argv[argv.index("--name") + 1] == identity
            if argv[:3] == ["docker", "network", "inspect"]:
                assert argv[-1] == identity + "-network"
        for document in yaml_documents(root / "cats-metallb-native.yaml"):
            assert document["metadata"]["labels"]["cats.clanhq.io/validation-run"] == identity
