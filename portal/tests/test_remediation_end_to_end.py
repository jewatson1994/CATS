"""Remediation must work end to end on realistic Helm charts.

Regression coverage for failures seen on real services:
* chart sources containing YAML documents with a ``kind`` but no ``metadata``
  (Kustomization, ``kind: List``) crashed the planner and the Remediations tab;
* rendered ``# Source:`` paths use the chart *name*, while retained sources keep the
  uploaded directory name, so no value mapping was ever proven;
* image values in templates with conditionals, several documents or several image
  lines were never mapped, even when the rendered evidence proves the value;
* patched images whose chart mapping needs review made static validation BLOCKING.

The end-to-end test drives the real HTTP routes with real Helm. Only the image
patch worker (Docker/BuildKit) and the runtime validator are simulated.
"""
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import main, managed_validators, validator_client
from app.auth import seed_auth, token_hash
from app.database import Base, SessionLocal, engine
from app.models import RemediationExecution, Service, UserSession
from app.remediation import build_plan
from app.remediation_delivery import DeliveryAttempt
from app.remediation_sources import retained_source_paths, structured_mapping, verify_rendered_scope

DEPLOYMENT = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
              "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "registry.example/web:1"}]}}}}
DEPLOYMENT_SOURCE = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n"
                     "      containers:\n      - name: web\n        image: registry.example/web:1\n")
KUSTOMIZATION = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- web.yaml\n"


def test_source_documents_without_metadata_are_skipped_not_fatal():
    files = {"chart/templates/web.yaml": DEPLOYMENT_SOURCE, "chart/kustomization.yaml": KUSTOMIZATION,
             "chart/templates/list.yaml": "apiVersion: v1\nkind: List\nitems: []\n"}
    mapping = structured_mapping(DEPLOYMENT, files, "securityContext.runAsNonRoot", "web", "containers")
    assert mapping and mapping["template"] == "chart/templates/web.yaml"
    # A metadata-less document can never be a mutation target.
    assert structured_mapping({"apiVersion": "v1", "kind": "List", "items": []}, files, "securityContext.runAsNonRoot") is None


def test_render_scope_ignores_unaddressable_documents_but_detects_their_changes():
    listed = {"apiVersion": "v1", "kind": "List", "items": [{"kind": "Role"}]}
    assert verify_rendered_scope([DEPLOYMENT, listed], [DEPLOYMENT, listed], [])["status"] == "PASS"
    changed = {**listed, "items": [{"kind": "ClusterRole"}]}
    assert verify_rendered_scope([DEPLOYMENT, listed], [DEPLOYMENT, changed], [])["status"] == "FAIL"


def test_rendered_paths_resolve_through_the_chart_name_not_the_upload_directory():
    files = {"demo/Chart.yaml": "apiVersion: v2\nname: catalog\nversion: 1.0.0\n",
             "demo/templates/api.yaml": "kind: Deployment\n"}
    assert retained_source_paths("catalog/templates/api.yaml", files) == ["demo/templates/api.yaml"]
    assert retained_source_paths("demo/templates/api.yaml", files) == ["demo/templates/api.yaml"]
    assert retained_source_paths("other/templates/api.yaml", files) == []
    # Two uploads of the same chart name stay ambiguous; callers fail closed.
    files["copy/Chart.yaml"] = files["demo/Chart.yaml"]
    files["copy/templates/api.yaml"] = files["demo/templates/api.yaml"]
    assert sorted(retained_source_paths("catalog/templates/api.yaml", files)) == ["copy/templates/api.yaml", "demo/templates/api.yaml"]


def _rendered(kind, name, image, source):
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": {"name": name}, "_cats_source_file": source,
            "spec": {"template": {"spec": {"containers": [{"name": name, "image": image}]}}}}


def test_image_value_mapping_is_proven_by_the_rendered_image():
    template = ("{{- if .Values.enabled }}\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: db\nspec:\n  template:\n"
                "    spec:\n      containers:\n        - name: db\n          image: {{ .Values.images.db }}\n{{- end }}\n---\n"
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: cache\nspec:\n  template:\n    spec:\n"
                "      containers:\n        - name: cache\n          image: {{ .Values.images.cache | quote }}\n")
    files = {"upload/Chart.yaml": "apiVersion: v2\nname: data\nversion: 1.0.0\n",
             "upload/values.yaml": "enabled: true\nimages:\n  db: postgres:16\n  cache: redis:7\n",
             "upload/templates/data.yaml": template}
    resources = [_rendered("Deployment", "db", "postgres:16", "data/templates/data.yaml"),
                 _rendered("Deployment", "cache", "redis:7", "data/templates/data.yaml"),
                 _rendered("Deployment", "drifted", "redis:6", "data/templates/data.yaml")]
    payload = {"service_overview": {"rendered_resources": resources}}
    main._enrich_values_source_mappings(payload, files)
    main._enrich_values_source_mappings(payload, files)  # idempotent: re-enrichment never duplicates mappings
    keys = [[item.get("values_key") for item in resource.get("_cats_source_mappings") or [] if item.get("values_key")]
            for resource in resources]
    assert keys == [[".Values.images.db"], [".Values.images.cache"], []]
    assert resources[0]["_cats_source_mappings"][0]["template"] == "upload/templates/data.yaml"


# --------------------------------------------------------------------------- end to end

CHART = {
    "Chart.yaml": "apiVersion: v2\nname: catalog\nversion: 1.4.0\n",
    "values.yaml": ("images:\n  api: registry.example/catalog-api:2.4.1\n  worker: registry.example/catalog-worker:2.4.1\n"
                    "worker:\n  enabled: true\nauth:\n  password: \"\"\n"),
    "kustomization.yaml": KUSTOMIZATION,
    "templates/api.yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  selector:\n    matchLabels: {app: api}\n"
                           "  template:\n    metadata:\n      labels: {app: api}\n    spec:\n      containers:\n        - name: api\n"
                           "          image: {{ .Values.images.api }}\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"
                           "spec:\n  selector: {app: api}\n  ports:\n    - port: 80\n"),
    "templates/worker.yaml": ("{{- if .Values.worker.enabled }}\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: worker\n"
                              "spec:\n  selector:\n    matchLabels: {app: worker}\n  template:\n    metadata:\n      labels: {app: worker}\n"
                              "    spec:\n      containers:\n        - name: worker\n          image: {{ .Values.images.worker }}\n"
                              "---\napiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: worker-nightly\nspec:\n  schedule: \"0 1 * * *\"\n"
                              "  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n          containers:\n"
                              "            - name: nightly\n              image: {{ .Values.images.worker }}\n{{- end }}\n"),
    "templates/secret.yaml": ("apiVersion: v1\nkind: Secret\nmetadata:\n  name: credentials\ntype: Opaque\n"
                              "data:\n  password: {{ .Values.auth.password | b64enc | quote }}\n"),
    "templates/list.yaml": ("apiVersion: v1\nkind: List\nitems:\n  - apiVersion: rbac.authorization.k8s.io/v1\n    kind: Role\n"
                            "    metadata:\n      name: reader\n    rules: []\n"),
}


def _docker_archive(path: Path, tag: str) -> None:
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as tar:
        data = b"patched\n"; info = tarfile.TarInfo("etc/cats-patched"); info.size = len(data); tar.addfile(info, io.BytesIO(data))
    layer_bytes = layer.getvalue(); layer_digest = hashlib.sha256(layer_bytes).hexdigest()
    config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_digest}"]}}).encode()
    config_name = hashlib.sha256(config).hexdigest() + ".json"
    manifest = json.dumps([{"Config": config_name, "RepoTags": [tag], "Layers": [f"{layer_digest}/layer.tar"]}]).encode()
    with tarfile.open(path, "w") as tar:
        for name, data in ((config_name, config), (f"{layer_digest}/layer.tar", layer_bytes), ("manifest.json", manifest)):
            info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))


@pytest.fixture
def remediation_portal(monkeypatch, tmp_path):
    if not shutil.which("helm"):
        pytest.skip("Helm is required for the end-to-end remediation test")
    Base.metadata.drop_all(engine); Base.metadata.create_all(engine); seed_auth()
    for name in ("REMEDIATION_JOB_ROOT", "PATCH_JOB_ROOT"):
        monkeypatch.setattr(main, name, tmp_path / name.lower())
    monkeypatch.setattr(main, "remediation_enabled", lambda _db: True)
    monkeypatch.setattr(main, "REMEDIATION_WORKERS", SimpleNamespace(submit=lambda fn, *args: fn(*args)))
    patched = []

    def patch_job(job_id, _credentials):
        root = main.PATCH_JOB_ROOT / job_id
        config = json.loads((root / "job-config.json").read_text())
        patched.append(config["source_image"])
        out = root / "output"; out.mkdir(parents=True, exist_ok=True)
        _docker_archive(out / "patched-image.tar", config["destination_image"])
        for name in ("grype-before.json", "grype-after.json", "grype-full-after.json"):
            (out / name).write_text(json.dumps({"matches": []}))
        result = {"patch_status": "PATCHED", "delivery_status": "download", "artifact_available": True,
                  "artifact_sha256": hashlib.sha256((out / "patched-image.tar").read_bytes()).hexdigest(),
                  "vulnerabilities_before": 2, "vulnerabilities_after": 0,
                  "remediation_evidence": {"sbom": "complete", "scan_before": "complete", "scan_after": "complete"}}
        (out / "patch-result.json").write_text(json.dumps(result))
    monkeypatch.setattr(main, "_run_patch_job", patch_job)

    def validate(_configuration, request, artifact_path=None, **_kwargs):
        from app.deployment_bundle import validate_bundle
        if request["validation_type"] == "standard-bundle":
            validate_bundle(artifact_path, expected_type="standard-bundle")
        return {"request_id": request["request_id"], "validation_type": request["validation_type"],
                "service": request["service"], "artifact_digest": request["artifact"]["digest"], "status": "VERIFIED",
                "cleanup_status": "COMPLETE", "validation_id": "validation-1", "validator_id": "validator-1",
                "helm_result": {"install": "PASS", "release_status": "DEPLOYED", "execution_mode": "HELM", "helm_release_verified": True}}
    monkeypatch.setattr(validator_client, "validate", validate)
    monkeypatch.setattr(managed_validators, "select_configuration",
                        lambda *_args: {"endpoint": "https://validator.invalid", "expected_validator_id": "validator-1"})

    client = TestClient(main.app)
    assert client.post("/login", data={"username": "admin", "password": "test-password-long"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        csrf = db.scalar(select(UserSession.csrf_token).where(UserSession.token_hash == token_hash(client.cookies.get("cats_session"))))

    # The uploaded directory ("upload") differs from the chart name ("catalog"), as it often does.
    chart_dir = tmp_path / "upload"
    for relative, content in CHART.items():
        (chart_dir / relative).parent.mkdir(parents=True, exist_ok=True)
        (chart_dir / relative).write_text(content)
    rendered = subprocess.run(["helm", "template", "catalog", str(chart_dir)], capture_output=True, text=True, check=True).stdout
    resources = []
    for document in re.split(r"(?m)^---\s*$", rendered):
        source = re.search(r"(?m)^# Source: (.+)$", document)
        item = yaml.safe_load(document)
        if isinstance(item, dict) and item.get("kind"):
            item["_cats_source_file"] = source.group(1).strip() if source else None
            resources.append(item)
    payload = {
        "schema_version": "1.0", "execution_id": "pipeline-1", "scanned_at": main.utcnow().isoformat(), "complete": True,
        "fixable_only": True, "artifact_type": "helm",
        "service": {"id": "catalog", "name": "Catalog", "version": "1.4.0"},
        "helm_source_files": {f"upload/{relative}": content for relative, content in CHART.items()},
        "service_overview": {"rendered_resources": resources},
        "findings": [{"cve": "CVE-2026-0001", "severity": "High", "image": image, "package": "openssl", "fixed_version": "3.0.9"}
                     for image in ("registry.example/catalog-api:2.4.1", "registry.example/catalog-worker:2.4.1")],
        "policy_findings": [],
    }
    assert client.post("/api/v1/pipeline-results", json=payload, headers={"Authorization": "Bearer test-token"}).status_code == 201
    return client, csrf, patched


def test_remediation_runs_end_to_end_on_a_realistic_chart(remediation_portal):
    client, csrf, patched = remediation_portal
    page = {"Accept": main.PAGE_MEDIA_TYPE} if hasattr(main, "PAGE_MEDIA_TYPE") else {"Accept": "application/vnd.cats.page+json"}

    tab = client.get("/services/catalog?remediations=true&tab=pipeline", headers=page)
    assert tab.status_code == 200
    assert tab.json()["data"]["remediation_preview"]["error"] is None
    preview = client.get("/api/v1/services/catalog/remediation-preview")
    assert preview.status_code == 200 and preview.json()["error"] is None and preview.json()["images"] == 2

    plan = client.get("/services/catalog/remediations/plan").json()
    assert {image["original"]: image["classification"] for image in plan["images"]} == {
        "registry.example/catalog-api:2.4.1": "REVIEW REQUIRED", "registry.example/catalog-worker:2.4.1": "REVIEW REQUIRED"}

    started = client.post("/services/catalog/remediations/start", follow_redirects=False, data={
        "csrf_token": csrf, "remediation_mode": "automated", "decisions": "{}", "plan_digest": plan["plan_digest"],
        "source_execution_id": plan["source_execution_id"], "output_mode": "standard-bundle", "destination_id": "", "verify_runtime": "no"})
    assert started.status_code == 303

    with SessionLocal() as db:
        record = db.scalar(select(RemediationExecution))
        attempts = db.scalars(select(DeliveryAttempt)).all()
        assert record.failure_reason is None, record.failure_reason
        assert sorted(patched) == ["registry.example/catalog-api:2.4.1", "registry.example/catalog-worker:2.4.1"]
        # Both images are proven through values (chart name != upload directory; conditional,
        # multi-document template; one key shared by a Deployment and a CronJob).
        assert {image["original"]: image["classification"] for image in record.patched_images} == {
            "registry.example/catalog-api:2.4.1": "AUTO-REMEDIABLE", "registry.example/catalog-worker:2.4.1": "AUTO-REMEDIABLE"}
        checks = record.validation_results["checks"]
        assert checks["image_references"]["status"] == "PASS"
        assert checks["change_scope"]["status"] == "PASS"
        assert record.validation_results["status"] != "BLOCKING"
        assert record.stages["deployment_validation"]["status"] == "success"
        assert record.verification_status == "verified"
        assert [attempt.status for attempt in attempts] == ["download_ready"]
        job_key = record.job_key

    candidate = client.get(f"/services/catalog/remediations/{job_key}/candidate.zip")
    assert candidate.status_code == 200
    with zipfile.ZipFile(io.BytesIO(candidate.content)) as archive:
        values = yaml.safe_load(archive.read("candidate/upload/values.yaml"))
        rendered = archive.read("scans/rendered-after.yaml").decode()
    assert values["images"]["api"].endswith(f"-cats-{job_key.lower()}")
    assert values["images"]["worker"].endswith(f"-cats-{job_key.lower()}")
    assert "registry.example/catalog-api:2.4.1\n" not in rendered
    assert client.get(f"/services/catalog/remediations/{job_key}", headers=page).status_code == 200


def test_remediation_tab_survives_a_failing_plan_preview(remediation_portal, monkeypatch):
    client, _csrf, _patched = remediation_portal

    def broken(*_args, **_kwargs):
        raise main.MutationError("Resource has no metadata") if hasattr(main, "MutationError") else ValueError("broken")
    monkeypatch.setattr(main, "build_plan", broken)
    main._REMEDIATION_PREVIEW_CACHE.clear() if hasattr(main, "_REMEDIATION_PREVIEW_CACHE") else None
    response = client.get("/services/catalog?remediations=true&tab=pipeline", headers={"Accept": "application/vnd.cats.page+json"})
    assert response.status_code == 200
    # The tab never waits for the preview; the deferred preview reports the failure.
    assert response.json()["data"]["remediation_preview"]["pending"] is True
    preview = client.get("/api/v1/services/catalog/remediation-preview")
    assert preview.status_code == 200 and "could not be built" in preview.json()["error"]


def test_plan_builds_when_sources_include_kustomization_and_lists():
    files = {"chart/Chart.yaml": "apiVersion: v2\nname: chart\nversion: 1.0.0\n", "chart/templates/web.yaml": DEPLOYMENT_SOURCE,
             "chart/kustomization.yaml": KUSTOMIZATION, "chart/templates/list.yaml": "apiVersion: v1\nkind: List\nitems: []\n"}
    resources = [{**DEPLOYMENT, "_cats_source_file": None}, {"apiVersion": "v1", "kind": "List", "items": []}]
    finding = SimpleNamespace(id=1, finding="KSV012", title="Runs as root", description="", remediation="Set runAsNonRoot",
                              severity="HIGH", target="Deployment/web", framework="Kubernetes Security Check",
                              scanner="Trivy", type="configuration", evidence={}, fingerprint="f1", namespace="")
    plan = build_plan({"artifact_type": "helm", "helm_source_files": files,
                       "service_overview": {"rendered_resources": resources}}, [finding], "PREVIEW")
    assert plan["configuration_changes"]
