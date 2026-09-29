import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract-workload-images.py"
SPEC = importlib.util.spec_from_file_location("extract_workload_images", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_only_kubernetes_workload_container_locations_are_images(tmp_path):
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text("""apiVersion: v1
kind: ConfigMap
metadata: {name: settings}
data:
  image: registry.example.invalid/not-an-artifact:1
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.internal/app:1
      initContainers:
        - name: setup
          image: registry.internal/setup:2
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: scheduled}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: registry.internal/job:3
""", encoding="utf-8")
    assert MODULE.extract(rendered) == ["registry.internal/app:1", "registry.internal/setup:2", "registry.internal/job:3"]
