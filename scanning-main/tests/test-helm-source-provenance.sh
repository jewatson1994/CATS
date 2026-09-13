#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT

for executable in awk bash find jq python3 sort tr yq; do
  command -v "$executable" >/dev/null 2>&1 || {
    echo "Missing required executable for Helm provenance test: $executable" >&2
    exit 1
  }
done

mkdir -p "$TEMPORARY_DIRECTORY/helm-rendered"
cat > "$TEMPORARY_DIRECTORY/helm-rendered/rendered.yaml" <<'YAML'
---
# Source: neptunetrial/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels:
    app: api
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: registry.example.com/project/api:1.0
          ports:
            - name: metrics
              containerPort: 9090
              protocol: TCP
---
# Source: neptunetrial/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: api
  labels:
    app: api
spec:
  selector:
    app: api
  ports:
    - name: http
      port: 8080
      targetPort: 9090
      protocol: TCP
---
# Source: neptunetrial/charts/postgresql/templates/primary/statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgresql
spec:
  template:
    spec:
      containers:
        - name: postgresql
          image: docker.io/library/postgres:17
          ports:
            - name: postgres
              containerPort: 5432
              protocol: TCP
---
# Source: neptunetrial/templates/job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: api-job
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.example.com/project/api:1.0
      restartPolicy: Never
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: no-source
YAML

(
  cd "$TEMPORARY_DIRECTORY"
  bash "$REPOSITORY_ROOT/scripts/extract-service-overview.sh" helm-rendered portal-result-overview.json
)

cat > "$TEMPORARY_DIRECTORY/images.yml" <<'YAML'
images: []
YAML
cat > "$TEMPORARY_DIRECTORY/service.yml" <<'YAML'
service:
  id: helm-provenance
  name: Helm Provenance
  version: 1.0.0
YAML
cp "$TEMPORARY_DIRECTORY/portal-result-overview.json" "$TEMPORARY_DIRECTORY/service-overview.json"
mkdir -p "$TEMPORARY_DIRECTORY/results" "$TEMPORARY_DIRECTORY/sboms"
(
  cd "$TEMPORARY_DIRECTORY"
  CI_PROJECT_DIR="$TEMPORARY_DIRECTORY" \
  CI_PROJECT_ID=provenance \
  CI_PIPELINE_ID=1 \
  CI_PIPELINE_URL=https://gitlab.example/pipeline/1 \
  CI_COMMIT_SHA=provenance \
  REPORT_ONLY=true \
    bash "$REPOSITORY_ROOT/scripts/report-to-portal.sh"
)

jq -e '
  ([.service_overview.rendered_resources[] | select(.kind == "Deployment")] | length == 2) and
  ([.service_overview.rendered_resources[] | select(.kind == "Service")] | length == 1) and
  ([.service_overview.rendered_resources[] | select(.kind == "ConfigMap")] | length == 1) and
  (.service_overview.images | any(.[]; .image == "registry.example.com/project/api:1.0" and .source_file == "templates/deployment.yaml")) and
  (.service_overview.images | any(.[]; .image == "registry.example.com/project/api:1.0" and .source_file == "templates/job.yaml")) and
  (.service_overview.images | any(.[]; .image == "docker.io/library/postgres:17" and .source_file == "charts/postgresql/templates/primary/statefulset.yaml")) and
  (.service_overview.ports | any(.[]; .port == 9090 and .source_file == "templates/deployment.yaml")) and
  (.service_overview.ports | any(.[]; .port == 8080 and .source_file == "templates/service.yaml")) and
  (.service_overview.ports | any(.[]; .port == 5432 and .source_file == "charts/postgresql/templates/primary/statefulset.yaml")) and
  ([.service_overview.images[] | select(.image == "registry.example.com/project/api:1.0")] | length == 2) and
  ([.service_overview.images[] | select(.image == "docker.io/library/api:unknown")] | length == 0)
' "$TEMPORARY_DIRECTORY/portal-result.json" >/dev/null

# A document without a Helm source comment must not receive an invented path.
jq -e 'all(.service_overview.images[]?, .service_overview.ports[]?; (.source_file // "") != "no-source")' \
  "$TEMPORARY_DIRECTORY/portal-result.json" >/dev/null

echo "Helm source provenance extraction tests passed."
