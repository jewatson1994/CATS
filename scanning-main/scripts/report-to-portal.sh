#!/bin/bash

set -euo pipefail

CATS_PORTAL_URL="${CATS_PORTAL_URL:-}"
CATS_PORTAL_TOKEN="${CATS_PORTAL_TOKEN:-}"
CATS_PORTAL_CA_FILE="${CATS_PORTAL_CA_FILE:-${CATS_PORTAL_CA_CERT:-}}"
REPORT_ONLY="${REPORT_ONLY:-false}"
REPORT_RAW_FINDINGS="${REPORT_RAW_FINDINGS:-false}"
if [ "$REPORT_ONLY" != "true" ]; then
  : "${CATS_PORTAL_URL:?CATS_PORTAL_URL is required}"
  : "${CATS_PORTAL_TOKEN:?CATS_PORTAL_TOKEN is required}"
fi

MANIFEST="$CI_PROJECT_DIR/images.yml"
SERVICE_MANIFEST="$CI_PROJECT_DIR/service.yml"

echo "Portal report working directory: $(pwd)"
echo "Manifest: $MANIFEST"
if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: images.yml was not present in the portal job workspace."
  exit 1
fi
[ -f "$SERVICE_MANIFEST" ] || { echo "ERROR: service.yml was not present in the portal job workspace."; exit 1; }
yq -e '.service.id' "$SERVICE_MANIFEST" >/dev/null \
  || { echo "ERROR: service.yml must define service.id."; exit 1; }
METADATA_MANIFEST="$SERVICE_MANIFEST"

mkdir -p results sboms
if [ ! -f skipped_images.txt ]; then
  : > skipped_images.txt
fi
if [ ! -f skipped_charts.txt ]; then
  : > skipped_charts.txt
fi

echo "Available Grype result files:"
find results -maxdepth 1 -type f -name '*-results.json' -print | sort || true
echo "Available SBOM image maps:"
find sboms -maxdepth 1 -type f -name '*.image' -print | sort || true

jq -n '[]' > portal-findings.json
if [ ! -f portal-policy-findings.json ]; then
  jq -n '[]' > portal-policy-findings.json
fi

shopt -s nullglob
RESULT_COUNT=0
for RESULT in results/*-results.json; do
  RESULT_COUNT=$((RESULT_COUNT + 1))
  SAFE_NAME=$(basename "$RESULT" -results.json)
  if [ ! -f "sboms/${SAFE_NAME}.image" ]; then
    echo "WARNING: No image mapping found for $RESULT; skipping this result."
    continue
  fi
  IMAGE=$(cat "sboms/${SAFE_NAME}.image")
  DIGEST=""
  [ -f "sboms/${SAFE_NAME}.digest" ] && DIGEST=$(cat "sboms/${SAFE_NAME}.digest")

  RAW_COUNT=$(jq '(.matches // []) | length' "$RESULT")
  FIXABLE_COUNT=$(jq '[((.matches // [])[] | select((.vulnerability.fix.versions // []) | length > 0))] | length' "$RESULT")
  echo "${SAFE_NAME}: ${RAW_COUNT} raw finding(s), ${FIXABLE_COUNT} fixable finding(s)"

  PROVENANCE_FILE="sboms/${SAFE_NAME}.provenance"
  if [ ! -f "$PROVENANCE_FILE" ]; then
    PROVENANCE_FILE="current-image-provenance.json"
    printf '%s\n' 'null' > "$PROVENANCE_FILE"
  fi
  SBOM_FILE="sboms/${SAFE_NAME}.json"
  if [ ! -f "$SBOM_FILE" ]; then
    SBOM_FILE="current-sbom-identity.json"
    printf '%s\n' 'null' > "$SBOM_FILE"
  fi
  jq --slurpfile image_provenance "$PROVENANCE_FILE" --slurpfile sbom_input "$SBOM_FILE" --arg image "$IMAGE" --arg digest "$DIGEST" --arg raw "$REPORT_RAW_FINDINGS" '
    # Keep source evidence separate from authoritative applicability context.
    def bounded($kind; $limit):
      if type == $kind and ((tojson | utf8bytelength) <= $limit) then . else null end;
    def image_source:
      if type == "object" then
        {type, name, target: (if (.target | type) == "object" then
          (.target | {userInput, imageID, manifestDigest, repoDigests, architecture, os, labels, annotations})
          else .target end),
         metadata: (if (.metadata | type) == "object" then
          (.metadata | {userInput, imageID, manifestDigest, repoDigests, architecture, os, labels, annotations})
          else null end)} | bounded("object"; 32768)
      else null end;
    def scanner_descriptor:
      if type == "object" then
        with_entries(select(.key == "name" or .key == "version" or .key == "timestamp"))
        | bounded("object"; 1024)
      else null end;
    def package_identity:
      {id, name, version, purl, type, language, metadataType, foundBy,
       metadata: (if (.metadata | type) == "object" then
         (.metadata | with_entries(select(.key == "package" or .key == "name" or .key == "version"
           or .key == "architecture" or .key == "source" or .key == "sourceVersion" or .key == "sourceRpm"
           or .key == "originPackage" or .key == "vendor" or .key == "modularityLabel"
           or .key == "epoch" or .key == "release"))) | bounded("object"; 8192)
         else null end),
       locations: (if (.locations | type) == "array" then
         [.locations[] | select(type == "object")
          | with_entries(select(.key == "path" or .key == "accessPath" or .key == "layerID" or .key == "annotations"))]
         | bounded("array"; 8192) else null end),
       upstreams: (.upstreams | bounded("array"; 8192)),
       cpes: (.cpes | bounded("array"; 8192))} | bounded("object"; 32768);
    # Grype can omit package metadata that remains in its input Syft SBOM.
    # Join only a unique exact artifact ID in this image, and reject conflicts.
    ($sbom_input[0] // {}) as $sbom
    | ([$sbom.artifacts[]? | select(type == "object")
        | select((.id | type) == "string") | select((.id | length) > 0)]
        | group_by(.id) | map(select(length == 1) | {key: .[0].id, value: .[0]})
        | from_entries) as $sbom_by_id
    | (.descriptor | scanner_descriptor) as $scanner_descriptor
    | (.source | image_source) as $scanner_source
    | # Preserve bounded scanner identities without translating distribution names.
    (if (.distro | type) == "object" and ((.distro | tojson | utf8bytelength) <= 4096) then .distro else null end) as $scanner_distro
    | [
      (.matches // [])[]
      | select($raw == "true" or ((.vulnerability.fix.versions // []) | length > 0))
      | .artifact as $artifact
      | (if ($artifact.id | type) == "string" then $sbom_by_id[$artifact.id] else null end) as $sbom_candidate
      | (if $sbom_candidate != null and $sbom_candidate.name == $artifact.name
          and $sbom_candidate.version == $artifact.version and $sbom_candidate.type == $artifact.type
          and (($sbom_candidate.purl // "") == ($artifact.purl // "")
            or $sbom_candidate.purl == null or $artifact.purl == null)
          then ($sbom_candidate | package_identity) else null end) as $sbom_artifact
      | (if (.relatedVulnerabilities | type) == "array" then
          [.relatedVulnerabilities[] | select(type == "object") | .id
            | select(type == "string") | select(length > 0)] | unique
          else [] end) as $raw_aliases
      | [$raw_aliases[] | select(length <= 160)] as $aliases
      | {
          cve: .vulnerability.id,
          severity: (.vulnerability.severity // "Unknown"),
          image: $image,
          image_digest: (if ($digest | length) > 0 then $digest else null end),
          package: .artifact.name,
          installed_version: .artifact.version,
          fixed_version: ((.vulnerability.fix.versions // []) | join(", ")),
          evidence: {
            description: (.vulnerability.description // ""),
            data_source: (.vulnerability.dataSource // ""),
            urls: (.vulnerability.urls // []),
            cvss: (.vulnerability.cvss // []),
            namespace: .vulnerability.namespace,
            package_type: .artifact.type,
            purl: (if (.artifact.purl | type) == "string" then
              (if (.artifact.purl | startswith("pkg:")) and ((.artifact.purl | utf8bytelength) <= 1500) then .artifact.purl else null end)
              else null end),
            scanner_distro: $scanner_distro,
            scanner_source: $scanner_source,
            scanner_descriptor: $scanner_descriptor,
            image_provenance: (($image_provenance[0] // null) | bounded("object"; 32768)),
            scanner_artifact: (.artifact | package_identity),
            sbom_artifact: $sbom_artifact,
            sbom_distro: ($sbom.distro | bounded("object"; 4096)),
            sbom_source: ($sbom.source | image_source),
            sbom_descriptor: ($sbom.descriptor | scanner_descriptor),
            sbom_schema: (if ($sbom.schema | type) == "object" then
              ($sbom.schema | with_entries(select(.key == "version" or .key == "url")))
              | bounded("object"; 2048) else null end),
            aliases: ($aliases | bounded("array"; 8192)),
            alias_count: ($raw_aliases | length),
            aliases_truncated: (($aliases | length) != ($raw_aliases | length)
              or ($aliases | tojson | utf8bytelength) > 8192),
            related_vulnerabilities: (.relatedVulnerabilities | bounded("array"; 32768)),
            match_details: (.matchDetails | bounded("array"; 32768)),
            locations: (.artifact.locations // [])
          }
        }
    ]
  ' "$RESULT" > current-findings.json

  jq -s '.[0] + .[1]' portal-findings.json current-findings.json > portal-findings.next.json
  mv portal-findings.next.json portal-findings.json
done

FINDING_COUNT=$(jq 'length' portal-findings.json)
POLICY_FINDING_COUNT=$(jq 'length' portal-policy-findings.json)
echo "Portal report summary: ${RESULT_COUNT} result file(s), ${FINDING_COUNT} fixable vulnerability finding(s), ${POLICY_FINDING_COUNT} configuration finding(s)."
if [ "$RESULT_COUNT" -eq 0 ]; then
  echo "WARNING: No results/*-results.json files were available in this job."
fi

REQUESTED=$(yq -r '.images | length' "$MANIFEST")
SCANNED=$(find results -maxdepth 1 -name '*-results.json' -type f 2>/dev/null | wc -l | tr -d ' ')
SKIPPED=$(grep -cve '^[[:space:]]*$' skipped_images.txt 2>/dev/null || true)
SKIPPED_IMAGES=$(jq -R -s 'split("\n") | map(select(length > 0))' skipped_images.txt 2>/dev/null || echo '[]')
SKIPPED_CHARTS=$(jq -R -s 'split("\n") | map(select(length > 0))' skipped_charts.txt 2>/dev/null || echo '[]')
SKIPPED_CHART_COUNT=$(grep -cve '^[[:space:]]*$' skipped_charts.txt 2>/dev/null || true)
COMPLETE=false
CONFIGURATION_COMPLETE=true
if [ -f configuration-scan-status.json ]; then
  jq -e '.complete == true' configuration-scan-status.json >/dev/null 2>&1 \
    || CONFIGURATION_COMPLETE=false
elif [ "${TRIVY_CONFIG_SCAN_ENABLED:-false}" = "true" ] || [ "${HELM_SCAN_ENABLED:-false}" = "true" ]; then
  # An enabled job that produced no status artifact is incomplete evidence.
  CONFIGURATION_COMPLETE=false
fi
[ "$REQUESTED" -eq "$SCANNED" ] \
  && [ "$SKIPPED" -eq 0 ] \
  && [ "$SKIPPED_CHART_COUNT" -eq 0 ] \
  && [ "$CONFIGURATION_COMPLETE" = true ] \
  && COMPLETE=true

SCANNED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DB_METADATA="${GRYPE_DB_METADATA:-${GRYPE_DB_CACHE_DIR:-${CATS_SCANNING_ROOT:-}/grype-db}/latest.json}"
[ -f "$DB_METADATA" ] || DB_METADATA="${CATS_SCANNING_ROOT:-}/grype-db/latest.json"
DB_BUILT=$(jq -r '.built // empty' "$DB_METADATA" 2>/dev/null || true)
SERVICE_ID=$(yq -r '.service.id' "$METADATA_MANIFEST")
SERVICE_NAME=$(yq -r '.service.name // .service.id' "$METADATA_MANIFEST")
SERVICE_VERSION=$(yq -r '.service.version // "Unknown"' "$METADATA_MANIFEST")
SERVICE_OWNER=$(yq -r '.service.owner // "Not provided"' "$METADATA_MANIFEST")
SERVICE_POC=$(yq -r '.service.poc // "Not provided"' "$METADATA_MANIFEST")
SERVICE_GROUPS=$(yq -o=json '.service.groups // []' "$METADATA_MANIFEST")
# Accept the current `overview:` key and the earlier `runtime:` spelling so
# services can migrate without losing their declared architecture metadata.
SERVICE_OVERVIEW=$(yq -o=json '(.overview // .runtime // {})' "$SERVICE_MANIFEST")
if [ -f service-overview.json ]; then
  SERVICE_OVERVIEW=$(jq -s '((.[0] // {}) * (.[1] // {}))' <(printf '%s\n' "$SERVICE_OVERVIEW") service-overview.json)
fi
# Keep large Helm evidence in files. Passing it through --argjson expands it
# into the jq process argument vector and fails with E2BIG/"Argument list too
# long" on charts with substantial rendered architecture evidence.
REPORT_TMP_DIR=$(mktemp -d)
trap 'rm -rf "$REPORT_TMP_DIR"' EXIT
HELM_RENDER_WARNINGS_FILE="$REPORT_TMP_DIR/helm-render-warnings.json"
HELM_DISCOVERY_FILE="$REPORT_TMP_DIR/helm-discovery.json"
HELM_CHART_GRAPH_FILE="$REPORT_TMP_DIR/helm-chart-graph.json"
printf '%s\n' '[]' > "$HELM_RENDER_WARNINGS_FILE"
printf '%s\n' '[]' > "$HELM_DISCOVERY_FILE"
printf '%s\n' '{}' > "$HELM_CHART_GRAPH_FILE"
# jq exits successfully for an empty input file but emits no text. Slurp and
# flatten the file so empty, array, or JSON-lines warning artifacts always
# become one valid JSON array in a temporary file.
if [ -s helm-render-warnings.json ]; then
  if jq -s -c '[.[] | if type == "array" then .[] else . end]' helm-render-warnings.json > "$HELM_RENDER_WARNINGS_FILE.tmp" 2>/dev/null; then
    mv "$HELM_RENDER_WARNINGS_FILE.tmp" "$HELM_RENDER_WARNINGS_FILE"
  else
    rm -f "$HELM_RENDER_WARNINGS_FILE.tmp"
  fi
fi
if [ -s helm-discovery.jsonl ]; then
  if jq -s -c 'map(select(type == "object"))' helm-discovery.jsonl > "$HELM_DISCOVERY_FILE.tmp" 2>/dev/null; then
    mv "$HELM_DISCOVERY_FILE.tmp" "$HELM_DISCOVERY_FILE"
  else
    rm -f "$HELM_DISCOVERY_FILE.tmp"
  fi
fi
if [ -s .cats-helm-graph.json ]; then
  if jq -s -c 'map(select(type == "object"))[0] // {}' .cats-helm-graph.json > "$HELM_CHART_GRAPH_FILE.tmp" 2>/dev/null; then
    mv "$HELM_CHART_GRAPH_FILE.tmp" "$HELM_CHART_GRAPH_FILE"
  else
    rm -f "$HELM_CHART_GRAPH_FILE.tmp"
  fi
fi
# The slurpfile values are one JSON document each, so unwrap the normalized
# array/object before applying the existing overview transformation.
SERVICE_OVERVIEW=$(jq --slurpfile helm_warnings_input "$HELM_RENDER_WARNINGS_FILE" \
  --slurpfile helm_discovery_input "$HELM_DISCOVERY_FILE" \
  --slurpfile helm_chart_graph_input "$HELM_CHART_GRAPH_FILE" \
  '($helm_warnings_input[0] // []) as $helm_warnings
   | ($helm_discovery_input[0] // []) as $helm_discovery
   | ($helm_chart_graph_input[0] // {}) as $helm_chart_graph
   | (.rendered_resources // []) as $rendered_resources
   | . + {
      warnings: (((.warnings // []) + $helm_warnings) | unique_by(tojson)),
      helm_components: (($helm_discovery // []) | reverse | unique_by([.chart, .path, .declared_by]) | reverse),
      helm_chart_graph: ($helm_chart_graph | .charts = ((.charts // []) | map(
        . as $chart
        | ($rendered_resources | map(select((._cats_chart_provenance.chart_id // "") == ($chart.chart_id // "")))) as $chart_resources
        | .resource_count = ($chart_resources | length)
        | .image_count = ([$chart_resources[]? | .. | .image? | select(type == "string")] | unique | length)
      ))),
      missing_evidence: ((.missing_evidence // []) + [
        $helm_discovery[]? | select((.status // "") == "unresolved") |
        {type:"Chart", item:(.chart // .name // "Unknown chart"), reason:(.reason // "Declared Helm component could not be resolved"), source_file:(.declared_by // "—")}
      ] + (($helm_chart_graph.charts // []) | map(select(((.status // "") | ascii_downcase) as $status | ($status == "render failed" or $status == "unresolved" or $status == "partially rendered"))) | map({type:"Chart", item:(.chart // .name // "Unknown chart"), reason:("stage=" + (.render_stage // "unknown") + (if (.yaml_path // "") != "" then " template=" + .yaml_path else "" end) + " error=" + (.render_error // .error // "Chart render did not complete")), source_file:(.discovery_source_file // .source // "—"), yaml_path:(.yaml_path // "—"), stage:(.render_stage // null), instance:(.instance // null)})) + (($helm_chart_graph.unresolved // []) | map({type:(.type // "Helm Chart"), item:(.item // "Unknown chart"), reason:(.reason // "Referenced Helm chart could not be resolved"), source_file:(.source_file // "—"), yaml_path:(.yaml_path // "—"), repository:(.repository // null), version:(.version // null)})) | unique_by(tojson))
    }' \
  <<< "$SERVICE_OVERVIEW")

# Keep the potentially large overview JSON out of jq's command-line arguments.
# Architecture evidence can make this payload exceed the OS argument limit.
SERVICE_OVERVIEW_FILE="$REPORT_TMP_DIR/service-overview.json"
printf '%s\n' "$SERVICE_OVERVIEW" > "$SERVICE_OVERVIEW_FILE"
python3 "$(dirname "$0")/extract-image-identities.py" sboms "$SERVICE_OVERVIEW_FILE"
cp "$SERVICE_OVERVIEW_FILE" service-overview.json
SBOM_COMPONENTS_FILE="$REPORT_TMP_DIR/sbom-components.json"
python3 "$(dirname "$0")/extract-sbom-components.py" sboms "$SBOM_COMPONENTS_FILE"
EXPORT_EVIDENCE_FILE="$REPORT_TMP_DIR/export-evidence.json"
python3 "$(dirname "$0")/retain-export-evidence.py" . "$EXPORT_EVIDENCE_FILE"

jq -n \
  --arg execution_id "gitlab:${CI_PROJECT_ID}:pipeline:${CI_PIPELINE_ID}" \
  --arg scanned_at "$SCANNED_AT" \
  --argjson complete "$COMPLETE" \
  --arg pipeline_url "$CI_PIPELINE_URL" \
  --arg commit_sha "$CI_COMMIT_SHA" \
  --arg db_built "$DB_BUILT" \
  --arg service_id "$SERVICE_ID" \
  --arg service_name "$SERVICE_NAME" \
  --arg service_version "$SERVICE_VERSION" \
  --arg service_owner "$SERVICE_OWNER" \
  --arg service_poc "$SERVICE_POC" \
  --argjson service_groups "$SERVICE_GROUPS" \
  --slurpfile service_overview "$SERVICE_OVERVIEW_FILE" \
  --slurpfile sbom_components "$SBOM_COMPONENTS_FILE" \
  --slurpfile export_evidence "$EXPORT_EVIDENCE_FILE" \
  --arg raw_findings "$REPORT_RAW_FINDINGS" \
  --argjson skipped_images "$SKIPPED_IMAGES" \
  --argjson skipped_charts "$SKIPPED_CHARTS" \
  --slurpfile findings portal-findings.json \
  --slurpfile policy_findings portal-policy-findings.json \
  '{
    schema_version: "1.0",
    execution_id: $execution_id,
    scanned_at: $scanned_at,
    complete: $complete,
    skipped_images: $skipped_images,
    skipped_charts: $skipped_charts,
    fixable_only: ($raw_findings != "true"),
    pipeline_url: $pipeline_url,
    commit_sha: $commit_sha,
    scanner_db_built_at: (if ($db_built | length) > 0 then $db_built else null end),
    service: {
      id: $service_id,
      name: $service_name,
      version: $service_version,
      owner: (if ($service_owner | length) > 0 then $service_owner else null end),
      poc: (if ($service_poc | length) > 0 then $service_poc else null end),
      groups: $service_groups
    },
    findings: $findings[0],
    policy_findings: $policy_findings[0],
    sbom_components: ($sbom_components[0].components // []),
    sbom_images: ($sbom_components[0].images // []),
    evidence_documents: ($export_evidence[0].evidence_documents // []),
    evidence_unavailable: ($export_evidence[0].evidence_unavailable // []),
     service_overview: $service_overview[0]
  }' > portal-result.json

if [ "$REPORT_ONLY" = "true" ]; then
  echo "Generated portal-result.json without uploading (REPORT_ONLY=true)."
  exit 0
fi

curl_tls_args=()
if [ -n "$CATS_PORTAL_CA_FILE" ]; then
  curl_tls_args+=(--cacert "$CATS_PORTAL_CA_FILE")
fi

curl --fail-with-body --silent --show-error "${curl_tls_args[@]}" \
  --connect-timeout 5 --max-time 30 \
  -X POST "${CATS_PORTAL_URL%/}/api/v1/pipeline-results" \
  -H "Authorization: Bearer ${CATS_PORTAL_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @portal-result.json
