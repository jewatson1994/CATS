#!/usr/bin/env bash

# Standalone, non-GitLab scan orchestrator. It preserves the existing stage
# scripts and their evidence contract while running them in one ephemeral job.
set -u

INPUT_DIR="${1:?input directory is required}"
OUTPUT_DIR="${2:?output directory is required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# When invoked through the installed /usr/local/bin/cats-scan symlink,
# BASH_SOURCE points at /usr/local/bin rather than the bundled phase scripts.
# Prefer the adjacent scripts when present, otherwise use the image location.
if [ ! -f "$SCRIPT_DIR/prepare-inputs.sh" ] && [ -f /opt/cats/scanning/scripts/prepare-inputs.sh ]; then
  SCRIPT_DIR=/opt/cats/scanning/scripts
fi

mkdir -p "$OUTPUT_DIR" || exit 1
cd "$OUTPUT_DIR" || exit 1

# Preserve diagnostics, but never assemble or ingest reports after a fatal phase.
fatal_phase() {
  local name="$1" rc="$2"
  printf '{"phase":"%s","status":"failed","exit_code":%s}\n' "$name" "$rc" > "phase-${name}.json"
  printf '{"phase":"%s","exit_code":%s,"error":"Required scanner phase failed; see phase log and worker.log"}\n' "$name" "$rc" > scan-failure.json
  printf '{"status":"failed","failed_phase":"%s","exit_code":%s}\n' "$name" "$rc" > scan-summary.json
  printf 'failed\n' > scan-status.txt
  echo "[cats-scan] phase=$name exit=$rc (fatal; diagnostic files retained)" >&2
  exit "$rc"
}
cp -a "$INPUT_DIR"/. ./ 2>input_copy.log || fatal_phase input_copy "$?"

# Syntax checks alone do not reject all CRLF scripts (e.g. a CR-tainted source
# path). Check both before any phase runs, including indirectly sourced helpers.
for runtime_script in "$SCRIPT_DIR"/*.sh; do
  if LC_ALL=C od -An -t x1 "$runtime_script" | grep -qw '0d'; then
    printf 'CR byte in Linux runtime script: %s\n' "$runtime_script" > preflight.log
    cat preflight.log >&2
    fatal_phase preflight 2
  fi
  bash -n "$runtime_script" >> preflight.log 2>&1 || fatal_phase preflight "$?"
done

echo "[cats-scan] input=$INPUT_DIR output=$OUTPUT_DIR"
echo "[cats-scan] runner=$(command -v bash)"
echo "[cats-scan] tools: yq=$(command -v yq || true) jq=$(command -v jq || true) syft=$(command -v syft || true) grype=$(command -v grype || true) trivy=$(command -v trivy || true) dockle=$(command -v dockle || true) helm=$(command -v helm || true)"

# Image access. The CATS portal (HQ) deliberately has no Docker socket, so
# images are read straight from their registry or archive there. CI runners
# and other hosts with a reachable Docker daemon keep using it.
if [ -z "${CATS_IMAGE_SOURCE:-}" ]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    CATS_IMAGE_SOURCE=docker
  else
    CATS_IMAGE_SOURCE=daemonless
  fi
fi
case "$CATS_IMAGE_SOURCE" in
  docker|daemonless) ;;
  *) echo "[cats-scan] unsupported CATS_IMAGE_SOURCE: $CATS_IMAGE_SOURCE" >&2; exit 2 ;;
esac
export CATS_IMAGE_SOURCE
echo "[cats-scan] image source: $CATS_IMAGE_SOURCE"

# Split archives exist only for this job's phases; never keep a second copy
# of uploaded images in the retained job output.
cleanup_split_archives() { rm -rf -- image-archives/.split; }
trap cleanup_split_archives EXIT

# Load locally uploaded image archives before image preparation. Every tag an
# archive contains becomes an image input and is scanned without registry
# connectivity. Without a Docker daemon the archive is read directly and the
# image-to-archive mapping is recorded in image-archive-map.tsv.
if [ -d image-archives ]; then
  : > loaded-images.txt
  : > image-archive-map.tsv
  for archive in image-archives/*; do
    [ -f "$archive" ] || continue
    echo "[cats-scan] loading local image archive: $archive"
    if [ "$CATS_IMAGE_SOURCE" = docker ]; then
      if load_output="$(docker load -i "$archive" 2>&1)"; then
        printf '%s\n' "$load_output" | sed -n 's/^Loaded image: //p' >> loaded-images.txt
      else
        echo "[cats-scan] WARNING: unable to load local image archive: $archive"
        printf '%s\n' "$load_output"
      fi
    elif map_output="$(python3 "$SCRIPT_DIR/split-image-archive.py" "$archive" --output-dir image-archives/.split)"; then
      printf '%s\n' "$map_output" | sed '/^[[:space:]]*$/d' >> image-archive-map.tsv
      printf '%s\n' "$map_output" | cut -f1 | sed '/^[[:space:]]*$/d' >> loaded-images.txt
    else
      echo "[cats-scan] WARNING: unable to read local image archive: $archive"
    fi
  done
  sed -i '/^[[:space:]]*$/d' loaded-images.txt 2>/dev/null || true
  if [ -s loaded-images.txt ]; then
    cat loaded-images.txt >> images.txt
  fi
fi

# Public/API callers may submit one image per line instead of images.yml.
if [ ! -f images.yml ] && [ -f images.txt ]; then
  {
    printf 'images:\n'
    sed -e '/^[[:space:]]*$/d' -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/- "/' -e 's/$/"/' images.txt
  } > images.yml
fi
# A chart-only submission is valid: prepare still expects an image manifest,
# while the later phases will skip SBOM work and continue with Helm config.
if [ ! -f images.yml ]; then
  printf 'images: []\n' > images.yml
fi

# The existing prepare stage validates service.yml even for non-persistent jobs.
if [ ! -f service.yml ]; then
  cat > service.yml <<'YAML'
service:
  id: standalone-scan
  name: Standalone scan
YAML
fi

export CI_PROJECT_DIR="$OUTPUT_DIR"
# The reusable report script normally receives these from GitLab. Public jobs
# are not GitLab jobs, so provide deterministic local identities instead of
# allowing set -u in report-to-portal.sh to abort the final report phase.
export CI_PROJECT_ID="${CI_PROJECT_ID:-standalone}"
export CI_PIPELINE_ID="${CI_PIPELINE_ID:-standalone}"
export CI_PIPELINE_URL="${CI_PIPELINE_URL:-}"
export CI_COMMIT_SHA="${CI_COMMIT_SHA:-standalone}"
export TRIVY_CONFIG_SCAN_ENABLED="${TRIVY_CONFIG_SCAN_ENABLED:-true}"
export HELM_SCAN_ENABLED="${HELM_SCAN_ENABLED:-$([ -d charts ] && echo true || echo false)}"
export HELM_ALLOW_NETWORK="${HELM_ALLOW_NETWORK:-false}"
export TRIVY_OFFLINE="${TRIVY_OFFLINE:-true}"
export TRIVY_CONFIG_STRICT="${TRIVY_CONFIG_STRICT:-false}"
export TRIVY_IMAGE_CONFIG_SCAN_ENABLED="${TRIVY_IMAGE_CONFIG_SCAN_ENABLED:-true}"
export DOCKLE_IMAGE_CONFIG_SCAN_ENABLED="${DOCKLE_IMAGE_CONFIG_SCAN_ENABLED:-true}"
# Public/self-service scans show every vulnerability match. Authenticated
# GitLab ingestion leaves this unset and continues to submit fixable findings.
export REPORT_RAW_FINDINGS="${REPORT_RAW_FINDINGS:-true}"
JOB_MODE="${CATS_JOB_MODE:-scan}"
case "$JOB_MODE" in
  scan|sbom) ;;
  *) echo "[cats-scan] unsupported CATS_JOB_MODE: $JOB_MODE" >&2; exit 2 ;;
esac

run_phase() {
  local name="$1" script="$2"
  echo "[cats-scan] phase=$name start script=$script"
  printf '{"phase":"%s","status":"running"}\n' "$name" > "phase-${name}.json"
  if bash "$SCRIPT_DIR/$script" >"${name}.log" 2>&1; then
    echo "[cats-scan] phase=$name exit=0"
    echo "[cats-scan] phase=$name artifacts:"
    find . -maxdepth 2 -type f -print | sort || true
    echo "[cats-scan] phase=$name log tail:"
    tail -n 80 "${name}.log" || true
    printf '{"phase":"%s","status":"complete"}\n' "$name" > "phase-${name}.json"
    return 0
  else
    rc=$?
  fi
  echo "[cats-scan] phase=$name exit=$rc"
  echo "[cats-scan] phase=$name log tail:"
  tail -n 80 "${name}.log" || true
  fatal_phase "$name" "$rc"
}

overall=complete
run_phase prepare_inputs prepare-inputs.sh || overall=incomplete
if command -v yq >/dev/null 2>&1 && [ -f images.yml ] && [ "$(yq -r '.images // [] | length' images.yml 2>/dev/null || echo 0)" -eq 0 ]; then
  mkdir -p sboms results
  : > skipped_images.txt
  printf '{"phase":"generate_sboms","status":"complete","note":"no images supplied"}\n' > phase-generate_sboms.json
  printf '{"phase":"scan_sboms","status":"complete","note":"no images supplied"}\n' > phase-scan_sboms.json
else
  run_phase generate_sboms generate-sboms.sh || overall=incomplete
  if [ "$JOB_MODE" = "scan" ]; then
    run_phase scan_sboms scan-sboms.sh || overall=incomplete
  fi
fi

if [ "$JOB_MODE" = "sbom" ]; then
  if command -v jq >/dev/null 2>&1; then
    sbom_count=0
    report_count=0
    skipped_count=0
    formats='[]'
    [ -d sboms ] && sbom_count="$(find sboms -maxdepth 1 -name '*.json' -type f | wc -l | tr -d ' ')"
    [ -f skipped_images.txt ] && skipped_count="$(grep -cve '^[[:space:]]*$' skipped_images.txt || true)"
    if [ -s sboms/formats/manifest.json ]; then
      report_count="$(jq '.reports // [] | length' sboms/formats/manifest.json 2>/dev/null || echo 0)"
      formats="$(jq -c '[.reports[]?.format] | unique' sboms/formats/manifest.json 2>/dev/null || echo '[]')"
    fi
    if [ "$report_count" -eq 0 ] || [ "$skipped_count" -gt 0 ]; then
      overall=incomplete
    fi
    jq -n --arg status "$overall" \
      --argjson sboms "$sbom_count" --argjson reports "$report_count" \
      --argjson skipped_images "$skipped_count" --argjson formats "$formats" \
      '{status:$status, sboms:$sboms, reports:$reports, formats:$formats, skipped_images:$skipped_images, skipped_charts:0, results:0, configuration_findings:0}' \
      > scan-summary.json || fatal_phase summary "$?"
  fi
  printf '%s\n' "$overall" > scan-status.txt || fatal_phase summary "$?"
  [ "$overall" = complete ]
  exit $?
fi

run_phase configuration_scan scan-configurations.sh || overall=incomplete
run_phase report_results report.sh || overall=incomplete
REPORT_ONLY=true run_phase report_to_portal report-to-portal.sh || overall=incomplete
run_phase results_assembly assemble-results.sh || overall=incomplete

if command -v jq >/dev/null 2>&1; then
  sbom_count=0; result_count=0; skipped_count=0; skipped_chart_count=0; policy_count=0
  [ -d sboms ] && sbom_count="$(find sboms -name '*.json' -type f | wc -l | tr -d ' ')"
  [ -d results ] && result_count="$(find results -name '*.json' -type f | wc -l | tr -d ' ')"
  [ -f skipped_images.txt ] && skipped_count="$(grep -cve '^[[:space:]]*$' skipped_images.txt || true)"
  [ -f skipped_charts.txt ] && skipped_chart_count="$(grep -cve '^[[:space:]]*$' skipped_charts.txt || true)"
  [ -f portal-policy-findings.json ] && policy_count="$(jq 'length' portal-policy-findings.json 2>/dev/null || echo 0)"
  jq -n --arg status "$overall" \
    --argjson sboms "$sbom_count" --argjson results "$result_count" \
    --argjson skipped_images "$skipped_count" --argjson skipped_charts "$skipped_chart_count" \
    --argjson configuration_findings "$policy_count" \
    '{status:$status, sboms:$sboms, results:$results, skipped_images:$skipped_images, skipped_charts:$skipped_charts, configuration_findings:$configuration_findings}' \
    > scan-summary.json || fatal_phase summary "$?"
fi

# REPORT_ONLY assembles the report without ingesting it. Portal ingestion is
# an explicit authenticated action performed after the public job completes.
printf '%s\n' "$overall" > scan-status.txt || fatal_phase summary "$?"
[ "$overall" = complete ]
