#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIRECTORY}/helm-render-helpers.sh"

TRIVY_CONFIG_SCAN_ENABLED="${TRIVY_CONFIG_SCAN_ENABLED:-false}"
TRIVY_IMAGE_CONFIG_SCAN_ENABLED="${TRIVY_IMAGE_CONFIG_SCAN_ENABLED:-false}"
DOCKLE_IMAGE_CONFIG_SCAN_ENABLED="${DOCKLE_IMAGE_CONFIG_SCAN_ENABLED:-false}"
HELM_SCAN_ENABLED="${HELM_SCAN_ENABLED:-false}"
TRIVY_CONFIG_STRICT="${TRIVY_CONFIG_STRICT:-false}"
TRIVY_OFFLINE="${TRIVY_OFFLINE:-true}"
TRIVY_SKIP_CHECK_UPDATE="${TRIVY_SKIP_CHECK_UPDATE:-$TRIVY_OFFLINE}"
TRIVY_CONFIG_SEVERITIES="${TRIVY_CONFIG_SEVERITIES:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/opt/catscan/trivy-cache}"
TRIVY_CHECKS_BUNDLE_REPOSITORY="${TRIVY_CHECKS_BUNDLE_REPOSITORY:-}"
TRIVY_CONFIG_PATHS="${TRIVY_CONFIG_PATHS:-}"
TRIVY_CONFIG_SKIP_DIRS="${TRIVY_CONFIG_SKIP_DIRS:-.git .cats-helm-graph sboms results trivy-results helm-rendered}"
HELM_CHART_ROOTS="${HELM_CHART_ROOTS:-charts}"
HELM_DEPENDENCY_MODE="${HELM_DEPENDENCY_MODE:-auto}"
HELM_ALLOW_NETWORK="${HELM_ALLOW_NETWORK:-false}"
HELM_DEFAULT_NAMESPACE="${HELM_DEFAULT_NAMESPACE:-default}"

RESULT_ROOT="trivy-results"
RAW_ROOT="${RESULT_ROOT}/raw"
NORMALIZED_ROOT="${RESULT_ROOT}/normalized"
RENDER_ROOT="helm-rendered"
SKIPPED_FILE="configuration-skipped.txt"
SKIPPED_CHARTS_FILE="skipped_charts.txt"
POLICY_FINDINGS_FILE="portal-policy-findings.json"
STATUS_FILE="configuration-scan-status.json"
HELM_DISCOVERY_FILE="helm-discovery.jsonl"
GRAPH_OUTPUT="${HELM_GRAPH_OUTPUT:-.cats-helm-graph.json}"
GRAPH_ENTRIES="${HELM_GRAPH_ENTRIES:-.cats-helm-entries.jsonl}"

mkdir -p "$RAW_ROOT" "$NORMALIZED_ROOT" "$RENDER_ROOT"
: > "$SKIPPED_FILE"
touch "$SKIPPED_CHARTS_FILE"
printf '[]\n' > "$POLICY_FINDINGS_FILE"
[ -f "$HELM_DISCOVERY_FILE" ] || : > "$HELM_DISCOVERY_FILE"

# A chart can be reached from more than one catalog entry (or can refer back
# to an ancestor).  Keep identity by normalized path so recursive discovery is
# finite and does not duplicate the normal Helm processing path.
declare -A HELM_PROCESSED_CHARTS=()

SOURCE_REQUESTED=0
SOURCE_SUCCEEDED=0
DOCKLE_REQUESTED=0
DOCKLE_SUCCEEDED=0
HELM_REQUESTED=0
HELM_SUCCEEDED=0
HELM_SKIPPED=0
FAILURES=0
SCAN_SEQUENCE=0
HELM_SKIPPED=$(grep -cve '^[[:space:]]*$' "$SKIPPED_CHARTS_FILE" 2>/dev/null || true)

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

values_files() {
  if [ -n "${HELM_VALUES_FILES:-}" ]; then
    printf '%s\n' "$HELM_VALUES_FILES" | tr ':' '\n'
  fi
  if [ -f charts.yml ] && command -v yq >/dev/null 2>&1; then
    yq -r '.values_files[]? // .valuesFiles[]? // empty' charts.yml 2>/dev/null || true
  fi
}

safe_name() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '-'
}

record_failure() {
  local kind="$1" target="$2" reason="$3"
  reason="${reason//$'\n'/ }"
  reason="${reason//$'\t'/ }"
  printf '%s\t%s\t%s\n' "$kind" "$target" "$reason" >> "$SKIPPED_FILE"
  FAILURES=$((FAILURES + 1))
  echo "WARNING: ${kind} scan incomplete for ${target}: ${reason}" >&2
}

record_chart_failure() {
  local target="$1" reason="$2"
  reason="${reason//$'\n'/ }"
  reason="${reason//$'\t'/ }"
  printf '%s\t%s\n' "$target" "$reason" >> "$SKIPPED_CHARTS_FILE"
  HELM_SKIPPED=$((HELM_SKIPPED + 1))
  echo "WARNING: Helm chart skipped for ${target}: ${reason}" >&2
}

update_chart_graph_status() {
  local chart_id="$1" chart_path="$2" status="$3" stage="$4" reason="${5:-}" rendered="${6:-}"
  [ -s "$GRAPH_OUTPUT" ] || return 0
  local next_file="${GRAPH_OUTPUT}.next"
  jq --arg id "$chart_id" --arg path "$chart_path" --arg status "$status" --arg stage "$stage" --arg reason "$reason" --arg rendered "$rendered" \
    '(.charts // []) |= map(if (($id != "" and .chart_id == $id) or ($id == "" and .path == $path)) then .status=$status | .render_stage=$stage | (if $reason != "" then .render_error=$reason else . end) | (if $rendered != "" then .rendered_manifest=$rendered else . end) else . end)' \
    "$GRAPH_OUTPUT" > "$next_file" 2>/dev/null && mv "$next_file" "$GRAPH_OUTPUT"
}

merge_policy_findings() {
  local input="$1" next_file="${POLICY_FINDINGS_FILE}.next"
  jq -s '.[0] + .[1] | unique_by(.fingerprint)' \
    "$POLICY_FINDINGS_FILE" "$input" > "$next_file"
  mv "$next_file" "$POLICY_FINDINGS_FILE"
}

write_status() {
  local complete=true
  [ "$FAILURES" -eq 0 ] && [ "$HELM_SKIPPED" -eq 0 ] || complete=false
  jq -n \
    --argjson enabled "$(if is_true "$TRIVY_CONFIG_SCAN_ENABLED" || is_true "$TRIVY_IMAGE_CONFIG_SCAN_ENABLED" || is_true "$DOCKLE_IMAGE_CONFIG_SCAN_ENABLED" || is_true "$HELM_SCAN_ENABLED"; then echo true; else echo false; fi)" \
    --argjson complete "$complete" \
    --argjson source_requested "$SOURCE_REQUESTED" \
    --argjson source_succeeded "$SOURCE_SUCCEEDED" \
    --argjson dockle_requested "$DOCKLE_REQUESTED" \
    --argjson dockle_succeeded "$DOCKLE_SUCCEEDED" \
    --argjson helm_requested "$HELM_REQUESTED" \
    --argjson helm_succeeded "$HELM_SUCCEEDED" \
    --argjson helm_skipped "$HELM_SKIPPED" \
    --argjson failures "$FAILURES" \
    --arg offline "$TRIVY_OFFLINE" \
    --arg dependency_mode "$HELM_DEPENDENCY_MODE" \
    '{
      enabled: $enabled,
      complete: $complete,
      offline: ($offline | ascii_downcase) == "true",
      helm_dependency_mode: $dependency_mode,
      source: {requested: $source_requested, succeeded: $source_succeeded},
      dockle: {requested: $dockle_requested, succeeded: $dockle_succeeded},
      helm: {requested: $helm_requested, succeeded: $helm_succeeded, skipped: $helm_skipped},
      failures: $failures
    }' > "$STATUS_FILE"
}

finish() {
  sort -u "$SKIPPED_CHARTS_FILE" -o "$SKIPPED_CHARTS_FILE" 2>/dev/null || true
  write_status
  local finding_count
  finding_count="$(jq 'length' "$POLICY_FINDINGS_FILE")"
  echo "Configuration scan summary: ${finding_count} finding(s); ${FAILURES} incomplete target(s)."
  if [ "$FAILURES" -gt 0 ] && is_true "$TRIVY_CONFIG_STRICT"; then
    return 1
  fi
  return 0
}

run_trivy_config() {
  local kind="$1" label="$2" input_path="$3" deployment_namespace="$4" framework="$5"
  local safe raw normalized
  local -a command skip_dirs

  SCAN_SEQUENCE=$((SCAN_SEQUENCE + 1))
  safe="$(printf '%03d-%s' "$SCAN_SEQUENCE" "$(safe_name "$label")")"
  raw="${RAW_ROOT}/${safe}.json"
  normalized="${NORMALIZED_ROOT}/${safe}.json"

  command=(trivy config
    --format json
    --output "$raw"
    --severity "$TRIVY_CONFIG_SEVERITIES"
    --exit-code 0
    --cache-dir "$TRIVY_CACHE_DIR"
    --skip-version-check
    --disable-telemetry)

  if is_true "$TRIVY_SKIP_CHECK_UPDATE"; then
    command+=(--skip-check-update)
  fi

  if [ -n "$TRIVY_CHECKS_BUNDLE_REPOSITORY" ]; then
    command+=(--checks-bundle-repository "$TRIVY_CHECKS_BUNDLE_REPOSITORY")
  fi

  read -r -a skip_dirs <<< "$TRIVY_CONFIG_SKIP_DIRS"
  for skip_dir in "${skip_dirs[@]}"; do
    [ -n "$skip_dir" ] && command+=(--skip-dirs "$skip_dir")
  done

  command+=("$input_path")
  echo "Scanning ${kind} configuration target: ${label} (${input_path})"
  if ! "${command[@]}"; then
    if [ "$kind" = "helm" ]; then
      record_chart_failure "$label" "Trivy execution failed"
    else
      record_failure "$kind" "$label" "Trivy execution failed"
    fi
    return 1
  fi

  if ! bash "${SCRIPT_DIRECTORY}/normalize-trivy-config.sh" \
      "$raw" "$normalized" "$label" "$deployment_namespace" "$framework"; then
    if [ "$kind" = "helm" ]; then
      record_chart_failure "$label" "Trivy result normalization failed"
    else
      record_failure "$kind" "$label" "Trivy result normalization failed"
    fi
    return 1
  fi

  merge_policy_findings "$normalized"
  return 0
}

run_trivy_image_config() {
  local image="$1" safe raw normalized
  local -a command

  SOURCE_REQUESTED=$((SOURCE_REQUESTED + 1))
  safe="$(safe_name "$image")"
  raw="${RAW_ROOT}/image-${safe}.json"
  normalized="${NORMALIZED_ROOT}/image-${safe}.json"

  if grep -Fqx "$image" skipped_images.txt 2>/dev/null; then
    record_failure image "$image" "Image was unavailable during SBOM generation"
    return 1
  fi

  command=(trivy image
    --scanners misconfig
    --image-config-scanners misconfig
    --format json
    --output "$raw"
    --severity "$TRIVY_CONFIG_SEVERITIES"
    --exit-code 0
    --cache-dir "$TRIVY_CACHE_DIR"
    --skip-version-check
    --disable-telemetry)

  if is_true "$TRIVY_SKIP_CHECK_UPDATE"; then
    command+=(--skip-check-update)
  fi

  if [ -n "$TRIVY_CHECKS_BUNDLE_REPOSITORY" ]; then
    command+=(--checks-bundle-repository "$TRIVY_CHECKS_BUNDLE_REPOSITORY")
  fi

  echo "Scanning image configuration: ${image}"
  if ! "${command[@]}" "$image"; then
    record_failure image "$image" "Trivy image configuration scan failed"
    return 1
  fi

  if ! bash "${SCRIPT_DIRECTORY}/normalize-trivy-config.sh" \
      "$raw" "$normalized" "$image" "" "Docker Image Configuration"; then
    record_failure image "$image" "Image configuration result normalization failed"
    return 1
  fi

  merge_policy_findings "$normalized"
  SOURCE_SUCCEEDED=$((SOURCE_SUCCEEDED + 1))
  return 0
}

run_dockle_image_config() {
  local image="$1" safe raw normalized
  local -a command

  DOCKLE_REQUESTED=$((DOCKLE_REQUESTED + 1))
  safe="$(safe_name "$image")"
  raw="${RAW_ROOT}/image-${safe}-dockle.json"
  normalized="${NORMALIZED_ROOT}/image-${safe}-dockle.json"

  # Trivy already records unavailable images as missing evidence. Do not
  # duplicate that entry when Dockle sees the same skipped image.
  if grep -Fqx "$image" skipped_images.txt 2>/dev/null; then
    echo "Skipping Dockle for unavailable image: ${image}"
    return 0
  fi

  command=(dockle
    --format json
    --output "$raw"
    --exit-code 0)

  echo "Scanning image hardening: ${image}"
  if ! "${command[@]}" "$image"; then
    record_failure image "$image" "Dockle image hardening scan failed"
    return 1
  fi

  if ! bash "${SCRIPT_DIRECTORY}/normalize-dockle-config.sh" \
      "$raw" "$normalized" "$image"; then
    record_failure image "$image" "Dockle result normalization failed"
    return 1
  fi

  merge_policy_findings "$normalized"
  DOCKLE_SUCCEEDED=$((DOCKLE_SUCCEEDED + 1))
  return 0
}

verify_vendored_dependencies() {
  local chart_root="$1" chart_yaml dependency_dir dependency_name dependency_alias dependency_version expected_name
  local missing=0

  while IFS= read -r chart_yaml; do
    dependency_dir="$(dirname "$chart_yaml")"
    while IFS=$'\t' read -r dependency_name dependency_alias dependency_version; do
      [ -n "$dependency_name" ] || continue
      expected_name="${dependency_alias:-$dependency_name}"
      if [ -d "${dependency_dir}/charts/${expected_name}" ]; then
        continue
      fi
      if find "${dependency_dir}/charts" -maxdepth 1 -type f \( \
          -name "${dependency_name}-*.tgz" -o -name "${dependency_alias}-*.tgz" \) -print -quit 2>/dev/null \
          | grep -q .; then
        continue
      fi
      echo "Missing vendored dependency ${dependency_name} ${dependency_version} for ${chart_yaml}" >&2
      missing=1
    done < <(yq -r '.dependencies[]? | [.name, (.alias // ""), (.version // "")] | @tsv' "$chart_yaml")
  done < <(find "$chart_root" -type f -name Chart.yaml -print | sort)

  [ "$missing" -eq 0 ]
}

prepare_chart_dependencies() {
  local chart_dir="$1" mode="$2" repository
  case "$mode" in
    auto)
      if verify_vendored_dependencies "$chart_dir"; then
        return 0
      fi
      if ! is_true "$HELM_ALLOW_NETWORK"; then
        return 1
      fi
      helm dependency build "$chart_dir" && verify_vendored_dependencies "$chart_dir"
      ;;
    vendored)
      verify_vendored_dependencies "$chart_dir"
      ;;
    local)
      while IFS= read -r repository; do
        [ -z "$repository" ] && continue
        case "$repository" in
          file://*) ;;
          *)
            echo "Dependency repository is not local: ${repository}" >&2
            return 1
            ;;
        esac
      done < <(yq -r '.dependencies[]?.repository // ""' "${chart_dir}/Chart.yaml")
      helm dependency build --skip-refresh "$chart_dir" && verify_vendored_dependencies "$chart_dir"
      ;;
    online)
      if ! is_true "$HELM_ALLOW_NETWORK"; then
        echo "HELM_DEPENDENCY_MODE=online requires HELM_ALLOW_NETWORK=true" >&2
        return 1
      fi
      helm dependency build "$chart_dir" && verify_vendored_dependencies "$chart_dir"
      ;;
    *)
      echo "Unknown Helm dependency mode: ${mode}" >&2
      return 1
      ;;
  esac
}

is_vendored_chart() {
  local chart_yaml="$1" probe parent
  probe="$(dirname "$chart_yaml")"
  while [ "$probe" != "." ] && [ "$probe" != "/" ]; do
    parent="$(dirname "$probe")"
    if [ "$(basename "$probe")" = "charts" ] && [ -f "${parent}/Chart.yaml" ]; then
      return 0
    fi
    [ "$parent" = "$probe" ] && break
    probe="$parent"
  done
  return 1
}

materialize_remote_chart() {
  local entry_json="$1" destination="$2" reference repository version chart_name chart_yaml
  local -a pull_command
  reference="$(jq -r '.reference // .chart // empty' <<< "$entry_json")"
  repository="$(jq -r '.repository // empty' <<< "$entry_json")"
  version="$(jq -r '.version // empty' <<< "$entry_json")"
  chart_name="$(jq -r '.name // empty' <<< "$entry_json")"

  if ! is_true "$HELM_ALLOW_NETWORK"; then
    echo "Remote chart ${reference:-$chart_name} requires HELM_ALLOW_NETWORK=true" >&2
    return 1
  fi

  mkdir -p "$destination"
  pull_command=(helm pull "${reference:-$chart_name}" --untar --untardir "$destination")
  [ -n "$repository" ] && pull_command+=(--repo "$repository")
  [ -n "$version" ] && pull_command+=(--version "$version")
  "${pull_command[@]}" >&2 || return 1
  chart_yaml="$(find "$destination" -mindepth 2 -maxdepth 2 -type f -name Chart.yaml -print -quit)"
  [ -n "$chart_yaml" ] || return 1
  dirname "$chart_yaml"
}

chart_identity() {
  local chart_path="$1" resolved
  if resolved="$(cd "$chart_path" 2>/dev/null && pwd -P)"; then
    printf '%s' "$resolved"
  else
    printf '%s' "$chart_path"
  fi
}

source_path_for() {
  local value="$1"
  case "$value" in
    "$PWD"/*) printf '%s' "${value#"$PWD"/}" ;;
    *) printf '%s' "$value" ;;
  esac
}

record_chart_discovery() {
  local chart_name="$1" chart_path="$2" declared_by="$3" enabled="$4" status="$5" reason="${6:-}"
  jq -cn --arg chart "$chart_name" --arg path "$chart_path" --arg declared_by "$declared_by" \
    --arg enabled "$enabled" --arg status "$status" --arg reason "$reason" \
    '{chart:$chart,path:$path,declared_by:$declared_by,enabled:$enabled,declared_state:(if $enabled == "true" then true elif $enabled == "false" then false else null end),status:$status} + (if $reason != "" then {reason:$reason} else {} end)' \
    >> "$HELM_DISCOVERY_FILE"
}

resolve_declared_chart() {
  local parent_chart="$1" component_name="$2" explicit_path="${3:-}" candidate chart_yaml
  local parent_root parent_parent
  parent_root="$(chart_identity "$parent_chart")"
  parent_parent="$(dirname "$parent_root")"

  # Explicit paths are preferred, but still require a real Chart.yaml.
  if [ -n "$explicit_path" ]; then
    case "$explicit_path" in
      /*) candidate="$explicit_path" ;;
      *) candidate="${parent_root}/${explicit_path}" ;;
    esac
    [ -f "${candidate}/Chart.yaml" ] && { chart_identity "$candidate"; return 0; }
  fi

  # These layouts cover charts/<component>, a sibling chart directory, and a
  # root chart whose own charts/ directory contains the component.
  for candidate in \
    "${parent_root}/charts/${component_name}" \
    "${parent_parent}/${component_name}" \
    "${parent_parent}/charts/${component_name}"; do
    [ -f "${candidate}/Chart.yaml" ] && { chart_identity "$candidate"; return 0; }
  done

  # Last, search only chart directories with the requested basename.  The
  # Chart.yaml check prevents arbitrary values keys from becoming charts.
  while IFS= read -r chart_yaml; do
    [ -n "$chart_yaml" ] || continue
    candidate="$(dirname "$chart_yaml")"
    [ "$(basename "$candidate")" = "$component_name" ] || continue
    chart_identity "$candidate"
    return 0
  done < <(find "$parent_root" "$parent_parent" -type f -path "*/${component_name}/Chart.yaml" -print 2>/dev/null | sort -u)
  return 1
}

discover_local_components() {
  local parent_chart="$1" declared_by="$2" values_file="$1/values.yaml"
  declared_by="$(source_path_for "$declared_by")"
  local encoded entry component enabled explicit_path resolved reason repo_url repo_name chart_ref version
  [ -f "$values_file" ] || return 0

  # Only the established services/service catalog sections are interpreted.
  # A random `metrics.enabled` (or any other top-level enabled key) is never a
  # chart unless it resolves to an actual chart directory.
  while IFS= read -r encoded; do
    [ -n "$encoded" ] || continue
    entry="$(printf '%s' "$encoded" | base64 -d 2>/dev/null || true)"
    component="$(jq -r '.name // empty' <<< "$entry")"
    [ -n "$component" ] || continue
    enabled="$(jq -r 'if .enabled == true then "true" elif .enabled == false then "false" else "unknown" end' <<< "$entry")"
    explicit_path="$(jq -r '.path // .chartPath // .chart_path // .localPath // .local_path // empty' <<< "$entry")"
    repo_url="$(jq -r '.repo_url // empty' <<< "$entry")"
    repo_name="$(jq -r '.repo_name // empty' <<< "$entry")"
    chart_ref="$(jq -r '.chart_ref // empty' <<< "$entry")"
    version="$(jq -r '.version // empty' <<< "$entry")"
    if resolved="$(resolve_declared_chart "$parent_chart" "$component" "$explicit_path")"; then
      record_chart_discovery "$component" "$resolved" "$declared_by" "$enabled" "resolved"
      process_chart_entry "$(jq -c --arg path "$resolved" --arg name "$component" --arg declared_by "$declared_by" --arg enabled "$enabled" \
        '. + {path:$path,name:$name,declared_by:$declared_by,declared_enabled:$enabled}' <<< "$entry")"
    elif [ -n "$repo_url" ] && [ -n "${chart_ref:-$component}" ]; then
      # A catalog may intentionally point at a remote child chart.  Reuse the
      # existing remote materialization path; network policy still controls
      # whether it is permitted.
      record_chart_discovery "$component" "" "$declared_by" "$enabled" "remote"
      process_chart_entry "$(jq -c --arg name "$component" --arg reference "${chart_ref:-$component}" --arg repository "$repo_url" --arg version "$version" --arg declared_by "$declared_by" --arg enabled "$enabled" \
        '. + {name:$name,reference:$reference,repository:$repository,version:$version,declared_by:$declared_by,declared_enabled:$enabled}' <<< "$entry")"
    else
      reason="Declared Helm component could not be resolved (source: ${declared_by})"
      record_chart_discovery "$component" "" "$declared_by" "$enabled" "unresolved" "$reason"
      record_chart_failure "$component" "$reason"
    fi
  done < <(yq -o=json '(.services // .service // {}) | select(type == "object") | to_entries[] | select(.value | type == "object") | select((.value | has("enabled")) or (.value | has("path")) or (.value | has("chartPath")) or (.value | has("chart_path")) or (.value | has("localPath")) or (.value | has("local_path")) or (.value | has("helmRepo")) or (.value | has("helm_repo"))) | {name:.key, enabled:(.value.enabled // null), path:(.value.path // null), chartPath:(.value.chartPath // null), chart_path:(.value.chart_path // null), localPath:(.value.localPath // null), local_path:(.value.local_path // null), repo_name:(.value.helmRepo.repoName // .value.helm_repo.repo_name // ""), repo_url:(.value.helmRepo.repoUrl // .value.helm_repo.repo_url // ""), version:(.value.helmRepo.version // .value.helm_repo.version // ""), chart_ref:(.value.helmRepo.chart // .value.helm_repo.chart // .value.chart // "")}' "$values_file" 2>/dev/null | jq -r '. | @base64' 2>/dev/null)
}

process_chart_entry() {
  local entry_json="$1" path reference name release namespace dependency_mode include_crds framework declared_by declared_enabled
  local rendered safe chart_name values_file set_value chart_workspace chart_source_identity chart_identity_digest normalized_identity chart_instance_id
  local -a helm_command

  path="$(jq -r '.path // empty' <<< "$entry_json")"
  reference="$(jq -r '.reference // .chart // empty' <<< "$entry_json")"
  name="$(jq -r '.name // empty' <<< "$entry_json")"
  release="$(jq -r '.release // .name // empty' <<< "$entry_json")"
  namespace="$(jq -r --arg default_namespace "$HELM_DEFAULT_NAMESPACE" '.namespace // $default_namespace' <<< "$entry_json")"
  dependency_mode="$(jq -r --arg mode "$HELM_DEPENDENCY_MODE" '.dependency_mode // $mode' <<< "$entry_json")"
  include_crds="$(jq -r '.include_crds // true' <<< "$entry_json")"
  framework="$(jq -r '.framework // empty' <<< "$entry_json")"
  declared_by="$(jq -r '.declared_by // empty' <<< "$entry_json")"
  declared_enabled="$(jq -r '.declared_enabled // empty' <<< "$entry_json")"
  chart_source_identity="${path:-${reference:-$name}}"

  HELM_REQUESTED=$((HELM_REQUESTED + 1))
  chart_workspace="${RESULT_ROOT}/charts/${HELM_REQUESTED}"
  if [ -z "$path" ]; then
    if [ -z "$reference" ] && [ -z "$name" ]; then
      record_chart_failure "entry-${HELM_REQUESTED}" "Chart entry has neither path nor reference"
      return
    fi
    path="$(materialize_remote_chart "$entry_json" "$chart_workspace")" || {
      record_chart_failure "${reference:-$name}" "Unable to download remote chart"
      return
    }
  fi

  if [ ! -f "${path}/Chart.yaml" ]; then
    record_chart_failure "${name:-$path}" "Chart.yaml not found at ${path}"
    return
  fi

  normalized_identity="$(chart_identity "$path")"
  chart_instance_id="$(jq -r '.chart_id // empty' <<< "$entry_json" 2>/dev/null || true)"
  [ -n "$chart_instance_id" ] && normalized_identity="${normalized_identity}|${chart_instance_id}"
  if [ -n "${HELM_PROCESSED_CHARTS[$normalized_identity]:-}" ]; then
    return
  fi
  HELM_PROCESSED_CHARTS["$normalized_identity"]=1
  [ -n "$declared_by" ] && record_chart_discovery "${name:-$(basename "$path")}" "$normalized_identity" "$declared_by" "${declared_enabled:-unknown}" "processing"

  chart_name="$(yq -r '.name // empty' "${path}/Chart.yaml")"
  chart_name="${chart_name:-$(basename "$path")}"
  name="${name:-$chart_name}"
  release="${release:-$name}"
  release="${release:-chart-${HELM_REQUESTED}}"
  # Discover declared children even if dependency resolution or rendering
  # later fails; useful inventory and Missing Evidence must not be erased by a
  # separate Helm failure.
  if ! jq -e '.graph_discovery == true' <<< "$entry_json" >/dev/null 2>&1; then
    discover_local_components "$path" "${normalized_identity}/values.yaml"
  fi
  if ! prepare_chart_dependencies "$path" "$dependency_mode"; then
    update_chart_graph_status "$chart_instance_id" "$path" "Render Failed" "dependencies" "Helm dependencies are unavailable for mode ${dependency_mode}"
    record_chart_failure "$name" "Helm dependencies are unavailable for mode ${dependency_mode}"
    return
  fi

  chart_identity_digest="$(
    printf '%s' "${chart_source_identity}|${release}|${namespace}|${chart_instance_id}" \
      | sha256sum | awk '{print substr($1, 1, 12)}'
  )"
  safe="$(printf '%s-%s' "$(safe_name "$name")" "$chart_identity_digest")"
  rendered="${RENDER_ROOT}/${safe}.yaml"
  helm_command=(helm template "$release" "$path" --namespace "$namespace")
  is_true "$include_crds" && helm_command+=(--include-crds)

  while IFS= read -r values_file; do
    [ -n "$values_file" ] || continue
    if [ ! -f "$values_file" ]; then
      update_chart_graph_status "$chart_instance_id" "$path" "Render Failed" "values" "Values file not found: ${values_file}"
      record_chart_failure "$name" "Values file not found: ${values_file}"
      return
    fi
    helm_command+=(-f "$values_file")
  done < <(jq -r '.values[]?' <<< "$entry_json")

  while IFS= read -r set_value; do
    [ -n "$set_value" ] && helm_command+=(--set-string "$set_value")
  done < <(jq -r '
    (.set // [])
    | if type == "object"
      then to_entries[] | "\(.key)=\(.value)"
      else .[]?
      end
  ' <<< "$entry_json")

  echo "Rendering Helm chart ${name} as release ${release} in namespace ${namespace}"
  if ! helm_render_with_bitnami_retry "$rendered" "$name" "$chart_source_identity" "${helm_command[@]}"; then
    reason="helm template failed"
    [ -n "$HELM_RENDER_LAST_ERROR" ] && reason="${reason}: ${HELM_RENDER_LAST_ERROR}"
    record_chart_failure "$name" "$reason"
    update_chart_graph_status "$chart_instance_id" "$path" "Render Failed" "helm template" "$reason"
    return
  fi
  if [ ! -s "$rendered" ]; then
    update_chart_graph_status "$chart_instance_id" "$path" "Render Failed" "helm template" "helm template produced no Kubernetes manifests"
    record_chart_failure "$name" "helm template produced no Kubernetes manifests"
    return
  fi
  printf '%s\n' "$entry_json" > "${rendered%.yaml}.chart.json"
  update_chart_graph_status "$chart_instance_id" "$path" "Rendered" "helm template" "" "$rendered"

  if run_trivy_config helm "${name} (${release})" "$rendered" "$namespace" "$framework"; then
    HELM_SUCCEEDED=$((HELM_SUCCEEDED + 1))
  else
    update_chart_graph_status "$chart_instance_id" "$path" "Partially Rendered" "trivy config" "Helm rendered successfully, but configuration evidence was not produced"
  fi
}

# Values-file application catalogs are an alternate chart input contract used
# by self-service environments. Every services.* entry whose sourceType is
# helm is processed; enabled/disabled is intentionally not a gate. A failed
# repository/chart is recorded as skipped evidence and does not abort the scan.
process_values_file_apps() {
  local values_file="$1" encoded entry app_name source_type repo_name repo_url version chart_ref
  [ -f "$values_file" ] || { record_chart_failure "$values_file" "Values file not found"; return; }
  while IFS= read -r encoded; do
    [ -n "$encoded" ] || continue
    entry="$(printf '%s' "$encoded" | base64 -d 2>/dev/null || true)"
    app_name="$(jq -r '.name // empty' <<< "$entry")"
    source_type="$(jq -r '.source_type // empty' <<< "$entry")"
    [ "$source_type" = "helm" ] || continue
    repo_name="$(jq -r '.repo_name // empty' <<< "$entry")"
    repo_url="$(jq -r '.repo_url // empty' <<< "$entry")"
    version="$(jq -r '.version // empty' <<< "$entry")"
    chart_ref="$(jq -r '.chart_ref // empty' <<< "$entry")"
    if [ -z "$repo_url" ] || [ -z "$repo_name" ]; then
      record_chart_failure "$app_name" "Helm app is missing helmRepo.repoName or helmRepo.repoUrl"
      continue
    fi
    chart_ref="${chart_ref:-$app_name}"
    entry="$(jq --arg name "$app_name" --arg reference "$chart_ref" --arg repository "$repo_url" --arg version "$version" --arg declared_by "$values_file" \
      '(. // {}) + {name:$name, reference:$reference, repository:$repository, version:$version, declared_by:$declared_by, declared_enabled:(if .enabled == true then "true" elif .enabled == false then "false" else "unknown" end)}' <<< "$entry")"
    process_chart_entry "$entry"
  done < <(yq -o=json '.services // {} | to_entries[] | {name:.key, enabled:(.value.enabled // null), source_type:(.value.sourceType // .value.source_type // ""), repo_name:(.value.helmRepo.repoName // .value.helm_repo.repo_name // ""), repo_url:(.value.helmRepo.repoUrl // .value.helm_repo.repo_url // ""), version:(.value.helmRepo.version // .value.helm_repo.version // ""), chart_ref:(.value.helmRepo.chart // .value.helm_repo.chart // .value.chart // ""), values:(.value.valuesFiles // .value.values_files // [])} ' "$values_file" 2>/dev/null | jq -r '. | @base64' 2>/dev/null)
}

if ! is_true "$TRIVY_CONFIG_SCAN_ENABLED" && ! is_true "$TRIVY_IMAGE_CONFIG_SCAN_ENABLED" && ! is_true "$DOCKLE_IMAGE_CONFIG_SCAN_ENABLED" && ! is_true "$HELM_SCAN_ENABLED"; then
  echo "Trivy configuration and Helm scanning are disabled."
  finish
  exit $?
fi

# A rendered Helm scan is authoritative for charts. Excluding the chart roots
# from the general source scan avoids reporting each chart rule twice.
if is_true "$HELM_SCAN_ENABLED"; then
  TRIVY_CONFIG_SKIP_DIRS="${TRIVY_CONFIG_SKIP_DIRS} ${HELM_CHART_ROOTS}"
  if [ -f charts.yml ] && command -v yq >/dev/null 2>&1; then
    while IFS= read -r configured_chart_path; do
      [ -n "$configured_chart_path" ] \
        && TRIVY_CONFIG_SKIP_DIRS="${TRIVY_CONFIG_SKIP_DIRS} ${configured_chart_path}"
    done < <(yq -r '.charts[]?.path // ""' charts.yml)
  fi
fi

for required_tool in base64 jq sha256sum trivy; do
  if ! command -v "$required_tool" >/dev/null 2>&1; then
    record_failure tooling "$required_tool" "Required executable is not installed in the CATScan image"
  fi
done
if is_true "$DOCKLE_IMAGE_CONFIG_SCAN_ENABLED" && ! command -v dockle >/dev/null 2>&1; then
  record_failure tooling dockle "Required executable is not installed in the CATScan image"
fi
if command -v trivy >/dev/null 2>&1; then
  if ! mkdir -p "$TRIVY_CACHE_DIR" 2>/dev/null || [ ! -w "$TRIVY_CACHE_DIR" ]; then
    record_failure tooling "$TRIVY_CACHE_DIR" "Trivy cache directory is not writable"
  fi
fi
if [ "$FAILURES" -gt 0 ]; then
  finish
  exit $?
fi

if is_true "$TRIVY_IMAGE_CONFIG_SCAN_ENABLED" || is_true "$DOCKLE_IMAGE_CONFIG_SCAN_ENABLED"; then
  if [ -f final_images.txt ]; then
    while IFS= read -r image; do
      [ -n "$image" ] || continue
      if is_true "$TRIVY_IMAGE_CONFIG_SCAN_ENABLED"; then
        run_trivy_image_config "$image" || true
      fi
      if is_true "$DOCKLE_IMAGE_CONFIG_SCAN_ENABLED"; then
        run_dockle_image_config "$image" || true
      fi
    done < final_images.txt
  else
    echo "No final_images.txt found; image configuration scanning is not applicable."
  fi
fi

if is_true "$TRIVY_CONFIG_SCAN_ENABLED"; then
  config_paths="$TRIVY_CONFIG_PATHS"
  if [ -z "$config_paths" ]; then
    if [ -n "${UPSTREAM_PROJECT_ID:-}" ]; then
      [ -d configuration ] && config_paths="configuration"
    else
      config_paths="."
    fi
  fi

  if [ -z "$config_paths" ]; then
    record_failure source "configuration inputs" "No source configuration directory was supplied by the upstream pipeline"
  else
    read -r -a source_paths <<< "$config_paths"
    for source_path in "${source_paths[@]}"; do
      SOURCE_REQUESTED=$((SOURCE_REQUESTED + 1))
      if [ ! -e "$source_path" ]; then
        record_failure source "$source_path" "Configuration path does not exist"
        continue
      fi
      if run_trivy_config source "$source_path" "$source_path" "" ""; then
        SOURCE_SUCCEEDED=$((SOURCE_SUCCEEDED + 1))
      fi
    done
  fi
fi

if is_true "$HELM_SCAN_ENABLED"; then
  helm_tools_ready=true
  for required_tool in helm yq; do
    if ! command -v "$required_tool" >/dev/null 2>&1; then
      record_chart_failure "tooling:${required_tool}" "Required executable is not installed in the CATScan image"
      helm_tools_ready=false
    fi
  done

  if is_true "$helm_tools_ready"; then
    if command -v python3 >/dev/null 2>&1; then
      python3 "${SCRIPT_DIRECTORY}/discover-helm-graph.py" --root . --output "$GRAPH_OUTPUT" --entries "$GRAPH_ENTRIES" \
        || record_chart_failure "helm-discovery" "Recursive Helm graph discovery failed; using configured chart signals"
    fi
    if [ -s "$GRAPH_ENTRIES" ]; then
      while IFS= read -r graph_entry; do
        [ -n "$graph_entry" ] || continue
        if jq -e '.embedded_dependency == true' <<< "$graph_entry" >/dev/null 2>&1; then
          continue
        fi
        process_chart_entry "$(jq -c '. + {graph_discovery:true}' <<< "$graph_entry")"
      done < "$GRAPH_ENTRIES"
    elif [ -f charts.yml ]; then
      charts_json="$(yq -o=json '.charts // []' charts.yml)"
      while IFS= read -r encoded_entry; do
        [ -n "$encoded_entry" ] || continue
        process_chart_entry "$(printf '%s' "$encoded_entry" | base64 -d)"
      done < <(jq -r '.[] | @base64' <<< "$charts_json")
    else
      discovered_file="${RESULT_ROOT}/discovered-charts.txt"
      : > "$discovered_file"
      read -r -a chart_roots <<< "$HELM_CHART_ROOTS"
      for chart_root in "${chart_roots[@]}"; do
        [ -d "$chart_root" ] || continue
        while IFS= read -r discovered_chart; do
          is_vendored_chart "$discovered_chart" \
            || printf '%s\n' "$discovered_chart" >> "$discovered_file"
        done < <(find "$chart_root" -type f -name Chart.yaml -print | sort)
      done
      sort -u "$discovered_file" -o "$discovered_file"
      while IFS= read -r chart_yaml; do
        [ -n "$chart_yaml" ] || continue
        chart_path="$(dirname "$chart_yaml")"
        process_chart_entry "$(jq -n --arg path "$chart_path" '{path: $path}')"
      done < "$discovered_file"
    fi

      while IFS= read -r values_file; do
        [ -n "$values_file" ] || continue
        process_values_file_apps "$values_file"
      done < <(values_files | sort -u)

if [ "$HELM_REQUESTED" -eq 0 ]; then
      echo "No Helm charts found; Helm scanning is not applicable for this service."
    fi
  fi
fi

if [ -d helm-rendered ]; then
  echo "Rendered Helm resources:"
  find helm-rendered -type f \( -name '*.yaml' -o -name '*.yml' \) -print | sort || true
  echo "Rendered Helm byte count:"
  find helm-rendered -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 \
    | xargs -0r wc -c || true
  bash "$(dirname "$0")/extract-service-overview.sh" helm-rendered service-overview.json || \
    echo "WARNING: Unable to generate service overview from rendered Helm resources."
fi

finish
