#!/usr/bin/env bash

# Best-effort Helm image handoff. Chart rendering problems are evidence gaps,
# except for the narrowly handled Bitnami verification retry; scan-configurations
# will append its own chart results to the same skipped_charts.txt file later.
set -uo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIRECTORY}/helm-render-helpers.sh"

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

# Image handoff is automatic when chart inputs are present. HELM_SCAN_ENABLED
# still controls whether the later Trivy configuration/policy scan runs, but it
# is not required just to discover images referenced by submitted charts.
if [ ! -f charts.yml ] && [ ! -d charts ] && [ -z "$(values_files | sed '/^[[:space:]]*$/d' | head -n 1)" ] \
  && [ -z "$(find . -type f \( -name 'Chart.yaml' -o -name '*.tgz' -o -name '*.tar.gz' -o -name '*.zip' -o -name '*.yaml' -o -name '*.yml' \) -print -quit 2>/dev/null)" ]; then
  exit 0
fi

SKIPPED_CHARTS_FILE="${SKIPPED_CHARTS_FILE:-skipped_charts.txt}"
RENDER_ROOT="${HELM_IMAGE_RENDER_ROOT:-helm-image-rendered}"
IMAGE_FILE="helm-images.txt"
DISCOVERY_FILE="helm-discovery.jsonl"
HELM_DEPENDENCY_MODE="${HELM_DEPENDENCY_MODE:-auto}"
: > "$IMAGE_FILE"
: > "$DISCOVERY_FILE"
touch "$SKIPPED_CHARTS_FILE"
mkdir -p "$RENDER_ROOT"
declare -A PROCESSED_CHARTS=()

record_skip() {
  local target="$1" reason="$2"
  reason="${reason//$'\n'/ }"
  reason="${reason//$'\t'/ }"
  printf '%s\t%s\n' "$target" "$reason" >> "$SKIPPED_CHARTS_FILE"
  echo "WARNING: Helm image handoff skipped for ${target}: ${reason}" >&2
}

chart_identity() {
  local chart_path="$1"
  cd "$chart_path" 2>/dev/null && pwd -P || printf '%s' "$chart_path"
}

source_path_for() {
  local value="$1"
  case "$value" in
    "$PWD"/*) printf '%s' "${value#"$PWD"/}" ;;
    *) printf '%s' "$value" ;;
  esac
}

record_discovery() {
  local name="$1" path="$2" declared_by="$3" enabled="$4" status="$5" reason="${6:-}"
  jq -cn --arg chart "$name" --arg path "$path" --arg declared_by "$declared_by" --arg enabled "$enabled" --arg status "$status" --arg reason "$reason" \
    '{chart:$chart,path:$path,declared_by:$declared_by,enabled:$enabled,declared_state:(if $enabled == "true" then true elif $enabled == "false" then false else null end),status:$status} + (if $reason != "" then {reason:$reason} else {} end)' >> "$DISCOVERY_FILE"
}

resolve_declared_chart() {
  local parent="$1" name="$2" explicit="${3:-}" root candidate chart_yaml
  root="$(chart_identity "$parent")"
  if [ -n "$explicit" ]; then
    case "$explicit" in /*) candidate="$explicit" ;; *) candidate="$root/$explicit" ;; esac
    [ -f "$candidate/Chart.yaml" ] && { chart_identity "$candidate"; return 0; }
  fi
  for candidate in "$root/charts/$name" "$(dirname "$root")/$name" "$(dirname "$root")/charts/$name"; do
    [ -f "$candidate/Chart.yaml" ] && { chart_identity "$candidate"; return 0; }
  done
  while IFS= read -r chart_yaml; do
    candidate="$(dirname "$chart_yaml")"
    [ "$(basename "$candidate")" = "$name" ] && { chart_identity "$candidate"; return 0; }
  done < <(find "$root" "$(dirname "$root")" -type f -path "*/${name}/Chart.yaml" -print 2>/dev/null | sort -u)
  return 1
}

discover_components() {
  local parent="$1" declared_by="$2" values_file="$1/values.yaml" encoded entry name enabled explicit resolved reason repo_url chart_ref version download_dir
  declared_by="$(source_path_for "$declared_by")"
  [ -f "$values_file" ] || return 0
  while IFS= read -r encoded; do
    [ -n "$encoded" ] || continue
    entry="$(printf '%s' "$encoded" | base64 -d 2>/dev/null || true)"
    name="$(jq -r '.name // empty' <<< "$entry")"
    [ -n "$name" ] || continue
    enabled="$(jq -r 'if .enabled == true then "true" elif .enabled == false then "false" else "unknown" end' <<< "$entry")"
    explicit="$(jq -r '.path // .chartPath // .chart_path // .localPath // .local_path // empty' <<< "$entry")"
    repo_url="$(jq -r '.repo_url // empty' <<< "$entry")"
    chart_ref="$(jq -r '.chart_ref // empty' <<< "$entry")"
    version="$(jq -r '.version // empty' <<< "$entry")"
    if resolved="$(resolve_declared_chart "$parent" "$name" "$explicit")"; then
      record_discovery "$name" "$resolved" "$declared_by" "$enabled" "resolved"
      render_chart "$resolved" "$name" "$RENDER_ROOT/component-$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '-').yaml" \
        "$(jq -c --arg path "$resolved" --arg name "$name" --arg declared_by "$declared_by" --arg enabled "$enabled" '. + {path:$path,name:$name,declared_by:$declared_by,declared_enabled:$enabled}' <<< "$entry")"
    elif [ -n "$repo_url" ]; then
      record_discovery "$name" "" "$declared_by" "$enabled" "remote"
      # Keep remote catalog entries on the same Helm pull/render path already
      # used by charts.yml and values-file applications.
      if is_true "${HELM_ALLOW_NETWORK:-false}"; then
        download_dir="${RENDER_ROOT}/component-$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '-')"
        mkdir -p "$download_dir"
        if helm pull "${chart_ref:-$name}" --repo "$repo_url" ${version:+--version "$version"} --untar --untardir "$download_dir" >/dev/null 2>&1; then
          resolved="$(find "$download_dir" -mindepth 1 -maxdepth 2 -type f -name Chart.yaml -print -quit | xargs -r dirname)"
          [ -n "$resolved" ] && render_chart "$resolved" "$name" "$RENDER_ROOT/component-$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '-').yaml" "$entry" || record_skip "$name" "Downloaded child chart did not contain Chart.yaml"
        else
          record_skip "$name" "Unable to download declared child chart"
        fi
      else
        record_skip "$name" "Declared remote child chart requires HELM_ALLOW_NETWORK=true"
      fi
    else
      reason="Declared Helm component could not be resolved (source: ${declared_by})"
      record_discovery "$name" "" "$declared_by" "$enabled" "unresolved" "$reason"
      record_skip "$name" "$reason"
    fi
  done < <(yq -o=json '(.services // .service // {}) | select(type == "object") | to_entries[] | select(.value | type == "object") | select((.value | has("enabled")) or (.value | has("path")) or (.value | has("chartPath")) or (.value | has("chart_path")) or (.value | has("localPath")) or (.value | has("local_path")) or (.value | has("helmRepo")) or (.value | has("helm_repo"))) | {name:.key, enabled:(.value.enabled // null), path:(.value.path // null), chartPath:(.value.chartPath // null), chart_path:(.value.chart_path // null), localPath:(.value.localPath // null), local_path:(.value.local_path // null), repo_url:(.value.helmRepo.repoUrl // .value.helm_repo.repo_url // ""), version:(.value.helmRepo.version // .value.helm_repo.version // ""), chart_ref:(.value.helmRepo.chart // .value.helm_repo.chart // .value.chart // "")}' "$values_file" 2>/dev/null | jq -r '. | @base64' 2>/dev/null)
}

chart_dependencies_local() {
  local chart_path="$1" dependency name alias package
  while IFS=$'\t' read -r name alias; do
    [ -n "$name" ] || continue
    if [ -d "${chart_path}/charts/${alias}" ] || [ -d "${chart_path}/charts/${name}" ]; then
      continue
    fi
    package="$(find "${chart_path}/charts" -maxdepth 1 -type f \( -name "${name}-*.tgz" -o -name "${alias}-*.tgz" \) -print -quit 2>/dev/null || true)"
    [ -n "$package" ] || return 1
  done < <(yq -r '.dependencies[]? | [(.name // ""), (.alias // "")] | @tsv' "${chart_path}/Chart.yaml" 2>/dev/null)
  return 0
}

prepare_chart_dependencies() {
  local chart_path="$1" mode="${2:-$HELM_DEPENDENCY_MODE}"
  case "$mode" in
    vendored)
      chart_dependencies_local "$chart_path"
      ;;
    online)
      is_true "${HELM_ALLOW_NETWORK:-false}" && helm dependency build "$chart_path" >/dev/null 2>&1
      ;;
    auto)
      chart_dependencies_local "$chart_path" && return 0
      is_true "${HELM_ALLOW_NETWORK:-false}" && helm dependency build "$chart_path" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

if ! command -v helm >/dev/null 2>&1 || ! command -v yq >/dev/null 2>&1; then
  record_skip "tooling" "helm and yq are required to extract chart images"
  exit 0
fi

# One shared graph walk covers every Chart.yaml, values.yaml/values.yml, and
# recursively reachable YAML reference. The established catalog paths below
# remain a fallback for older scanner images or malformed graph output.
GRAPH_OUTPUT="${HELM_GRAPH_OUTPUT:-.cats-helm-graph.json}"
GRAPH_ENTRIES="${HELM_GRAPH_ENTRIES:-.cats-helm-entries.jsonl}"
if command -v python3 >/dev/null 2>&1; then
  python3 "${SCRIPT_DIRECTORY}/discover-helm-graph.py" --root . --output "$GRAPH_OUTPUT" --entries "$GRAPH_ENTRIES" \
    || record_skip "helm-discovery" "Recursive Helm graph discovery failed; using configured chart signals"
fi

render_chart() {
  local chart_path="$1" chart_name="$2" rendered="$3" entry_json="${4:-}"
  local values_file set_value dependency_mode
  local -a helm_command
  [ -n "$entry_json" ] || entry_json='{}'
  [ -f "${chart_path}/Chart.yaml" ] || {
    record_skip "$chart_name" "Chart.yaml not found at ${chart_path}"
    return
  }
  local identity chart_instance_id declared_by declared_enabled
  identity="$(chart_identity "$chart_path")"
  chart_instance_id="$(jq -r '.chart_id // empty' <<< "$entry_json" 2>/dev/null || true)"
  [ -n "$chart_instance_id" ] && identity="${identity}|${chart_instance_id}"
  [ -n "${PROCESSED_CHARTS[$identity]:-}" ] && return
  PROCESSED_CHARTS["$identity"]=1
  declared_by="$(jq -r '.declared_by // empty' <<< "$entry_json" 2>/dev/null || true)"
  declared_enabled="$(jq -r '.declared_enabled // "unknown"' <<< "$entry_json" 2>/dev/null || printf unknown)"
  record_discovery "$chart_name" "$identity" "$declared_by" "$declared_enabled" "processing"
  if ! jq -e '.graph_discovery == true' <<< "$entry_json" >/dev/null 2>&1; then
    discover_components "$chart_path" "$identity/values.yaml"
  fi
  dependency_mode="$(jq -r --arg mode "$HELM_DEPENDENCY_MODE" '.dependency_mode // $mode' <<< "$entry_json" 2>/dev/null || printf '%s' "$HELM_DEPENDENCY_MODE")"
  if ! prepare_chart_dependencies "$chart_path" "$dependency_mode"; then
    record_skip "$chart_name" "Helm dependencies are unavailable for image extraction (mode: ${dependency_mode})"
    return
  fi
  chart_name="${chart_name:-$(basename "$chart_path")}"
  helm_command=(helm template "${chart_name:-chart}" "$chart_path" --namespace "${HELM_DEFAULT_NAMESPACE:-default}")
  if jq -e '.include_crds == true' <<< "$entry_json" >/dev/null 2>&1; then
    helm_command+=(--include-crds)
  fi
  while IFS= read -r values_file; do
    [ -n "$values_file" ] && helm_command+=(-f "$values_file")
  done < <(jq -r '.values[]?' <<< "$entry_json" 2>/dev/null)
  while IFS= read -r set_value; do
    [ -n "$set_value" ] && helm_command+=(--set-string "$set_value")
  done < <(jq -r '(.set // []) | if type == "object" then to_entries[] | "\(.key)=\(.value)" else .[]? end' <<< "$entry_json" 2>/dev/null)
  if ! helm_render_with_bitnami_retry "$rendered" "$chart_name" "$chart_path" "${helm_command[@]}"; then
    reason="helm template failed during image extraction"
    [ -n "$HELM_RENDER_LAST_ERROR" ] && reason="${reason}: ${HELM_RENDER_LAST_ERROR}"
    record_skip "$chart_name" "$reason"
    return
  fi
  if [ ! -s "$rendered" ]; then
    record_skip "$chart_name" "helm template produced no manifests during image extraction"
    return
  fi
  printf '%s\n' "$entry_json" > "${rendered%.yaml}.chart.json"
  # Restrict extraction to Kubernetes workload pod specs. The fallback map
  # query also handles init/ephemeral containers and keeps this compatible
  # with yq versions that do not support a recursive path expression.
  yq -r '
    .. | select(tag == "!!map" and has("image") and (.image | tag) == "!!str") | .image
  ' "$rendered" 2>/dev/null | sed '/^null$/d;/^[[:space:]]*$/d' >> "$IMAGE_FILE" || {
    record_skip "$chart_name" "Unable to extract image references from rendered manifests"
  }
}

render_values_file_apps() {
  local values_file="$1" encoded entry app_name source_type repo_name repo_url version chart_ref
  local download_dir path safe_name_value
  local -a pull_command
  [ -f "$values_file" ] || { record_skip "$values_file" "Values file not found"; return; }
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
      record_skip "$app_name" "Helm app is missing helmRepo.repoName or helmRepo.repoUrl"
      continue
    fi
    chart_ref="${chart_ref:-$app_name}"
    entry="$(jq --arg name "$app_name" --arg reference "$chart_ref" --arg repository "$repo_url" --arg version "$version" --arg declared_by "$values_file" \
      '(. // {}) + {name:$name, reference:$reference, repository:$repository, version:$version, declared_by:$declared_by, declared_enabled:(if .enabled == true then "true" elif .enabled == false then "false" else "unknown" end)}' <<< "$entry")"
    safe_name_value="$(printf '%s' "$app_name" | tr -cs 'A-Za-z0-9._-' '-')"
    download_dir="${RENDER_ROOT}/values-${safe_name_value}"
    mkdir -p "$download_dir"
    path=""
    if ! is_true "${HELM_ALLOW_NETWORK:-false}"; then
      record_skip "$app_name" "Values-file Helm references require HELM_ALLOW_NETWORK=true"
      continue
    fi
    pull_command=(helm pull "$chart_ref" --repo "$repo_url")
    [ -n "$version" ] && pull_command+=(--version "$version")
    pull_command+=(--untar --untardir "$download_dir")
    if ! "${pull_command[@]}" >/dev/null 2>&1; then
      record_skip "$app_name" "Unable to download Helm chart ${chart_ref}"
      continue
    fi
    path="$(find "$download_dir" -mindepth 1 -maxdepth 2 -type f -name Chart.yaml -print -quit | xargs -r dirname)"
    [ -n "$path" ] || { record_skip "$app_name" "Downloaded chart did not contain Chart.yaml"; continue; }
    render_chart "$path" "$app_name" "${RENDER_ROOT}/values-${safe_name_value}.yaml" "$entry"
  done < <(yq -o=json '.services // {} | to_entries[] | {name:.key, enabled:(.value.enabled // null), source_type:(.value.sourceType // .value.source_type // ""), repo_name:(.value.helmRepo.repoName // .value.helm_repo.repo_name // ""), repo_url:(.value.helmRepo.repoUrl // .value.helm_repo.repo_url // ""), version:(.value.helmRepo.version // .value.helm_repo.version // ""), chart_ref:(.value.helmRepo.chart // .value.helm_repo.chart // .value.chart // ""), values:(.value.valuesFiles // .value.values_files // [])} ' "$values_file" 2>/dev/null | jq -r '. | @base64' 2>/dev/null)
}

if [ -s "$GRAPH_ENTRIES" ]; then
  graph_index=0
  while IFS= read -r graph_entry; do
    [ -n "$graph_entry" ] || continue
    if jq -e '.embedded_dependency == true' <<< "$graph_entry" >/dev/null 2>&1; then
      continue
    fi
    graph_index=$((graph_index + 1))
    chart_path="$(jq -r '.path // empty' <<< "$graph_entry")"
    chart_name="$(jq -r '.name // .chart // "chart"' <<< "$graph_entry")"
    if [ -z "$chart_path" ]; then
      reference="$(jq -r '.reference // empty' <<< "$graph_entry")"
      repository="$(jq -r '.repository // empty' <<< "$graph_entry")"
      version="$(jq -r '.version // empty' <<< "$graph_entry")"
      if [ -z "$reference" ] || ! is_true "${HELM_ALLOW_NETWORK:-false}"; then
        record_skip "$chart_name" "External chart reference requires HELM_ALLOW_NETWORK=true"
        continue
      fi
      download_dir="${RENDER_ROOT}/graph-remote-${graph_index}"
      mkdir -p "$download_dir"
      pull_command=(helm pull "$reference" --untar --untardir "$download_dir")
      [ -n "$repository" ] && pull_command+=(--repo "$repository")
      [ -n "$version" ] && pull_command+=(--version "$version")
      if ! "${pull_command[@]}" >/dev/null 2>&1; then
        record_skip "$chart_name" "Unable to resolve external chart reference"
        continue
      fi
      chart_path="$(find "$download_dir" -mindepth 1 -maxdepth 3 -type f -name Chart.yaml -print -quit | xargs -r dirname)"
      [ -n "$chart_path" ] || { record_skip "$chart_name" "Resolved external artifact did not contain Chart.yaml"; continue; }
    fi
    render_chart "$chart_path" "$chart_name" "${RENDER_ROOT}/graph-${graph_index}.yaml" \
      "$(jq -c '. + {graph_discovery:true}' <<< "$graph_entry")"
  done < "$GRAPH_ENTRIES"
elif [ -f charts.yml ]; then
  while IFS= read -r encoded; do
    [ -n "$encoded" ] || continue
    entry="$(printf '%s' "$encoded" | base64 -d 2>/dev/null || true)"
    path="$(jq -r '.path // empty' <<< "$entry" 2>/dev/null || true)"
    reference="$(jq -r '.reference // .chart // empty' <<< "$entry" 2>/dev/null || true)"
    name="$(jq -r '.name // .chart // .path // "chart"' <<< "$entry" 2>/dev/null || true)"
    if [ -z "$path" ]; then
      if [ -z "$reference" ] || ! is_true "${HELM_ALLOW_NETWORK:-false}"; then
        record_skip "$name" "Remote chart references require HELM_ALLOW_NETWORK=true"
        continue
      fi
      download_dir="${RENDER_ROOT}/download-$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '-')"
      mkdir -p "$download_dir"
      if ! helm pull "$reference" --untar --untardir "$download_dir" >/dev/null 2>&1; then
        record_skip "$name" "Unable to download remote chart for image extraction"
        continue
      fi
      path="$(find "$download_dir" -mindepth 1 -maxdepth 2 -type f -name Chart.yaml -print -quit | xargs -r dirname)"
      [ -n "$path" ] || { record_skip "$name" "Downloaded chart did not contain Chart.yaml"; continue; }
    fi
    render_chart "$path" "$name" "${RENDER_ROOT}/$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '-').yaml" "$entry"
  done < <(yq -o=json '.charts // []' charts.yml 2>/dev/null | jq -r '.[] | @base64' 2>/dev/null)
else
  while IFS= read -r chart_yaml; do
    chart_path="$(dirname "$chart_yaml")"
    case "$chart_path" in
      */charts/*) continue ;;
    esac
    chart_name="$(yq -r '.name // "chart"' "$chart_yaml" 2>/dev/null || echo chart)"
    render_chart "$chart_path" "$chart_name" "${RENDER_ROOT}/$(printf '%s' "$chart_name" | tr -cs 'A-Za-z0-9._-' '-').yaml"
  done < <(find charts -type f -name Chart.yaml -print 2>/dev/null | sort)
fi

while IFS= read -r values_file; do
  [ -n "$values_file" ] || continue
  render_values_file_apps "$values_file"
done < <(values_files | sort -u)

sort -u "$IMAGE_FILE" -o "$IMAGE_FILE"
if [ -s "$IMAGE_FILE" ]; then
  echo "Helm image references discovered:"
  cat "$IMAGE_FILE"
fi
