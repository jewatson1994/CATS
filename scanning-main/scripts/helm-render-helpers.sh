#!/usr/bin/env bash

# Narrow Helm retry used only by CATS static analysis.  Bitnami charts can
# reject mirrored/substituted images before rendering; this helper retries
# only that known diagnostic and never edits the chart or its values.

HELM_RENDER_LAST_ERROR=""
HELM_RENDER_RETRY_USED=false

helm_render_sanitize_error() {
  printf '%s' "${1:-}" | tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g' | cut -c1-1200
}

helm_render_is_bitnami_verification_failure() {
  local text="${1:-}"
  [[ "$text" == *"Original containers have been substituted for unrecognized ones"* ]] \
    && [[ "$text" == *"Unrecognized images:"* ]]
}

helm_render_unrecognized_images_json() {
  local text="${1:-}"
  printf '%s\n' "$text" \
    | sed -n '/Unrecognized images:/,/^[[:space:]]*$/p' \
    | sed -n 's/^[[:space:]]*-[[:space:]]*//p' \
    | sed '/^[[:space:]]*$/d' \
    | jq -R -s 'split("\n") | map(select(length > 0)) | unique'
}

helm_render_record_warning() {
  local chart_name="$1" source_identity="$2" original_error="$3"
  local warnings_file="${HELM_RENDER_WARNINGS_FILE:-helm-render-warnings.json}"
  local warnings_tmp images_json message
  # prepare-inputs creates this file as an empty placeholder. Initialize both
  # missing and empty files so jq always receives an array when a retry warning
  # is recorded.
  [ -s "$warnings_file" ] || printf '[]\n' > "$warnings_file"
  images_json="$(helm_render_unrecognized_images_json "$original_error")"
  message="Bitnami container image verification blocked the initial Helm render. CATS retried with image verification disabled for static analysis only. The submitted Helm chart was not modified."
  warnings_tmp="${warnings_file}.tmp"
  jq --arg chart "$chart_name" \
    --arg source "$source_identity" \
    --arg message "$message" \
    --arg original_error "$(helm_render_sanitize_error "$original_error")" \
    --argjson images "$images_json" \
    '. + [{type:"bitnami-image-verification-override", chart:$chart, source:$source, message:$message, original_error:$original_error, unrecognized_images:$images}] | unique_by([.type,.chart,.source,.original_error])' \
    "$warnings_file" > "$warnings_tmp" && mv "$warnings_tmp" "$warnings_file"
  echo "WARNING: ${message} Chart: ${chart_name}." >&2
}

# Usage: helm_render_with_bitnami_retry rendered-file chart-name source-id helm args...
helm_render_with_bitnami_retry() {
  local rendered="$1" chart_name="$2" source_identity="$3"
  local error_file retry_error_file original_error retry_error
  shift 3
  HELM_RENDER_LAST_ERROR=""
  HELM_RENDER_RETRY_USED=false
  error_file="$(mktemp)"
  if "$@" > "$rendered" 2> "$error_file"; then
    rm -f "$error_file"
    return 0
  fi
  original_error="$(cat "$error_file")"
  cat "$error_file" >&2
  if ! helm_render_is_bitnami_verification_failure "$original_error"; then
    HELM_RENDER_LAST_ERROR="$(helm_render_sanitize_error "$original_error")"
    rm -f "$error_file"
    return 1
  fi

  retry_error_file="$(mktemp)"
  if "$@" --set 'global.security.allowInsecureImages=true' > "$rendered" 2> "$retry_error_file"; then
    helm_render_record_warning "$chart_name" "$source_identity" "$original_error"
    HELM_RENDER_RETRY_USED=true
    rm -f "$error_file" "$retry_error_file"
    return 0
  fi
  retry_error="$(cat "$retry_error_file")"
  cat "$retry_error_file" >&2
  HELM_RENDER_LAST_ERROR="$(helm_render_sanitize_error "$retry_error")"
  [ -n "$HELM_RENDER_LAST_ERROR" ] || HELM_RENDER_LAST_ERROR="$(helm_render_sanitize_error "$original_error")"
  rm -f "$error_file" "$retry_error_file"
  return 1
}
