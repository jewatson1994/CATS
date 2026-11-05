#!/usr/bin/env bash

# Every workflow uses app.rendering. Compatibility overrides must be supplied
# explicitly in chart values; failures never silently change submitted values.
HELM_RENDER_LAST_ERROR=""

helm_render_sanitize_error() {
  printf '%s' "${1:-}" | tr '\r\n\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g' | cut -c1-1200
}

helm_render() {
  local rendered="$1" chart_name="$2" source_identity="$3" error_file
  shift 3
  HELM_RENDER_LAST_ERROR=""
  error_file="$(mktemp)"
  if python3 "${SCRIPT_DIRECTORY}/render-helm.py" "$@" > "$rendered" 2> "$error_file"; then
    rm -f "$error_file"
    return 0
  fi
  HELM_RENDER_LAST_ERROR="$(helm_render_sanitize_error "$(cat "$error_file")")"
  cat "$error_file" >&2
  rm -f "$error_file" "$rendered"
  return 1
}
