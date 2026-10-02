#!/usr/bin/env bash

verify_vendored_dependencies() {
  "${HELM_DEPENDENCY_PYTHON:-python3}" "${SCRIPT_DIRECTORY}/inspect-helm-dependencies.py" "$1" >/dev/null
}

chart_dependencies_local() {
  verify_vendored_dependencies "$1"
}

prepare_chart_dependencies() {
  local chart_dir="$1" mode="${2:-$HELM_DEPENDENCY_MODE}"
  case "$mode" in auto|vendored|local|online) ;; *)
    echo "Unknown Helm dependency mode" >&2; return 1 ;;
  esac
  # Even an OCI repository declaration needs no retrieval when its artifact
  # already contains valid dependencies. All modes share this first decision.
  verify_vendored_dependencies "$chart_dir" && return 0
  if ! "${HELM_DEPENDENCY_PYTHON:-python3}" "${SCRIPT_DIRECTORY}/inspect-helm-dependencies.py" "$chart_dir" --can-build >/dev/null; then
    echo "Invalid or unsafe Helm dependency metadata" >&2; return 1
  fi
  case "$mode" in
    vendored) echo "Missing or invalid vendored dependencies" >&2; return 1 ;;
    local)
      if ! "${HELM_DEPENDENCY_PYTHON:-python3}" "${SCRIPT_DIRECTORY}/inspect-helm-dependencies.py" "$chart_dir" --local-only >/dev/null; then
        echo "Dependency repository is not local or metadata is invalid" >&2; return 1
      fi
      helm dependency build --skip-refresh "$chart_dir" && verify_vendored_dependencies "$chart_dir"
      ;;
    auto|online)
      if ! is_true "${HELM_ALLOW_NETWORK:-false}"; then
        echo "HELM_ALLOW_NETWORK=false" >&2; return 1
      fi
      helm dependency build "$chart_dir" && verify_vendored_dependencies "$chart_dir"
      ;;
  esac
}

# Keep diagnostics in the calling shell so both inventory and image extraction
# can report the same bounded, credential-safe reason.
run_dependency_preparation() {
  local output status
  HELM_DEPENDENCY_FAILURE=""
  if output="$(prepare_chart_dependencies "$@" 2>&1)"; then
    return 0
  else
    status=$?
  fi
  HELM_DEPENDENCY_FAILURE="$(printf '%s' "$output" | "${HELM_DEPENDENCY_PYTHON:-python3}" "${SCRIPT_DIRECTORY}/helm-dependency-diagnostic.py")"
  HELM_DEPENDENCY_FAILURE="${HELM_DEPENDENCY_FAILURE:-Dependency preparation failed}"
  HELM_DEPENDENCY_FAILURE="${HELM_DEPENDENCY_FAILURE}; preparation exit ${status}"
  return 1
}
