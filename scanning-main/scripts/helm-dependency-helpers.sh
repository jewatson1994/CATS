#!/usr/bin/env bash

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
  HELM_DEPENDENCY_FAILURE="$(printf '%s' "$output" | python3 "${SCRIPT_DIRECTORY}/helm-dependency-diagnostic.py")"
  HELM_DEPENDENCY_FAILURE="${HELM_DEPENDENCY_FAILURE:-Dependency preparation failed}"
  HELM_DEPENDENCY_FAILURE="${HELM_DEPENDENCY_FAILURE}; preparation exit ${status}"
  return 1
}
