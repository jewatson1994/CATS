#!/usr/bin/env bash
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Distinguish an unpublished tag from registry or authentication failures.
lookup() {
  local reference=$1
  if skopeo inspect --raw "docker://$reference" > "$work/manifest" 2> "$work/error"; then
    skopeo manifest-digest "$work/manifest"
  elif ! grep -Eiq 'manifest unknown|name unknown|manifest_unknown|name_unknown|status code: 404' "$work/error"; then
    cat "$work/error" >&2
    return 1
  fi
}

publish_tested_image() {
  skopeo copy --all --preserve-digests --src-tls-verify=false --retry-times 3 \
    "docker://localhost:5000/cats-tool@$CATS_IMAGE_DIGEST" "docker://$IMAGE:$1"
}

# A nightly refresh can update latest with a new offline vulnerability database.
# Keep the first successfully published commit image available for pinned installs.
commit_digest=$(lookup "$IMAGE:$GITHUB_SHA")
if [[ -z "$commit_digest" ]]; then
  publish_tested_image "$GITHUB_SHA"
  commit_digest=$(lookup "$IMAGE:$GITHUB_SHA")
  [[ "$commit_digest" == "$CATS_IMAGE_DIGEST" ]]
fi

# A slow or retried older run must not roll back the default image.
main_sha=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq '.object.sha')
if [[ "$main_sha" == "$GITHUB_SHA" ]]; then
  if [[ "$GITHUB_EVENT_NAME" == schedule ]]; then
    publish_tested_image latest
  else
    latest_digest=$(lookup "$IMAGE:latest")
    # A retry of the same commit must preserve a newer scheduled refresh.
    if [[ -z "$latest_digest" ]] || ! jq -e --arg sha "$GITHUB_SHA" '.annotations["org.opencontainers.image.revision"] == $sha' "$work/manifest" >/dev/null; then
      skopeo copy --all --preserve-digests --retry-times 3 "docker://$IMAGE@$commit_digest" "docker://$IMAGE:latest"
    fi
  fi
fi

owner=${GITHUB_REPOSITORY_OWNER,,}
chart_digest=$(lookup "ghcr.io/$owner/charts/cats-runtime:$CHART_VERSION")
if [[ -n "$chart_digest" ]]; then
  echo "Runtime chart $CHART_VERSION is already published."
  exit 0
fi

# A retry can complete an interrupted chart upload after the commit image exists.
if [[ "$commit_digest" != "$CATS_IMAGE_DIGEST" ]]; then
  CATS_IMAGE_DIGEST="$commit_digest" python .github/scripts/runtime-chart.py package
fi
echo "$GH_TOKEN" | helm registry login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
helm push "dist/cats-runtime-$CHART_VERSION.tgz" "oci://ghcr.io/$owner/charts"
echo "chart_published=true" >> "$GITHUB_OUTPUT"
