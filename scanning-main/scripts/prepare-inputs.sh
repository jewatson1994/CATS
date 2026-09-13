#!/usr/bin/env bash

set -euo pipefail

if [ -n "${UPSTREAM_PROJECT_ID:-}" ] && [ -n "${UPSTREAM_PIPELINE_ID:-}" ]; then
  echo "Triggered by Patching. Downloading upstream image and evidence artifacts..."
  curl --fail --location --header "JOB-TOKEN: $CI_JOB_TOKEN" --output jobs.json \
    "$CI_API_V4_URL/projects/${UPSTREAM_PROJECT_ID}/pipelines/${UPSTREAM_PIPELINE_ID}/jobs?per_page=100"
  PATCH_JOB_ID=$(jq -r '[.[] | select(.name == "patch_image" and .status == "success")][0].id // empty' jobs.json)
  [ -n "$PATCH_JOB_ID" ] || { echo "ERROR: No successful patch_image job was found."; exit 1; }
  curl --fail --location --header "JOB-TOKEN: $CI_JOB_TOKEN" --output artifacts.zip \
    "$CI_API_V4_URL/projects/${UPSTREAM_PROJECT_ID}/jobs/${PATCH_JOB_ID}/artifacts"
  unzip -oq artifacts.zip images.yml
  unzip -oq artifacts.zip service.yml
  if unzip -Z1 artifacts.zip | grep -Fxq "skipped_images.txt"; then unzip -oq artifacts.zip skipped_images.txt; else : > skipped_images.txt; fi
  if unzip -Z1 artifacts.zip | grep -Fxq "charts.yml"; then unzip -oq artifacts.zip charts.yml; fi
  if unzip -Z1 artifacts.zip | grep -q '^charts/'; then unzip -oq artifacts.zip 'charts/*'; fi
  if unzip -Z1 artifacts.zip | grep -q '^configuration/'; then unzip -oq artifacts.zip 'configuration/*'; fi
else
  [ -f service.yml ] || { echo "ERROR: service.yml not found."; exit 1; }
  [ -f images.yml ] || { echo "ERROR: images.yml not found."; exit 1; }
  : > skipped_images.txt
fi

yq -e '.service.id' service.yml >/dev/null \
  || { echo "ERROR: service.yml must define service.id."; exit 1; }
echo "Using service metadata and overview from service.yml"

touch skipped_charts.txt
: > helm-render-warnings.json
bash "$(dirname "$0")/extract-helm-images.sh"

helm_images_json='[]'
if [ -s helm-images.txt ]; then
  helm_images_json="$(jq -R -s 'split("\n") | map(select(type == "string")) | map(gsub("^\\s+|\\s+$"; "")) | map(select((ascii_downcase as $v | ["", "---", "—", "-", "null", "none", "nil", "n/a", "na", "not provided", "unknown image"] | index($v) | not)))' helm-images.txt)"
fi
yq -o=json '.' images.yml \
  | jq --argjson helm_images "$helm_images_json" \
      'def valid_image: type == "string" and (gsub("^\\s+|\\s+$"; "") | ascii_downcase as $v | ["", "---", "—", "-", "null", "none", "nil", "n/a", "na", "not provided", "unknown image"] | index($v) | not); .images = ([((.images // [])[]?, $helm_images[]?) | select(valid_image) | gsub("^\\s+|\\s+$"; "")] | unique)' \
  | yq -P - > images.yml.next
mv images.yml.next images.yml

echo "Prepared image manifest:"
yq -r '.images[]' images.yml
