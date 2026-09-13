#!/usr/bin/env bash
set -euo pipefail

# Normalize rendered Kubernetes resources into the CATS service_overview shape.
# Empty sections are omitted so declared service.yml values are preserved when
# the report job merges this generated object.
ROOT="${1:-helm-rendered}"
OUT="${2:-service-overview.json}"
TMP="$(mktemp)"
RESOURCES="$(mktemp)"
DOCUMENT_ROOT="$(mktemp -d)"
trap 'rm -rf "$DOCUMENT_ROOT"; rm -f "$TMP" "$RESOURCES" "${OUT}.tmp"' EXIT

if [ ! -d "$ROOT" ] || ! find "$ROOT" -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
  printf '{}\n' > "$OUT"
  exit 0
fi

: > "$RESOURCES"
while IFS= read -r -d '' file; do
  # Helm emits one `# Source:` comment per rendered YAML document. Split the
  # stream first so that source metadata remains attached to the exact object
  # that produced it (including objects from vendored subcharts).
  document_dir="${DOCUMENT_ROOT}/$(printf '%s' "$(basename "$file")" | tr -cs 'A-Za-z0-9._-' '-')"
  mkdir -p "$document_dir"
  awk -v output_dir="$document_dir" '
    function flush(    yaml_path, source_path) {
      if (!started) return
      document_number++
      yaml_path = output_dir "/" document_number ".yaml"
      source_path = output_dir "/" document_number ".source"
      printf "%s", document > yaml_path
      close(yaml_path)
      printf "%s\n", source > source_path
      close(source_path)
      document = ""
      source = ""
      started = 0
    }
    /^---[[:space:]]*$/ {
      flush()
      started = 1
      document = $0 "\n"
      next
    }
    {
      if (!started) started = 1
      if ($0 ~ /^[[:space:]]*#[[:space:]]*Source:[[:space:]]*/) {
        source = $0
        sub(/^[[:space:]]*#[[:space:]]*Source:[[:space:]]*/, "", source)
      }
      document = document $0 "\n"
    }
    END { flush() }
  ' "$file"

  while IFS= read -r -d '' document; do
    source_file=""
    chart_provenance='{}'
    [ -f "${document%.yaml}.source" ] && source_file="$(cat "${document%.yaml}.source")"
    [ -f "${file%.yaml}.chart.json" ] && chart_provenance="$(cat "${file%.yaml}.chart.json" 2>/dev/null || printf '{}')"
    # yq emits one object for each split document. Compact it before appending
    # to the JSON-lines resource stream consumed below.
    while IFS= read -r resource; do
      [ -n "$resource" ] || continue
      jq --arg source_file "$source_file" --argjson chart_provenance "$chart_provenance" '. + {
        _cats_source_file: $source_file,
        _cats_chart_provenance: $chart_provenance,
        _cats_source_mappings: (if $source_file == "" then [] else [{template: $source_file, values_key: null, values_file: null, ambiguous: true}] end)
      }' <<< "$resource" >> "$RESOURCES"
    done < <(yq -o=json 'select(.kind != null)' "$document" 2>/dev/null | jq -c . 2>/dev/null || true)
  done < <(find "$document_dir" -type f -name '*.yaml' -print0 | sort -z)
done < <(find "$ROOT" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0)
jq -s 'map(select(type == "object" and .kind != null))' "$RESOURCES" > "$TMP"
echo "Rendered Kubernetes objects available for overview: $(jq 'length' "$TMP")"
echo "Rendered Kubernetes kinds available for overview:"
jq -r 'group_by(.kind)[] | "\(length) \(.[0].kind)"' "$TMP"

TMP_OUT="${OUT}.tmp"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/normalize-service-overview.py" "$TMP" "$TMP_OUT"

if [ -s "$TMP_OUT" ]; then
  mv "$TMP_OUT" "$OUT"
else
  printf '{}\n' > "$OUT"
  rm -f "$TMP_OUT"
fi

echo "Generated normalized service overview: $OUT"
