#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 INPUT_JSON OUTPUT_JSON IMAGE" >&2
  exit 2
fi

INPUT_JSON="$1"
OUTPUT_JSON="$2"
IMAGE="$3"

[ -f "$INPUT_JSON" ] || { echo "ERROR: Dockle result not found: $INPUT_JSON" >&2; exit 1; }

UNHASHED_OUTPUT="${OUTPUT_JSON}.unhashed"
trap 'rm -f "$UNHASHED_OUTPUT"' EXIT

jq --arg image "$IMAGE" '
  def severity_name:
    (ascii_upcase) as $level
    | if $level == "FATAL" or $level == "CRITICAL" then "Critical"
      elif $level == "WARN" or $level == "WARNING" or $level == "HIGH" then "High"
      elif $level == "INFO" or $level == "LOW" then "Low"
      else "Unknown"
      end;

  [
    (.details // [])[]
    | select(((.level // "") | ascii_upcase) as $level | ($level != "PASS" and $level != "SKIP"))
    | (.code // .id // "DOCKLE-CONFIG") as $finding_id
    | {
        type: "Configuration",
        finding: $finding_id,
        severity: ((.level // "Unknown") | severity_name),
        scanner: "Dockle",
        framework: "Docker Image Configuration",
        target: $image,
        namespace: "",
        title: (.title // .code // $finding_id),
        description: ((.description // .message // "") | tostring),
        remediation: ((.remediation // .resolution // "") | tostring),
        fingerprint: (["dockle", $finding_id, $image, (.title // "")] | join("|"))
      }
  ]
  | unique_by(.fingerprint)
' "$INPUT_JSON" > "$UNHASHED_OUTPUT"

while IFS= read -r encoded_finding; do
  [ -n "$encoded_finding" ] || continue
  finding_json="$(printf '%s' "$encoded_finding" | base64 -d)"
  fingerprint_material="$(jq -r '.fingerprint' <<< "$finding_json")"
  fingerprint_digest="$(printf '%s' "$fingerprint_material" | sha256sum | awk '{print $1}')"
  jq --arg fingerprint "dockle:${fingerprint_digest}" '.fingerprint = $fingerprint' <<< "$finding_json"
done < <(jq -r '.[] | @base64' "$UNHASHED_OUTPUT") | jq -s 'unique_by(.fingerprint)' > "$OUTPUT_JSON"
