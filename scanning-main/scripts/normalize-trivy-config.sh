#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 5 ]; then
  echo "Usage: $0 INPUT_JSON OUTPUT_JSON [SCAN_TARGET] [DEPLOYMENT_NAMESPACE] [FRAMEWORK]" >&2
  exit 2
fi

INPUT_JSON="$1"
OUTPUT_JSON="$2"
SCAN_TARGET="${3:-}"
DEPLOYMENT_NAMESPACE="${4:-}"
FRAMEWORK="${5:-}"

[ -f "$INPUT_JSON" ] || { echo "ERROR: Trivy result not found: $INPUT_JSON" >&2; exit 1; }

UNHASHED_OUTPUT="${OUTPUT_JSON}.unhashed"
trap 'rm -f "$UNHASHED_OUTPUT"' EXIT

jq \
  --arg scan_target "$SCAN_TARGET" \
  --arg deployment_namespace "$DEPLOYMENT_NAMESPACE" \
  --arg framework_override "$FRAMEWORK" '
  def severity_name:
    ascii_downcase
    | if . == "critical" then "Critical"
      elif . == "high" then "High"
      elif . == "medium" then "Medium"
      elif . == "low" then "Low"
      elif . == "unknown" then "Unknown"
      else (.[0:1] | ascii_upcase) + .[1:]
      end;

  [
    (.Results // [])[] as $result
    | ($result.Misconfigurations // [])[]
    | select(((.Status // "FAIL") | ascii_upcase) == "FAIL")
    | (.ID // .AVDID // .RuleID // "TRIVY-CONFIG") as $finding_id
    | (
        if ($scan_target | length) > 0 then
          if (($result.Target // "") | length) > 0
          then $scan_target + " :: " + $result.Target
          else $scan_target
          end
        else ($result.Target // "")
        end
      ) as $finding_target
    | (
        if ($deployment_namespace | length) > 0
        then $deployment_namespace
        else (.Namespace // "")
        end
      ) as $finding_namespace
    | {
        type: "Configuration",
        finding: $finding_id,
        severity: ((.Severity // "Unknown") | severity_name),
        scanner: "Trivy",
        framework: (
          if ($framework_override | length) > 0
          then $framework_override
          else (.Type // $result.Type // $result.Class // "Configuration")
          end
        ),
        target: $finding_target,
        namespace: $finding_namespace,
        title: (.Title // $finding_id),
        description: (.Description // .Message // ""),
        remediation: (.Resolution // ""),
        fingerprint: (
          [
            "trivy",
            $finding_id,
            $finding_target,
            $finding_namespace,
            (.CauseMetadata.Resource // .CauseMetadata.Provider // "")
          ]
          | map(tostring)
          | join("|")
        )
      }
  ]
  | unique_by(.fingerprint)
' "$INPUT_JSON" > "$UNHASHED_OUTPUT"

# Keep fingerprints deterministic and bounded even when Trivy returns a very
# long filesystem target or resource path. The prefix identifies the producer;
# the digest is the stable identity material assembled above.
while IFS= read -r encoded_finding; do
  [ -n "$encoded_finding" ] || continue
  finding_json="$(printf '%s' "$encoded_finding" | base64 -d)"
  fingerprint_material="$(jq -r '.fingerprint' <<< "$finding_json")"
  fingerprint_digest="$(printf '%s' "$fingerprint_material" | sha256sum | awk '{print $1}')"
  jq --arg fingerprint "trivy:${fingerprint_digest}" '.fingerprint = $fingerprint' <<< "$finding_json"
done < <(jq -r '.[] | @base64' "$UNHASHED_OUTPUT") | jq -s 'unique_by(.fingerprint)' > "$OUTPUT_JSON"
