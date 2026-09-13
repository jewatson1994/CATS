#!/bin/bash

set -e

echo ""
echo "======================================"
echo "         DETAILED FINDINGS"
echo "======================================"

found=0
for report_file in results/*-results.json; do
  [ -f "$report_file" ] || continue
  found=1
  image_name=$(basename "$report_file" -results.json)
  echo "Image: $image_name"
  jq -r '.matches[]? | [.vulnerability.id, (.vulnerability.severity // "Unknown"), (.artifact.name // ""), (.artifact.version // ""), ((.vulnerability.fix.versions // []) | join(", "))] | @tsv' "$report_file" \
    | column -t -s $'\t' || true
done

if [ "$found" -eq 0 ]; then
  echo "No raw Grype results"
fi

echo "======================================"

echo ""

if [ -s skipped_images.txt ]; then
  echo "Skipped Images:"
  cat skipped_images.txt
fi

if [ -f portal-policy-findings.json ]; then
  echo ""
  echo "======================================"
  echo "      CONFIGURATION FINDINGS"
  echo "======================================"
  jq -r '.[]? | [.finding, .severity, .framework, .target, .title] | @tsv' \
    portal-policy-findings.json | column -t -s $'\t' || true
fi

if [ -s configuration-skipped.txt ]; then
  echo ""
  echo "Incomplete configuration targets:"
  column -t -s $'\t' configuration-skipped.txt || cat configuration-skipped.txt
fi

if [ -s skipped_charts.txt ]; then
  echo ""
  echo "Skipped Helm charts (non-blocking):"
  column -t -s $'\t' skipped_charts.txt || cat skipped_charts.txt
fi

if [ -s helm-render-warnings.json ] && [ "$(jq 'length' helm-render-warnings.json 2>/dev/null || echo 0)" -gt 0 ]; then
  echo ""
  echo "Helm static-analysis warnings:"
  jq -r '.[] | [.chart, .message, (.unrecognized_images | join(", "))] | @tsv' helm-render-warnings.json \
    | column -t -s $'\t' || cat helm-render-warnings.json
fi
