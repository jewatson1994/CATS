#!/bin/bash

set -e

mkdir -p results

[ -f skipped_images.txt ] || : > skipped_images.txt

shopt -s nullglob

SBOM_FILES=(sboms/*.json)

if [ ${#SBOM_FILES[@]} -eq 0 ]; then

  echo ""
  echo "WARNING: No SBOMs found to scan. Preserving the assessment as incomplete evidence."
  echo ""

  exit 0
fi

for SBOM in "${SBOM_FILES[@]}"; do

  SAFE_NAME=$(basename "$SBOM" .json)

  echo ""
  echo "======================================"
  echo "Scanning: $SAFE_NAME"
  echo "======================================"

  if ! grype "sbom:$SBOM" \
      --only-fixed -o json \
      > "results/${SAFE_NAME}-results.json"; then

    echo "WARNING: Failed scanning $SBOM"
    if [ -f "sboms/${SAFE_NAME}.image" ]; then
      cat "sboms/${SAFE_NAME}.image" >> skipped_images.txt
    fi

    # A failed Grype invocation must not be counted as a scanned result.
    rm -f "results/${SAFE_NAME}-results.json"

    continue
  fi

  echo ""
  echo "RESULT CREATED:"
  ls -lah "results/${SAFE_NAME}-results.json"

done

sort -u skipped_images.txt -o skipped_images.txt

echo ""
echo "======================================"
echo "SCAN RESULTS"
echo "======================================"

ls -lah results/
