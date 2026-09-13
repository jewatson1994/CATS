#!/usr/bin/env bash
set -euo pipefail

DB_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)/grype-db}"
GRYPE_DB_UPDATE_URL="${GRYPE_DB_UPDATE_URL:-https://grype.anchore.io/databases/v6/latest.json}"

command -v grype >/dev/null 2>&1 || { echo "grype is required to prepare the database" >&2; exit 1; }
mkdir -p "$DB_DIR"
echo "Preparing current Grype DB in $DB_DIR"
curl --fail --location --retry 3 --silent --show-error "$GRYPE_DB_UPDATE_URL" --output "$DB_DIR/latest.json"
GRYPE_DB_CACHE_DIR="$DB_DIR" GRYPE_DB_UPDATE_URL="$GRYPE_DB_UPDATE_URL" \
  GRYPE_DB_AUTO_UPDATE=true GRYPE_DB_VALIDATE_AGE=false grype db update

db_file="$(find "$DB_DIR" -type f -name vulnerability.db -size +0c -print -quit 2>/dev/null || true)"
metadata_file=""
if [[ -s "$DB_DIR/latest.json" ]]; then
  metadata_file="$DB_DIR/latest.json"
else
  metadata_file="$(find "$DB_DIR" -type f -name metadata.json -size +0c -print -quit 2>/dev/null || true)"
fi
if [[ -z "$db_file" || -z "$metadata_file" ]] || ! jq -e '
  type == "object" and
  (.built | type == "string" and length > 0) and
  ((.schemaVersion // .version) | type == "string" and length > 0)
' "$metadata_file" >/dev/null 2>&1; then
  echo "Prepared Grype DB failed structural validation" >&2
  exit 1
fi
GRYPE_DB_CACHE_DIR="$DB_DIR" GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_REQUIRE_UPDATE_CHECK=false GRYPE_DB_VALIDATE_AGE=false GRYPE_CHECK_FOR_APP_UPDATE=false grype db status
echo "Prepared Grype DB: $(du -sh "$DB_DIR" | awk '{print $1}')"
