#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

bash "$ROOT/scripts/normalize-dockle-config.sh" \
  "$ROOT/tests/fixtures/dockle-config.json" "$TMP/out.json" \
  "docker.io/library/example:1.2.3"

jq -e 'length == 2' "$TMP/out.json" >/dev/null
jq -e 'all(.[]; .scanner == "Dockle" and .framework == "Docker Image Configuration")' "$TMP/out.json" >/dev/null
jq -e 'any(.[]; .finding == "CIS-DI-0001" and .severity == "Critical")' "$TMP/out.json" >/dev/null
jq -e 'any(.[]; .finding == "DKL-DI-0005" and .severity == "High")' "$TMP/out.json" >/dev/null
jq -e 'all(.[]; (.fingerprint | startswith("dockle:")))' "$TMP/out.json" >/dev/null

echo "Dockle normalization test passed."
