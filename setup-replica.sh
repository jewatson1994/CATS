#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$ROOT/scripts/setup-cats.py" --mode replica "$@"
