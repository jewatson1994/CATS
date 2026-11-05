#!/usr/bin/env python3
"""Bridge the standalone scanner to the same Helm action as other workers."""
from pathlib import Path
import sys

for root in (Path(__file__).resolve().parents[2] / "portal", Path("/app")):
    if (root / "app" / "rendering.py").is_file():
        sys.path.insert(0, str(root))
        break

from app.rendering import main

if __name__ == "__main__":
    raise SystemExit(main())
