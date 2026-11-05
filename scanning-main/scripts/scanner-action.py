#!/usr/bin/env python3
"""Small shell adapter for shared offline scanner actions."""
import argparse
from pathlib import Path
import sys

for location in (Path(__file__).resolve().parents[2] / "portal", Path("/opt/portal"), Path("/app")):
    if (location / "app/scanner_actions.py").is_file():
        sys.path.insert(0, str(location))
        break

from app.scanner_actions import inventory, scan_configuration, scan_image_configuration


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inventory", "configuration", "image-configuration", "image-hardening"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--severity", default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
    parser.add_argument("--skip-dir", action="append", default=[])
    parser.add_argument("--source-type", choices=("dir", "docker-archive", "oci-archive"), default="dir")
    options = parser.parse_args()
    try:
        if options.action == "inventory":
            inventory(options.source, options.output, source_type=options.source_type)
        elif options.action == "configuration":
            scan_configuration(options.source, options.output, cache=options.cache,
                               severity=options.severity, skip_dirs=options.skip_dir)
        else:
            scan_image_configuration(options.source, options.output,
                tool="trivy" if options.action == "image-configuration" else "dockle",
                cache=options.cache, severity=options.severity)
    except (RuntimeError, OSError, ValueError):
        print("Offline scanner action failed; no completed evidence was retained", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
