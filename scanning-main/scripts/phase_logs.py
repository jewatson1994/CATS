"""Offline CATS scanner phase journal and authenticated upload to the portal."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request
import uuid

from push_result import project_endpoint


PHASES = ("prepare", "evaluate", "patch")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def record(directory, phase, run, status):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stage = "started" if status is None else "finished"
    event_id = f"scanner:{run}:{stage}"
    data = {"component": "cats-cli", "operation": phase, "run_id": run, "stage": stage}
    if status is not None:
        data["exit_code"] = status
    event = {"event_id": event_id, "category": "operational", "data": data,
             "timestamp": datetime.now(timezone.utc).isoformat()}
    # A reporter opening the directory concurrently sees only complete envelopes.
    with tempfile.NamedTemporaryFile(dir=directory, mode="w", encoding="utf-8", delete=False) as tmp:
        json.dump(event, tmp)
        tmp.flush()
        os.fsync(tmp.fileno())
    os.replace(tmp.name, directory / f"cats-phase-{run}-{stage}.json")


def upload(directory, endpoint, token, ca_file):
    if not directory.is_dir():
        raise ValueError("The scanner phase journal directory does not exist")
    if not re.fullmatch(r"cats-log-[A-Za-z0-9_-]{43}", token):
        raise ValueError("Set CATS_COMPONENT_LOG_TOKEN to the HQ-issued reporting credential")
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    count = 0
    paths = sorted(directory.glob("cats-phase-*.json"),
                   key=lambda path: (path.stem.rsplit("-", 1)[0], path.stem.endswith("-finished")))
    for path in paths:
        # Never follow links from a workspace or send arbitrary CI artifacts.
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as source:
            blob = source.read(2049)
        if len(blob) > 2048:
            raise ValueError("Invalid scanner phase record size")
        event = json.loads(blob)
        data = event.get("data") if isinstance(event, dict) else None
        if (not isinstance(data, dict) or data.get("component") != "cats-cli"
                or data.get("operation") not in PHASES or data.get("stage") not in ("started", "finished")
                or set(data) - {"component", "operation", "run_id", "stage", "exit_code"}
                or set(event) != {"event_id", "timestamp", "category", "data"}
                or event["category"] != "operational"
                or not re.fullmatch(r"[a-f0-9]{32}", str(data.get("run_id", "")))
                or ("exit_code" in data and (type(data["exit_code"]) is not int or not 0 <= data["exit_code"] <= 255))
                or ("exit_code" in data) != (data["stage"] == "finished")
                or not isinstance(event["timestamp"], str) or len(event["timestamp"]) > 40
                or datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).tzinfo is None
                or event["event_id"] != f"scanner:{data['run_id']}:{data['stage']}"):
            raise ValueError("Invalid scanner phase record")
        request = Request(endpoint, data=blob, headers={"Authorization": "Bearer " + token,
                                                        "Content-Type": "application/json"})
        with opener.open(request, timeout=10) as response:
            receipt = json.loads(response.read(4097))
        if (not isinstance(receipt, dict) or receipt.get("event_id") != event["event_id"]
                or receipt.get("status") not in ("accepted", "duplicate")):
            raise ValueError("HQ did not acknowledge the scanner phase event")
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    finish = sub.add_parser("finish")
    for cmd in (start, finish):
        cmd.add_argument("phase", choices=PHASES)
        cmd.add_argument("directory", type=Path)
    finish.add_argument("run", type=lambda value: uuid.UUID(value).hex)
    finish.add_argument("status", type=int)
    sub.add_parser("upload").add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "upload":
            endpoint = project_endpoint(os.getenv("CATS_PORTAL_URL", ""), "/api/v1/component-logs/events", parser)
            count = upload(args.directory, endpoint, os.getenv("CATS_COMPONENT_LOG_TOKEN", ""),
                           os.getenv("CATS_PORTAL_CA_FILE") or os.getenv("CATS_PORTAL_CA_CERT"))
            print(f"HQ acknowledged {count} scanner phase events.")
        elif args.command == "start":
            run = uuid.uuid4().hex
            record(args.directory, args.phase, run, None)
            print(run)
        else:
            record(args.directory, args.phase, args.run, args.status)
    except HTTPError as exc:
        print(f"HQ rejected the scanner phase upload (HTTP {exc.code}).", file=sys.stderr)
        return 1
    except (OSError, ValueError, URLError):
        print("Scanner phase journal unavailable or invalid. Retain it and retry the upload.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
