"""Dump page data for findings-related views, for exact parity comparisons.

Run it once per code revision (or classification setting) against the same
benchmark database and the same frozen instant, then compare the dumps:

    python scripts/benchmark-classification-parity.py dump URL --at 2026-10-08T06:00:00+00:00 \\
        --service perf-9999 --output new.json
    CATS_FINDING_CLASSIFICATION=false python scripts/benchmark-classification-parity.py dump ... --output live.json
    python scripts/benchmark-classification-parity.py compare old.json new.json live.json

Every page is requested through the real ASGI app as the page JSON envelope
(the frontend contract) and as the members API. Volatile fields (CSRF token,
request instant) are removed; the clock is frozen with ``--at`` so ages, due
dates and exception windows are identical across runs. Run ``dump`` twice per
configuration: the first pass builds any classification rows inline, the
second is the one compared (``--passes``).
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VOLATILE = {"csrf_token", "now", "generated_at", "request_id", "session", "elapsed_ms", "timings"}


def strip(value):
    if isinstance(value, dict):
        return {key: strip(item) for key, item in value.items() if key not in VOLATILE}
    if isinstance(value, list):
        return [strip(item) for item in value]
    return value


def urls_for(client, key, page_headers):
    simplified = f"/services/{key}?findings=true&findings_view=simplified"
    raw = f"/services/{key}?findings_view=raw"
    urls = [simplified, simplified + "&page=2", simplified + "&page=3", simplified + "&page_size=250&page=2",
            simplified + "&finding_state=resolved", simplified + "&finding_state=noncompliant",
            simplified + "&finding_state=exceptions", simplified + "&severity=Critical", simplified + "&severity=High,Low",
            simplified + "&q=package-01", simplified + "&q=cve-", simplified + "&resource=image-3",
            simplified + "&q=package-0&severity=Medium",
            raw, raw + "&page=2", raw + "&page=40", raw + "&page_size=250", raw + "&finding_state=resolved",
            raw + "&finding_state=exceptions", raw + "&finding_state=exceptions&page=2", raw + "&finding_state=exceptions&severity=High",
            raw + "&finding_state=exceptions&q=package-01", raw + "&finding_state=noncompliant",
            raw + "&finding_state=noncompliant&page=3", raw + "&finding_state=warnings", raw + "&severity=High",
            raw + "&q=package-01", raw + "&resource=image-2", raw + "&severity=Critical&q=cve-",
            raw + "&finding_type=vulnerability", raw + "&finding_type=configuration",
            f"/services/{key}?overview=true", f"/services/{key}?architecture=true",
            f"/services/{key}?validation=true", f"/services/{key}?poam=true"]
    data = client.get(simplified, headers=page_headers).json()["data"]
    groups = [group for group in (data.get("simplified_groups") or data.get("groups") or []) if isinstance(group, dict)]
    for group in groups[:3]:
        gid = group.get("group_id") or group.get("id")
        base = f"/api/v1/services/{key}/findings/simplified/{gid}/members"
        urls += [base, base + "?page=2", base + "?finding_state=exceptions", base + "?q=package-01",
                 base + "?severity=High"]
    return urls


def dump(args):
    os.environ.update(DATABASE_URL=args.database_url, PIPELINE_API_TOKEN="bench-token",
                      CATS_BOOTSTRAP_USERNAME="admin", CATS_BOOTSTRAP_PASSWORD="bench-password-long",
                      SESSION_COOKIE_SECURE="false", CATS_DEPLOYMENT_VALIDATION_ENABLED="false")
    sys.path.insert(0, str(Path(args.repo).resolve() / "portal"))
    from fastapi.testclient import TestClient
    from app import main
    from app import models
    frozen = datetime.fromisoformat(args.at)
    main.utcnow = lambda: frozen
    models.utcnow = lambda: frozen
    client = TestClient(main.app)
    response = client.post("/login", data={"username": "admin", "password": "bench-password-long"}, follow_redirects=False)
    assert response.status_code == 303, response.status_code
    page = {"Accept": "application/vnd.cats.page+json"}
    results = {}
    for _ in range(args.passes):
        for key in args.service:
            for url in urls_for(client, key, page):
                response = client.get(url, headers=page if not url.startswith("/api/") else {})
                body = response.json() if response.headers.get("content-type", "").startswith("application") else response.text
                results[url] = {"status": response.status_code, "data": strip(body.get("data", body) if isinstance(body, dict) else body)}
        for url in ("/api/dashboard/services?lifecycle=active", "/api/dashboard/cybersecurity"):
            response = client.get(url)
            results[url] = {"status": response.status_code, "data": strip(response.json())}
    Path(args.output).write_text(json.dumps(results, sort_keys=True, default=str))
    print(f"{len(results)} pages -> {args.output}")


def first_difference(left, right, path=""):
    if type(left) is not type(right):
        return path, left, right
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return f"{path}.{key}", left.get(key, "<absent>"), right.get(key, "<absent>")
            found = first_difference(left[key], right[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return f"{path}[len]", len(left), len(right)
        for index, (a, b) in enumerate(zip(left, right)):
            found = first_difference(a, b, f"{path}[{index}]")
            if found:
                return found
        return None
    return None if left == right else (path, left, right)


def compare(args):
    reference = json.loads(Path(args.files[0]).read_text())
    failures = 0
    for other in args.files[1:]:
        candidate = json.loads(Path(other).read_text())
        same = 0
        for url in sorted(reference):
            if url not in candidate:
                print(f"MISSING {other} {url}")
                failures += 1
                continue
            difference = first_difference(reference[url], candidate[url])
            if difference:
                failures += 1
                path, left, right = difference
                print(f"DIFF {other} {url}\n     at {path}: {str(left)[:200]!r} != {str(right)[:200]!r}")
            else:
                same += 1
        print(f"{other}: {same}/{len(reference)} pages identical to {args.files[0]}")
    raise SystemExit(1 if failures else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    dumping = commands.add_parser("dump")
    dumping.add_argument("database_url")
    dumping.add_argument("--repo", default=str(ROOT))
    dumping.add_argument("--service", action="append", required=True)
    dumping.add_argument("--at", required=True, help="frozen instant (ISO 8601 with offset)")
    dumping.add_argument("--passes", type=int, default=2)
    dumping.add_argument("--output", required=True)
    comparing = commands.add_parser("compare")
    comparing.add_argument("files", nargs="+")
    args = parser.parse_args()
    (dump if args.command == "dump" else compare)(args)


if __name__ == "__main__":
    main()
