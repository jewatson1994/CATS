"""Concurrent interactive requests against a running CATS server.

Several logged-in clients (threads, one connection each) issue a mix of
ordinary navigation requests for a fixed duration. Latency percentiles are
reported per scenario, from the client side (the full HTTP round trip), with
the request count and errors. Optionally a background load runs at the same
time, to show how background work competes with interactive requests:

* ``--background reclassify``: full classification rebuilds of the named
  service in a loop, through the application's own refresh, in this process
  and on the server's database (the same work a scan or a catalog change
  schedules).

    python scripts/benchmark-concurrency.py http://127.0.0.1:8131 --service perf-9999 \\
        --clients 4 --seconds 60 --output concurrency.json [--background reclassify --database-url URL]

Point it only at disposable benchmark servers.
"""
import argparse
import json
import statistics
import sys
import threading
import time
from pathlib import Path

import httpx

PAGE = {"Accept": "application/vnd.cats.page+json"}


def scenarios(service):
    root = f"/services/{service}"
    return [
        ("services rows", "/api/dashboard/services?lifecycle=active", {}),
        ("cybersecurity data", "/api/dashboard/cybersecurity", {}),
        ("overview", f"{root}?overview=true", PAGE),
        ("findings simplified", f"{root}?findings=true&findings_view=simplified", PAGE),
        ("findings simplified search", f"{root}?findings=true&findings_view=simplified&q=package-01", PAGE),
        ("findings raw", f"{root}?findings_view=raw", PAGE),
        ("findings raw search", f"{root}?findings_view=raw&q=package-01", PAGE),
        ("findings raw exceptions", f"{root}?findings_view=raw&finding_state=exceptions", PAGE),
        ("architecture", f"{root}?architecture=true", PAGE),
    ]


def quantile(values, q):
    values = sorted(values)
    return round(values[min(len(values) - 1, int(round(q * (len(values) - 1))))], 1) if values else None


def client_loop(base, username, password, service, deadline, offset, results, errors):
    with httpx.Client(base_url=base, timeout=120) as client:
        response = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
        if response.status_code != 303:
            errors.append(f"login {response.status_code}")
            return
        mix = scenarios(service)
        index = offset
        while time.monotonic() < deadline:
            name, url, headers = mix[index % len(mix)]
            index += 1
            started = time.perf_counter()
            try:
                response = client.get(url, headers=headers)
                elapsed = (time.perf_counter() - started) * 1000
                if response.status_code != 200:
                    errors.append(f"{name} {response.status_code}")
                else:
                    results.setdefault(name, []).append(elapsed)
            except httpx.HTTPError as exc:
                errors.append(f"{name} {type(exc).__name__}")


def background_loop(database_url, service, deadline, stats):
    import os
    os.environ.setdefault("DATABASE_URL", database_url)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
    from sqlalchemy import select
    from app import finding_classification as fc
    from app.database import background_engine, SessionLocal
    from app.models import Service
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == service))
    while time.monotonic() < deadline:
        started = time.perf_counter()
        summary = fc.refresh(background_engine, service_id, full=True)
        stats.append({"ms": round((time.perf_counter() - started) * 1000, 1), "done": summary is not None})


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("base_url")
    parser.add_argument("--service", required=True)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="bench-password-long")
    parser.add_argument("--background", choices=["none", "reclassify"], default="none")
    parser.add_argument("--database-url")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results, errors, background = {}, [], []
    deadline = time.monotonic() + args.seconds
    threads = [threading.Thread(target=client_loop, args=(args.base_url, args.username, args.password, args.service,
                                                          deadline, offset, results, errors))
               for offset in range(args.clients)]
    if args.background == "reclassify":
        if not args.database_url:
            raise SystemExit("--background reclassify needs --database-url")
        threads.append(threading.Thread(target=background_loop, args=(args.database_url, args.service, deadline, background)))
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.monotonic() - started
    report = {"clients": args.clients, "seconds": round(wall, 1), "background": args.background,
              "requests": sum(len(values) for values in results.values()),
              "throughput_rps": round(sum(len(values) for values in results.values()) / wall, 2),
              "errors": errors[:20], "error_count": len(errors),
              "background_runs": background,
              "scenarios": {name: {"n": len(values), "p50_ms": quantile(values, 0.5), "p95_ms": quantile(values, 0.95),
                                   "max_ms": round(max(values), 1), "mean_ms": round(statistics.mean(values), 1)}
                            for name, values in sorted(results.items())}}
    print(json.dumps(report, indent=2))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
