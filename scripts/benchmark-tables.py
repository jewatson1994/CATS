"""Before/after Markdown tables from benchmark-navigation.py JSON results.

    python scripts/benchmark-tables.py BEFORE.json AFTER.json [--user admin]

Warm figures are medians over the repeats after the first request; "first"
is the first request to that scenario in the measuring process (see the
harness docstring), and "isolated" a first request in a fresh process.
"""
import argparse
import json


def load(path):
    data = json.load(open(path))
    rows = {(row["user"], row["scenario"]): row for row in data["results"]}
    isolated = {(row["user"], row["scenario"]): row for row in data.get("isolated_first", [])}
    return data, rows, isolated


def value(row, *keys):
    if row is None:
        return None
    for key in keys:
        if row.get(key) is not None:
            return row[key]
    return None


def fmt(number, unit=""):
    if number is None:
        return "n/a"
    if isinstance(number, float):
        number = round(number) if number >= 100 else round(number, 1)
    return f"{number:,}{unit}" if isinstance(number, int) else f"{number}{unit}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--only", help="scenario substring")
    args = parser.parse_args()
    _, before, before_isolated = load(args.before)
    after_data, after, after_isolated = load(args.after)
    print("| Request | Before: warm ms / SQL ms / queries / bytes | After: warm ms / SQL ms / queries / bytes | After: fresh-process first ms |")
    print("|---|---|---|---:|")
    for (user, scenario), row in after.items():
        if user != args.user or (args.only and args.only not in scenario):
            continue
        old = before.get((user, scenario))
        if old is not None and old.get("status") != 200:
            old = None

        def cell(r):
            if r is None or r.get("status") != 200:
                return "n/a"
            return " / ".join([fmt(value(r, "warm_median_ms")), fmt(value(r, "warm_query_ms_median", "query_ms_median")),
                               fmt(value(r, "queries")), fmt(value(r, "bytes"))])
        isolated = after_isolated.get((user, scenario), {}).get("duration_ms")
        print(f"| {scenario} | {cell(old)} | {cell(row)} | {fmt(isolated)} |")


if __name__ == "__main__":
    main()
