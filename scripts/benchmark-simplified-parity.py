"""Compare Simplified Findings pages (groups and members) with and without the LATERAL form."""
import json, os, sys
os.environ.update(DATABASE_URL=sys.argv[1], PIPELINE_API_TOKEN="bench-token", CATS_BOOTSTRAP_USERNAME="admin",
                  CATS_BOOTSTRAP_PASSWORD="bench-password-long", SESSION_COOKIE_SECURE="false")
sys.path.insert(0, "/home/claude/w/cats/portal")
from fastapi.testclient import TestClient
from app import main, simplified_queries
client = TestClient(main.app)
assert client.post("/login", data={"username": "admin", "password": "bench-password-long"}, follow_redirects=False).status_code == 303
PAGE = {"Accept": "application/vnd.cats.page+json"}
urls = []
for key in sys.argv[2:]:
    base = f"/services/{key}?findings=true&findings_view=simplified"
    urls += [base, base + "&page=2", base + "&finding_state=resolved", base + "&finding_state=noncompliant",
             base + "&severity=Critical", base + "&q=package-01", base + "&page_size=250&page=3"]
mismatches = 0
for url in urls:
    simplified_queries.LATERAL_CURRENT_OBSERVATION = False
    reference = client.get(url, headers=PAGE).json()["data"]
    simplified_queries.LATERAL_CURRENT_OBSERVATION = True
    candidate = client.get(url, headers=PAGE).json()["data"]
    strip = lambda data: json.dumps({k: v for k, v in data.items() if k not in {"csrf_token", "now", "generated_at"}}, sort_keys=True, default=str)
    same = strip(reference) == strip(candidate)
    groups = reference.get("simplified_groups") or reference.get("groups") or []
    mismatches += not same
    print(("SAME " if same else "DIFF ") + url, len(json.dumps(reference)), "bytes")
# Group member pages too.
for key in sys.argv[2:]:
    data = client.get(f"/services/{key}?findings=true&findings_view=simplified", headers=PAGE).json()["data"]
    groups = [g for g in (data.get("simplified_groups") or data.get("groups") or []) if isinstance(g, dict)][:3]
    for group in groups:
        gid = group.get("group_id") or group.get("id")
        url = f"/services/{key}?findings=true&findings_view=simplified&group={gid}"
        simplified_queries.LATERAL_CURRENT_OBSERVATION = False
        reference = client.get(url, headers=PAGE).text
        simplified_queries.LATERAL_CURRENT_OBSERVATION = True
        candidate = client.get(url, headers=PAGE).text
        same = json.loads(reference)["data"] == json.loads(candidate)["data"]
        mismatches += not same
        print(("SAME " if same else "DIFF ") + url)
print("mismatches", mismatches)
