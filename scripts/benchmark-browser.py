"""Browser time-to-useful-content for CATS pages (Playwright, headless Chromium).

Run against a CATS server seeded by scripts/benchmark-navigation.py (admin
password ``bench-password-long``; service ``perf-0001``)::

    python scripts/benchmark-browser.py http://127.0.0.1:8101 out.json 3
    MODE=inapp python scripts/benchmark-browser.py http://127.0.0.1:8101 inapp.json 3

Times are taken on the page clock: from navigation start (full loads) or
from the dispatched click (in-app), to the first animation frame in which the
page's useful content is present and no navigation is pending. Hover
prefetch is not exercised (clicks are dispatched directly). Byte counts are
response bodies as transferred (GZip applies). CHROMIUM overrides the
browser executable.
"""
import json, os, sys, time
from playwright.sync_api import sync_playwright

BASE, OUT = sys.argv[1], sys.argv[2]
ROUNDS = int(sys.argv[3]) if len(sys.argv) > 3 else 3
SVC = "/services/perf-0001"
# (name, url, tab link label, JS predicate for "useful content")
def has(selector, text):
    return f"[...document.querySelectorAll({json.dumps(selector)})].some(e => {text}.test(e.textContent))"
PAGES = [
    ("Services", "/", None, has("main table tbody td", "/Performance 1/")),
    ("Cybersecurity", "/cybersecurity", None, has("main table tbody td", "/Performance 1/") + " && /Active vulnerabilities/.test(document.querySelector('main').textContent)"),
    ("Service Overview", SVC + "?overview=true", "Overview", "/Active Fixable/.test(document.querySelector('main').textContent)"),
    ("Findings", SVC + "?findings=true", "Findings", has("main table tbody td", "/CVE-/")),
    ("Architecture", SVC + "?architecture=true", "Architecture", has("main svg text, main svg *", "/ConfigMap/") + " || " + has("main [class*=node]", "/ConfigMap/")),
    ("Dependencies", SVC + "?dependencies=true", "Dependencies", has("main table tbody td", "/package-/")),
    ("Deployment Validation", SVC + "?validation=true", "Deployment Validation", "/Validation run/.test(document.querySelector('main').textContent)"),
    ("Remediation", SVC + "?remediations=true&tab=pipeline", "Remediations", "/Remediation candidates/.test(document.querySelector('main').textContent)"),
]
READY = "(() => { const m = document.querySelector('main'); if (!m || document.querySelector('.page-navigating')) return false; return %s; })()"


class Traffic:
    def __init__(self, page):
        self.items = []
        page.on("requestfinished", self.finished)

    def finished(self, request):
        try:
            size = request.sizes()["responseBodySize"]
        except Exception:
            size = 0
        self.items.append((request.resource_type, request.url, size))

    def mark(self):
        return len(self.items)

    def since(self, mark):
        items = self.items[mark:]
        api = [item for item in items if item[0] in ("fetch", "xhr", "document")]
        return {"requests": len(items), "api_requests": len(api), "api_bytes": sum(item[2] for item in api),
                "all_bytes": sum(item[2] for item in items)}


def wait_ready(page, predicate, url_part, timeout=120000):
    """Milliseconds (page clock) from window.__catsT0 (or navigation start) to useful content."""
    handle = page.wait_for_function(
        "(() => (location.href.includes(%s) && %s) ? performance.now() - (window.__catsT0 || 0) : false)()"
        % (json.dumps(url_part), READY % predicate), polling="raf", timeout=timeout)
    return handle.json_value()


def login(context):
    response = context.request.post(BASE + "/login", form={"username": "admin", "password": "bench-password-long"}, max_redirects=0)
    assert response.status == 303, response.status


def full_loads(browser):
    results = []
    for name, url, _tab, predicate in PAGES:
        samples = []
        for _ in range(ROUNDS):
            context = browser.new_context()  # empty HTTP cache: a first visit
            login(context)
            page = context.new_page()
            traffic = Traffic(page)
            page.goto(BASE + url, wait_until="commit")
            try:
                elapsed = wait_ready(page, predicate, url.split("?")[0])
            except Exception:
                print("TIMEOUT", name, page.evaluate("document.querySelector('main') && document.querySelector('main').textContent.slice(0, 400)"), flush=True)
                raise
            page.wait_for_timeout(300)
            samples.append({"ms": round(elapsed, 1), **traffic.since(0)})
            context.close()
        results.append({"page": name, "kind": "full load", "samples": samples})
    return results


def js_click(page, selector, text):
    """Dispatch a real click in the page and start the page clock at that instant."""
    found = page.evaluate("""([selector, text]) => {
        const el = [...document.querySelectorAll(selector)].find(e => e.textContent.trim() === text || e.textContent.includes(text));
        if (!el) return false;
        window.__catsT0 = performance.now();
        el.click();
        return true;
    }""", [selector, text])
    assert found, (selector, text)


def click_tab(page, label):
    js_click(page, "main .service-tabs a", label)


def in_app(browser):
    context = browser.new_context()
    login(context)
    page = context.new_page()
    traffic = Traffic(page)
    page.goto(BASE + "/", wait_until="commit")
    wait_ready(page, PAGES[0][3], "/")
    page.wait_for_timeout(1500)
    results = []

    def step(name, action, url_part, predicate, kind):
        mark = traffic.mark()
        action()
        elapsed = wait_ready(page, predicate, url_part)
        page.wait_for_timeout(600)  # let deferred/background requests finish, attribute them to this step
        results.append({"page": name, "kind": kind, "ms": round(elapsed, 1), **traffic.since(mark)})

    step("Service Overview", lambda: js_click(page, "main table tbody a", "Performance 1"),
         SVC, PAGES[2][3], "navigate from Services")
    for round_number in (1, 2, 3):
        kind = "first tab visit" if round_number == 1 else "repeat tab visit"
        for name, url, tab, predicate in PAGES[3:] + [PAGES[2]]:
            step(name, lambda tab=tab: click_tab(page, tab), url.split("?")[1].split("&")[0].split("=")[0], predicate, kind)
    step("Services", lambda: js_click(page, "nav.account-nav a", "Services"), "/", PAGES[0][3], "navigate back to Services")
    step("Cybersecurity", lambda: js_click(page, "nav.account-nav a", "Cybersecurity"), "/cybersecurity", PAGES[1][3], "navigate")
    step("Services", lambda: page.evaluate("window.__catsT0 = performance.now(); history.back()"), "/", PAGES[0][3], "browser back")
    context.close()
    return results


def polling(browser, url, seconds=15):
    context = browser.new_context()
    login(context)
    page = context.new_page()
    page.goto(BASE + url, wait_until="networkidle")
    traffic = Traffic(page)
    page.wait_for_timeout(seconds * 1000)
    data = traffic.since(0)
    context.close()
    return {"page": url, "kind": f"polling over {seconds}s", **data}


import os
if os.getenv("MODE") == "inapp":
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.getenv("CHROMIUM") or None)
        runs = [in_app(browser) for _ in range(ROUNDS)]
        browser.close()
    json.dump(runs, open(OUT, "w"), indent=2)
    for index, row in enumerate(runs[0]):
        values = sorted(run[index]["ms"] for run in runs)
        print(f"{row['page']:<22} {row['kind']:<26} median {values[len(values)//2]:8.1f} ms  all {values}")
    sys.exit(0)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.getenv("CHROMIUM") or None)
    output = {"base": BASE, "full_loads": full_loads(browser), "in_app": in_app(browser),
              "polling": [polling(browser, SVC + "/remediations/R-BENCH-ACTIVE"),
                          polling(browser, SVC + "?validation=true")]}
    browser.close()
json.dump(output, open(OUT, "w"), indent=2)
for row in output["full_loads"]:
    ms = sorted(s["ms"] for s in row["samples"])
    print(f"{row['page']:<22} full load median {ms[len(ms)//2]:8.1f} ms  api_requests {row['samples'][-1]['api_requests']}  api_bytes {row['samples'][-1]['api_bytes']}")
for row in output["in_app"]:
    print(f"{row['page']:<22} {row['kind']:<26} {row['ms']:8.1f} ms  api_requests {row['api_requests']}  api_bytes {row['api_bytes']}")
for row in output["polling"]:
    print(row)
