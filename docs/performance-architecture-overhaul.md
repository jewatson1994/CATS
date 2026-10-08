# CATS performance architecture overhaul

Branch `feature/performance-architecture-overhaul`, from `main` at
`f56bbf8963d72fabe9c8060fe5e6868d1d3564b7`. Not merged, not pushed.

Goal: CATS should feel fast and seamless during normal use, without weakening
evidence authority, provenance, isolation, authorization or offline operation.

A second pass, "Second pass: precomputed finding classification" below, adds
a rebuildable per-finding classification read model for services with tens
of thousands of findings, with its own before/after measurements.

This revision incorporates an independent source review of the first
implementation. Its eight blocking defects are fixed, its measurement
criticisms are addressed (labels, percentiles, byte accounting, metadata,
fresh-process first requests), and the scale it called untested was measured
as far as this environment allows (see "Scale").

## How it was measured

Every number here comes from the retained JSON in
`docs/performance-architecture/`. Nothing is estimated or extrapolated.

* **Database:** PostgreSQL 16, local socket, default server settings. The
  baseline runs with the server's JIT on; the branch turns JIT off for its own
  sessions.
* **Datasets:**
  * SMALL: 10 services × 2 scans × 1,000 findings.
  * MEDIUM: 100 services × 2 scans × 10,000 findings (1,000,000 active
    findings, about 10 MB of retained payload per scan).
  * LARGE (portfolio): 1,000 services × 2 scans × 1,000 findings.
  * LARGE (dense): one more service with 2 scans × 50,000 findings, on the
    same database (1,050,000 active findings, 2.1 M observations).
* **Server harness** (`scripts/benchmark-navigation.py`). It drives the real
  ASGI app and records CATS' own per-request metrics: duration, SQL time,
  query count and uncompressed response bytes.
  * *warm*: the median of 4 repeats after the first request, never including
    the first.
  * *fresh-process first*: each scenario's first request in its own new
    process, with only the login before it (`--isolated-first`).
  * Every sample, the git revision, the dataset size and the preparation
    state are stored with each run.
  * Background maintenance does not run under this harness. Upgrade
    preparation was measured on a real server instead.
* **Browser harness** (`scripts/benchmark-browser.py`). It drives headless
  Chromium against uvicorn.
  * Time is taken on the page clock, from navigation start or click to the
    first frame showing the page's real data (a service row, a CVE row, graph
    nodes, run status) with no navigation pending.
  * Hover prefetch is not exercised, so these are conservative figures.
  * Transferred bytes and uncompressed API bytes are reported separately.
    Unknown sizes are counted, never summed.
* **Baseline:** the same harnesses against a worktree at `f56bbf8`, on the
  same database.

## Results

### Services and Cybersecurity (server, warm, admin)

Before, Services needed two requests: the page shell, then its rows. Now the
rows arrive with the page.

| Scale | Services before | Services after | Cybersecurity before | Cybersecurity after |
|---|---:|---:|---:|---:|
| SMALL | 8 + 54 ms (2 requests) | 16 ms (1) | 334 ms | 11 ms |
| MEDIUM | 9 + 1,659 ms (2 requests) | 29 ms (1) | 12,612 ms | 15 ms |
| LARGE portfolio | 7 + 2,187 ms (2 requests) | 72 ms (1) | 27,336 ms | 62 ms |
| MEDIUM, restricted user | 12 + 344 ms | 19 ms | 2,338 ms | 14 ms |

Fresh-process first requests on the branch take 24–96 ms at every scale.
The warm cost still grows with the number of authorized services (see
"Remaining costs").

### Service tabs (server, warm, admin)

| Request | MEDIUM before → after | Dense 50,000-finding service before → after |
|---|---|---|
| Overview | 94 → 67 ms | 521 → 135 ms |
| Findings, Simplified | 192 → 166 ms | 2,237 → 562 ms |
| Findings, Raw | 90 → 69 ms | 409 → 188 ms |
| Findings, search | 304 → 105 ms | 1,695 → 363 ms |
| Architecture | 42 → 36 ms | 34 → 38 ms |
| Dependencies | 53 ms, 211 KB → 58 ms, 39 KB | 93 ms, 926 KB → 45 ms, 39 KB |
| Remediations | 37 → 42 ms | 35 → 33 ms |

The full per-scenario tables, with SQL time, query counts and bytes, are in
`docs/performance-architecture/tables.md`.

**Run-to-run variance.** A few paths that this work did not change measured
slower in the branch's MEDIUM run: Validation 28 → 38 ms, Activity 31 →
48 ms, and the legacy full validation endpoint 120 → 257 ms. The same paths
measured equal or faster in the SMALL and LARGE runs, so these are reported,
not explained away.

### Polling

| Workflow | Before | After |
|---|---|---|
| Remediation report | 280,719 bytes every 1.5 s, full report | 1,908 bytes, ~9 ms, backoff. The report is fetched only when its revision changes, and at the end. |
| Deployment Validation | 96,723 bytes (full evidence) | 633 bytes, ~8 ms |
| Dependency preparation | Reloaded the whole page | 142 bytes, ~10 ms. Updates in place. |
| Hidden tab | Kept polling (remediation) | No requests |

### Startup and upgrade

* **Fresh process, ready to serve (harness):** about 33.4 s before (import
  ran the upgrade backfills in every process) vs about 1.5 s after (MEDIUM
  and LARGE).
* **Upgrading the LARGE database** (seeded by the baseline) on a real server:
  * The first page was served 1.7 s after start.
  * During preparation, Services and Cybersecurity answered in about 1.0 s
    each. They listed the 25 services prepared inline and stated that 976
    were "still being prepared"; totals excluded them, and no values were
    invented.
  * Background posture for every service was ready about 24 s after start.
* **Preparation steps on that upgrade** (one process; others skip them):

| Step | Time |
|---|---:|
| Summary field backfill (one-time) | 120 s |
| Legacy policy backfill (now skips services synced at ingest) | 219 s |
| Incomplete-scan repair (payload now deferred) | 1.2 s |
| Posture rows | 11 s |
| Stored overviews | 76 s |

### Browser

**Direct document load, MEDIUM** (new browser context; median of 3):

| Page | Before | After | API requests | API body bytes (uncompressed) |
|---|---:|---:|---|---|
| Services | 2,076 ms | 137 ms | 2 → 1 | 15,960 → 16,304 |
| Cybersecurity | 13,742 ms | 138 ms | 3 → 1 | 25,191 → 26,087 |
| Service Overview | 245 ms | 173 ms | 1 → 1 | 10,447 → 10,489 |
| Findings | 340 ms | 250 ms | 1 → 1 | 22,619 → 22,661 |
| Architecture | 155 ms | 160 ms | 2 → 2 | 144,508 → 144,550 |
| Dependencies | 208 ms | 184 ms | 1 → 1 | 231,720 → 43,720 |
| Deployment Validation | 176 ms | 190 ms | 1 → 1 | 33,762 → 33,840 |
| Remediation | 146 ms | 166 ms | 1 → 1 | 4,385 → 4,454 |

**In-app navigation, MEDIUM** (median of 3 runs):

| Step | Before | After |
|---|---:|---:|
| Navigate from Services: Service Overview | 152 ms | 151 ms |
| First tab visit: Findings | 245 ms | 196 ms |
| First tab visit: Architecture | 83 ms | 90 ms |
| First tab visit: Dependencies | 138 ms | 108 ms |
| First tab visit: Deployment Validation | 76 ms | 90 ms |
| First tab visit: Remediation | 87 ms | 95 ms |
| Return to Overview (first round; it was visited before the tabs) | 130 ms | 21 ms |
| Repeat tab visit: Findings | 246 ms | 49 ms |
| Repeat tab visit: Architecture | 80 ms | 30 ms |
| Repeat tab visit: Dependencies | 115 ms | 37 ms |
| Repeat tab visit: Deployment Validation | 66 ms | 36 ms |
| Repeat tab visit: Remediation | 74 ms | 18 ms |
| Repeat tab visit: Service Overview | 130 ms | 24 ms |
| Navigate back to Services: Services | 1,753 ms | 21 ms |
| Navigate: Cybersecurity | 13,236 ms | 91 ms |
| Browser back: Services | 1,846 ms | 26 ms |

Remediation report open for 15 s: 9 requests and 95,472 bytes transferred before; 4 requests and 2,760 bytes after.

**Direct document load, LARGE portfolio; service tabs on a 1,000-finding service** (new browser context; median of 3):

| Page | Before | After | API requests | API body bytes (uncompressed) |
|---|---:|---:|---|---|
| Services | 2,516 ms | 194 ms | 2 → 1 | 16,010 → 16,354 |
| Cybersecurity | 28,601 ms | 191 ms | 3 → 1 | 72,676 → 77,189 |
| Service Overview | 184 ms | 164 ms | 1 → 1 | 10,445 → 10,487 |
| Findings | 178 ms | 164 ms | 1 → 1 | 22,211 → 22,253 |
| Architecture | 151 ms | 196 ms | 2 → 2 | 144,508 → 144,550 |
| Dependencies | 173 ms | 159 ms | 1 → 1 | 55,457 → 43,642 |
| Deployment Validation | 168 ms | 197 ms | 1 → 1 | 33,763 → 33,841 |
| Remediation | 153 ms | 163 ms | 1 → 1 | 4,385 → 4,454 |

**In-app navigation, LARGE portfolio; service tabs on a 1,000-finding service** (median of 3 runs):

| Step | Before | After |
|---|---:|---:|
| Navigate from Services: Service Overview | 104 ms | 100 ms |
| First tab visit: Findings | 101 ms | 117 ms |
| First tab visit: Architecture | 80 ms | 98 ms |
| First tab visit: Dependencies | 105 ms | 83 ms |
| First tab visit: Deployment Validation | 83 ms | 98 ms |
| First tab visit: Remediation | 71 ms | 93 ms |
| Return to Overview (first round; it was visited before the tabs) | 81 ms | 19 ms |
| Repeat tab visit: Findings | 90 ms | 23 ms |
| Repeat tab visit: Architecture | 69 ms | 23 ms |
| Repeat tab visit: Dependencies | 103 ms | 62 ms |
| Repeat tab visit: Deployment Validation | 63 ms | 34 ms |
| Repeat tab visit: Remediation | 69 ms | 25 ms |
| Repeat tab visit: Service Overview | 88 ms | 19 ms |
| Navigate back to Services: Services | 2,309 ms | 35 ms |
| Navigate: Cybersecurity | 27,224 ms | 131 ms |
| Browser back: Services | 2,343 ms | 28 ms |

Remediation report open for 15 s: 9 requests and 95,454 bytes transferred before; 4 requests and 2,760 bytes after.

**What the browser numbers show.**

* **Big wins:** Services, Cybersecurity and every return to a page already
  visited.
* **Unchanged or slightly faster:** direct loads of most service tabs.
* **Two trade-offs:**
  * A direct document load of a code-split page (Architecture, Deployment
    Validation, Remediation) is about 5–45 ms slower, because it fetches its
    chunk before the first render.
  * First in-app visits to some tabs are about 10–25 ms slower. The previous
    page stays visible, inert, until the next one is ready; removing it
    happens at reveal, and the new request-generation checks add a little.
  * Neither is perceptible against the repeat-visit and portfolio gains, but
    both are real.

## Second pass: precomputed finding classification

A follow-up pass on the same branch, aimed at the remaining backend cost of
services with tens of thousands of findings. Every number below was measured
for this pass. The retained JSON, the per-scenario tables (`tables.md`),
storage and parity outputs are in
`docs/performance-architecture/classification/`.

### What was implemented

* **A current-classification read model** (`finding_classifications`, one
  row per finding). It stores what Findings, Simplified Findings and the
  service header used to recompute for every finding on every page view:
  * risk eligibility (minimum severity, KEV and EPSS evidence and catalogs),
  * the non-compliance rule,
  * the current exception state,
  * the current observation, with its Simplified group, package,
    remediation and fixed version,
  * KEV/EPSS evidence values, fixability,
  * the search surface (the finding's text plus its latest twenty
    observations' text).

  Overdue status is deliberately **not** stored. It changes with time alone,
  so readers evaluate the canonical overdue expression on the stored
  severity and episode start at the request's instant.
* **Reads served from it, when current:**
  * Simplified groups and members;
  * Raw Active, Resolved and Exceptions. Exceptions is now SQL-paged; it
    previously ran the Python evaluator over the whole service.
  * Raw Non-Compliant;
  * the service header's compliance test;
  * Overview counts;
  * the per-service finding counts behind Services posture rebuilds and
    the Raw header.
* **The live queries remain the reference.** Every reader falls back to the
  original query when the rows are not current, and
  `CATS_FINDING_CLASSIFICATION=false` turns the model off entirely.
* **Simplified aggregation over the stored rows.** This is a leaner
  evaluation of the same result:
  * members carry grouping columns only;
  * each page's package and remediation are read from one member (they are
    uniform within a group, whose id is their hash);
  * the severity representative is one integer key;
  * the distinct-CVE count is two hash aggregations, not a sort;
  * image counts use per-member index lookups.
  * In a UTC database session, the due date is the earliest due instant,
    formatted once. In other zones each member's due date is formatted, as
    before, because a daylight-saving hour breaks ordering.
* **Severity filter choices** are stored with each service's classification,
  so both findings pages stop scanning every finding for them.
* **Other measurable backend fixes found on the way:**
  * The posture and classification write listeners each tested
    `instance in session.dirty` for every flushed object. `dirty` is
    recomputed on every access, so a 2,000-finding ingest spent 1.4 s and
    1.3 s in them; it is now 0.15 s and 0.11 s.
  * The classification build parses each finding's evidence once instead of
    once per expression (50,000 findings: 4.1 s → 2.4 s; 1,000: 190 →
    63 ms).
  * Targeted reclassification switches to a full rebuild above a quarter of
    the service (1,000 of 1,050 findings took 1.1 s targeted, 67 ms full).

### Database and schema changes

New tables, created by the existing startup path. There are no changes to
existing tables, and nothing authoritative is moved or rewritten:

| Table | Rows | Purpose |
|---|---|---|
| `finding_classifications` | one per finding | The stored values above. Index `(service_id, active, eligible, excepted)`. |
| `finding_classification_state` | one per service | Provenance: algorithm version, posture epoch, configuration digest (with the KEV/EPSS catalog token when the configuration uses the catalogs), latest execution, the exception validity window `[valid_from, valid_until)`, build time, severity choices. |
| `finding_classification_changes` | transient | Change log written in the writer's own transaction: a finding id, or NULL for the whole service. |

No foreign keys: a cache row can never block a deletion. A deleted service's
rows are removed in the same transaction, and startup removes any orphans.

### Background classification behavior

| Change | Effect |
|---|---|
| A scan is ingested (new execution) | Whole service, rebuilt in the background after the commit. |
| A finding or observation is added, edited or deleted | Those findings only. |
| An exception is created, edited or revoked | That finding only. |
| An exception starts or expires (time alone) | The state's validity window ends, and the findings with exceptions are reclassified. |
| A finding becomes overdue (time alone) | Nothing: overdue is evaluated at read time. |
| A classification-relevant policy setting changes (compliance mode, minimum severity, KEV/EPSS rules) | Every service using it, by configuration digest. Due-date settings change only the read-time overdue term and trigger nothing. |
| The KEV/EPSS catalogs change | Only services whose configuration uses the catalogs (risk-based with KEV or EPSS enabled). In raw mode, the default, nothing. |
| A bulk statement names its services, or names none | Those services in full; or none named: the posture epoch is replaced and everything is stale. |

* **Refresh.** One transaction under a per-service PostgreSQL advisory lock.
  It reads the pending change rows, reclassifies those findings (or the
  service), writes the state row, and deletes exactly the change rows it
  read.
  * A write that commits meanwhile leaves its own change row, so the
    service stays stale and is refreshed again.
  * An interrupted refresh rolls back and changes nothing.
  * Tests cover both, plus stale-time recovery, configuration and catalog
    changes, bulk statements, orphans and the off/on switch.
* **Readers.**
  * One statement checks currency, and the result is cached for the
    request.
  * Findings pages repair small staleness inline: targeted refreshes, or a
    full rebuild of services up to `CATS_CLASSIFICATION_SYNC_FINDINGS`
    (5,000). Above that they schedule a background refresh and serve the
    live query meanwhile.
  * Overview and the other tabs never write during a GET; they only use
    rows that are already current.
* **Background work.**
  * A single coalescing worker on the background connection pool.
  * Startup preparation runs as a step-logged maintenance step before
    posture, so posture rebuilds count from it.
* **Switched off.** Writers drop the touched services' state rows instead of
  logging, so switching it back on rebuilds exactly what changed and the log
  cannot grow.

### Measurements

Environment as in "How it was measured":
* Hardware and data: 2 vCPU, PostgreSQL 16 on the same VM, the same LARGE
  and MEDIUM databases.
* **Statistics:** both databases were `ANALYZE`d first. The container's
  earlier restarts had discarded PostgreSQL's statistics, which distorted
  plans for both sides.
* **Session time zone:** UTC (the PostgreSQL container default) for every
  run, before and after.
* **Before:** this branch at `e20f906`, immediately before this pass, with
  the same harness. The harness gained the findings scenarios below.
* **Classification mix:** a deterministic fixture
  (`scripts/benchmark-classification-fixture.py`) gives the measured
  services real variety.
  * About 35% of active findings are 100–400 days old and 25% are 31–99
    days old.
  * 3% have exceptions: current, expired, future and revoked.

**Dense service: 50,000 findings per scan (LARGE database, 1,001 services; server, warm median of 4, admin)**

| Request | Before ms (SQL ms) | After ms (SQL ms) |
|---|---:|---:|
| Findings, Simplified | 407 (380) | 171 (139) |
| Simplified, page 3 | 361 (332) | 163 (130) |
| Simplified, search | 378 (348) | 108 (78) |
| Simplified, severity filter | 125 (97) | 78 (49) |
| Simplified, Non-Compliant | 288 (264) | 127 (98) |
| Simplified group members | 302 (281) | 51 (36) |
| Findings, Raw | 213 (177) | 120 (78) |
| Raw, page 20 | 213 (174) | 144 (107) |
| Raw, search | 416 (382) | 124 (84) |
| Raw, severity filter | 183 (145) | 102 (64) |
| Raw, Exceptions | 3,360 (569) | 94 (53) |
| Raw, Resolved | 161 (127) | 86 (49) |
| Raw, Non-Compliant | 117 (83) | 99 (66) |
| Overview | 191 (152) | 146 (101) |

**10,000-finding service (MEDIUM database, 100 services)**

| Request | Before ms (SQL ms) | After ms (SQL ms) |
|---|---:|---:|
| Findings, Simplified | 108 (80) | 67 (37) |
| Simplified, page 3 | 114 (86) | 63 (36) |
| Simplified, search | 166 (136) | 52 (25) |
| Simplified, Non-Compliant | 107 (79) | 59 (32) |
| Simplified group members | 87 (64) | 25 (11) |
| Findings, Raw | 75 (42) | 73 (35) |
| Raw, search | 133 (98) | 70 (34) |
| Raw, Exceptions | 702 (132) | 65 (28) |
| Raw, Resolved | 70 (34) | 62 (26) |
| Raw, Non-Compliant | 67 (35) | 71 (35) |
| Overview | 72 (39) | 77 (38) |

**Fresh-process first request, dense service:**

| Request | Before | After |
|---|---:|---:|
| Simplified | 440 ms | 227 ms |
| Raw | 269 ms | 183 ms |
| Raw, search | 511 ms | 188 ms |
| Raw, Exceptions | 3,268 ms | 147 ms |
| Simplified group members | 312 ms | 100 ms |

**Concurrent interactive requests.** A real uvicorn server with 4 logged-in
clients for 60 s, cycling through nine views of the dense service and the
portfolio. Latencies are client-side.

| | Before | After | After, with back-to-back background full rebuilds of the dense service |
|---|---:|---:|---:|
| Throughput | 1.85 req/s (134 requests) | 15.1 req/s (908) | 11.8 req/s (734) |
| Simplified p50 / p95 | 779 / 851 ms | 343 / 444 ms | 454 / 633 ms |
| Raw p50 / p95 | 438 / 497 ms | 315 / 433 ms | 358 / 527 ms |
| Raw, Exceptions p50 / p95 | 13,091 / 14,133 ms | 252 / 364 ms | 279 / 382 ms |
| Raw, search p50 / p95 | 945 / 1,327 ms | 318 / 438 ms | 372 / 533 ms |
| Overview p50 / p95 | 455 / 837 ms | 348 / 484 ms | 468 / 686 ms |
| Services rows p50 / p95 | 412 / 929 ms | 185 / 284 ms | 219 / 355 ms |
| Errors | 0 | 0 | 0 |

* **Before**, each Raw Exceptions request held the CPU for about 13 s of
  Python evaluation, and every other view queued behind it.
* **Background load:** the third column is a deliberate worst case,
  13 back-to-back full rebuilds of the 50,000-finding service (about 4.6 s
  each under this load) for the whole minute. It cost 22% of interactive
  throughput. A real deployment rebuilds once per scan of that service.

**Classification processing** (median of 3 full rebuilds, one transaction each):

| Service size | Full rebuild | 1 / 100 / 1,000 changed findings |
|---|---:|---|
| 1,050 findings | 63 ms | 31 / 45 ms / (full) 67 ms |
| 10,500 findings | 405 ms | 50 / 54 / 311 ms |
| 52,500 findings | 2.4 s | 98 / 85 / 236 ms |
| Whole LARGE portfolio (1,001 services, 1.1 M findings) | 67 s | — |
| Whole MEDIUM portfolio (100 services, 1.05 M findings) | 63 s | — |

Peak resident memory of the process running these builds: about 125 MB,
compared with 62 MB after import.

**Storage** (after `VACUUM FULL`):

| Database | Classification rows | Size | Share of the database | For comparison |
|---|---:|---:|---:|---|
| LARGE | 1,102,500 | 588 MB (555 MB table, 32 MB index) | 14% of 4.2 GB | findings 656 MB, observations 1,372 MB |
| MEDIUM | 1,050,000 | 558 MB | 21% of 2.6 GB | findings 550 MB, observations 1,303 MB |

That is about 480 bytes per finding: the search surface is 36% of it and the
group id 14%. Each rescan rewrites the service's rows. Before vacuum, after
repeated test rebuilds, the table was 1.1 GB, so autovacuum must keep up,
much as it already must for observations.

**Ingest** (a fresh database, 20 services × 2 scans × 2,000 findings,
through the real pipeline route, one process):

| | Total |
|---|---:|
| Before (`e20f906`) | 143 s |
| After | 132 s |
| After, classification off | 122 s |

* **After is faster than before.** The posture write listener added
  earlier on this branch had the quadratic `session.dirty` check; fixing it
  in both listeners saves more than the change log costs.
* **The background reclassification** of the 40 new scans costs about 10 s
  of this run, in the same process, after each commit.

### Correctness

* **Page parity on real PostgreSQL data.**
  `scripts/benchmark-classification-parity.py` requests 102 findings-
  related pages per run and compares them across three runs at a frozen
  instant:
  * the code before this pass,
  * this code reading classification rows,
  * this code with classification off.

  The pages are the page JSON contract plus the members API: every Simplified
  and Raw state, filters, searches, pages and page sizes, members, Overview,
  header tabs, Services and Cybersecurity. All 102 were identical:
  * on LARGE (the 50,000- and 1,000-finding services), in UTC and in
    America/New_York sessions, both with rows from an earlier build and
    with rows built by the final code;
  * on MEDIUM (a fixture service and an untouched one).
* **Regression tests** (`tests/test_finding_classification.py`, 21 tests,
  also run against PostgreSQL with `CATS_TEST_DATABASE_URL`):
  * Stored sets match both the live SQL and the Python `service_view`
    evaluator across six configurations: raw mode with and without due
    rules, risk-based with minimum severity, KEV, KEV with EPSS, and an
    EPSS-threshold fallback. Evidence covers JSON truthiness and EPSS
    parsing edge cases.
  * Months later, overdue still agrees without a rebuild.
  * Whole pages are identical with and without the stored classification.
  * Stored values are the expressions' own three-valued results.
  * Targeted versus whole-service invalidation; only changed findings are
    rewritten.
  * Exception boundaries; a write racing a refresh; an interrupted
    refresh.
  * Configuration and catalog changes; bulk statements; orphans; the
    off/on switch; reused finding ids; a service deleted mid-request.

### Independent review

A separate reviewer read the change cold. It confirmed:
* the parity of every classified read path, line by line: three-valued
  logic, the rule-AND-overdue decomposition, and the Simplified aggregation
  rewrite;
* the configuration digest's coverage;
* invalidation and concurrency.

It found two defects, both fixed with tests that fail on the earlier code:
* **SQLite reuses deleted row ids.** A refresh could remove another
  service's row for a reused finding id, then report that service current.
  Rows are now removed only by their own service, or by the service that
  owns the finding id now.
* **A service deleted mid-request** made the currency check raise. The
  reader now falls back to the live query.

Two concerns are accepted and documented rather than changed:
* **A write that commits between a request's currency check and its page
  query** may be missing from that one response. It is visible from the
  next request, as with any read that started before the write committed.
* **An inline refresh uses a second pooled connection** for its own
  transaction. Under a burst of first reads after a large scan, waits are
  bounded by the pool timeout, then the live query is served.

The UTC due-date shortcut is now decided per pooled connection, so per-role
or per-database time zone settings are respected.

### Regressions and trade-offs (measured)

* **One more query on every service tab.** The currency check costs about
  1 ms, but tabs that only render the header measured 1–6 ms slower:
  Architecture 37.5 → 44.0 ms, Validation 28.8 → 31.2 ms, Artifacts
  28.1 → 31.4 ms.
* **Raw pages: 36 → 37 queries.** The retained runs show 38: a final
  cleanup removed a redundant latest-execution query. A re-run after it
  measured the same latency (Raw 125 ms, Exceptions 91 ms).
* **Cybersecurity data on LARGE measured 66 → 80 ms (warm), but that path
  did not change.** It reads posture rows, and this metric is noisy (its
  p95 has ranged up to 149 ms in earlier runs). It is reported, not
  explained away.
* **MEDIUM Raw Non-Compliant 67 → 71 ms and Overview 72 → 77 ms.** Both are
  within run-to-run variance at this size; the dense service shows the
  gains.
* **Storage and write amplification**, as above: about 14–21% more
  database, plus one rewritten row per finding per rescan.
* **Background work**: one full rebuild per scan (2.4 s for 50,000
  findings), and a one-time preparation after upgrade (67 s for the LARGE
  database). Readers stay correct, on the live queries, until it finishes.

### Pre-existing defects found (not changed)

* **Cybersecurity fails on PostgreSQL for non-boolean KEV evidence.** Its
  own KEV test casts the evidence text to a boolean, so a scanner value
  such as `"kev": ""`, `[]` or `2` makes `/api/dashboard/cybersecurity`
  return 500, and the posture rebuild fails.
  * Reproduced on `e20f906`; the same expression is on `main`.
  * Cybersecurity's formulas differ from Services' by design, so changing
    them is a product decision. The minimal fix would be the
    JSON-truthiness expression Services already uses.
* **Simplified due dates in non-UTC database sessions.** The due date is
  formatted in the session's time zone but labelled UTC. Correct with the
  default container, shifted by the offset otherwise. The behavior is
  preserved here, not fixed.

## Review findings and what was done

| Finding | Priority | Fix |
|---|---|---|
| Older-scope responses could re-enter the cache or the screen | P1 | Request generations. Scope changes, mutations and session end abort in-flight reads; obsolete responses are neither stored nor delivered, and consumers get a fresh read. |
| A session-wide 401 removed only the current page | P1 | Any 401 or redirect to sign-in forgets every saved page and hides the current one. Tabs announce an opaque session identity and their scope over a BroadcastChannel. Same session with a new authorization: saved pages are dropped, but the shown page (and unsaved input) stays. Another session, or a sign-in page reached after sign-out completed: the tab forgets and reloads. Sign-out is announced only after it has been processed, avoiding a race with the logout request. Saved pages older than 10 minutes are re-fetched rather than shown. A second, independent review verified the eight fixes and raised the sign-out race and the lost-input issue, both now fixed. |
| A deleted service left its posture row (blocks id reuse on SQLite) | P1 | The row is deleted with the service (ORM and bulk). New services replace leftovers, startup removes orphans, and warming considers live services only. |
| A refresh after a mutation could join a pre-mutation request | P2 | Same generation boundary. Mutations whose response was lost also invalidate. |
| A rebuild raced by a write could be served as current | P2 | Provenance is re-checked after an inline rebuild. The row is rebuilt once more, otherwise reported as refreshing. |
| A terminal remediation detail failure stopped recovery | P2 | A status whose handler fails is "not handled". Polling continues with backoff until the final report loads. |
| An old validation detail could overwrite a new run | P2 | Detail requests are cancelled with the poll and applied only to the selected run. |
| Dependency "Refresh assessment" did nothing after the timeout | P2 | It is now an action: refresh in place, plus a new bounded round of status checks. |
| POA&M due-time equality boundary | non-blocking | Boundary is due + 1 µs. |
| Missing posture rebuilt the whole portfolio inside a GET | non-blocking | Bounded inline (25). The rest is prepared in the background and reported as preparing. |
| Overview read-misses always recomputed | non-blocking | Still computed for that response (correct, no GET-time write). The stored copy is now queued for later visits; the queue is bounded and deduplicated, and startup drains it in batches. |
| Duplicate startup work across processes | non-blocking | A PostgreSQL advisory lock makes shared preparation single-owner. Each step logs its duration. |
| Dependency count/facet queries | non-blocking | 11 statements → 3. Per-component vulnerability detail now loads on demand. |
| Validator polling | non-blocking | Moved onto the shared polling loop. |
| Status contracts' selected columns untested | non-blocking | A test asserts that no evidence columns are selected, and that the detail routes do select them. |
| SQL diagnostics missed the background pool | non-blocking | Both pools are instrumented. |
| Benchmark labels, p95, sample counts, byte totals, metadata | non-blocking | All corrected (see "How it was measured"). |

## Architecture

* **Status contracts.**
  * Remediation, deployment validation and dependency preparation each have
    a small, revisioned status endpoint: `service.view`, service-scoped,
    `no-store`.
  * Polling (`usePoll`) keeps one request in flight, cancels on navigation,
    pauses while hidden and backs off with jitter.
  * A terminal state stops polling only once its final detail has been
    handled.
* **Frontend workspace.**
  * An LRU page cache bounded in entries and bytes, partitioned by a
    server-issued scope (session + user + authorization revision).
  * Request generations sit at every authorization, mutation and session
    boundary, and cross-tab session coordination keeps tabs consistent.
  * Cached pages render immediately and revalidate quietly; tabs are
    prefetched on hover.
  * Code-split pages render synchronously once their chunk is loaded.
* **Service Posture read model.**
  * Per-service Services and Cybersecurity rows, each with its provenance:
    data generation, algorithm, epoch, intelligence token, configuration
    digest and time validity.
  * Rows are invalidated in the writer's transaction.
  * Inline refresh is bounded; larger refreshes are reported as preparing
    or refreshing.
  * Shadow mode is available for acceptance; 0 mismatches on MEDIUM data.
* **Findings.**
  * Search is evaluated once, and the page count comes from a window over
    the same rows.
  * On PostgreSQL, Simplified chooses each finding's current observation
    with an indexed LATERAL lookup. Its results are identical on real data
    across 30 page variants (`scripts/benchmark-simplified-parity.py`).
  * JIT is off for CATS sessions (`CATS_DB_JIT=server` restores the server
    policy).
* **Finding classification (second pass).**
  * Per-finding stored eligibility, non-compliance rule, exception state,
    current observation, Simplified group and search surface.
  * Per-service provenance, and a transactional change log for targeted
    reclassification.
  * Overdue is evaluated at read time.
  * Live queries are the fallback whenever the rows are not current.
* **Evidence on demand.**
  * Summary-backed evidence flags for Cybersecurity.
  * Stored normalized overviews (`execution_overviews`).
  * Deferred remediation plan preview.
  * Dependency component detail on demand.
  * Evidence deferred in the startup repair.
* **Background work and resources.**
  * Separate interactive and background pools.
  * Single-owner, step-logged startup preparation.
  * Bounded queues.
  * No outbox. Every background product is derived and idempotent, readers
    detect staleness from persisted provenance, and the next start
    re-prepares. Remediation and validation keep their durable state machines.

## Invariants

* The frontend cache is never authoritative for a mutation, and every
  mutation is authorized and validated server-side.
* Cached data cannot cross sessions, users or authorization revisions: they
  form the scope, and generations make the boundary hold for in-flight
  requests. Within a session, page keys include the full URL, so services
  and versions stay separate.
* Evidence stays authoritative. Every derived table records what it was
  built from, is ignored when that differs, and is removed with its service.
* Classification rows are used only while provably current: no pending
  change, and the same algorithm, epoch, configuration digest (including the
  catalog token where it matters), latest execution and exception validity
  window. Every stored value is the canonical expression's own result,
  three-valued NULLs included, and overdue is never stored.
* Status contracts and on-demand detail routes keep service scoping and
  identity checks (an execution must belong to the named service).
* The dedicated CSRF, OIDC, account-disablement, CATSchrödinger mTLS,
  trusted-CA, redaction and audit implementations were not changed. The
  authorization-revision module and the frontend scope handling are new code
  that does affect security behavior; they are covered by the tests above.
* Offline: all chunks are local, and there is no CDN, remote font or
  telemetry. The bundle holds the same external URL strings as the baseline.

## Scale

* **Measured:** a 1,000-service portfolio, and a single service with 50,000
  findings per scan.
* **Not measured:** the full 1,000 × 50,000 target (50 M findings). Seeding
  1 M findings through the real ingest path took about 50 minutes here.
* **Measured in the second pass:** 4 concurrent interactive clients against a
  real server, with and without continuous background rebuilds (see
  "Concurrent interactive requests"). Many more simultaneous users, and
  multi-process deployments, are still not measured here.

## Remaining costs (measured)

* **Services and Cybersecurity scale with authorized services:** about 26 ms
  at 100, about 70 ms at 1,000. Posture rows are small, but filtering,
  sorting and totals run over every authorized row. The next step would be
  sort and filter columns in `service_posture`, with SQL paging.
* **Simplified Findings for a dense service.** Implemented in the second
  pass; it is now 171 ms at 50,000 findings. What remains is aggregating
  the about 28,000 current members of the default view: scan, two hash
  aggregations and the page's joins, about 130 ms of SQL. Going further
  would need group aggregates per state, which overdue (time-dependent)
  makes a trade against correctness and write cost.
* **Raw Findings for a dense service:** 120 ms. Its candidate sort and
  window count over 49,000 rows are about 45 ms; an ordered covering index
  on the classification rows would remove the sort, for more storage.
* **Background classification:** one full rebuild per scan (2.4 s at
  50,000 findings) and a one-time preparation after upgrade (about 1 minute
  per million findings here). A catalog refresh in risk-based KEV/EPSS mode
  rebuilds every service using it, in the background.
* **Cybersecurity's own counts** are still evaluated live inside its posture
  rebuilds: its formulas differ from the stored classification by design.
* **Upgrade preparation:** about 7 minutes on the LARGE database, entirely in
  the background. It is dominated by the one-time summary field (120 s) and
  the legacy policy backfill, now reduced.
* **Fresh-process Overview, dense service:** about 0.4–0.46 s. The
  Architecture core graph is built once per process per scan, then cached.
* **Code-split pages:** a direct document load waits for one chunk before
  the first render (see Browser).

## Deployment notes

* **Connections per process:** up to (10 + 10) interactive plus (4 + 4)
  background. That is 28 at most per process, and it multiplies with the
  process count; size `max_connections` with headroom. Optional
  `CATS_DB_POOL_RECYCLE` and `CATS_DB_BACKGROUND_POOL_RECYCLE` set an age
  limit for pooled connections.
* **Dense services:** a 50,000-finding scan exceeds the default 16 MB
  pipeline limit; raise `CATS_PIPELINE_MAX_REQUEST_BYTES`.
* **New tables:** `service_posture`, `execution_overviews` and the
  classification tables are created by the existing startup path. Watch
  `maintenance_step` log records for preparation progress
  (`finding_classifications` runs before `service_posture`) and
  `finding_classification_refreshed` for each refresh.
* **Classification settings:**
  * `CATS_FINDING_CLASSIFICATION=false` serves the live queries; set it the
    same way for every process.
  * `CATS_CLASSIFICATION_SYNC_FINDINGS` (5,000) is the largest service a
    page read rebuilds in full inline.
  * `CATS_CLASSIFICATION_TARGET_LIMIT` (2,000) is the most findings
    reclassified individually.
  * Budget about 480 bytes per finding of storage, and keep autovacuum
    enabled: each rescan rewrites the service's rows.
* **Acceptance:**
  1. Run once with `CATS_POSTURE_SHADOW=true` and check the logs for
     `service_posture_shadow_mismatch`.
  2. Run the review's offline acceptance plan: authorization transitions
     with reordered responses, posture lifecycle, workflow recovery,
     multi-process, concurrency.

## Product decisions left open

* Services and Cybersecurity use different compliance formulas (preserved
  from the baseline).
* The maximum acceptable stale-display age is 10 minutes for the frontend
  cache. Posture is shown stale only with a visible notice.

## Tests

* **Backend:** the full suite passes except the same 25 tests that fail on
  `f56bbf8` (validator release, TLS and OCI tooling in this environment).
  The second pass adds 21 classification tests, which also pass against
  PostgreSQL (`CATS_TEST_DATABASE_URL`).
* **PostgreSQL syntax:** with `pglast` installed, every statement the pages
  issue parses as PostgreSQL, including the new LATERAL form.
* **Frontend:** `tsc` is clean, all tests pass and `vite build` succeeds.
* **Tests changed:** only where a contract changed deliberately (deferred
  preview, statement shape, delivery of superseded reads, link → button,
  poll signal). Each new recovery test was confirmed to fail on the previous
  code.
