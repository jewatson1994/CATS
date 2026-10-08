# CATS performance architecture overhaul

Branch `feature/performance-architecture-overhaul`, from `main` at
`f56bbf8963d72fabe9c8060fe5e6868d1d3564b7`. Not merged, not pushed.

Goal: CATS should feel fast and seamless during normal use, without weakening
evidence authority, provenance, isolation, authorization or offline operation.

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
* **Not measured:** concurrency (many simultaneous users, or background work
  under interactive load). Acceptance should measure both.

## Remaining costs (measured)

* **Services and Cybersecurity scale with authorized services:** about 26 ms
  at 100, about 70 ms at 1,000. Posture rows are small, but filtering,
  sorting and totals run over every authorized row. The next step would be
  sort and filter columns in `service_posture`, with SQL paging.
* **Simplified Findings for a dense service:** 562 ms at 50,000 findings
  (about 330 ms to assemble members, 180 ms to group). The next step, now
  justified by this evidence, is a rebuildable current-classification layer:
  each finding's current observation and group persisted at ingest.
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
* **New tables:** `service_posture` and `execution_overviews` are created by
  the existing startup path. Watch `maintenance_step` log records for
  preparation progress.
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
* **PostgreSQL syntax:** with `pglast` installed, every statement the pages
  issue parses as PostgreSQL, including the new LATERAL form.
* **Frontend:** `tsc` is clean, all tests pass and `vite build` succeeds.
* **Tests changed:** only where a contract changed deliberately (deferred
  preview, statement shape, delivery of superseded reads, link → button,
  poll signal). Each new recovery test was confirmed to fail on the previous
  code.
