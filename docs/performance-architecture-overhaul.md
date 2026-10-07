# CATS performance architecture overhaul

Branch `feature/performance-architecture-overhaul`, from `main` at
`f56bbf8963d72fabe9c8060fe5e6868d1d3564b7`. Not merged, not pushed.

Goal: CATS should feel fast and seamless during normal use, without weakening
evidence authority, provenance, isolation, authorization or offline operation.

## How it was measured

All numbers below were measured in this work; nothing is estimated.

* **Database:** PostgreSQL 16, local socket, default server settings.
* **SMALL:** 10 services × 2 scans × 1,000 findings.
* **MEDIUM:** 100 services × 2 scans × 10,000 findings (1,000,000 active
  findings; 2,000,000 observations; ~10 MB retained payload per scan).
* **Server:** `scripts/benchmark-navigation.py` drives the real ASGI app and
  records `PerformanceMiddleware` metrics per request: duration, SQL time,
  query count and uncompressed response bytes. "cold" is the first request in
  a fresh process; "warm" is the median of four repeats. It runs as `admin`
  and as a group-scoped Assessor (`restricted`).
* **Browser:** `scripts/benchmark-browser.py` drives headless Chromium
  against a uvicorn server on MEDIUM. It reports time to useful content on
  the page clock (navigation start or click → first frame in which the page's
  real content is present and no navigation is pending), plus request counts
  and transferred bytes. Hover prefetch is not used, so these are
  conservative figures. In-app figures are medians of 3 runs.
* **Baseline:** the same harnesses run against a worktree at `f56bbf8`, on
  the same database.
* **Raw data:** `docs/performance-architecture/*.json`.

## Results

### Browser, MEDIUM: time to useful content

**Direct document load (new browser context, empty cache):**

| Page | Before | After | API requests (before → after) | API bytes on the wire (before → after) |
|---|---:|---:|---|---|
| Services | 1,888 ms | 164 ms | 2 → 1 | 2,078 → 1,641 |
| Cybersecurity | 13,882 ms | 141 ms | 3 → 1 | 3,213 → 2,173 |
| Service Overview | 224 ms | 171 ms | 1 → 1 | 2,479 → 2,507 |
| Findings | 324 ms | 239 ms | 1 → 1 | 4,413 → 4,442 |
| Architecture | 167 ms | 197 ms | 2 → 2 | 12,672 → 12,702 |
| Dependencies | 209 ms | 206 ms | 1 → 1 | 18,856 → 18,884 |
| Deployment Validation | 176 ms | 212 ms | 1 → 1 | 2,616 → 2,665 |
| Remediation | 164 ms | 152 ms | 1 → 1 | 1,762 → 1,788 |

**In-app navigation (median of 3):**

| Step | Before | After |
|---|---:|---:|
| Services → Service Overview | 156 ms | 133 ms |
| First visit: Findings | 258 ms | 193 ms |
| First visit: Architecture | 87 ms | 113 ms |
| First visit: Dependencies | 130 ms | 141 ms |
| First visit: Deployment Validation | 90 ms | 119 ms |
| First visit: Remediations | 76 ms | 83 ms |
| Repeat visit: Overview | 136–143 ms | 21–46 ms |
| Repeat visit: Findings | 237–240 ms | 23–32 ms |
| Repeat visit: Architecture | 70–80 ms | 28–32 ms |
| Repeat visit: Dependencies | 112–123 ms | 47–87 ms |
| Repeat visit: Deployment Validation | 66–74 ms | 41–44 ms |
| Repeat visit: Remediations | 64–73 ms | 19–27 ms |
| Back to Services | 1,747 ms | 22 ms |
| To Cybersecurity | 13,846 ms | 74 ms |
| Browser back to Services | 1,949 ms | 25 ms |

**Polling, remediation report open for 15 s:** 9 requests and 95,508 bytes
before; 4 requests and 2,760 bytes after.

### Server, MEDIUM, warm median (admin unless noted)

| Request | Before: ms / SQL ms / queries / bytes | After: ms / SQL ms / queries / bytes |
|---|---|---|
| Services rows | 1,630 / 1,607 / 23 / 14,166 | 22 / 6 / 16 / 14,172 |
| Services rows (restricted) | 355 / 336 / 22 / 3,607 | 19 / 6 / 18 / 3,613 |
| Cybersecurity data | 12,991 / 12,900 / 15 / 22,459 | 17 / 3 / 10 / 22,494 |
| Cybersecurity data (restricted) | 2,449 / 2,393 / 18 / 4,414 | 15 / 4 / 13 / 4,449 |
| Service Overview, cold | 567 / – / 35 / 9,029 | 165 / – / 36 / 9,137 |
| Service Overview | 97 / 68 / 35 | 64 / 33 / 36 |
| Findings simplified | 191 / 165 / 23 | 138 / 111 / 24 |
| Findings raw | 83 / 51 / 36 | 77 / 38 / 36 |
| Findings search | 268 / 232 / 36 | 106 / 74 / 36 |
| Remediations tab, cold | 608 | 47 |
| Remediation report poll | 33 ms, 280,719 bytes, every 1.5 s | status contract: 9 ms, 1,908 bytes, with backoff |
| Deployment validation poll | 122 ms, 96,723 bytes | status contract: 8 ms, 633 bytes |
| Dependency preparation poll | full page reload | status contract: 13 ms, 142 bytes |

Two further measurements:

* **Startup to first served page (MEDIUM):** about 35 s before (import-time
  backfills), about 3 s after.
* **Initial JS bundle:** 548 KB (153 KB gz) before, 328 KB (96 KB gz) after.

### Trade-offs the measurements show

* **Direct document loads of code-split pages** (Architecture, Deployment
  Validation) are about 30 ms slower than the single-bundle baseline. Those
  pages now fetch their chunk before the first render.
* **First in-app visits to some tabs** are 10–30 ms slower. The previous page
  stays visible and inert while the next one loads (no blank flash), so
  unmounting it moves into the reveal.
* **Every repeat visit** is 2–8× faster, because pages render from the
  session-scoped workspace and revalidate quietly.

## What changed, by phase

**Phase 0: measurement.**

* One `PerformanceMiddleware` instead of a duplicate registration.
* Both harnesses, with `--only`, `--profile` and `--explain`.

**Phase 1: lightweight status contracts and polling.**

* New `GET …/remediations/{job}/status`, `…/deployment-validations/{run}/status`
  and `…/dependencies/status` endpoints. They return scalar state and a
  revision only, and are `no-store`, `service.view` and service-scoped.
* `usePoll` keeps a single request in flight, pauses while the tab is
  hidden, backs off with jitter and stops at terminal states. The full detail
  is fetched only when the revision changes.

**Phase 2: persistent frontend workspace.**

* `PageStore` is an LRU with byte bounds. Every entry is keyed to the
  server-issued `cacheScope`, a hash of session, user and authorization
  revision. A scope change, any non-GET request, or a 401/403/404 on
  revalidation purges or evicts entries.
* Cached pages render at once and then revalidate.
* Tabs are prefetched on hover or focus.
* The Services page no longer fetches its rows separately (no waterfall).
* Pages are code-split, but a chunk that is already loaded renders
  synchronously, and the initial page's chunk loads before the first render.
* Architecture rendering is memoized.

**Phase 3: Service Posture read model (`service_posture`).**

* It stores the Services and Cybersecurity rows per service. Each row
  records its provenance: data generation, algorithm, epoch, intelligence
  token, configuration digest and time validity.
* Rows are invalidated in the same transaction as the write that changes
  them:
  * ORM changes are tracked per service.
  * Bulk statements are narrowed to the services they name.
  * Statements that name no service replace the epoch.
* Inline refresh is bounded (`CATS_POSTURE_SYNC_LIMIT`, default 25). Larger
  invalidations serve the previous rows with a visible "refreshing" notice
  and rebuild in the background.
* Shadow mode (`CATS_POSTURE_SHADOW=true`) recomputes every row and logs any
  mismatch. On MEDIUM it found 0 mismatches across 100 services, both
  projections, admin and scoped users.

**Phase 4: findings.**

* Raw search evaluates the observation-history subquery once, and counts
  with a window over the paged candidates.
* PostgreSQL JIT is off per connection by default (`CATS_DB_JIT=server`
  keeps the server setting).
* No index was added. The plans use index scans throughout. The Simplified
  view costs about 110 ms of SQL to group 10,000 active findings in a single
  statement, so neither a classification table nor an index is justified by
  that plan.

**Phase 5: evidence on demand.**

* The Cybersecurity computation reads SBOM-presence and missing-evidence
  flags from current execution summaries. It falls back to the payload
  reading when a summary is stale. This cut a full rebuild from 13.8 s to
  6.0 s.
* Service Overview stores its normalized overview as derived data
  (`execution_overviews`). Each row is valid only for the exact digest,
  completeness and algorithm. Background work writes it after ingest and at
  startup; GETs never write it.
* The Remediations tab defers its plan preview to
  `GET /api/v1/services/{key}/remediation-preview`, which requires
  `remediation.execute`.

**Phase 6: background work and resources.**

* Interactive and background connection pools are separate (`CATS_DB_*`,
  `CATS_DB_BACKGROUND_*`).
* Upgrade backfills moved out of module import into the maintenance thread.
  They are bounded, resumable and once-only.

**Phase 7: bounded reads.**

* Services and Cybersecurity read pre-computed rows. Paging stays in the
  database.

## Durable background work: decision

No outbox or queue was introduced. Everything moved to the background is
derived and idempotent:

* posture rows;
* stored overviews;
* summary fields;
* upgrade backfills.

If a process stops mid-task, nothing is lost:

* readers detect the stale or missing row and recompute from authoritative
  evidence;
* the maintenance thread re-prepares on the next start.

Remediation, validation and patch jobs keep their existing durable state
machines unchanged. A queue would add an operational dependency without
fixing a failure mode that exists. No Redis, Kafka, cloud queue or object
storage was added, and CATS remains disconnected-first: no runtime CDN,
fonts or telemetry, and the bundle holds the same external URL strings as
before.

## Invariants preserved

* Cached frontend data is never authoritative for a mutation, and every
  mutation is still authorized and validated server-side.
* Cached pages are bound to session, user and authorization revision, so
  they cannot cross users, sessions or permission scopes. Page keys include
  the full URL, so services and versions stay separate.
* Evidence stays authoritative. Every derived table (summaries, posture,
  overviews, dependency projections) records what it was built from, is
  ignored when that differs, and is removed with service deletion.
* Status contracts expose no evidence, secrets or validator configuration.
* None of the following were touched: CSRF, OIDC, account disablement,
  CATSchrödinger mTLS, trusted-CA behavior, redaction, audit, remediation
  recovery and validation cleanup.

## Deployment notes

* **Connections per process:** up to (10 + 10) interactive plus (4 + 4)
  background. Size PostgreSQL `max_connections` for the number of portal
  processes.
* **New tables** (`service_posture`, `execution_overviews`) are created by
  the existing `create_all` startup path.
* **First start after upgrade:** the maintenance thread fills the summary
  field, prepares posture rows and prepares overviews. On MEDIUM this took
  about 45 s, 6 s and 40 s, in the background. Until it finishes, the first
  Services or Cybersecurity view may compute rows inline, as before.
* **Recommended acceptance step:** run once with `CATS_POSTURE_SHADOW=true`
  and check the logs for `service_posture_shadow_mismatch`.

## Known follow-ups

* Services and Cybersecurity use slightly different compliance formulas.
  This is preserved as-is and is a product decision.
* Dependencies rows are 211 KB uncompressed for 50 rows at 25 CVEs per
  component. They are bounded by pagination and GZip applies.
* The Architecture core graph is built once per process per scan, about
  55 ms at MEDIUM, and then cached.
* The full `GET /api/v1/…/remediations/{job}` returns about 1.1 MB. It is
  kept for API compatibility; the UI no longer polls it.
* A cold Cybersecurity rebuild of 100 services × 10,000 findings is still
  about 6 s. It now happens only in the background or on first upgrade.

## Tests

* **Backend:** 1,755 passed, 8 skipped (Helm on PATH). The same 25 tests fail on `f56bbf8`; they are
  environment-dependent (validator release, TLS and OCI tooling) and
  unchanged by this work.
* **Frontend:** 205 tests passed. `tsc` is clean and `vite build` succeeds.
* **Tests changed:** only where a contract changed deliberately (deferred
  preview, statement shape of raw findings). Every behavioral assertion was
  kept.
