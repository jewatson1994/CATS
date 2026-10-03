# Service findings performance

## Repeatable benchmark

Run from the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe tools/benchmark_service_findings.py --repeats 1
```

The default run measures 1,000, 5,000, and 10,000 vulnerability findings with six
observations per finding across six scan executions. Twenty percent are resolved;
active findings rotate four severities, twelve images, and 150 package names.
Each request uses the canonical raw or simplified Findings URL and page size 50.
The tool authenticates through the real login route and measures the entire
in-process HTTP response. It always creates and removes a temporary SQLite
database and deliberately ignores any configured `DATABASE_URL`.

JSON output reports the first request and repeated requests, cursor statement
count and execution time, ORM load counts, response bytes, and total request time.
SQL time excludes row fetching and object hydration. ORM counts come from
SQLAlchemy's `loaded_as_persistent` event. Total time includes fetching,
hydration, application processing, and template rendering. This is a local
backend benchmark; network time and browser rendering are excluded.

## Baseline before findings data-access changes

Captured October 2, 2026, on Windows with Python 3.12.14 from `.venv`.
The table uses the single repeated request after the first request warmed caches.
Synthetic datasets contain no policy findings, exceptions, or POA&Ms.

| Findings | Observations | View | SQL count | SQL ms | Finding hydrated | Observation hydrated | Response bytes | Total ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 6,000 | raw | 127 | 16.84 | 1,000 | 6,000 | 14,857 | 150.35 |
| 1,000 | 6,000 | simplified | 76 | 10.90 | 1,000 | 6,000 | 24,929 | 162.27 |
| 5,000 | 30,000 | raw | 143 | 21.30 | 5,000 | 30,000 | 14,858 | 671.10 |
| 5,000 | 30,000 | simplified | 92 | 14.53 | 5,000 | 30,000 | 41,654 | 634.29 |
| 10,000 | 60,000 | raw | 163 | 27.20 | 10,000 | 60,000 | 14,859 | 1,265.00 |
| 10,000 | 60,000 | simplified | 112 | 18.34 | 10,000 | 60,000 | 62,429 | 1,272.13 |

First-request total milliseconds, raw/simplified respectively: 200.14/130.28
(1,000), 705.62/627.96 (5,000), 1,350.85/1,245.00 (10,000).
Both views hydrate every finding and its entire observation history despite
displaying a bounded page. Cursor execution accounts for only a small fraction
of request latency; Python-side fetching, hydration and processing dominate.
Raw SQL count also includes per-visible-row date formatting configuration reads.

For additional sampling, omit `--repeats` (default three), or supply
`--count 10000 --history 6 --repeats 3`. Compare matching dataset shapes and
sample medians; SQLite results establish scaling behavior rather than production
PostgreSQL latency guarantees.

## Optimized findings route

Same command, dataset, and runtime after integrating the narrow route loaders:

| Findings | Observations | View | SQL count | SQL ms | Finding hydrated | Observation hydrated | Response bytes | Total ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 6,000 | raw | 32 | 7.52 | 50 | 0 | 14,857 | 32.71 |
| 1,000 | 6,000 | simplified | 27 | 6.06 | 0 | 0 | 24,929 | 31.16 |
| 5,000 | 30,000 | raw | 32 | 13.59 | 50 | 0 | 14,858 | 110.10 |
| 5,000 | 30,000 | simplified | 27 | 12.07 | 0 | 0 | 41,654 | 100.07 |
| 10,000 | 60,000 | raw | 32 | 23.33 | 50 | 0 | 14,859 | 206.16 |
| 10,000 | 60,000 | simplified | 27 | 20.92 | 0 | 0 | 62,429 | 251.64 |

Response sizes match the baseline. At 10,000 findings, request latency falls
approximately 84% raw and 80% simplified. Raw hydration is bounded to the 50
displayed Finding objects; observation support and simplified rows use scalar
projections and do not hydrate ORM FindingObservation objects.

The benchmark now reports named, inclusive stage times and repeated SQL
signatures. A separate 10,000-finding warm sample measured:

| Stage | Raw ms | Simplified ms |
| --- | ---: | ---: |
| configuration_for_service | 0.57 | 0.55 |
| service_view | 25.46 | 53.78 |
| get_raw_finding_page | 8.76 | — |
| load_page_support | 1.73 | 31.27 |
| load_simplified_support | — | 32.72 |
| page_context | 0.44 | 0.41 |
| page_data serialization | 30.84 | 16.21 |
| TemplateResponse including serialization | 31.46 | 16.87 |

Stages overlap: `load_simplified_support` includes `load_page_support`, and
`TemplateResponse` includes `page_data`; SQL also overlaps stages. Their sum
is not total request time. Stage profiles do not measure browser React render.

An additional bounded N+1 was date formatting: `configured_time` in
`portal/app/main.py` opens a new session and reads global configuration when
its configuration argument is absent. The `cats_date` / `cats_datetime`
globals previously omitted that argument. `portal/app/frontend.py` formats raw due dates and
last-seen dates per displayed row, and simplified due dates per displayed row.
The intermediate benchmark recorded the same settings query 102 times raw and
52 times simplified. Request-local date formatter binding now reuses the loaded
configuration, removing those per-row reads. Version menus likewise select the
version JSON scalar rather than hydrating every execution and its scan payload.

## Implementation and compatibility

Changed files: `app/main.py` (early findings dispatch, narrow loading, indexes),
`app/findings_query.py` (scalar compliance/header and bounded page evidence),
`app/findings_sql.py` (count/filter/order/page), `app/frontend.py` (request-local
date formatting), `app/exchange.py` (scalar version menu), their regression tests,
this report, and `tools/benchmark_service_findings.py`.

Raw active/resolved/exception pages use service-scoped SQL union candidates,
COUNT, deterministic kind/date/name/ID ordering, LIMIT and OFFSET. Text/resource
search retains the existing latest-20-observations and text truncation rules.
SQLite uses a deterministic casefold function. PostgreSQL uses scalar candidate
search before SQL pagination to preserve exact Unicode casefold semantics.
Policy records and active, unexpired, unrevoked exceptions remain distinct.
Risk-based visibility is not imposed on canonical Raw active findings.

Findings no longer eagerly hydrate Service -> all Finding -> all Observation
histories. Supporting images/observations for raw pages are retrieved set-wise
for selected finding/execution pairs. Active findings retain global latest-scan
image semantics; service header metadata retains current-version semantics.
Simplified grouping occurs before group pagination and preserves package,
remediation, CVEs, fixes, severity, finding IDs, images and due dates.
Authorization dependencies, action permission checks, URLs and React UI remain
unchanged. No new online dependencies were introduced.

Startup migration adds `(finding_id, execution_id, id)` for observation support,
and `(service_id, active, episode_started, identity, id)` on vulnerability and
policy findings for state-scoped stable ordering. Existing exception and
observation indexes remain. SQLite EXPLAIN regression verifies indexed service
and observation lookup. PostgreSQL SQL compiles, but its runtime plans were not
validated locally.

## Remaining limits

Verification: full backend suite 910 passed, 1 skipped (7 existing warnings).
After adding the final scalar-version and request-local-formatter regressions,
the focused frontend-projection/query suite passed 24 tests. New query tests
cover lifecycle/exception eligibility, filters, Unicode, mixed types, service
isolation, stable ties, empty/high/negative pages, 50/100/250 sizes, indexed plans,
cross-version metadata and image/observation semantics. Existing full-suite
tests provide warning/noncompliance, simplified and authorization coverage.
Frontend: 82 tests passed across 23 files; production build and lint passed.
`git diff --check` passed. No commits or pushes were made.

Header/risk/noncompliance/warning evaluation still processes scalar findings
and one latest observation per finding. Exact simplified grouping still needs
all matching active scalar rows and their applicable scan observations before
pagination. Thus total CPU is not constant in service size, although historical
ORM hydration and query counts are bounded. Non-findings tabs retain their
existing loaders. Further aggregate/schema work would be needed to eliminate
these service-sized scalar passes without altering policy semantics.

The stage table above is an intermediate profile, before the final date/menu
optimization; final totals are in the optimized table. Stage instrumentation is
inclusive and does not yet separately isolate all warning/grouping and query
sub-stages. No browser rendering benchmark was performed; no additional React
bottleneck is established by this backend benchmark.
