# Backend performance second-pass report

Branch: `feature/backend-performance-refactor`. No branch creation, commit, or push. The primary simplified blocker is fixed. **The comprehensive backend objective remains incomplete**, for the explicit reasons in items 37–39.

Measurements invoke actual route bodies and JSON DTO serialization in fresh ORM sessions on disposable SQLite fixtures with cProfile/tracemalloc enabled. They exclude HTTP middleware, authentication overhead, and transport. Database rows fetched count DBAPI results, not internal rows scanned; aggregate SQL still examines eligible population. Defaults put half the fixture findings in the selected service; all-target scenarios place all 100,000 there. These are individual instrumented observations, not production p95 or throughput claims. Source hashes and representative SQLite plans are recorded in `backend-performance-pages.json`.

1. **6.91-second root cause:** Candidate scalar collection, Python grouping and page-member collection processed tens of thousands of observations. Nested CVE/image/member arrays caused the 876,469-byte response. Page support bounded groups but did not bound member materialization.
2. **Contract:** Before: groups with complete CVE/member/image arrays. After: group ID, package/remediation/fixed-version summary, severity/due, representative CVE/finding ID, member/image counts. Expanded members use a separate authorized endpoint, loaded only on expansion. Text previews are bounded to 500/1,200 characters.
3. **Grouping:** Persisted canonical SHA256 package/remediation identity, Unicode normalized sort/search metadata; SQL current-execution observation selection with latest-ever fallback, reusable CTE, GROUP BY, distinct normalized CVE count and representative aggregates. Package/version/remediation/severity/due/image characterization tests compare canonical helpers. Configuration findings remain excluded from this vulnerability remediation grouping, preserving existing behavior.
4. **Groups:** SQL sorts and limits groups before selected-group aggregation crosses the DBAPI boundary; 50 groups maximum at default size, exact aggregate totals and clamped pages.
5. **Members:** `/api/v1/services/{service_key}/findings/simplified/{group_id}/members` uses SQL filtering and independent pagination. Identity is trimmed uppercase CVE, duplicate images do not duplicate identities; minimum finding ID is canonical representative. Group predicate is pushed inside candidate materialization. No observation collection hydration.
6. **Filtered fallback:** Simplified route no longer invokes full Python grouping for search/resource/severity/state/type. Shared risk SQL handles exceptions, KEV/EPSS policy eligibility, overdue/noncompliance and resolved state. Existing route has no separate scanner/KEV/EPSS controls; no new unsupported filter API is claimed. Raw PostgreSQL search/severity scalar Python fallback also removed.
7. **Remaining Python grouping:** Legacy canonical helpers remain for parity and older representations. Portfolio/service selectors and full exports retain scalar Python ordering/filtering; comprehensive removal is not claimed.
8. **Headers:** Architecture/validation/dependencies/artifacts/remediations/activity/POAM and simplified headers use SQL risk existence predicates and persisted execution summaries. Raw active/resolved page headers now defer authoritative payload and use the same summary helper. Header evidence previews cap at ten entries with exact counts. Overview/full service and some raw other-state preparation still have broad canonical paths.
9. **Dependencies:** Durable projection validity uses payload/catalog tokens without repeatedly decoding finding graphs; warm lists page projected rows. Cold projection rebuilding still transfers and constructs the complete SBOM/finding representation; see item 26.
10. **Activity:** Service and global audit filter/count/order/page in SQL, deterministic timestamp/ID ties. Global default/show/full preserves 10/60/200 choices with bounded paging. DTOs now carry pagination fields to the UI. JSON service scope excludes booleans and applies before limit.
11. **Selectors/portfolio:** First-pass aggregate/paged loaders preserved. This pass does not assert all scalar Python selector/portfolio preparation has been eliminated. Existing scoped authorization tests remain green.
12. **Validators:** List rendering uses persisted verified installation/release metadata. No SSH, network, archive hashing or live payload inventory runs during ordinary list rendering. Explicit provisioning/release operations retain verification.
13. **Evidence:** Execution summaries v3 retain bounded header previews, counts/version and summary metadata. Large detail/download readers still fetch authoritative evidence when explicitly required. Latest evidence selection occurs in SQL before hydration. Version choices still use scalar JSON extraction and can scale with retained scan history.
14. **Exports:** Focused findings/mitigation XLSX routes fixed from shadowing by generic export route. Database projections iterate in batches of 500, avoiding retained observations/evidence graphs. 100k extraction: four queries, one ORM object peak, 0.77 MiB Python, 2.207 seconds. Removed quadratic worksheet `max_row` lookup per cell: 10k styled/saved workbook 74.059→7.581 seconds; workbook memory 67.19 MiB remains proportional to output. Full workbook/snapshot still retain broad graphs, although historical raw payloads are deferred.
15. **JSON/digests:** Recursive mutable dictionaries/lists track nested execution payload and observation evidence changes. ORM writes refresh summaries/search/projection metadata. SQLAlchemy bulk payload/complete updates clear potentially stale digests transactionally, including executemany supplied digests. Rollback leaves durable state consistent. External direct SQL writers must explicitly invalidate/rebuild derived state.
16. **Invalidation:** Tests cover nested dictionary/list append/update/remove, replacement, scalar/bulk updates, stale digest clearing, rollback, observation/finding/watchlist changes and catalog-token refresh. Catalog indexes are immutable cached views of loaded catalog content; explicit catalog refresh changes token.
17. **Indexes:** Added observation `(finding_id, execution_id, id)` composite index and simplified-key index; retained service/state/episode/exception indexes. Startup upgrades add/backfill normalized Finding, PolicyFinding and observation metadata in bounded batches. Direct Core insert fixtures supply derived fields; external writers must use supported ingestion or rebuild metadata.
18. **SQLite plans:** Actual simplified first page and member CTE plans are embedded in the pages artifact. Index-assisted observation lookup replaces Python candidate transfer. SQL aggregate/temp sorting still processes eligible rows internally; bounded DBAPI counts do not hide that work.
19. **PostgreSQL:** PostgreSQL dialect compilation tests pass. No `docker` or `psql` executable/server was available; real PostgreSQL plans, runtime and concurrent ingestion remain unverified.
20. **1k simplified:** 166.6 ms, 17 queries, 35 fetched rows, 2.00 MiB traced peak, 9,156 bytes.
21. **10k simplified:** 158.9 ms, 17 queries, 35 rows, 1.34 MiB, 9,177 bytes.
22. **100k default simplified:** 450.4 ms, 17 queries, 35 rows, 1.33 MiB, 9,198 bytes. All-target 3,500-visible-group first page: 674.6 ms, 64 rows, 1.40 MiB, 19,943 bytes. Old checkpoint: 6,910.1 ms, 70,034 rows, ~45.2 MiB, 876,469 bytes.
23. **100k simplified filters:** Search 365.5 ms; resource 360.0; severity 343.8; active 587.4; resolved 223.1; exceptions 203.3; noncompliant 397.0. All return 200 and bounded 15–64 fetched rows. Exact filter fixtures/results in artifact.
24. **Deep pages:** All-target simplified first/middle/late 674.6/621.8/624.4 ms (64 rows each); members 473.9/449.2/389.0 ms (53/53/37 rows). Raw 363.0/323.6/337.6 ms. Stable ordered IDs and counts tested; production OFFSET cost still needs representative database validation.
25. **100k raw:** All-target first 363.0 ms, 31 queries, 269 rows, 1.51 MiB, 12,279 bytes. Nonempty High+resource filter 414.6 ms, 269 rows. Raw late page contains configuration rows and remains bounded; broader raw states retain compatibility paths.
26. **Dependencies:** 100k components/findings: warm 318.9 ms, second page 296.4 ms, 28 queries/91 rows/2 ORM, ~0.30/0.26 MiB, 31,804/31,817 bytes. Cold: 21.22 seconds, 437 queries/100,091 rows/~422.35 MiB. Warm requirement improved; cold rebuild remains a closure blocker. Reproduce with `scripts/benchmark-dependencies.py`.
27. **Activity benchmark:** 100k audit events: service first/middle/late175.5/136.9/145.8 ms,13 queries/73 fetched rows; filtered107.1 ms. Global first/middle/late48.7/47.9/51.5 ms,5 queries/71 rows; filtered109.0 ms/56 rows. Responses12–13 KB; first service traced peak1.40 MiB, subsequent pages~0.2 MiB. Reproducible actual route/DTO results and budget assertions: `scripts/benchmark-activity.py`, `backend-activity-second-pass.json`.
28. **Fetched rows:** Group defaults 35, all-target pages64; members53/53/37; raw269/269/160; warm dependencies91. None hides tens of thousands of members behind serialization. Cold dependencies remain100,091.
29. **Memory:** Default100k simplified1.33 MiB versus old~45.2 MiB. Many-group first1.40 MiB; members0.82/0.63/0.44 MiB. Full export cell memory and cold dependency rebuild explicitly remain large.
30. **Response size:** Default simplified9.2 KB; actual50-group pages19.9–20.0 KB; members6.9 KB; raw12–15 KB; dependencies31.8 KB. Metrics include serialized DTO body without gzip.
31. **Query budgets:** Automated real-route budgets pass at1k and10k fixtures in `test_finding_page_budgets.py`: group/member <=25 queries; raw <=40; <=350 fetched rows; <=100,000 response bytes; no FindingObservation hydration. Extended100k benchmark also enforces limits. Measured group17/member6/raw31–34/dependency28. Aggregate and auth helper queries are included in counts; no N+1 member evidence loads.
32. **Row budgets:** Enforce selected-page/helper result budgets independently from eligible population; group <=350, member <=350, raw <=400 for benchmark fixtures. Dependency warm91. Cold rebuild is explicitly outside a warm-list guarantee.
33. **Backend:** Full suite:1,427 passed,1 skipped,7 warnings in155.78 seconds. Additional two actual-route performance budget tests passed separately after their creation. Focused canonical/member/header/invalidation/export tests also pass. `git diff --check` passes.
34. **Frontend:** 29 files,165 tests passed.
35. **TypeScript:** `tsc --noEmit` passed.
36. **Production build:** Vite build passed. Existing >500KB chunk and static app.css reference warnings remain; not backend performance errors.
37. **Limitations:** Cold dependency rebuild; full workbook/snapshot retained graphs and normal-workbook cell memory; overview/full-service/other-state raw preparation; history-version scalar JSON extraction and metadata list growth; remaining portfolio/selector Python scalar work; direct SQL mutation protocol; real PostgreSQL/concurrency/production acceptance unverified. Benchmarks are synthetic individual samples and do not measure DB-internal rows scanned.
38. **Comprehensive complete?** No. The primary simplified acceptance requirement and warm dependency list are met locally; that does not establish every backend route has page-bounded preparation.
39. **Closure blockers:** Move cold dependency projection construction off ordinary list requests or batch a durable build without full Python graphs; replace remaining broad header/raw/overview/selector preparation; stream/full-export extraction and workbook creation; finish history metadata paging and complete per-route budget coverage; execute real PostgreSQL plans and production/concurrent acceptance. No commit or push was performed.

## Complete page measurements

| Scenario (fixture findings) | ms | queries | fetched rows | traced peak MiB | response bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| simplified_default (1,000) | 166.6 | 17 | 35 | 2.00 | 9,156 |
| simplified_default (10,000) | 158.9 | 17 | 35 | 1.34 | 9,177 |
| simplified_default (100,000) | 450.4 | 17 | 35 | 1.33 | 9,198 |
| simplified_all_target_first (100,000) | 674.6 | 17 | 64 | 1.40 | 19,943 |
| simplified_all_target_middle (100,000) | 621.8 | 17 | 64 | 0.69 | 20,040 |
| simplified_all_target_late (100,000) | 624.4 | 17 | 64 | 0.69 | 20,040 |
| simplified_filter_search (100,000) | 365.5 | 17 | 15 | 0.91 | 2,341 |
| simplified_filter_resource (100,000) | 360.0 | 17 | 64 | 0.72 | 20,095 |
| simplified_filter_severity (100,000) | 343.8 | 17 | 64 | 0.95 | 19,963 |
| simplified_filter_active (100,000) | 587.4 | 17 | 64 | 0.68 | 19,943 |
| simplified_filter_resolved (100,000) | 223.1 | 17 | 64 | 0.88 | 19,651 |
| simplified_filter_exceptions (100,000) | 203.3 | 17 | 64 | 0.89 | 19,272 |
| simplified_filter_noncompliant (100,000) | 397.0 | 17 | 64 | 0.94 | 19,724 |
| raw_all_target_first (100,000) | 363.0 | 31 | 269 | 1.51 | 12,279 |
| raw_all_target_middle (100,000) | 323.6 | 31 | 269 | 0.83 | 12,347 |
| raw_all_target_late (100,000) | 337.6 | 34 | 160 | 0.86 | 15,340 |
| raw_all_target_filter (100,000) | 414.6 | 31 | 269 | 0.98 | 12,359 |
| members_first (100,000) | 473.9 | 6 | 53 | 0.82 | 6,860 |
| members_middle (100,000) | 449.2 | 6 | 53 | 0.63 | 6,950 |
| members_late (100,000) | 389.0 | 6 | 37 | 0.44 | 4,774 |
