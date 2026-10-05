# Backend performance reconstruction completion report

Branch: `recovery/performance-only`. Exact parent/base: `ddc39b6f45745a5025c91dcf8706617b9576eacb`. Recovery source: `bcc8cd2170731bf1b25f4f5f55c6bccd383c07a7`. Selective reconstruction; no snapshot cherry-pick.

## Scope audit

Final files: **79**. No deleted files, Docker/Compose changes, dependency manifest changes, standalone migration files, unrelated or ambiguous feature changes. Schema upgrades reside in models/query helpers/startup.

Every changed file belongs to backend performance, required schema/support, performance testing/benchmarking, or required frontend API compatibility. Excluded pending HQ validator provisioning, payload/release assets, validator_assets, Ubuntu/Docker/Python closure and host tools; SchrÃ¶dinger v2/four-mode/deployment_bundle/schrodinger_validation; Offline Bundle implementation; remediation source/mutation/delivery/new lifecycle; OIDC issuer/subject/collision/disabled-account changes; Risk Profile; scanner reliability; README/mojibake/UI cleanup. Pre-existing functionality on the base is retained unchanged.

Mixed files `main.py`, `models.py`, `frontend.py`, `test_portal.py` were selectively reconstructed. Frontend changes only consume pagination/lightweight APIs and dependency lifecycle status. Models and startup upgrades are additive; legacy schema preservation and repeated upgrade checks are covered.

| File | Category | Meaningful change |
|---|---|---|
| `docs/backend-activity-second-pass.json` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `docs/backend-dependencies-second-pass.json` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `docs/backend-history-export-final.json` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `docs/performance-reconstruction-100k.json` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `docs/performance-reconstruction-backend.json` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `docs/performance-reconstruction-report.md` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/app/activity_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/artifact_tab_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/dashboard_paging.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/dependency_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/exchange.py` | Backend performance | Bounded extraction/latest observation selection for existing exports. |
| `portal/app/exchange_routes.py` | Backend performance | History metadata pagination for existing exchange endpoints; no new bundle feature. |
| `portal/app/execution_summaries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/findings_query.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/findings_sql.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/frontend.py` | Required frontend/API compatibility | Bounded simplified/group DTOs and transformation diagnostics only. |
| `portal/app/frontend_admin.py` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/app/frontend_governance.py` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/app/frontend_service_operations.py` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/app/frontend_service_secondary.py` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/app/history_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/main.py` | Backend performance | Selective route integration: SQL findings/group members; bounded tabs, overview, history, audit, POAM and existing remediation lists; export extraction; diagnostics; derived-state cleanup; additive startup upgrades. Static focused exports precede generic export route. Authentication, validator and remediation mutation routes excluded. |
| `portal/app/models.py` | Required schema / derived-state support | Mutable nested evidence/digest; normalized finding/policy/observation fields; dependency projection/header rows, ExecutionSummary and query indexes. Existing validator-related base models unchanged. |
| `portal/app/overview_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/performance.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/poam_query.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/policy_data.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/recursive_json.py` | Required schema / derived-state support | Track evidence changes and maintain performance-derived state. |
| `portal/app/remediation_list_queries.py` | Backend performance | Paginated existing remediation records only; no mutation, delivery or new lifecycle. |
| `portal/app/risk_sql.py` | Backend performance | SQL implementation of existing risk display semantics; no Risk Profile feature. |
| `portal/app/security_dashboard.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/service_read_model.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/service_tab_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/simplified_queries.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/app/watchlist.py` | Backend performance | SQL query/read-model, batching, projection, summary, bounded extraction or diagnostics implementation. |
| `portal/frontend/src/features/admin.test.tsx` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/frontend/src/features/audit.tsx` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/frontend/src/features/poam-pagination.test.tsx` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/frontend/src/features/poam.tsx` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/frontend/src/features/service-dependencies.test.tsx` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/frontend/src/features/service-dependencies.tsx` | Required frontend/API compatibility | Pending/building/failed/ready projection status, null counts and refresh/retry compatibility. |
| `portal/frontend/src/features/service.test.tsx` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/frontend/src/features/service.tsx` | Required frontend/API compatibility | Lazy separately paginated group members and lightweight summaries. |
| `portal/frontend/src/features/service_activity.test.tsx` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/frontend/src/features/service_activity.tsx` | Required frontend/API compatibility | Expose/consume bounded pagination or lightweight projection metadata. |
| `portal/frontend/src/features/service_history.tsx` | Required frontend/API compatibility | Retained scan/history pagination. |
| `portal/tests/test_activity_pagination.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_artifact_tab_queries.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_dashboard_paging.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_dependency_lifecycle.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_dependency_queries.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_exchange_query_bounds.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_execution_summaries.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_finding_page_budgets.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_findings_query.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_findings_sql.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_focused_export_bounds.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_frontend_service_operations.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_overview_queries.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_performance_diagnostics.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_performance_ingestion.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_performance_scoped_activity.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_poam_query.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_portal.py` | Performance tests / benchmarks / report | Simplified/member, audit/POAM/focused-export coverage; existing watchlist assertion adapted to pending then ready contract. |
| `portal/tests/test_remediation_list_queries.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_remediations_mixed_paging.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_risk_sql.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_security_dashboard.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_service_raw_read_model.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_service_tab_queries.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_services_export_bounds.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_simplified_contract.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_simplified_members.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `portal/tests/test_simplified_sql_page.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `scripts/benchmark-activity.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `scripts/benchmark-backend.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `scripts/benchmark-dependencies.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `scripts/benchmark-history-export.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |
| `scripts/benchmark-simplified-pages.py` | Performance tests / benchmarks / report | Query/row/DTO/lifecycle correctness coverage, synthetic measurement or audit evidence. |

## Fresh 100k measurements

SQLite disposable fixtures, actual route bodies and DTO serialization, profiling/tracemalloc enabled. These are fresh reconstruction measurements, not historical snapshot results. They exclude HTTP authentication/network/middleware and are not PostgreSQL production latency. Report hashes identify the measurement revision; later changes only concerned dependency lifecycle DTO/status and its tests, measured again separately. Fetched rows measure DBAPI returns, not database rows examined.

| Scenario | ms | Queries | Fetched rows | Response rows | Bytes |
|---|---:|---:|---:|---:|---:|
| simplified_default | 394.8 | 17 | 35 | 21 | 9198 |
| simplified_all_target_first | 644.4 | 17 | 64 | 50 | 19943 |
| simplified_all_target_middle | 578.5 | 17 | 64 | 50 | 20040 |
| simplified_all_target_late | 576.8 | 17 | 64 | 50 | 20040 |
| simplified_filter_search | 359.3 | 17 | 15 | 1 | 2341 |
| simplified_filter_resource | 353.2 | 17 | 64 | 50 | 20095 |
| simplified_filter_severity | 339.6 | 17 | 64 | 50 | 19963 |
| simplified_filter_active | 571.0 | 17 | 64 | 50 | 19943 |
| simplified_filter_resolved | 215.6 | 17 | 64 | 50 | 19651 |
| simplified_filter_exceptions | 194.1 | 17 | 64 | 50 | 19272 |
| simplified_filter_noncompliant | 380.9 | 17 | 64 | 50 | 19724 |
| raw_all_target_first | 359.8 | 31 | 269 | 50 | 12279 |
| raw_all_target_middle | 313.8 | 31 | 269 | 50 | 12347 |
| raw_all_target_late | 321.3 | 34 | 160 | 18 | 14740 |
| raw_all_target_filter | 419.4 | 31 | 269 | 50 | 12359 |
| members_first | 457.4 | 6 | 53 | 50 | 6860 |
| members_middle | 435.9 | 6 | 53 | 50 | 6950 |
| members_late | 384.3 | 6 | 37 | 34 | 4774 |
| /services/bench-1?findings_view=raw | 311.9 | 31 | 269 | 50 | 12179 |
| /services/bench-1?findings_view=simplified | 361.4 | 17 | 35 | 21 | 9198 |
| /api/dashboard/services | 227.3 | 16 | 81 | 10 | 3346 |
| /api/dashboard/cybersecurity | 569.5 | 10 | 40 | 10 | 4161 |
| service-first | 177.9 | 13 | 73 | â€” | 12683 |
| service-middle | 134.2 | 13 | 73 | â€” | 12679 |
| service-late | 144.7 | 13 | 73 | â€” | 12522 |
| service-filter-other | 103.2 | 13 | 73 | â€” | 12679 |
| global-first | 46.0 | 5 | 71 | â€” | 12213 |
| global-middle | 47.0 | 5 | 71 | â€” | 12210 |
| global-late | 48.6 | 5 | 71 | â€” | 12051 |
| global-action-filter | 106.2 | 5 | 56 | â€” | 12280 |
| cold | 101.4 | 18 | 11 | 0 | 2702 |
| background-build | 19779.6 | 416 | 100008 | 0 | 2 |
| warm | 304.5 | 28 | 91 | 50 | 31878 |
| warm-second-page | 297.4 | 28 | 91 | 50 | 31891 |
| /services/bench-1/history | 175.7 | 15 | 1014 | 10 | 6464 |
| /services/bench-1/exports/findings.xlsx | 1312.0 | 4 | 50027 | â€” | 24 |

## Dependency lifecycle and limits

Cold GET returns bounded PENDING (101.4 ms, 18 queries, 11 fetched rows, 2,702 bytes, no component rows, unknown totals). A bounded worker pool/queue performs generation separately, claims with tokens, and activates only the current revision. Stale input invalidates/requeues derived state. Failed builds expose sanitized status and explicit retry; abandoned leases, concurrent claims and obsolete activation are tested. READY warm requests return 50 components in 304.5/297.4 ms, 28 queries, 91 fetched rows.

Background generation still consumes all 100k components: 19.78 seconds, 416 queries, 100,008 fetched rows, approximately 281 MiB traced peak. It is asynchronous, not a bounded-memory streaming builder. This cost is isolated from the cold GET; at most two workers run with four outstanding slots.

History benchmark uses 100k findings plus 1,000 retained scans: 175.7 ms, 15 queries, 1,014 fetched rows, ten hydrated snapshots, 6,464 bytes. Metadata remains proportional to history count. An additional 100,000-retained-scan SQLite stress exceeded two minutes and was interrupted; that scale is not validated.

Focused findings export consumes 50,000 target-service findings in 1.312 seconds, four queries, 50,027 fetched rows, one ORM object, approximately 1.03 MiB peak. Workbook generation is excluded; the 24-byte synthetic response is not workbook size. Export intentionally consumes all selected records.

## Validation and safety

Full backend suite: 1,101 passed, 1 skipped, 7 warnings in 135.83 seconds. Frontend: 26 files / 95 tests passed. TypeScript passed. Production frontend build passed. Diff whitespace check passed. Targeted lifecycle/DTO tests passed.

Original worktree HEAD and exact NUL-delimited status match the recovery baseline. All 2,446 accessible checked source/Git files match hashes except two missing Codex transient turn-diff refs; source files have no mismatches. Recovery working tree: 1,433 checked files match, HEAD remains recovery snapshot. Generated dependencies/cache/test directories are excluded from this source hash recheck.

The performance checkout is a linked worktree of the recovery repository. Creating its authorized commit necessarily writes shared Git objects/refs; recovery checked-out source, branch HEAD and working tree remain unchanged. No push or merge is performed. Commit hash is supplied in the completion response.

Scope is suitable for a standalone backend performance merge, with the documented background-build and very-large-history limitations; no claim of passing PostgreSQL or live deployment acceptance.
