# Posture refresh and Discovery limits acceptance

Baseline: ade951eae7d592dbf9c9041530e079552443cceb. Branch: fix/posture-refresh-and-discovery-limits.

## Confirmed posture defect

With separate disposable PostgreSQL operational and intelligence databases, an explicit operational Session caused intelligence generation lookup to raise UndefinedTable for intelligence_generation. Background posture rebuilds use such sessions; routed requests do not. This could prevent rebuilding or leave a token which normal readers rejected.

Generation reads and guards now map only the configured operational engines to their corresponding intelligence engines, including Connection-bound sessions. Independent tenant/test engines retain their isolation, and single-database routing remains unchanged. Existing transaction guards, post-transaction connection cleanup and conservative invalidation remain enabled. The explicit-session callers in authorization_revision, evidence_reads, dependency_queries, finding_classification and main's export path use this central correction.

Unavailable intelligence cannot be persisted as a valid posture token. Requests report pending posture, and refresh scheduling coalesces queued and running work per database engine. Above the existing synchronous threshold all invalid rows rebuild in the background. Rate-limited scheduling, freshness rejection and failure messages omit connection details; existing completion logs include duration. The dashboard distinguishes pending inventory from an empty inventory and does not invent totals.

## Verification

- Real split PostgreSQL suite: 26 passed, including explicit engine/connection routing and guard cleanup.
- Real 27-service test: initial background preparation, three repeated reads, stable calculated timestamps, intelligence trust change invalidation, actual unavailable PostgreSQL endpoint, and recovery after restoration. Real projection calculations were used; no production data was modified.
- Posture regression suite: 15 passed. The prior expectation of one inline rebuild above the threshold was updated to assert all four services remain pending until background work completes.
- Intelligence routing/native VEX regressions: 49 passed, 9 environment-dependent skips.
- Frontend dashboard tests: 8 passed; typecheck and production build passed (existing build warnings remain).
- Discovery targeted regressions: 310 passed plus 72 follow-up checks. Both Compose configurations validated.
- Discovery resource tests cover a 129 MiB archive and extracted payload, encrypted retained-source round trip, 10,002 entries, files above 4 MiB, malformed/encrypted/traversal cases, cancellation/cleanup and resource failures. Streaming allocation measurement remained below 32 MiB Python traced peak; this is not a whole-process/container RSS guarantee.

## Deployment

Build the normal CATS image from this branch after review; update portal and Discovery worker together. Apply the supplied Compose changes and recreate affected services. No data migration, token edit, deletion, reimport or rescan is required. Opening Service Snapshot schedules invalid summaries; subsequent reads expose completed summaries. After an intelligence outage, restore intelligence connectivity and refresh; valid rows become usable and invalid rows rebuild. Do not increase CATS_POSTURE_SYNC_LIMIT.

The five optional Discovery limits default to 0 (unlimited):

```
CATS_DISCOVERY_MAX_UPLOAD_BYTES=0
CATS_DISCOVERY_MAX_FILE_BYTES=0
CATS_DISCOVERY_MAX_EXTRACTED_BYTES=0
CATS_DISCOVERY_MAX_FILES=0
CATS_DISCOVERY_MAX_RENDERED_BYTES=0
```

Compose passes these settings to portal and discovery-worker. The worker's fixed 512 MiB /tmp tmpfs is replaced by the discovery_scratch named disk volume mounted at /tmp. See discovery-workflow.md for resource and security details. Direct Compose ingestion retains its existing limits.

Finite disk, worker memory/CPU/PID constraints, renderer timeouts, structural parser safeguards, inventory complexity and externally managed proxy request/time limits still apply. ZIP metadata, parsed individual documents and inventory structures require memory proportional to their complexity. This does not guarantee arbitrary repositories fit finite hardware. No production deployment or full user-repository render was performed for this fix; the supplied acceptance inputs exercise ingestion and retained-source processing locally.

## Reproduction

Set PYTHONPATH=portal and CATS_TEST_SPLIT_POSTGRES_URL to an isolated PostgreSQL administrator connection able to create/drop test databases, then run:

```
python -m pytest portal/tests/test_split_intelligence_postgres.py portal/tests/test_service_posture.py -q
python -m pytest portal/tests/test_discovery_unlimited.py portal/tests/test_compose_discovery_streaming.py -q
```

The split database fixture creates and removes uniquely named databases. Never point tests at production databases.
