# Risk Intelligence implementation handoff

## Scope and isolation

Implemented on `feature/risk-profiles-vex`, based on local main `85d628e`. OCI development remains paused at `feature/oci-compliance-proxy` / `588a6d5`. This feature is visual only: risk scores and human decisions do not modify scanner findings, compliance enforcement, publication approvals, remediation, or container admission.

## Delivered capability

- Dedicated Risk Intelligence page with source administration, VEX exploration, versioned profiles, assignments, service assessments, previews, history, and informational human decisions.
- Additive database models with indexed evidence lookups and immutable policy, assessment, decision, and VEX evidence history. Models are registered before the existing metadata migration/create step; no existing table columns are changed.
- OpenVEX v0.2.0 and CSAF 2.0 VEX normalization. Real Red Hat provider evidence is included with provenance and licensing. The 18-source research catalog distinguishes applicability authorities from enrichment providers; it is not a claim that all 18 have working ingestion adapters.
- Explicit authenticated HTTPS retrieval with conditional synchronization, bounded parsing, raw-document preservation, revision history, and conservative exact-product evaluation.
- Ed25519-signed offline snapshot export/import with pinned keys, source scope and integrity verification. No external feed fetch at startup or during assessment.
- Configurable informational severity/EPSS/KEV/age/fix/exception/VEX model with uncertainty floors and immutable version history. Existing KEV/EPSS catalogs and classification state are reused.
- Service-to-single-owning-group inheritance, dedicated recommendation/delegated/AO permissions, authenticated reviewer identity, expiry and reassessment indicators.
- Durable `risk-worker` service in both Compose manifests, using the existing queue and database mounts.

See [source research](risk-intelligence-sources.md), [ingestion and offline operations](vex-ingestion.md), and [risk model](risk-model.md).

## Deployment

Build the normal CATS release from this branch so the frontend bundle includes the new page. Deploy the web application and `risk-worker` with the same database and policy catalog volumes. Existing schema creation adds the new tables and database immutability guards. Back up the database before deployment and validate against a representative restored database first.

Use the operator CLI `python scripts/vex-intelligence.py --help` to configure reviewed authorities, retrieve explicitly approved documents, and export snapshots in the connected environment. Independently provision the signing public key in the disconnected deployment, then import via CLI or the Sources UI. Only use keys and authority namespaces reviewed by your organization. Unsigned manual uploads stay unverified.

Prefer a separate versioned signed intelligence package, optionally transported through an OCI artifact, over embedding feeds in every application image. This decouples application releases from intelligence updates and supports rollback and air-gap transfer. OCI artifact retrieval/attestation verification is not implemented here; transfer the signed JSON package through your approved channel. Do not rebuild the application solely to refresh intelligence.

## Security review

CSRF and global/scoped permissions protect mutations. Authority labels cannot grant privileges. Human decisions cannot override technical results or activate enforcement. Source verification is never accepted from uploaded JSON. Trusted applicability requires configured publisher scope, authenticated provenance, exact observed product/version, current evidence, and no conflicting or withdrawn evidence. Missing, old, incomplete, or ambiguous scan evidence prevents safety reductions. TLS remains enabled; outbound retrieval checks DNS addresses, pins a public address, preserves hostname verification, and rejects redirects.

Database guards prevent ordinary updates/deletes to evidence/history. Database administrators can alter schema; this is not a cryptographic audit ledger. Snapshot signatures authenticate the configured distributor, not independently every upstream vendor. A fresh repository has no external latest-revision watermark, so pinned signer trust and issue-time expiry remain important replay boundaries.

## Coverage gaps and operational limits

- No DSSE/Cosign/OCI-attached VEX verification, vendor catalog crawler, scheduled feed synchronizer, or generic vendor API adapters. HTTPS synchronization is explicit per document. Existing KEV/EPSS integrations remain separate enrichment inputs.
- No inferred distro backports, CPE matching, CSAF relationship expansion, version-range inference, or image-tag resolution. Unsupported identity remains uncertain instead of falsely safe.
- Scoring is a configurable CATS proposal, not a federal standard. It uses existing normalized severity, not a new CVSS vector interpreter. Aggregation currently uses the maximum observation/CVE score; alternate aggregation methods and independently configurable CVSS/EPSS thresholds are future work.
- Profiles use a validated JSON editor. Preview covers a selected service, not fleet-wide side-by-side comparison. Human supporting documentation is stored as references, not file uploads. `mitigate` represents a conditional informational decision with required controls.
- Assessment reads are materialized. Observation reads are batched and capped at 100,000, but final assessment JSON and candidate VEX rows can still be large. Million-record production workload, retention/archive policy, and repeated-CVE candidate fanout need capacity testing. Append-only tables deliberately have no automatic deletion job.
- Source repository freshness does not mean every contained statement is trusted. Explorer exposes provenance, while conflict resolution is performed in the service/product context. API audit events exist; a dedicated ingestion audit browsing interface remains future work.
- Offline deployment, user acceptance/browser layout across supported browsers, real operational signing-key provisioning, and representative production database migration require environment validation.

## Verification

The final test inventory and PostgreSQL/performance results are recorded with this handoff. TypeScript checking, the production frontend build, and both Compose configuration validations passed. Existing frontend, Cyber approval and durable-job regressions passed (45 tests). Existing publication TLS and scan intelligence tests passed (13 tests).

The broader classification suite has 21 fixture failures because its seed requests omit the now-required single owning group. The first failure was reproduced on unchanged main `85d628e` with the same HTTP 422 message. These tests did not reach classification assertions and are not reported as passing. No unrelated ownership behavior was changed to accommodate those old fixtures.

Final verification additions:

- New risk calculation/worker tests: 24 passed. New VEX repository/security tests: 31 passed.
- Frontend Risk Intelligence tests: 8 passed; TypeScript check and Vite production build passed.
- PostgreSQL 16: 10 integration cases passed, including repeat schema creation, signed snapshot import, worker assessments and UPDATE/DELETE rejection on all six immutable tables. The isolated test container and schemas were removed.
- Database benchmark: 10,000 VEX statements and 1,000 findings/observations evaluated and persisted in 0.738-1.089 seconds, 13 SELECTs and one INSERT per run. Signed ingestion took 0.431 seconds. Reproduce with `scripts/benchmark-risk-vex.py`; see risk-model.md for exclusions and full dimensions.

## Reproduce the checks

From the feature worktree, use the portal Python environment and set `PYTHONPATH=portal`. Run:

```text
python -m pytest portal/tests/test_risk_profiles.py portal/tests/test_vex_repository.py portal/tests/test_risk_routes.py -q
python -m pytest portal/tests/test_frontend.py portal/tests/test_cyber_approvals.py portal/tests/test_durable_jobs.py portal/tests/test_publication_tls.py portal/tests/test_scan_intelligence.py -q
```

For PostgreSQL, set `CATS_TEST_POSTGRES_URL` to a dedicated test database URL and run `portal/tests/test_risk_vex_postgres.py`. The opt-in suite creates and removes uniquely named schemas. For Windows installations with a locked default pytest temp directory, pass a fresh writable `--basetemp` directory.

From `portal/frontend`, run the project typecheck/build and `vitest run src/features/risk_intelligence.test.tsx`. Validate both Compose files with your normal environment settings before deployment.

Disconnected acceptance should include provisioning a reviewed source and independent signer key, importing a valid snapshot twice, rejecting a modified snapshot, assessing a service with real PURLs and fresh KEV/EPSS catalogs, observing stale-evidence warnings, recording scoped recommendation/delegated/AO decisions, and confirming existing compliance/publication behavior stays separate. Also verify cancellation/retry and restart behavior with the deployed worker/database versions.

Final combined feature run: **95 passed** (24 risk, 31 VEX, 40 route tests). With the separately executed 58 existing regression checks, 10 PostgreSQL integration cases and 8 frontend checks, the passing verification inventory totals 171 tests. The 21 pre-existing classification fixture failures described above are additional and excluded from that count.


## Group-scoped Risk Policy

Profiles and assessments are managed under Administration > Risk Policy at `/admin/risk-policy`; `/risk-intelligence` redirects there. Each service has one owning group. Group configuration managers see their authorized groups and profiles; global managers can select any group. Service-only configuration roles cannot create or assign group profiles.

New profiles belong to one group, with independent name/version sequences. Copies remain within that group. Assignments accept group scope only and require a profile owned by that group. Resolution follows the service's owning group, then parent groups; an empty assignment resumes inheritance. Built-in defaults apply when no scoped assignment is available.

The additive immutable `risk_policy_groups` table stores ownership and display names. Existing profile, assignment, assessment, and decision records remain intact. Historical service/default assignments and assignments to unscoped legacy profiles no longer determine current policy. Recreate reviewed legacy configurations within their intended groups and assign them explicitly. Historical assessments remain available and become stale when their resolved policy changes.
