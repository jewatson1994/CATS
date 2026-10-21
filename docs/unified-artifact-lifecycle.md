# Unified artifact lifecycle

This guide describes the combined implementation in the isolated unified-artifact-lifecycle worktree and its verification limits. The baseline is `494d689c3ac7a2d60eba8401784b9305efe809ad`. Source commits `20b917392134eb40bcec25553f65401b36d85d4d` and `588a6d5` were incorporated as cherry-picks `ffdd3fb` and `07d77bd`, respectively. The existing OCI branch is preserved. These changes and the checks below do not establish production or disconnected acceptance.

## Navigation and routes

Services, Discovery, Scan, and Patch are primary navigation. Cybersecurity groups the overview, Approvals, and Approved Releases. More contains the Artifact catalog and supporting workspaces. The shell preserves account, notification, active-route, responsive, and permission controls.

| Page | Route |
| --- | --- |
| Global artifact catalog | `/artifact-catalog` |
| Service recommendations | `/services/{service_key}/artifact-recommendations` |
| Multi-image Patch | `/patch-campaigns?service_id={service_key}` |
| Existing single-image Patch | `/patch` |

| API | Behavior |
| --- | --- |
| GET `/api/artifact-catalog` | Search/paginate artifacts visible through service assignments. |
| GET `/api/services/{service_key}/artifact-recommendations` | Scoped replacements, eligibility, retained image comparison, and persisted proposal IDs. |
| POST `/api/services/{service_key}/artifact-recommendations/{id}/adopt` | Record a proposed selection and, where applicable, an amendment against the active revision. Does not activate it. |
| POST `/api/services/{service_key}/artifact-recommendations/{id}/decision` | Defer, dismiss with a reason, or reopen; proposed recommendations cannot use these transitions. |
| GET `/api/services/{service_key}/amendment-proposals/{id}/readiness` | Specific proposed-assessment blockers and next steps. |
| POST `/api/v1/amendment-assessments/{id}` | Authenticated pipeline intake of complete proposed inventory evidence. |
| GET/POST `/api/services/{service_key}/patch-campaigns` | Read service images/campaigns or create a campaign. |
| GET `/api/patch-campaigns/{id}` | Per-image status, evidence, and allowed controls. |
| POST `/api/patch-campaigns/{id}/items/{item_id}/{action}` | Cancel or safely retry an eligible item. |
| GET `/api/approved-releases/{id}/revision` | Inspect frozen revision and current authority state. |
| POST `/api/approved-releases/{id}/revision/{action}` | Activate, suspend, or revoke with version checks. |

Session mutations require CSRF and server-side scoped permissions. Pipeline intake uses the existing pipeline authentication boundary. Hidden or disabled controls are not authorization boundaries.

## Schema and upgrade behavior

New catalog tables are `global_artifacts`, `global_artifact_locations`, `service_artifact_assignments`, `artifact_patch_lineage`, and `artifact_recommendations`. Identity is the digest, media type, and platform; locations, service relationships, and lineage are separate. Unique identities and savepoint-based duplicate handling support concurrent registration without discarding the caller's transaction.

`patch_campaigns` and `patch_campaign_items` link service campaigns to existing durable jobs and patch executions. `release_revisions` freezes manifests; `release_revision_states` tracks restrictions separately; `service_active_releases` holds the versioned active pointer. `release_amendment_proposals` and `proposal_assessments` retain proposed inventory and its isolated evidence.

The portal imports these models before its existing `Base.metadata.create_all` startup upgrade. Startup schema work is serialized through the migration transaction (PostgreSQL advisory transaction lock; SQLite `BEGIN IMMEDIATE`). The Cyber approval upgrade makes `destination_id` nullable so review can precede publication destination configuration. PostgreSQL changes the constraint; SQLite rebuilds the table while preserving columns, rows, and indexes and requires foreign keys disabled before the migration transaction. This is the repository's startup migration model, not a general historical-data conversion or downgrade framework. Existing approvals do not automatically acquire verified artifact evidence or an active governed revision. Back up the database and verify the upgrade against the deployment's existing schema before rollout.

## Evidence and shared recommendations

Eligibility requires retained authenticated worker evidence: immutable delivered output, verified Cosign image signature, retained artifact validation and vulnerability counters, and verified deployment validation for that exact artifact in the target service. Assignment alone is insufficient. Another service's validation or approval does not transfer with a shared artifact.

A verified validation enqueues `artifact_recommendations` in the same database transaction. This internal durable outbox uses a validation-specific deduplication key, bounded worker leases and up to five attempts; it survives user queue saturation. The remediation worker registers this handler and `patch_campaign_item`. Reconciliation rechecks retained validation/service binding and verified digest-bound patch lineage, then deduplicates recommendations for other active services that still use the known source image. It does not patch again, mutate another service's inventory, or activate its release.

The UI exposes exact retained image before/after vulnerability counters and their source/target digests only when trusted receipt checks succeed. Missing evidence is shown as unavailable. Counts are not summed into a service posture or converted into an estimated reduction. General OCI attestations and reusable patch recipes are not implemented by this catalog.

## Proposed assessment and approval

Adoption is explicitly proposed. The UI requires proposal permission and eligibility; the backend can retain a proposal before all activation evidence exists. Current inventory, current assessment, and active release remain unchanged. Persisted proposals can be reopened in the UI; readiness reports precise missing evidence and gates the Cyber request form.

The proposed scanner result is isolated in `proposal_assessments`, not ingested as the current service execution. It must cover the complete exact proposed immutable inventory, preserve original requested-reference mappings, identify platform/media type, contain no skipped inputs, and satisfy the existing whole-service assessment checks. It must follow the base approval, cannot be future-dated, and is bound to the still-active base revision. Evidence is immutable: identical resubmission is idempotent; conflicting replacement is rejected. A stale base blocks continuation.

There is **no automatic dispatch of a proposed-inventory scanner**. An authenticated pipeline must supply the actual scan through the amendment-assessments endpoint. The readiness endpoint exposes this limitation rather than manufacturing fresh posture. The existing approval request accepts `amendment_proposal_id`; the server derives the proposal revision and freezes the retained proposed-service-scan evidence. Cyber review, exact service validation, publication, and activation remain separate checks.

## Multi-image campaigns

A campaign selects one to twenty distinct active service images with valid immutable SHA-256 digests. Conflicting retained/reference digests are rejected. Publication uses a configured destination registry and optional safe relative prefix; the worker generates unique destinations. Creation requires `service.view`, `remediation.execute`, and `scan.ingest` on the active service, and authorization is checked again before dispatch.

Each image has independent durable status, patch execution, error, and retained results. Completed, partial, and failed aggregate outcomes describe execution, not release eligibility. Publication is not atomic across images. The campaign workflow publishes to a registry; the existing individual workflow retains its separate output options.

Each durable dispatch allows one attempt to avoid automatically replaying uncertain registry writes. The owner with current patch permissions can cancel queued items immediately or request cancellation of running items; acknowledgment can be delayed. At most two manual retries are allowed for failed/cancelled terminal items **only when no patch execution was dispatched**. A retry creates a replacement durable job and preserves earlier attempts. Dispatched or uncertain publication is not retried through this control. The UI follows server capability flags.

## Signed releases, authority, and offline verification

Release publication retains the exact Export All `documentation.zip` and release manifest. Configured signing produces detached `documentation.zip.sig`, `release-manifest.sig`, and `release-public-key.pem`, and verifies the exact bytes before reporting verified status. Unsigned output is not a verified release.

Revision records freeze the approved manifest. Activation verifies current Cyber authority/expiry, artifact eligibility, manifest bytes, and the trusted signing fingerprint. Optimistic versions protect the active pointer and restriction transitions; suspend/revoke require a reason. Restrictions remain separate from the immutable decision. OCI distribution resolves current authority rather than trusting a retained pointer alone. A proposal, successful patch, or publication does not itself activate a revision.

Detached verification uses local Cosign offline, without a transparency-log lookup. Independently pin the publisher key fingerprint: the bundled public key alone proves consistency, not publisher identity. Keep ZIP bytes unchanged. Disconnected use also requires locally staged images, packages, scanner databases, charts, tools, registry access, and trust material. Offline signature verification does not supply those prerequisites. Consumers must enforce expiry and admission policy; learning later revocation requires an updated authority source.

## Verification record and limits

The latest reported broad backend run passed **1,005 tests with 28 skipped**. The frontend run passed **381 tests across 58 files**. Focused release checks passed **134 tests with 2 deselected**. The final combined catalog/campaign/proposal/revision/recommendation/gateway run passed **111 tests**. These are separate runs, not additive coverage totals; skipped/deselected cases remain unverified by those runs. Frontend HTTP mocks verify UI behavior and contracts, not live registry or worker integration.

Earlier fixture work exercised real PostgreSQL, TLS, Cosign, and HTTP interactions. Its scan and deployment-validation evidence was synthetic; it did not establish a real scanner/Copa/cluster patch-to-release flow. Keep that distinction when citing the fixture results. The checks do not demonstrate full Copa end-to-end execution or disconnected operational acceptance. No automatic proposed scanner dispatch, patch recipe reuse, or general OCI attestation workflow is claimed.

Remaining acceptance should exercise the deployed routers/workers, upgrade of a representative existing database, real scoped accounts, real patch/scan/service validation, Cyber decision, signed publication and activation, and OCI authority resolution. Include partial campaigns, worker interruption, permission changes, stale proposals, signature failures, expiry/revocation, and independently pinned offline ZIP verification. Build and validate the normal deployment images separately and retain actual environment/results as acceptance evidence.

See [Cyber approvals and approved releases](cyber-approved-releases.md) and the [installation guide](../README.md).

## Final local acceptance, 2026-10-21

The normal `scripts/build-cats-release.py` build succeeded using the existing `catscan-base:local`, producing `cats:lifecycle-local` and `cats-discovery:lifecycle-local`. TypeScript checking and the production Vite build passed. Normal Compose plus the OCI overlay configuration validated. No existing deployment was replaced. Build-time downloads were available; this is not proof of an air-gapped rebuild.

The reproducible harness in `tests/lifecycle/README.md` exercised PostgreSQL, a TLS registry, real Cosign signing/verification, and actual gateway HTTP. Signed revisions mapped stable tags to shared replacement content, rejected original digest substitution, and enforced independent service revocation and tampered-manifest rejection. Actual Docker pull/unpack and Helm OCI pull passed; both clients were denied after revocation. Those client checks use legacy approvals; signed revision checks use HTTP separately. Scan, validation, and Cyber decision records in this harness are fixtures, not operational acceptance of those stages.

Measured local client durations were 658 ms for Docker pull, 475 ms for Helm pull, and 252/166 ms for their revoked requests. Ten sequential gateway manifest reads measured 39.02–54.21 ms (median 42.05 ms). No concurrent load, query-count, CPU, memory, or storage benchmark was completed. Catalog tests verify one replacement and 24 recommendations across 25 service associations, including idempotency and retired-source rejection; they do not represent 25 real patched deployments.

Automatic proposed-inventory scanning requires further scanner integration: `generate-sboms.sh` retains digest and platform but not manifest media type; the overview/report path does not retain the exact original-to-effective reference mapping. Normal `scan_protocol.py` ingestion updates current execution and ServiceImage records. It must gain a proposal-bound isolated ingestion path before automatic dispatch can safely be enabled. The authenticated complete-assessment endpoint is implemented; metadata must not be invented to satisfy it.

Additional unverified or incomplete scope: equivalent patch-recipe reuse; general typed OCI attestation publication; catalog signing of arbitrary Helm/index artifacts and key-rotation acceptance; fresh artifact cryptographic verification on every pull (retained verified receipts are used); real concurrent amendment activation stress; and the complete real Copa → scanner → validator → Service Manager → Cyber → activation scenario. These limits prevent claiming full final operational acceptance. Existing scanner, Copa, validator, publication, Cyber review, signing, and durable remediation worker engines are reused rather than duplicated.
