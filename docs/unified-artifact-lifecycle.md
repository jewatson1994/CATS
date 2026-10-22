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

The UI exposes exact retained image before/after vulnerability counters and their source/target digests only when trusted receipt checks succeed. Missing evidence is shown as unavailable. Counts are not summed into a service posture or converted into an estimated reduction. Typed scan and patch attestations and coordinated recipe claims are implemented; production recipe identity provisioning remains deliberately gated as described below.

## Proposed assessment and approval

Adoption is explicitly proposed. The UI requires proposal permission and eligibility; the backend can retain a proposal before all activation evidence exists. Current inventory, current assessment, and active release remain unchanged. Persisted proposals can be reopened in the UI; readiness reports precise missing evidence and gates the Cyber request form.

The proposed scanner result is isolated in `proposal_assessments`, not ingested as the current service execution. It must cover the complete exact proposed immutable inventory, preserve original requested-reference mappings, identify platform/media type, contain no skipped inputs, and satisfy the existing whole-service assessment checks. It must follow the base approval, cannot be future-dated, and is bound to the still-active base revision. Evidence is immutable: identical resubmission is idempotent; conflicting replacement is rejected. A stale base blocks continuation.

Adoption automatically queues a durable proposed-inventory scan through the existing scanner. Proposal-bound ingestion retains isolated evidence and checks every immutable digest, platform, media type and requested reference. Failed or incomplete scans block review; retry creates a new generation. The authenticated amendment-assessments endpoint remains available. The existing approval request accepts `amendment_proposal_id`; the server derives the proposal revision and freezes the retained proposed-service-scan evidence. Cyber review, exact service validation, publication, and activation remain separate checks.

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

Earlier fixture work exercised real PostgreSQL, TLS, Cosign, and HTTP interactions. Its scan and deployment-validation evidence was synthetic; it did not establish a real scanner/Copa/cluster patch-to-release flow. Keep that distinction when citing the fixture results. The checks do not demonstrate full Copa end-to-end execution or disconnected operational acceptance. The continuation verification below supersedes the earlier automatic-dispatch and attestation limitations; fixture evidence still does not establish full operational acceptance.

Remaining acceptance should exercise the deployed routers/workers, upgrade of a representative existing database, real scoped accounts, real patch/scan/service validation, Cyber decision, signed publication and activation, and OCI authority resolution. Include partial campaigns, worker interruption, permission changes, stale proposals, signature failures, expiry/revocation, and independently pinned offline ZIP verification. Build and validate the normal deployment images separately and retain actual environment/results as acceptance evidence.

See [Cyber approvals and approved releases](cyber-approved-releases.md) and the [installation guide](../README.md).

## Final local acceptance, 2026-10-21

The normal `scripts/build-cats-release.py` build succeeded using the existing `catscan-base:local`, producing `cats:lifecycle-local` and `cats-discovery:lifecycle-local`. TypeScript checking and the production Vite build passed. Normal Compose plus the OCI overlay configuration validated. No existing deployment was replaced. Build-time downloads were available; this is not proof of an air-gapped rebuild.

The reproducible harness in `tests/lifecycle/README.md` exercised PostgreSQL, a TLS registry, real Cosign signing/verification, and actual gateway HTTP. Signed revisions mapped stable tags to shared replacement content, rejected original digest substitution, and enforced independent service revocation and tampered-manifest rejection. Actual Docker pull/unpack and Helm OCI pull passed; both clients were denied after revocation. Those client checks use legacy approvals; signed revision checks use HTTP separately. Scan, validation, and Cyber decision records in this harness are fixtures, not operational acceptance of those stages.

Measured local client durations were 658 ms for Docker pull, 475 ms for Helm pull, and 252/166 ms for their revoked requests. Ten sequential gateway manifest reads measured 39.02–54.21 ms (median 42.05 ms). No concurrent load, query-count, CPU, memory, or storage benchmark was completed. Catalog tests verify one replacement and 24 recommendations across 25 service associations, including idempotency and retired-source rejection; they do not represent 25 real patched deployments.

## Continuation acceptance, 2026-10-21

Automatic proposed-inventory dispatch and isolated ingestion are implemented in `proposal_scans.py`, `scan_protocol.py` and the existing remediation worker. The scanner now retains exact digest/platform/media-type identities and original-to-effective reference mappings. Proposed findings do not replace current service findings, assignments, classifications or gateway mappings. Durable maintenance detects changed intelligence, VEX, inherited Risk Policy, service configuration, artifact receipts and validation evidence. Generation checks prevent stale or cancelled work from overwriting newer results. Cyber decisions and activation bind to the reviewed inventory and evidence token. Default assessment freshness is 24 hours, controlled by `CATS_PROPOSAL_ASSESSMENT_MAX_AGE_HOURS`.

This implementation dispatches the whole proposed inventory; policy-aware cross-service per-artifact scan-cache reuse remains incomplete. It does not manufacture evidence from vulnerability-count subtraction.

`patch_recipes.py` adds a unique database-backed `PatchRecipeClaim`, deterministic recipe identities, coordinated concurrent requests, cancellation/lease checks and verified-result reuse. Reuse requires current verified receipts, compatible platform/source/destination and signing identity. A production `patch_recipe_identity` provider is intentionally not enabled: package metadata and payload snapshots, tool/runtime identity and remote execution inputs must be reliably bound before automatic equivalence is safe. Explicit adoption of a verified replacement already avoids another Copa run. Recipe coordination tests do not establish automatic production recipe reuse.

The patch worker optionally accepts `CATS_PATCH_GRYPE_DB_SNAPSHOT`. Its identity is derived from the actual snapshot bytes. `CATS_PATCH_GRYPE_DB_DIGEST` is an optional consistency check and requires the snapshot directory when supplied. The digest is the canonical tree digest produced by `scanner_inputs.snapshot_digest`, not an individual database-file checksum. The worker rejects symlinks/junctions, copies to a private cache, verifies integrity before/after use and disables Grype auto-update. No snapshot setting preserves existing scanning behavior; it does not establish a fully pinned patch recipe.

`oci_attestations.py` publishes and verifies typed digest-bound in-toto/DSSE evidence using existing Cosign and pinned trust. Patch publication integrates scan and patch statements. Verification checks subject, purpose, evidence identity and signer; wrong-purpose or mismatched evidence is rejected. Registry-compatible Cosign storage is used; OCI-referrers-only storage is not required. General orchestration for all requested SBOM, VEX, compliance and amendment statement types remains incomplete.

### Verified results

- Focused backend/scanner regression run: **221 passed, 1 skipped**, 33.54 seconds. Covers proposals, recipes, scanner snapshots, campaigns, patching, revisions, durable jobs, signing, attestations and scanner identity extraction. Separate runs are not additive.
- Frontend: **385 tests across 58 files passed**; TypeScript and production Vite build passed. Browser test mocks are not deployed worker acceptance.
- Fresh PostgreSQL/TLS-registry/Cosign/gateway fixture passed (`lifecycle-continue-20261021`). Real concurrent database sessions verified durable-job deduplication and preservation of the caller's unrelated transaction. Scan, validation and Cyber records in this fixture remain synthetic.
- Real OCI attestation smoke test passed against Distribution 2.8.3, including pinned offline verification and wrong-purpose/evidence/trust rejection.
- Real connected Copa 0.14.1 execution patched Alpine 3.20.0 amd64 from `sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd` to `sha256:e269e2a739a6444fba2b114e5a5d97a14ca5206b7b31903e1dd931514c1f106a`. Syft/Grype evidence recorded **72 findings before, 4 after: 69 removed, 3 retained, 1 new** (CVE-2026-85091, zlib). Eight OS package upgrades satisfied all 69 targeted native-report entries. Retained local evidence is in ignored `.test-temp/copa-real-20261021/`, including `RESULTS.txt`, reports, hashes and tool versions. A report-wrapper CRLF error occurred after patching; report comparison was rerun successfully without repeating the patch.

The real Copa run used public Alpine package sources and a connected disposable tool container. It did **not** traverse deployed Patch/Scan workers, service validation, Cyber approval and activation. The PostgreSQL fixture independently verifies signed activation and delivery using synthetic upstream evidence. Combining those results is not proof of one uninterrupted real lifecycle. Earlier Docker/Helm client results above were not rerun for this continuation. Normal release and Discovery image builds above predate these continuation changes; the frontend build was rerun.

Reproduce the focused suite from the repository root with `PYTHONPATH=portal` and `python -m pytest portal/tests/test_proposal_assessments.py portal/tests/test_patch_recipes.py portal/tests/test_scanner_inputs.py portal/tests/test_patch_campaigns.py portal/tests/test_patching.py portal/tests/test_release_revisions.py portal/tests/test_durable_jobs.py portal/tests/test_signing.py tests/test_oci_attestations.py scanning-main/tests/test_image_identities.py -q`. See `tests/lifecycle/README.md` for the real database/registry harness and `tests/smoke_oci_attestations.py` for the attestation probe. Test keys and private configuration must remain ignored.

### Rollout and remaining acceptance

Startup adds the recipe-claim table using the existing additive schema mechanism. Back up PostgreSQL, drain workers before changing versions, and preserve immutable revisions and receipts. Older images do not understand proposal jobs, recipe claims or attestation evidence; rollback requires stopping new job dispatch and draining or preserving those jobs, not dropping historical tables. Representative production-data upgrade/downgrade acceptance remains outstanding.

Full disconnected acceptance requires local package mirrors and pinned package payload/metadata, deployed scanner databases, validator infrastructure and an execution-bound recipe identity provider. These prerequisites were not established locally. A private Docker bridge is not egress isolation. Outstanding checks include the uninterrupted real worker-to-Cyber lifecycle, arbitrary Helm/index signing and key rotation, concurrent amendment activation stress, and realistic gateway load/query/CPU/memory measurements. No full operational acceptance is claimed. Protected branches and existing deployment data remain unchanged.

## Integration and acceptance checkpoint, 2026-10-22

The lifecycle branch now incorporates verified integration `e937f62322d55c9155076dd5593bb25e99deae2d`, including separate operational/intelligence databases, native VEX generation invalidation and Discovery hotfix `321cf1f`. See [the current acceptance report](lifecycle-acceptance-2026-10-22.md) for results, reproducibility and outstanding production work. This checkpoint is suitable for further isolated testing, not a declaration of full operational or disconnected acceptance.


## Execution-bound patch continuation

The earlier October 21 provider limitation is superseded by `patch_inputs.py`: production patch preparation now binds actual execution inputs and emits a consumed receipt checked by canonical recipe reuse. Configure the worker-owned `CATS_PATCH_BINDING_SPEC` and private `CATS_PATCH_BINDING_ROOT`; do not accept caller-provided snapshot assertions. The internal network, package and scanner snapshots, tool/runtime identity, platform, policy, signing identity and destination scope participate in equivalence. A real second-service campaign reused a successfully patched and signed output. See the [acceptance report](lifecycle-acceptance-2026-10-22.md) for exact evidence and operational limits.

Persistent execution fencing prevents automatic replay when ownership or publication is uncertain. Operators must reconcile orphan execution infrastructure and retained private snapshots after hard host failures. Do not delete ownership records or approve an uncertain output merely to unblock a retry. Full sequential lifecycle acceptance is separate from successful patch reuse and from the historical synthetic gateway harness.


## Final local operational acceptance, 2026-10-22

The preceding historical limitations concerning unavailable local mirrors and an unexecuted sequential lifecycle are superseded for the configured two-service container scenario. Actual Copa patching, rescan, Kubernetes validation, TLS publication, Cosign signing, shared recommendation, automatic proposed assessment, real Cyber API decisions, signed activation and gateway delivery passed. A second service reused one successful patch execution. Both services received the same patched digest; revoking the receiver denied its artifact routes while the producer remained authorized. No successful scan, validation or Cyber records were seeded for this path.

The current [acceptance report](lifecycle-acceptance-2026-10-22.md) records exact digests, evidence identities, regression counts, final image build and remaining limitations. This is readiness for controlled disconnected deployment testing, not blanket production certification. General attestation orchestration, multi-platform/key rotation, realistic concurrent load, full-corpus recovery and hard-host-failure cleanup remain outstanding. Historical synthetic Docker/Helm gateway tests above must not be presented as real upstream lifecycle evidence.
