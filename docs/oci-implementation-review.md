# OCI distribution implementation review and independent proof plan

## Review status and scope

This review describes the implementation on `feature/oci-compliance-proxy`. It is not a production certification. Final integration results below distinguish automated coverage, real local registry and signer checks, and acceptance work still requiring the deployment environment. Use the commit containing this document as the review revision.

Operational references: [proxy deployment and rollback](oci-proxy.md), [machine evidence retrieval](oci-evidence.md), and [Harbor integration testing](oci-harbor-testing.md) and [acceptance checklist](oci-proxy.md#harbor-acceptance-checklist).

The intended boundary is a read-only OCI Distribution facade. Harbor retains artifacts; CATS determines whether the requesting machine may receive the exact digest under current Cyber approval and service compliance. It does not create a second vulnerability classification engine, turn a signature into a Cyber approval, or provide a general-purpose writable registry.

## Delivered architecture

| Area | Implementation | Review expectation |
| --- | --- | --- |
| Distribution endpoint | `portal/app/oci_proxy.py` | Separate FastAPI process; machine authentication; manifest, blob, HEAD/range and supported referrer delivery; current authorization before response |
| Digest authorization | `portal/app/oci_authorization.py` | Current complete execution, frozen evidence integrity, exact upstream/repository/digest, current valid Cyber approval, canonical service policy and scoped exceptions |
| HTTPS transport and cache | `portal/app/oci_transport.py` | Origin restrictions, scoped registry token negotiation, bounded downloads, SHA-256 verification, atomic cache writes, interprocess writer lock and quota |
| Signature association | `portal/app/oci_signatures.py` | Supported simple-signing payloads bound to the authorized subject; bounded verified configuration limited to inert supported metadata |
| Configuration | `portal/app/oci_admin.py`, `portal/frontend/src/features/oci_distribution.tsx` | Existing release-destination admin permission and CSRF protection; upstreams, mappings, expiring scoped machine accounts, suspension, rotation and connection tests |
| Evidence | `portal/app/oci_evidence.py` | Existing verified published offline bundle selected by the live authorization decision; checksum/path checks; no substitute signature generated |
| Lifecycle | `portal/app/oci_lifecycle.py` and existing durable worker integration | Digest-pinned image reassessment, durable state, fresh pending renewal requiring Cyber decision, retained public verification key history |
| Deployment | `compose.oci-proxy.yml` | Optional service and persistent cache, shared existing database/encryption configuration, restricted host exposure |

The existing release-destination page contains the distribution controls. Upstream connection testing checks authenticated retrieval and manifest integrity for a selected tag or digest; success does not approve distribution. The configuration overview reports configured availability and active machine identities. It is not proof that an external client can reach the deployed endpoint. Runtime health and reverse-proxy/client connectivity need separate checks.

## Additive data and configuration

New tables retain upstream configuration (`oci_upstreams`), service repository mappings (`oci_repositories`), scoped machine identities (`oci_principals`), small raw manifests (`oci_manifests`), digest graph links (`oci_object_links`), and tag metadata (`oci_tags`). Lifecycle tables are `oci_reassessment_schedules`, `oci_reassessment_events`, and `approval_public_keys`. Existing approval, scan, service, audit and durable job records remain authoritative. Blob bytes are disk content, not database payloads. The independent review must confirm additive initialization against a copy of an existing database and preservation of its preexisting records.

Upstream credentials are encrypted with the existing `CATS_CONFIG_ENCRYPTION_KEY`. Machine passwords are randomly generated, displayed only when created or rotated, and retained as SHA-256 hashes; they require expiry and explicit repository grants. The public repository name includes a project namespace and maps to one service and one upstream repository. Optional `max_scan_age_days` and `max_approval_age_days` only tighten existing validity. They do not grant a temporary exception to Cyber approval.

| Setting | Deployment purpose |
| --- | --- |
| Existing database connection settings | Share canonical policy, approvals, identities and durable lifecycle state |
| `CATS_CONFIG_ENCRYPTION_KEY` | Decrypt existing encrypted upstream configuration; must match portal |
| `CATS_OCI_CACHE_DIR` | Persistent verified content directory |
| `CATS_OCI_CACHE_MAX_BYTES` | Total blob cache quota; default 10 GiB |
| `CATS_OCI_MAX_BLOB_BYTES` | Individual blob limit; default 4 GiB |
| `CATS_OCI_PORT` | Loopback published proxy port; default 5000 |
| `CATS_APPROVED_RELEASE_ROOT` | Consistent location of retained published evidence; proxy needs read-only access |

Use trusted HTTPS termination for clients and verified HTTPS to upstreams. Private CAs and delegated token/redirect origins are explicitly configured. Cross-origin redirects strip authorization. Token allowlists are sensitive because approved token services receive upstream credentials. Do not expose the loopback HTTP service directly to untrusted networks.

## Security review conclusions and limits

The authorization boundary is digest-specific and service-scoped. Mutable tags are resolved before approval evaluation; knowing a blob digest is insufficient without its authorized graph association. Multi-platform indexes require approved exposed children. Cache hits do not preserve expired or revoked authority. State is checked again after potentially slow content retrieval. Revocation affects subsequent checks; it cannot retract bytes already delivered or establish revocation status inside an isolated environment.

The narrow code review identified an unchecked signature configuration descriptor that could have exposed unrelated blob content. The fix fetches configuration with a size bound, verifies hash and declared size, rejects external URLs, and permits only supported empty or inert image configuration. Unknown fields, executable image configuration and duplicate JSON keys are rejected. Regression cases cover those failures. This is deliberately conservative: unusual signature configuration formats may require a reviewed extension.

Subject pointers alone do not authorize arbitrary referrers. Only the supported subject-bound simple-signing format is eligible. Subject binding and byte integrity are distinct from signer authenticity: clients must verify against independently trusted keys or identity policy. Existing published Cyber evidence is retrieved separately. The generic artifact-association path was removed during integration; regression coverage must continue to reject arbitrary subject-linked content.

Operational constraints requiring explicit acceptance:

- Cache quota covers blob bytes, not PostgreSQL manifest, graph, event or audit growth. Define database retention and monitoring before production.
- Cache eviction can force refetching. The service is not offline registry replication; upstream access remains necessary for fresh mutable tag resolution and uncached objects.
- Reassessment scheduling supports registry-backed digest-pinned image-only snapshots. Charts, archives and mixed releases require the existing full assessment workflow.
- Completed scans can create a pending renewal; only the existing Cyber decision grants validity. Failed, incomplete or competing evidence must not silently extend a release.
- Public-key retention starts with this feature. Preserve older keys needed for historical bundles before rotating them away.
- The evidence bundle may contain the approved service's full evidence, not just the requested image. Repository credential scope must match the consumer's entitlement to that evidence.
- The facade supports a bounded OCI subset. Unsupported signature/artifact forms and registry-specific APIs require separate approved workflows.
- Cache eviction/open races should fail closed and may require a retry. Test platform-specific filesystem behavior and sustained concurrent pulls on the deployment filesystem.

## Automated evidence available

Component validation during implementation included 26 authorization/admin backend tests, TypeScript typechecking, and 17 frontend checks spanning the new machine-account workflow and existing approval UI. The subsequent signature hardening run passed 22 signature/proxy tests. These counts refer to specific component runs, not a final combined suite or a final immutable revision. The integrating reviewer must append the exact revision, commands, environment and final results below.

Coverage includes exact identity isolation, current evidence and approval validity, canonical exception/deadline behavior, encrypted configuration and CSRF/RBAC, scoped expiring machine credentials, one-time password presentation, connection diagnostics, subject/config integrity, and existing proxy regressions. Fixtures and synthetic transport responses cannot establish real registry, signer or offline deployment compatibility.

## Five-day independent proof plan

Use a reviewer who did not implement the authorization logic, a staging Harbor instance, a copy of the deployment topology, synthetic nonproduction credentials and representative image/chart artifacts. Freeze the reviewed commit and record tool/client/Harbor versions. Retain redacted requests, responses, digest inventories, audit excerpts and test reports in an evidence package outside the source tree. Any security acceptance failure blocks promotion until fixed and retested.

### Day 1 — Build, migration and access boundary

Bring up the optional service against a copied existing database with trusted HTTPS. Record additive tables and compare preexisting service/approval counts. Exercise admin role and CSRF rejection, upstream secret redaction, machine expiry, grant isolation, rotation and disabled mappings. Verify process readiness, persistent volumes, read-only evidence mount and absence of privileged/socket access.

Acceptance evidence: reproducible build/revision identifiers; sanitized deployment configuration; database before/after checks; HTTP status matrix for permitted and forbidden requests; confirmation that logs and responses contain no upstream or machine secrets. A healthy process alone does not pass registry connectivity.

### Day 2 — Real Harbor content and immutable identity

Using read-only Harbor robot credentials, pull an approved image by tag and digest with Docker or equivalent. Compare raw manifest digest and every delivered blob digest with Harbor. Repeat using Helm and a multi-platform image whose children have explicit evidence. Exercise HEAD, ranges, warm cache and mutable tag reassignment. Test private CA failure, unapproved token realm, redirect restrictions and an unrelated known blob digest.

Acceptance evidence: client transcripts, digest comparison inventory, cache-hit behavior and negative request results. Any differing bytes, unapproved child access, credential forwarding to an unapproved origin or approval inherited across a moved tag fails the day.

### Day 3 — Compliance changes, revocation and concurrency

Populate the cache, then revoke Cyber approval, expire or rotate machine credentials, suspend a mapping, introduce overdue findings, invalidate current scan evidence and remove a scoped exception. Verify subsequent GET and HEAD denials. Confirm an exception on another service does not authorize this service. Race revocation against delayed upstream retrieval. Exercise simultaneous pulls, eviction, corrupted cached bytes, interrupted downloads and process restart.

Acceptance evidence: timestamped policy/audit changes correlated with response outcomes; bounded cache measurements; no partial/corrupted bytes served; explicit handling of allowed in-flight responses versus checks completed after revocation. Repeat on the intended production filesystem and database isolation configuration.

### Day 4 — Signing, evidence and lifecycle

Publish through the existing real signing workflow with a test key. Retrieve evidence through machine scope and independently verify checksum, signature and trusted fingerprint. Verify supported upstream signatures with the actual consumer tool. Try wrong-subject signatures, arbitrary config content, tampered bundles and revoked evidence retrieval. Rotate the signing key and verify old and new retained artifacts against trusted key history. Run scheduled reassessment through the actual scanner, including failure, worker restart and lost scan receipt; verify only fresh successful evidence leads to a pending Cyber review.

Acceptance evidence: independently executed verification logs, fingerprints established outside downloaded material, tamper denials, lifecycle event history, immutable prior approval snapshot and proof that renewal requires a Cyber decision. Fixture signatures and mocked scanner completion do not satisfy this day.

### Day 5 — Isolated consumption and operational handoff

Transfer a verified published offline bundle using the approved process to an actually isolated test environment. Verify authenticity and deploy the representative supported workload using the documented bundle procedure. Record exactly which artifacts/tools were available before isolation. Separately demonstrate that offline verification cannot determine current revocation and document the deployment organization's permitted offline validity process. Test proxy restart, evidence/cache persistence, upstream/database outages, alerting and rollback of only the optional service.

Acceptance evidence: independent offline verification and deployment logs, no unexpected network dependency, recovery measurements, operator runbook and rollback transcript preserving portal/database data. Conclude with a signed acceptance matrix listing supported client/artifact versions, unresolved limits and release decision. Do not label the feature offline-deployment verified until this test is performed successfully.

## Final integration verification — 2026-10-19

Windows host Python 3.12, Docker Desktop Linux containers, and the existing frontend dependency installation were used. All changes remain isolated to the feature branch; no push or merge was performed.

- Combined backend regression: **301 passed, 1 skipped** in 41.25 seconds. The suite covered the six `portal/tests/test_oci_*.py` modules, Cyber approvals/evidence/publication/worker, release signing/OCI/validity, service OCI, and both root transport/signature test modules. Run with `PYTHONPATH=portal`, `pytest -q --tb=short -rs -p no:cacheprovider`, and a fresh `--basetemp` under `.test-temp`.
- Frontend: TypeScript `tsc --noEmit` passed; the OCI distribution and Cyber approval Vitest files passed **19 tests**; Vite production build passed.
- Merged base Compose plus `compose.oci-proxy.yml` configuration validated. A disposable proxy process in the existing CATS image returned readiness 200 and unauthenticated registry challenge 401. A full new production image/stack deployment remains unverified.
- Real Harbor 2.15.4: trusted TLS, Bearer authentication, private access, exact tag/digest manifest bytes, blob integrity and anonymous rejection passed. The actual proxy plus real Harbor passed manifest/HEAD/range/referrer requests and denied revoked approvals, including cached blobs. This proxy fixture uses synthetic completed-scan and approval records; it does not exercise the real scanner or human Cyber decision.
- Independent Distribution 2.8.3: real TLS, Basic authentication, tag/digest/blob integrity and negative authentication/CA checks passed. See [registry validation](oci-registry-validation.md).
- The host skipped one Cosign executable test because Cosign is absent there. Separately, `tests/smoke_offline_signing.py` passed with the existing real CATS signer and Cosign inside a network-disabled container: encrypted key handling, signing, offline verification and tamper rejection. Full registry publication and consumer signature verification remain acceptance work.
- Harbor's ten-image offline archive was exported; regeneration and restart with pulls forbidden passed. Harbor remains running at `https://localhost:18443`. Clean disconnected-machine restoration has not been tested.

Reproducible helpers and commands are in [Harbor testing](oci-harbor-testing.md) and [registry validation](oci-registry-validation.md). Local result JSON, generated credentials, certificates, data and the offline archive reside under ignored `.test-temp`; they are not source artifacts. Never include the credentials in a review evidence package.

Still unverified: actual Docker/Helm client pulls, representative multi-platform artifacts, full scanner-to-human-approval renewal, real registry publication/consumer signature verification, copied PostgreSQL migration and sustained load/restart behavior, and isolated workload deployment. The five-day proof plan above is the acceptance procedure for those checks; implementation and passing fixtures do not substitute for it.
