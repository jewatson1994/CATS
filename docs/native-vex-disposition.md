# Native VEX effective disposition

CATS can automatically exclude a currently verified **Not Affected** observation from actionable vulnerability calculations. The global control is **disabled by default**, including upgrades. Original scanner findings, severities, observations and historical decisions remain available. This is an effective disposition over retained evidence, not a scanner rewrite or a Cyber approval.

## Architecture and lifecycle

`native_vex.py` is the shared decision boundary. Its SQL predicates, `observation_excluded` and `finding_excluded`, require a current published evaluation and the enabled global policy. Consumers must not interpret a stored exclusion boolean alone.

Additive tables retain the singleton policy/version, service generation and current-evaluation pointer, evaluation provenance, per-observation evidence and per-finding aggregates. The existing durable `risk-worker` evaluates services in the background using the installed local intelligence corpus. A scan does not depend on successful queue admission. Maintenance discovers missing service state, queues stale work and retries later when queue admission is unavailable. It admits up to 50 pending services per pass, discovers up to 100 missing states, avoids active duplicate jobs and backs off recently failed/cancelled work for one hour.

An evaluation uses the latest execution and requires a completed scan no more than 30 days old, with no future timestamp. It processes observations in batches of 250, with a 100,000-observation ceiling. Exceeding the ceiling fails the evaluation without publishing partial exclusions. It retains package/version/image/digest, original severity, matched evidence and provenance. The validity horizon is the earliest of 24 hours after evaluation, scan expiry and supporting exclusion-evidence expiry. An invalid scan produces no exclusions and a short retry horizon.

Before publication, the evaluator checks the captured policy version, global generation, service generation and latest execution again under locks. Changed inputs prevent publication of the obsolete result. Publication moves the service pointer atomically and invalidates posture caches. Background computation can continue while the control is disabled, supporting preview without changing current enforcement.

## Strict applicability rules

An exclusion requires trusted, fresh, applicable VEX that resolves to Not Affected, with accepted evidence for every CVE identity in the lookup. Accepted identity paths are an exact observed identity or a verified authoritative package relationship. Evidence with conflict, uncertainty, stale validity or evaluation limits cannot authorize exclusion.

Package name similarity, a CVE-only match, a versionless identity or an unverified source-package mapping is insufficient. Package version, ecosystem, namespace, distribution and applicable qualifiers must agree. Red Hat and SUSE additionally require the complete publisher-scoped CSAF containing-product context; the scanner's distribution alone does not establish an enterprise product, module or edition. Advisory recommendations, EPSS and KEV do not establish Not Affected.

A finding is fully excluded only when it has current observations and **every current observation** is excluded. A CVE affecting one package or image remains actionable even when another observation of that CVE is Not Affected. Missing, expired, ambiguous or failed evaluation is conservative: existing policy continues to apply.

See [identity resolution](authoritative-package-identity-resolution.md) and [VEX ingestion](vex-ingestion.md) for the underlying evidence and identity rules.

## Precedence and invalidation

The effective display precedence is resolved/inactive, active human exception, current enabled VEX exclusion, then the existing actionable policy. Native VEX does not revoke an exception, resolve a scanner finding, close a POAM, grant Cyber approval or alter an immutable approval snapshot.

PostgreSQL and SQLite generation triggers cover inserts, updates and deletes, including bulk writes. Finding, observation and execution changes invalidate their service; source trust, VEX documents, installed intelligence-package state and relevant portal settings invalidate the global generation. Authorization revision and posture-epoch bookkeeping are excluded from global invalidation. Resolver/algorithm changes are detected by the algorithm identifier. Expiry is checked at query time. Policy changes carry an optimistic version and invalidate consumers immediately.

Readers require matching generations, policy version, algorithm, service publication pointer and validity dates. Thus an old materialized Not Affected result cannot keep suppressing work while reevaluation is pending. Disabling the control immediately restores existing-policy treatment without deleting evidence. Numeric risk assessments remain historical computations: a changed native token marks them stale; automatic native evaluation does not itself promise a new numeric risk assessment.

## Operator controls and navigation

Use **Administration → General Policy** for the automatic VEX exclusion control and intelligence source/trust settings. Policy reads/writes and preview require `config.manage`; updates require authenticated authorization, CSRF protection and an exact current policy version. Changes record the authenticated actor, old/new values and policy version in the audit log. Concurrent edits return a conflict.

The UI requires a preview for the current policy version before enabling. The API enforces permission and version checks; it does not require proof that an operator opened the preview. Preview reads completed, current evidence with the enabled flag ignored and paginates 50 services at a time. It compares eligible/noncompliant counts and projects overall compliance before and after exclusion using canonical vulnerability checks together with the overview policy and evidence checks (`policy_noncompliant` and `evidence_noncompliant`). These `compliance_before`/`compliance_after` projections remain subject to current evidence; VEX does not bypass other compliance checks.

Services, finding detail and Raw Findings expose technical evidence and a separate **VEX Excluded** view. Evidence is fetched on demand with 100-observation pages and includes validity/provenance. Administration → Risk Policy contains group-scoped Risk Profiles and assessment review; Cyber review surfaces expose VEX evidence without substituting it for the human decision. Risk Intelligence is no longer a separate top-level navigation destination.

## Downstream behavior

- Classification and service posture use the shared current-evaluation predicates and generation/expiry-aware cache invalidation. Fully excluded findings leave actionable counts; mixed findings remain.
- Prospective remediation and patch selection use the same observation decisions. Exact payload identities are required before removing an image vulnerability entry; unmapped or ambiguous payload entries are retained. An image is removed only when all persisted observations are excluded and all payload identities are accounted for. An empty filtered list must not become an image-wide patch request.
- New retained remediation plans bind the native decision token. Confirmation and worker checks reject changed decisions. Existing jobs and historical artifacts are preserved.
- New vulnerability POAM creation checks current disposition. Existing POAM records retain status and remain visible, with an explicit review indicator when current VEX changes their relevance.
- Raw exports retain original rows and add effective disposition. POAM exports retain records with disposition/review columns. Asset exports distinguish VEX-excluded and retained observations. Existing saved custom column selections remain respected.
- When enabled, risk calculations use the materialized native decision for actionable totals and worst actionable observations; evidence details remain retained. An independent informational Not Affected lookup cannot discount an observation that lacks a current native exclusion. With the control disabled, legacy risk behavior remains.

## Deployment and offline operation

Upgrade the portal and workers together against the same persistent database and installed intelligence corpus, after the normal database backup. Schema/trigger installation is additive and idempotent; it does not rebuild the bundled corpus or enable the control. Both Compose definitions include the existing `risk-worker` running `python -m app.risk_worker`. Direct development must run that process as well as the web application. Build frontend assets for direct Python deployments.

No live vendor lookup or separate external service is needed for native evaluation offline. The worker, database and locally imported signed intelligence snapshot must be available. Without worker progress, absent or expired evidence remains conservative rather than authorizing exclusions. Check worker failures and pending/current evidence status before enabling. Validate disable/enable, a trust change, a rescan, expiry and a mixed-observation case in deployment acceptance.

## Evidence and performance limits

The rebuilt release image with SHA-256 digest `26b9838c8b9e79cf67547fb1ab48b3f5abbbecdc897c41a82bbc61e346233435` passed both offline verification checks. The frontend suite passed 346 tests and scanner checks passed 34 tests. These checks establish the tested release behavior, not production acceptance or genuine positive vendor applicability; 870 backend/PostgreSQL/offline tests passed, with 23 latest API/boundary tests and 8 final remediation workflow tests also passing (overlapping suites).

The [controlled PostgreSQL benchmark](evidence/native-vex/controlled-benchmark.json), recorded on 2026-10-20, measured:

| Findings / observations / images | Evaluation | SQL queries | Classification read | Result |
| --- | ---: | ---: | ---: | --- |
| 1,000 / 1,000 / 1 | 0.348 s | 30 | 0.0045 s | 1,000 fully excluded |
| 10,000 / 10,000 / 1 | 3.812 s | 174 | 0.0201 s | 10,000 fully excluded |
| 1,000 / 10,000 / 10 | 1.672 s | 214 | 0.0027 s | 5,000 excluded observations; 1,000 mixed findings retained |

The benchmark also confirmed conservative classification immediately after evidence mutation and measured disable/enable reads. These are single-run controlled fixtures, with asynchronous posture refresh disabled to isolate evaluator cost. They establish neither production latency nor performance against the full 29.2-million-statement corpus; they provide no statistical confidence interval.

The earlier [real-container audit](container-vex-applicability-audit.md) contained **483 unique findings and 1,118 observations, with zero applicable VEX results**. Although 482 of 483 CVEs/aliases appeared somewhere in the corpus, none passed the exact CVE/package-identity candidate gate. That audit demonstrates the real applicability gap, not a real positive exclusion. Controlled positive fixtures demonstrate behavior; a genuine publisher-backed positive case remains unproven in that audit. Missing identity or containing-product evidence must be improved through authoritative provenance, never relaxed matching.

Supported generation-trigger databases are PostgreSQL and SQLite. Evaluation bounds, pending worker work, unresolved package/product identity and historical saved export selections remain practical limitations. Existing POAMs and Cyber approvals require human review; native VEX does not automatically reconcile those historical decisions.
