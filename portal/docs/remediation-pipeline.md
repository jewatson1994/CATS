# Service remediation candidates

Automated and Guided remediation share a source-bound planner and executor. Requests bind to the service, execution, version, and plan hash. Ingested source remains unchanged. New remediation creates a new R-number; delivery retry reuses retained content and the same R-number.

## Decisions and partial outcomes

Automated accepts deterministic safe changes; Guided lets the operator review them. Decision-required changes need explicit acceptance, skip, or customization. Ambiguous source mappings remain unresolved; CATS never guesses Helm values keys. Unknown rules require manual work.

Candidates retain editable source, image archives, decisions, before/after changes, and post-scan evidence. Partial remediation preserves successful work and unresolved findings. A successful change does not imply every vulnerability was fixed.

## Source secret review

Planning inspects retained source content, not sensitive-looking filenames. Empty values, documented placeholders (such as `replace-me`), simple Helm value references, external Secret references, and environment references do not block a plan. Literal credential values, Secret data, private keys, and unresolved Secret templates require review. Diagnostics expose only the affected chart, file, field path, a fixed reason, and resolution guidance; credential values and parser excerpts are never included.

Affected charts remain visible as blocked opportunities. Safe charts and independent image patching remain available. Confirmation requires an explicit choice to exclude each affected whole root chart, including its dependencies. CATS does not silently remove a required file. The original assessment evidence remains unchanged. Replace literal credentials with external references and reassess to restore a full candidate, or approve a partial candidate with those charts excluded. `source-safety.json`, the approved plan, and the remediation summary retain the exclusion scope; partial remediation is not a complete service release.

The same inspection applies to candidate generation, validation inputs and rendered manifests, retained downloads, acquired chart dependencies, and packaged OCI charts before publication. Uninspectable or malformed source archives fail safely. This is a conservative content check, not a guarantee that arbitrary application-specific data cannot contain a secret; it has no bypass setting. A newly rendered literal secret remains blocked even if the original template only contained references.

The candidate source inspection budget is 64 MiB of deployment source, rendered manifests, referenced values, and packaged charts. Scan reports and SBOM evidence do not consume this source budget. Source and nested-chart inspection limits still apply.

## Comparable vulnerability evidence

The patch worker scans both the original and materialized candidate using the same extracted-filesystem Grype target. It creates stopped containers and copies their files for these scans; extraction does not launch the application entrypoint. Full before/after reports and fixable-only reports are retained separately. The results page includes all six severity categories and total vulnerability observations.

An unchanged image can appear to gain findings if one scan uses image cataloging and the other uses filesystem cataloging. Using the same method avoids that coverage difference. Historical results retain their original evidence; retry as a new job after upgrading to obtain a comparable pair. Actual package updates, scanner/database changes, and newly discovered dependencies can still change findings. `NO_APPLICABLE_FIXES` means no OS updates were applied; patching does not automatically rebuild vulnerable Python, Go, or other application dependencies.

## OCI delivery

Service destinations use encrypted credentials and scoped CA trust. Eligible saved global destinations remain available. Management requires service editing permission; delivery requires remediation permission. Connection tests establish connectivity/authentication, not push permissions.

Delivery checks archive integrity, publishes images, obtains registry manifest digests, and rewrites exact supported image mappings. Complete split registry/repository/tag/digest values are supported. Helm rendering must contain the rewritten immutable identities before chart publication. Unsupported mappings fail safely.

Configured signing applies to immutable published identities. Signature failure is separate from publication. Destination-specific delivery content does not mutate the original R candidate. Failed delivery can be retried while retained content exists. Some registry artifacts may remain after a later step fails; CATS does not delete them automatically.

## CATSchrödinger’s verification

Static checks, publication, signatures, and runtime verification have separate statuses. Missing tools are not passes. Optional remote validation checks the assembled delivery and binds results to its immutable digest. Primary CATS never runs candidate workloads. Download-only candidates do not imply runtime verification.

## Promotion lineage

Re-ingestion matches immutable artifact identities within the same service. Provenance includes source version, remediation R-number, and separate scan, runtime, and signature evidence. Matching an artifact does not prove promotion of an entire release. Newly ingested evidence remains authoritative.

## Retention

Defaults: terminal candidates 30 days, published content 7 days, retained storage 20 GiB. Configure CATS_REMEDIATION_RETENTION_DAYS, CATS_REMEDIATION_PUBLISHED_RETENTION_DAYS, and CATS_REMEDIATION_RETENTION_MAX_BYTES. Published retention cannot exceed general retention.

Cleanup runs at admission and worker completion, not on an independent timer. Active remediation and queued/running delivery or verification are protected. Expired terminal content is removed first; quota pressure can remove other terminal content. History and digests remain, but removed content cannot be downloaded or retried. Unknown content consumes quota without being automatically deleted. Unsafe or unmeasurable content blocks admission. Cleanup is audited.

## Source integration and operations

Integrations should supply editable helm_source_files and artifact type. Exact _cats_source_mappings identify field_path, template, values_file, values_key, and ambiguous: false. Template-only mappings remain ambiguous.

Backend/frontend tests do not establish live registry, CA, signing, or remote sandbox capabilities. Verify these in the deployment environment. Isolate the validator network from production and use the authenticated bounded result protocol.
