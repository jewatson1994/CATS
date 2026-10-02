# Service remediation candidates

Automated and Guided remediation share a source-bound planner and executor. Requests bind to the service, execution, version, and plan hash. Ingested source remains unchanged. New remediation creates a new R-number; delivery retry reuses retained content and the same R-number.

## Decisions and partial outcomes

Automated accepts deterministic safe changes; Guided lets the operator review them. Decision-required changes need explicit acceptance, skip, or customization. Ambiguous source mappings remain unresolved; CATS never guesses Helm values keys. Unknown rules require manual work.

Candidates retain editable source, image archives, decisions, before/after changes, and post-scan evidence. Partial remediation preserves successful work and unresolved findings. A successful change does not imply every vulnerability was fixed.

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
