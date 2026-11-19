# Diagnostics and troubleshooting

CATS exposes structured failures in operation notifications, retained job results, validation and remediation reports, and the administrative **Diagnostics Center** at `/admin/diagnostics`. The center uses the existing database and local frontend assets; it needs no external logging service or Internet connection.

## Investigate a failure

1. Expand **View error details** on the failed operation or job. Review the summary, observed cause, component, operation, failed stage, affected resource, timestamp, and recommended resolution.
2. Use **Copy sanitized report** to obtain a JSON report. The browser offers a selectable report when clipboard access is unavailable.
3. Administrators can open the Diagnostics Center, search an error code, error ID, or correlation ID, and filter by component, service ID, job ID, severity, or time. Related failures share the correlation ID. Recurring failures are grouped by code and component.
4. Inspect an event for sanitized exception types, messages and source frames where an exception was captured. Resource links retain normal authorization checks. Export downloads the currently displayed page of results; use filters and pagination for additional records.

For example, ingesting an existing service with no owning group returns HTTP 409 with `CAT-SVC-OWNERSHIP-001`, cause **Service has no owning group**, and the resolution to assign exactly one owning group in Edit service and retry. Multiple owning groups produce a distinct observed cause under the same code. The original HTTP detail remains available to older API clients.

Unknown failures leave their cause undetermined. Technical evidence is preserved for administrators instead of inventing an infrastructure explanation. A source filename/line is supplied only when a traceback exists; status-only failures cannot supply one.

## Access and redaction

The center and its APIs require both global `audit.view` and global `config.manage`. Scoped permissions, or either permission alone, do not grant access. Navigation follows the same rule. Diagnostic access does not grant service, job, approval, registry, or mutation permissions.

Ordinary operation responses and scoped job views contain a public projection: summary, known cause and resolution, identifiers, timestamps, and an allowlist of processing metadata. Technical exception chains and administrative policy context are available through the center. Authentication, forbidden and missing-resource responses must not confirm protected resource metadata.

Reports redact credential fields, authorization headers, cookies, tokens, private keys, URL user information and URL query parameters. SQL statement parameters, request bodies, validation input values, local variables, and environment dumps are not diagnostic evidence. OIDC failures use controlled stage/reason values rather than provider responses or token claims. Source frames contain filename, line and function, without source code or locals. Security audit records remain separate.

Reports are bounded to six nesting levels, 128 nodes, 40 mapping entries, 30 list entries and about 4 KiB per string. Oversized evidence is truncated. Redaction is defense in depth: integrations must never deliberately place credentials or raw authentication responses in diagnostics.

## Storage, retention and recovery

| Setting | Default | Bounds / behavior |
| --- | --- | --- |
| `CATS_DIAGNOSTIC_RETENTION_DAYS` | `30` | 1–365 days; queries immediately exclude older events |
| `CATS_DIAGNOSTIC_MAX_EVENTS` | `20000` | 100–200000 rows; bounded cleanup removes older excess records |
| `CATS_JOB_MAX_RUNTIME_SECONDS` | unset / disabled | Optional durable-worker runtime ceiling; existing tool-specific timeouts still apply |

Set retention consistently on the portal and database-connected workers. Each reporting process uses one lazily started thread and a queue limited to 128 events. Reporting uses a separate short transaction. Queue saturation or database failure does not change the operation's outcome. Cleanup removes at most 1,000 expired and 1,000 excess rows per pass; idle reporters also run cleanup approximately every minute. Lowering a large retention limit therefore converges in batches.

Central history is best effort. A process can exit before its queue drains; a full queue or unavailable database can lose an event. Durable job records retain their diagnostic alongside their failure state independently of this queue. Normal job/artifact retention settings continue to apply. An in-memory SQLite development database reports synchronously because it shares one connection; production databases use the queue.

Worker exceptions, tool failures, timeouts, and expired leases produce terminal or retry states with diagnostics. Retried work preserves attempt evidence in the center. Crash recovery requires the applicable coordinator/worker to run again. A live worker stuck inside an unbounded third-party operation additionally requires a configured timeout or the optional runtime ceiling. Review partial publication and validation cleanup evidence before retrying operations with side effects.

## Upgrade

`portal/app/diagnostic_migrations.py` adds `diagnostic_events` and its indexes under the portal's existing startup migration transaction/lock. It is repeatable and repairs missing indexes. Existing evidence, audit, authorization, and job tables are preserved; job diagnostics use existing JSON fields. Take the normal database backup and start the upgraded portal before upgraded workers. Rebuild frontend assets when running directly from a checkout; image builds already do this.

Indexes cover identity, correlation, time, service, job, component/time, severity/time and code/time. Queries and export pages are bounded to 200 records. Search scans only the retained, capped history and does not inspect container log files.

## Classification and OCI pulls

| Code | Observed condition | Primary action |
| --- | --- | --- |
| `CAT-SVC-OWNERSHIP-001` | Missing/multiple owning groups | Assign exactly one owning group |
| `CAT-REGISTRY-AUTH-001` | Registry authentication/access denied | Check credentials and repository permissions |
| `CAT-REGISTRY-TLS-001` | Certificate verification failure | Correct CA, hostname or certificate chain; keep verification enabled |
| `CAT-OCI-MISSING-001` | Manifest/blob missing | Verify reference and completed publication/replication |
| `CAT-OCI-POLICY-001` | OCI pull denied by policy | Inspect the policy decision and satisfy its approval/compliance requirements |
| `CAT-BUNDLE-INVALID-001` | Bundle validation failure | Re-export complete, valid, trusted content |
| `CAT-CHART-INVALID-001` | Invalid/unsupported chart or render failure | Correct chart, values and dependencies |
| `CAT-SCAN-CREDENTIALS-001` | Missing/invalid scan-worker credentials | Configure matching deployment credentials |
| `CAT-SCANNER-DB-001` | Trivy reports its offline vulnerability database is unavailable | Populate the worker cache using the approved connected update or offline database bundle |
| `CAT-TOOL-INPUT-001` | A supported tool explicitly reports a missing input/report file | Verify the preceding stage output, file path, and worker volume mounts |
| `CAT-STORAGE-FULL-001` | Insufficient disk capacity | Free expired output or increase capacity |
| `CAT-VALIDATOR-CONNECTION-001` | Validator connection failure | Check endpoint, readiness, mutual TLS and network |
| `CAT-SIGNATURE-001` | Signature verification failure | Check publisher trust and obtain valid signed content |
| `CAT-RELEASE-APPROVAL-001` | No applicable approved release | Complete authorized approval/publication and replication |
| `CAT-WORKER-LOST-001` | Worker stopped or lease expired | Restore worker and inspect partial results before retry |
| `CAT-REPLICA-SYNC-001` | Incomplete synchronization | Inspect per-release evidence and registry health |
| `CAT-TIMEOUT-001` | Timeout/deadline exceeded | Inspect stage, latency and capacity |
| `CAT-CONNECTION-001` | Dependency/DNS/network failure | Restore endpoint connectivity |
| `CAT-DATABASE-001` | Database connection/operation failure | Check health, connectivity and connection limits |
| `CAT-UNKNOWN-001` | Unclassified failure | Use preserved evidence; cause is undetermined |

Existing worker protocol codes remain compatible. Authorization, validation and missing-resource failures also have stable `CAT-AUTH-001`, `CAT-VALIDATION-001` and `CAT-NOT-FOUND-001` fallbacks. Classification uses observed messages/types and explicit component decisions, without changing business policy.

For both approved-release enforcement and service-compliance enforcement, OCI administrative events preserve the requested repository/reference, parsed service identity, artifact digest/tag, matched service, mode, evaluation and signature state when evaluated, decision and denial reason. Unevaluated signatures are not represented as verified. Public responses retain the OCI distribution envelope and opaque references; they do not disclose approval internals, credentials or protected services. Locate the event using the response's correlation/error reference.

## Developer contract and boundaries

Use `build_diagnostic()` for a portable schema, `capture_failure()` for handled partial failures, and `public_diagnostic()` before exposing retained diagnostics outside the center. HTTP middleware handles correlation, exception envelopes and legacy JSON errors centrally. Durable workers attach diagnostics when finishing/recovering work; isolated scan and patch workers use their existing authenticated protocols. Do not import database code into isolated scanner processes.

Schema fields are `schema_version`, `error_id`, `correlation_id`, `timestamp`, `component`, `operation`, `code`, `category`, `severity`, `status`, `summary`, nullable `cause`, `resolution`, `resource`, `retryable`, `context`, and administrative `technical`. Worker context can include worker/task identity, failed/last successful stage, attempts, tool/exit code and timeout. Missing evidence is omitted rather than fabricated. Preserve normal exception flow and business outcomes when reporting fails.

Host outages, database outages, failed startup before handlers initialize, or a container killed before recording evidence may still require infrastructure health checks and restricted host logs. This history complements security audit; it is not a complete log aggregation platform. See the [audit and verification record](diagnostics-audit.md).
