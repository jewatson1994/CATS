# Authoritative package identity audit evidence

This audit covers all 483 distinct finding roots and 1,118 package observations in the seven retained image scans. It uses the existing 29,212,947-statement package, without refreshing or rebuilding the corpus. Evaluation is fixed to `2026-10-20T05:40:57.930104+00:00`, matching the immutable earlier audit.

The resolver establishes 595 derived package identities across 319 observations and 119 finding roots. The real inputs still yield **zero direct or resolved VEX candidates and zero applicable VEX statements**. A shared CVE, a matching source name, or an advisory reference is not evidence of applicability. Controlled positive cases are recorded separately and are not discovered vendor matches.

## Files and provenance

- `before-root-cause.json` and `after-root-cause.json`: all root classifications, exclusive and overlapping counts, source identities, input hashes, and bounded diagnostic query plans. The `before` diagnostic was captured with an earlier version of this harness; its observation content is byte-identical to `after-observations.json`. Stage labels do not turn diagnostic near matches into production applicability.
- `before-observations.json` and `after-observations.json`: all 1,118 observation classifications, retained source-package fields, exact scanner identity, and representative named vendor statements with statement IDs and containing-product context.
- `*-named-vendor-statements.json.gz`: all 43,278 rows retrieved by the bounded exact-name diagnostic, including statement IDs, document IDs, versions, qualifiers, and product context. These are diagnostic candidates, not accepted VEX relationships.
- `after-evaluation.json`: production coverage and per-image results, installed package counts, exact raw join statistics, code hashes, baseline comparison, and full SQL/EXPLAIN plans.
- `after-evaluation-details.json.gz`: every observation's production identity resolution, candidates, provenance, status, and full applicable/rejected statement result.
- `after-benchmarks.json`: real retained workload timings, SQL counts, CPU, sampled process RSS, concurrent jobs, hashes, and measurement limitations.
- `controlled-positive-benchmark.json` and `controlled-positive-query-plans.json.gz`: explicitly synthetic positive, conflict, high-fanout, and cap-overflow cases in a private transactional schema. `schema_removed: true` confirms rollback removed that schema.
- `query-plan-comparison.json`: compact before/after index, LIMIT, buffer, and timing evidence, linked by file and SQL hashes to the full plans.
- `vendor-document-examples.json` and `vendor-document-*.json.gz`: 305 statements and three actual stored vendor documents. Raw content hashes are checked against the corpus. The SUSE document is a product-shape example, not a finding in these seven scans.
- `audit-validation.json`: final artifact/hash/count checks, runtime image identity, database isolation, and source hash confirmation.
- `verification/`: independent integration and test evidence maintained by the main task.

The immutable baseline is `../container-vex-scans/coverage-and-benchmark.json` (SHA-256 `89fc430c721704846eda25ba66e8a95421deaa7b834c73b47c34e60ee8c4ae3a`). Its original capture projections and evaluator remain unchanged. The manifest SHA-256 is `65122aca701681f6bb5b920a0b11bab977ab700a4c24a2fa9ef66e90a83fd42f`.

All 35 retained raw files are hash-checked against that manifest before evaluation. All 1,118 observations join to exactly one raw Syft artifact by artifact ID plus exact name/version/type/PURL, and to the exact Grype finding/artifact tuple. The harness reproduces the scanner's bounded metadata projection; it does not promote arbitrary inferred source fields into authority or retain unrestricted raw metadata. All 868 installed deb/RPM observations have database provenance in the raw artifact that the older projection omitted. No timestamp or containing-product identity is invented.

## Root-cause accounting

Exclusive observation categories total 1,118; exclusive finding categories total 483. A finding root receives the most-specific verified barrier among its observations, using the explicit ordered rule in the report. This prevents one unsupported observation from hiding a more specific barrier on another image. The separate multi-cause table unions all flags across observations; those percentages overlap and must not be added.

| Exclusive barrier | Observations | Findings |
| --- | ---: | ---: |
| CVE absent from corpus | 1 (0.0894%) | 1 (0.2070%) |
| Vendor or ecosystem not covered | 497 (44.4544%) | 205 (42.4431%) |
| CVE absent from matching vendor statements | 491 (43.9177%) | 194 (40.1656%) |
| Containing-product context unverified | 58 (5.1878%) | 47 (9.7308%) |
| Package version mismatch | 71 (6.3506%) | 36 (7.4534%) |

Other exclusive categories are zero. That does not prove every architecture, distribution, or qualifier matches: earlier barriers and missing vendor candidates can prevent that comparison. Multi-cause evidence includes 76 observations / 41 roots with a version difference, 81 / 50 with source/binary identity differences, 125 / 79 with distribution-qualifier differences, and 122 / 80 with upstream-qualifier differences. These are diagnostic differences, not permission to strip qualifiers.

The 53 observations / 44 roots labelled `missing_explicit_source_package_relationship` have an explicitly empty Debian source name in installed package metadata. Debian's documented same-name default supplies the relationship; this flag must not be read as missing authoritative evidence. Similarly, 310 observations have an explicitly empty source version whose documented default is the binary version. Production outcome counts are 276 `multiple_valid_candidate_identities`, 43 `authoritatively_resolved_identity`, 250 `unsupported_ecosystem`, and 549 `no_verified_relationship` (RPM source epoch and enterprise containing-product context are not established).

The diagnostic is restricted to the observed CVEs, the corresponding vendor source, and exact binary/source package names. It uses batches of 40 CVEs, an indexed presence/count query, and an indexed named-product query with a 50,001-row sentinel; it fails rather than silently truncating above 50,000. The completed diagnostic executed 27 SQL statements in 4.796407 seconds. It never enumerates the entire corpus or treats name-only matches as applicability.

`cve_absent_from_vendor_statements` describes observed absence. Corpus-wide import exclusion counters do not prove an individual missing CVE was excluded, so the report makes no such attribution.

## Actual product forms

Canonical's stored CVE-2026-53910 document uses Ubuntu binary and source PURLs with codename distributions and literal epoch colons. The scanned diffutils version is `1:3.8-0ubuntu2`; that document's fixed versions differ. Resolving an encoding or source relationship cannot make an installed older version equal a newer fixed version.

Red Hat's stored CVE-2025-11187 document contains a versionless `pkg:rpm/redhat/openssl?arch=src` under different containing products: a not-affected RHEL 7 context and an affected JBoss Core Services context. Neither proves the scanned UBI 9 package is not affected. SUSE's stored CVE-2006-2450 example contains `pkg:rpm/suse/libvncclient0@?upstream=LibVNCServer.src.rpm` with SLES 15 SP2 context. The scanner's `sles` namespace and a source RPM name alone do not establish that product relationship.

## Runtime measurements

These are single-run, warm/unknown-cache measurements on a shared host. No CPU reservation is enforced; release builds ran concurrently and may affect latency. Real workloads include VEX, advisory, KEV, and EPSS with 250 observations per batch. Repetition creates load, not additional scanned findings. The 1,000-observation input includes six images; the complete 1,118-observation and repeated 10,000-observation inputs include all seven.

| Real workload | Seconds | SQL statements | Process CPU seconds | Sampled peak process RSS, bytes |
| --- | ---: | ---: | ---: | ---: |
| Single observation | 0.010459 | 7 | 0.007547 | 261,173,248 |
| 1,000 observations | 0.733479 | 28 | 0.415601 | 268,390,400 |
| 10,000 observations | 7.464165 | 280 | 4.080802 | 282,615,808 |
| Seven images / 1,118 observations | 1.021068 | 35 | 0.569249 | 283,430,912 |
| Four concurrent jobs of 1,000 | 3.043648 wall | 112 total | Shared process; do not sum job values | 304,885,760 |

Earlier baseline times were 0.009386 / 0.385803 / 4.348488 / 0.499515 seconds for those sequential workloads, and 1.877344 seconds for four concurrent jobs. Query counts are unchanged. These measurements show added processing time; they do not demonstrate a latency improvement. RSS includes Python and materialized diagnostic inputs from earlier phases, while the baseline used a different capture lifecycle; a before/after memory delta is not a controlled comparison. Database CPU/RSS, cold-cache latency, throughput distributions, and long-duration saturation are not measured. Process CPU and RSS overlap across concurrent jobs and must not be summed.

Both real production plan samples use the CVE and product-ID indexes, with no sequential scan of `vex_statements`. The after pair query's planning/execution time is 39.76/7.803 ms versus 11.684/3.764 ms before; it contains additional exact resolved identities. The after CVE-presence probe executes in 1.162 ms (140 indexed one-row probes) versus 1.084 ms before (144 probes). LIMIT nodes bound both retrieval paths. These are representative first-batch plans, not an exhaustive plan trace of every batch.

The controlled cases use 20,004 synthetic statements in a new random schema, in one uncommitted transaction, then roll it all back. They exercise the production VEX evaluator only, excluding advisory/KEV/EPSS. Synthetic fixture trust is not newly accepted vendor evidence.

| Controlled case | Seconds | SQL | Result |
| --- | ---: | ---: | --- |
| One resolved positive | 0.006365 | 2 | `not_affected`, one resolved applicable statement |
| 10,000 resolved positives at cap | 0.958041 | 2 | `not_affected`, all 10,000 returned |
| 10,001 candidates, cap overflow | 0.847795 | 1 | `under_investigation`, `candidate_limit`, zero returned statements |
| Direct affected plus derived not-affected | 0.003493 | 2 | `conflicting` |

The overflow plan returns only the cap-plus-one sentinel (10,001); presence is unknown rather than fabricated. A separate identity-candidate limit of one returns `insufficient_identity_evidence` with `identity_candidate_limit`, retaining only the observed exact identity. All controlled pair plans use an index and LIMIT, with no sequential VEX scan. Their small private schema does not establish large-corpus positive latency.

## Reproduction

Requirements: the existing populated database container, the retained raw directory, Docker runtime image `cats:container-vex-audit-final`, and the same worktree code. The image ID is `sha256:f17f517ec2a16a535f1f39bdac62fea4eec886a8ae4a0ed89d11fc442a96688d`; the database container's network mode is `none`. The runner joins only that network namespace, and its socket guard permits only loopback PostgreSQL. Credentials are read into process memory without printing them. The following PowerShell command writes a new temporary replay directory, preserving this evidence.

```powershell
$auditWorkspace = 'C:\Users\lil-j\.codex\worktrees\risk-profiles-vex\Cyber Hygiene'
$auditRaw = 'C:\Users\lil-j\.codex\visualizations\2026\10\19\01a1526b-954e-73b2-b46b-e7d15d435d2e\container-vex-raw-evidence'
$auditOutput = Join-Path $env:TEMP ('cats-identity-replay-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $auditOutput | Out-Null
$auditDatabase = docker inspect cats-vex-expanded-db-20261020 | ConvertFrom-Json
$auditVars = @{}
foreach ($auditPair in $auditDatabase[0].Config.Env) {
    $auditParts = $auditPair.Split('=', 2)
    $auditVars[$auditParts[0]] = $auditParts[1]
}
$auditDatabaseUser = $auditVars['POSTGRES_USER']
if ([string]::IsNullOrWhiteSpace($auditDatabaseUser)) { $auditDatabaseUser = 'postgres' }
$auditUser = [uri]::EscapeDataString($auditDatabaseUser)
$auditPassword = [uri]::EscapeDataString($auditVars['POSTGRES_PASSWORD'])
$auditName = $auditVars['POSTGRES_DB']
$auditPreviousUrl = $env:DATABASE_URL
try {
    $env:DATABASE_URL = ('postgresql+psycopg://{0}:{1}@127.0.0.1:5432/{2}' -f $auditUser, $auditPassword, $auditName)
    $auditArgs = @(
        'run', '--rm', '--network', 'container:cats-vex-expanded-db-20261020',
        '--entrypoint', 'python',
        '--mount', "type=bind,src=$auditWorkspace,dst=/workspace,readonly",
        '--mount', "type=bind,src=$auditRaw,dst=/raw,readonly",
        '--mount', "type=bind,src=$auditOutput,dst=/evidence",
        '--env', 'DATABASE_URL', '--env', 'PYTHONDONTWRITEBYTECODE=1',
        'cats:container-vex-audit-final', '-B', '/workspace/scripts/audit-package-identity.py',
        '--evidence', '/workspace/docs/evidence/container-vex-scans',
        '--raw-evidence', '/raw', '--output', '/evidence', '--stage', 'after',
        '--evaluate', '--as-of', '2026-10-20T05:40:57.930104+00:00',
        '--benchmark', '--controlled-positive'
    )
    docker @auditArgs
    if ($LASTEXITCODE -ne 0) { throw 'Identity audit failed' }
} finally {
    $env:DATABASE_URL = $auditPreviousUrl
}
```

Omit `--controlled-positive` to avoid private-schema DDL entirely. Real diagnostic/evaluation/benchmark database connections enforce `default_transaction_read_only=on`; only the optional controlled branch creates and populates its random schema before rollback. Omit `--benchmark` as well for coverage evaluation only. Without `--evaluate`, the harness runs the root-cause diagnostic only. `--stage` selects output names; it does not switch evaluator versions. Reproducing historical before behavior requires the retained original code/projection, so this command does not overwrite or recalculate the immutable baseline.

## Verified source hashes

The measured harness SHA-256 is `e03474579e4650a48dc3e6670fab389e6675b078cc80e9f900736d0cc5d589ec`. The reused `verify-container-intelligence.py` helper hash is `16250313e02f4c10df9fb807e6d44b3f4085ecc004f2ec3ff5bdd60e06e627db`. The production hashes below matched disk after the run and remained unchanged during benchmarking:

| File | SHA-256 |
| --- | --- |
| `container_intelligence.py` | `a5e2b771a19c5b6ef6be7f745ea3a9260fb6e5b4c5da8fce12f099059c413111` |
| `package_identity_resolution.py` | `b03697e33a6b65a6d011c36978edfe59b4279184cd17ca70287e8196802caa05` |
| `vex_intelligence.py` | `915e54c257a8c1a26a5d379179ed413505386a15e77ee305bed3ff8e907929d0` |
| `packaged_risk_intelligence.py` | `cb92be0172b1d2265edf5a772e04833a44ebee639d94c5892a9e06945409f305` |
