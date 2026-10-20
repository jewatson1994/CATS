# Container VEX applicability audit and integration

Date: 2026-10-20. Branch: `feature/risk-profiles-vex`. Base: `69640275212766db5997c824f20f7528cee3b53c`.

## Findings

The embedded corpus is connected to container Risk Intelligence through bounded, offline lookups. This audit corrected identity loss, added conservative advisory enrichment, and exposed finding-level coverage and evidence in the UI. It did **not** establish positive VEX applicability for the real images tested.

| Stage | Measured result |
| --- | --- |
| Intelligence stored | 119,387 VEX documents; 29,212,947 statements; 76,243 CVEs; 2,245,117 product identities; 13 sources |
| Intelligence matching a finding | 482 of 483 unique service findings have a CVE/alias somewhere in VEX, but zero have an exact CVE/PURL candidate; 111 have current package-scoped advisory references |
| Intelligence trusted for applicability | Zero applicable VEX statements in this real-image sample; generic distro names are insufficient enterprise-product context |
| Intelligence influencing informational risk | All 483 findings have valid EPSS enrichment; zero affirmative KEV and zero VEX Not Affected reductions. Advisory references explain evidence but never lower a score |

These distinctions matter: a large stored corpus, CVE presence, or an advisory link does not prove that an image package is covered by an authoritative applicability statement. The implementation fails conservatively when it cannot establish the required identity.

The original signed package is unchanged. Its payload SHA-256 is `91235078016fa5245c98d9c651ae4dfa9e5fd0e55220cc221ad74b4c98e61a6e`; manifest SHA-256 is `dcb38c60838d0ce5d07489f6b2cfa3630422cb1ef434922cf6a8eab9a25edf3c`. Risk Profile assessments gain container evidence and coverage details; existing scoring policy configuration, Cyber decisions, ownership requirements, compliance enforcement, remediation, publication and OCI admission are preserved.

## Scanner-to-risk flow

| Boundary | Exact implementation and retained data |
| --- | --- |
| Container to Syft | `scanning-main/scripts/generate-sboms.sh` invokes Syft on registry/archive sources or exported root filesystems. Rootfs mode now explicitly selects image catalogers. Original image references/digests and source metadata remain evidence |
| Vulnerability detection | `scanning-main/scripts/report-to-portal.sh` reads Grype matches and retains artifact name/version/PURL, original vulnerability identifier, aliases, related vulnerabilities, distro, source and match details. Existing Grype `--only-fixed` selection is unchanged. Trivy supplies policy/misconfiguration results in the existing pipeline |
| SBOM normalization | `scanning-main/scripts/sbom_identity.py`, `extract-sbom-components.py`, and `generate-sbom-formats.py` retain ecosystem, PURL, qualifiers, version, architecture, distro and source-package metadata in Syft/CycloneDX/SPDX projections. SPDX package-manager external references are read as PURLs |
| Reporter join | `report-to-portal.sh` attaches `evidence.sbom_artifact`, `sbom_distro`, `sbom_source` and `image_provenance` only when the Syft artifact ID is unique and name, version and artifact type agree. Package-name-only joins are forbidden |
| HTTP ingest | `portal/app/schemas.py::ExecutionPayload` / `FindingPayload` validate the report and SBOM allowlist. `portal/app/main.py::ingest` handles `POST /api/v1/pipeline-results` and calls `ingest_payload` |
| Persistence | `Finding` is unique by service/CVE. Each `FindingObservation` retains execution, image, digest, package, installed/fixed versions and JSON evidence. `ingest_payload` copies finding evidence, and its `ensure_ingest_image` associates `ServiceImage` with the service and digest. Complete/incomplete scan reconciliation remains unchanged |
| Assessment job | `portal/app/risk_profiles.py::enqueue_assessment` submits the existing durable job. `portal/app/risk_worker.py::handler` calls `refresh_assessment`, checks its lease and commits. `refresh_assessment` pages latest-execution observations in batches of 250 |
| Identity and VEX | `portal/app/container_intelligence.py::observation_identity` builds context from observation evidence, not merely from the SBOM table. `evaluate_container_batch` calls `portal/app/vex_intelligence.py::evaluate_batch` with exact requested CVE/PURL pairs, then adds bounded rejection/CVE-presence diagnostics |
| Advisory and scores | `container_intelligence.py::advisory_batch` adds authenticated package-scoped references. `risk_worker.py::refresh_assessment` joins offline KEV/EPSS, preserves classification evidence and passes exact VEX results to `risk_profiles.py::score_observation`. The existing scoring policy alone controls informational weighting |
| UI and drilldown | `portal/app/risk_routes.py::assessment` returns stored coverage/details. `portal/frontend/src/features/risk_coverage.tsx` renders service/image coverage and observation evidence within `risk_intelligence.tsx`. `risk_routes.py::assessment_document` serves only original documents referenced by an assessment visible to the caller |

The worker checks classification freshness, latest execution and intelligence/policy tokens before and after assessment. A changing source causes a retry. This work does not write classification decisions or mark scanner findings resolved.

## Identity audit and corrections

Previously the report retained too little scanner/SBOM provenance for useful diagnostics, normalization dropped source-package fields, and rootfs directory catalog defaults could omit application dependencies. The corrected path preserves the following without claiming identity equivalence:

- Original PURL, ecosystem, exact package name/version, qualifier architecture/distro/epoch and image digest.
- Syft/Grype distro/release, artifact identifiers and source metadata; OCI labels remain raw provenance.
- Source package, source version, source RPM, origin, vendor, architecture, epoch/release and modularity metadata when the scanner supplies them.
- Original vulnerability ID and bounded aliases. The reporter records truncation explicitly; omitted aliases cannot create a safe status or a false claim that a CVE is absent.
- Explicit publisher-scoped `csaf_product_context` when supplied as validated machine identifiers. Generic distro names, OCI labels and image names are not converted into an enterprise product/edition/module.

`package_identity` rejects missing versions, malformed escapes/UTF-8, duplicate or empty qualifiers, whitespace/control characters and ambiguous subpaths. It does not rewrite the PURL.

Two scanner representation differences have proven, narrow handling in `_scanner_version`:

1. RPM `epoch:version` is reconciled only if the numeric epoch exactly equals the PURL's epoch qualifier and the remainder exactly equals its version.
2. Go `stdlib` versions such as `go1.x` are reconciled with PURL `1.x` only when the original scanner/SBOM artifact has the same exact PURL, package name, type and installed version.

The raw installed version and reason remain visible. These rules resolved 109 RPM and 76 Go observations in the primary sample. No Ubuntu binary-to-source mapping, cross-distribution mapping, architecture fallback, fuzzy version match or inferred enterprise context was introduced.

### Ubuntu, Red Hat and SUSE limitations

The retained Ubuntu observations use exact binary-package PURLs with architecture and release qualifiers. Embedded source-package identities can differ in package name, version or qualifiers. Retaining source metadata makes the mismatch inspectable; it does not prove that the binary inherits the source statement. The audit deliberately does not normalize those differences away.

The previously identified 115,416 Red Hat and 6,490 SUSE initially eligible rows require publisher-scoped containing-product context. Image labels, release files and SBOM distro metadata in these samples did not establish a reliable exact containing-product/edition identity. Existing service ownership/configuration does not supply such an identity. Explicit validated context can now propagate when provided, and tests verify its acceptance/rejection.

All real samples failed the earlier exact-product gate. Consequently, zero samples were rejected *solely* for missing enterprise context; this does not demonstrate that their context is complete. Missing context and source/binary mismatch remain independent barriers to positive applicability.

## Real image results

Actual Syft 1.31.0 and Grype 0.98.0 scans ran without network access against exported image filesystems. The retained Grype database was built on 2026-10-03, schema 6.1.10. Immutable image digests, commands, capture times, scanner/database provenance and raw file hashes are in [the manifest](evidence/container-vex-scans/manifest.json). Raw evidence remains outside Git at the manifest's recorded path; bounded projections are committed.

Counts below use Grype's production `--only-fixed` filter; they are not all-vulnerability counts. Finding columns use distinct service/CVE IDs within each image. Shared CVEs make image totals overlap.

| Image | Components / valid PURLs | Scanner observations | Unique findings | Exact VEX / applicable | Advisory-only | EPSS | Wrong VEX product / absent CVE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ubuntu jammy-20260731.1 | 101 / 101 | 71 | 36 | 0 / 0 | 0 | 36 | 36 / 0 |
| Debian 12.9-slim | 88 / 88 | 79 | 55 | 0 / 0 | 0 | 55 | 55 / 0 |
| Alpine 3.20.0 | 14 / 14 | 69 | 33 | 0 / 0 | 0 | 33 | 33 / 0 |
| Red Hat UBI 9.6 | 206 / 206 | 291 | 191 | 0 / 0 | 0 | 191 | 191 / 0 |
| SUSE BCI base 15.6 | 146 / 146 | 334 | 208 | 0 / 0 | 66 | 208 | 208 / 0 |
| Python 3.11.13 slim-bookworm | 123 / 109 | 181 | 128 | 0 / 0 | 10 | 128 | 128 / 0 |
| Node 20 bookworm-slim, image catalogers | 293 / 293 | 93 | 83 | 0 / 0 | 35 | 83 | 82 / 1 |

Together: 971 component occurrences, 957 valid nonempty PURLs, 1,118 scanner observations, 1,069 distinct CVE/package/version/PURL tuples, and **483 unique service findings**. The final denominator is unique findings, not package occurrences or statements.

For every primary image, no-current-intelligence, unresolved scanner identity, stale/conflicting matched evidence and missing-context-only rejection counts are zero. All findings have EPSS; therefore zero no-current-intelligence findings does **not** imply complete VEX coverage. Exact/applicable VEX is 0%; advisory-only is 22.981%; EPSS is 100%; affirmative KEV is 0%. VEX CVE presence with another product is 99.793%.

The one absent VEX CVE is `CVE-2024-21538`, reported as `GHSA-3xgq-45jj-v275` for `cross-spawn@7.0.3`. Its GitHub advisory and alias-based EPSS are still available. Bounded different-product samples prove only that the CVE is present, and are labelled accordingly in the UI.

Three additional captures are retained: latest Debian and Alpine genuinely returned zero matches under `--only-fixed`; the original Node directory-catalog scan found 58 observations. Re-scanning the same immutable Node image with image catalogers found 204 npm packages and 35 additional npm vulnerability observations. That evidence justified the cataloger correction.

Trivy 0.69.3 was installed, but its vulnerability database was absent. A real offline attempt failed with “The first run cannot skip downloading DB.” No successful Trivy vulnerability scan is claimed. Fourteen Python-image binary artifacts lack PURLs. These gaps are preserved rather than filled with invented identities.

## Supplemental advisories and Risk Profile behavior

`embedded_intelligence.py` now builds additive advisory catalog membership from the authenticated signed stream, including same-sequence backfill for already installed releases. Membership is deduplicated in bounded batches and committed atomically. Existing records with a matching `package_version` alone cannot establish membership. The 29.2-million-row VEX corpus and payload were not rebuilt.

The measured backfill took 86.61 seconds with a 94.2 MiB process peak and returned `unchanged` for the installed package. Current catalogs contain 10,094 Alpine, 32,256 GitHub, 4,428 Go, 7,667 PyPA, 607 RustSec and 1,576 SUSE advisory records; KEV and EPSS membership remain available. See [backfill evidence](evidence/container-vex-scans/advisory-backfill.json).

| Ecosystem | Correlation | Verification |
| --- | --- | --- |
| PyPI | Exact ecosystem/package using standard separator/case normalization; explicit versions or retained range references | Real Python packages: 10 advisory findings; positive and negative tests |
| Maven | Exact Maven coordinate (namespace/name to group:artifact), version evidence retained | Fixture tests; no live Maven observations in this sample |
| npm | Exact scoped/unscoped package name | Real Node packages: 35 advisory findings; tests |
| Go | Exact module path, with separately proven stdlib version representation | Real SUSE Go packages: 66 unique advisory findings; tests |
| NuGet | Exact package identity; no speculative case/version equivalence | Fixture tests; no live NuGet observations |
| Cargo | Exact crates.io package identity | Fixture tests; no live Cargo observations |
| Alpine | Exact Alpine package and release against SecDB | No current advisory match for the older captured release; negative tests |

Version ranges remain inspectable references, not a second vulnerability scanner. A range reference is explicitly marked `package_reference_ranges_not_evaluated`; it cannot establish affected or Not Affected. Advisory freshness, trust, withdrawal and source enablement are checked independently. Unsupported ecosystems remain unsupported; SUSE CVRF did not become an inferred RPM package match.

`container_intelligence.py::advisory_batch` retains the earliest expiry across all matched, current, trusted, enabled and non-withdrawn advisory references before truncating displayed records. Expiry uses the authenticated catalog acquisition time plus the source maximum age. Missing, malformed or future-dated acquisition timestamps, expiry arithmetic overflow, and already expired references cannot supply current coverage or an expiry; matched references remain inspectable as non-current evidence. `risk_worker.py::refresh_assessment` includes advisory and VEX expiries in the assessment expiry alongside existing scan, enrichment, policy and classification limits, so an advisory outside the displayed records still invalidates the assessment when it expires.

VEX retains `affected`, `not_affected`, `fixed`, `under_investigation`, `no_vex`, `stale`, `conflicting` and `missing_context` diagnostics. A VEX-based reduction in informational technical risk requires trusted, current, fully applicable Not Affected evidence and complete enrichment under the existing policy. Fixed does not resolve a finding. Ambiguous aliases, stale/conflicting evidence, unknown identity and candidate overflow cannot grant a safe assessment. KEV remains an override; EPSS must be finite and within [0,1].

`risk_worker.py::refresh_assessment` requires valid EPSS and a known boolean KEV result for every bounded CVE returned by `vex_intelligence.py::_item_cves`, with no alias overflow, before treating enrichment as complete for scoring. A GHSA with known CVE aliases requires enrichment for those CVEs, not for the non-CVE primary identifier. The maximum valid EPSS is retained and any affirmative KEV result wins; KEV is false only when every required CVE is explicitly false and aliases are complete. Missing enrichment for even one required CVE, or omitted aliases, keeps the observation uncertain and prevents score reductions. Any additional primary-identifier signal can only increase risk. Existing behavior for a CVE without aliases is preserved.

Coverage unions flags by Finding ID across observations. An image uses the same finding ID within its own digest/reference. Categories can overlap; advisory-only excludes findings with applicable VEX, and no-intelligence means no current applicable VEX, current advisory reference, affirmative KEV or valid EPSS. The UI states these denominators, displays “Not applicable (no findings)” for zero findings, separates image coverage, and exposes original identity, accepted/rejected candidates and raw evidence. Historical assessments need reassessment for algorithm-2 coverage.

Original VEX documents load only on explicit drilldown, with a 4 MiB byte cap and service visibility plus assessment-reference checks. Advisory details use the existing authorized records API. Assessment loops never load full original documents.

## Performance and bounds

Measurements used the actual populated PostgreSQL 16.15 database in an isolated Docker network namespace. Source/input hashes and plans are retained in [coverage-and-benchmark.json](evidence/container-vex-scans/coverage-and-benchmark.json). Database/OS caches were warm; the host was shared. Timings cover the measured unmatched-product path, not a positive high-fanout VEX workload. Larger workloads repeat real observations; they are not additional live image scans.

| Evaluator workload | Observations | SQL statements | Wall time | Sampled Python peak RSS |
| --- | ---: | ---: | ---: | ---: |
| One finding | 1 | 7 | 0.009386 s | 82.62 MiB |
| One batch | 250 | 7 | 0.061261 s | 82.80 MiB |
| 1,000 observations | 1,000 | 28 | 0.385803 s | 83.71 MiB |
| 10,000 observations | 10,000 | 280 | 4.348488 s | 100.29 MiB |
| Seven images, one service | 1,118 | 35 | 0.499515 s | 100.21 MiB |
| Four concurrent evaluator jobs | 4 x 1,000 | 112 | 1.877344 s | 107.65 MiB shared process |

The separate lifetime peak counter was 107.22 MiB; it and sampled `/proc` RSS are distinct counters and are not summed. Memory excludes PostgreSQL.

The real worker was measured separately against the same populated corpus. Retained scanner observations were staged through the model, followed by real classification and `refresh_assessment`. Each service had one owning group and produced 483 findings from 1,118 observations, with 111 findings having current advisory references and no applicable VEX. No fixture VEX was injected. Classification and original scan rows remained unchanged during assessment, and all staged rows were rolled back; PostgreSQL sequences may advance.

| Full assessment materialization | Worker SQL statements | Worker call time | Total including staging/classification/verification | Process peak RSS |
| --- | ---: | ---: | ---: | ---: |
| One service | 77 | 1.767262 s | 4.235054 s | 270.512 MiB |
| Four concurrent services | 308 total | 14.647940-15.944247 s per call | 33.127568 s | 430.914 MiB shared process |

The single-service classification took 0.784752 s before the measured worker call. Concurrent calls synchronize after evidence staging and classification. Their elapsed times include contention on this shared host and are not additive. This check exercises full materialization but does not submit HTTP ingestion requests or run durable queue lease/retry scheduling. Reports: [single worker](evidence/container-vex-scans/worker-final.json), [concurrent workers](evidence/container-vex-scans/worker-concurrent.json).


The worker pages 250 observations and rejects more than 100,000 observations/findings. Exact VEX retrieval retains existing candidate-overflow rejection and now uses requested CVE/PURL pairs rather than a Cartesian candidate set. CVE-presence diagnostics use indexed per-CVE LIMIT 1 probes in batches of 200. Advisory lookups use batches of 400 CVEs, a 2,000-candidate limit (one extra detects overflow), and at most 64 KiB of projected applicability fields per candidate. Overflow discards partial advisory candidates. Advisory records and rejected VEX candidate details are each limited to 20 per observation; accepted VEX statements remain bounded by the evaluator limit of 10,000 candidates per batch. Advisory aggregate flags and earliest current expiry are computed before record display truncation.

EXPLAIN plans show indexed VEX product/CVE, advisory record/CVE, membership, KEV and EPSS paths. The only sequential scan recorded is the eight-row catalog table. No full VEX corpus scan or per-finding application query loop is introduced in service assessment. PostgreSQL counts used to verify the audit corpus are verification operations, not assessment queries.

## Verification and reproduction

Final verification results are recorded below. The [evidence README](evidence/container-vex-scans/README.md) contains immutable image reproduction, raw file locations, offline Docker commands and denominator definitions.

- `scripts/capture-container-vex-scans.py` captures real scanner output and provenance; it rejects provenance changes in an existing capture set.
- `scripts/verify-container-intelligence.py` uses read-only transactions to measure the real populated corpus, bounded evaluator/advisory lookups, overlays and coverage.
- `scripts/verify-container-risk-worker.py` stages retained scan observations in temporary database transactions and runs the real classification/materialization functions; it rolls back its audit data. This is direct model staging, not an end-to-end HTTP ingestion test.
- `portal/tests/test_container_intelligence_identity.py`, `test_container_intelligence.py`, `test_risk_worker_vex_identity.py`, `test_vex_repository.py` cover exact matches, wrong version/distro/architecture/source/containing product, missing/malformed identity, aliases/truncation, stale/conflicting evidence and conservative overflow.
- `portal/tests/test_container_intelligence.py` verifies unusable acquisition timestamps, earliest current advisory expiry and assessment invalidation at advisory expiry. `portal/tests/test_risk_worker_vex_identity.py` verifies missing secondary-alias enrichment, complete multiple-CVE enrichment, GHSA-to-CVE enrichment and alias overflow.
- Retained-scan, SBOM, advisory membership, KEV/EPSS, API authorization and frontend tests cover duplicate findings, incomplete SBOMs, unsupported ecosystems, advisory-only evidence and coverage presentation.

| Final check | Result | Retained evidence |
| --- | --- | --- |
| Backend risk/VEX/container/embedded regression suites | 463 passed; 10 opt-in PostgreSQL cases skipped in this SQLite run; 126.78 s | `backend-final.xml`, `backend-final.json` |
| Classification suite | 21 passed; 13.75 s | `classification-final.xml` |
| Database verification | 80 passed, no failures or skips: risk 13, container/membership 50, projections 14 (7 SQLite + 7 PostgreSQL), source API 3 | `postgres-final-summary.json` and per-run XML/JSON |
| Scanner normalization/reporting | 15 passed, no skips | `scanner-final.xml` |
| Frontend | 22 passed; TypeScript and focused ESLint clean | `frontend-final.json` |
| Standard release build | Passed; version `2026.10.20.2`, 32.206 s | `offline-final.json`; retained external build log |
| Normal offline startup and repeat package install | Healthy in 7.973 s; no mounts; shared isolated database network has no external access; repeat install `unchanged` | `offline-final.json` |

No final test failures remain. Separate database runs cover the 10 opt-in cases skipped by the SQLite run; these rows are not a sum of unique tests across configurations. The additional 41-case advisory-expiry run and one-case PostgreSQL expiry recheck passed and are retained without adding them to the totals. The expiry regression fixture disables unrelated asynchronous classification scheduling so its controlled freshness boundary does not race a background rebuild; production validation is unchanged.

The normal release image is `sha256:f17f517ec2a16a535f1f39bdac62fea4eec886a8ae4a0ed89d11fc442a96688d`. All 14 recorded source hashes remained unchanged during build/verification; all 11 deployed portal/scanner hashes match. The build also compiled and validated the frontend bundle. Verification used the existing populated audit database, so this is not a new cold import. All signed package file hashes and the 119,387-document/29,212,947-statement counts remained unchanged. Existing audit and application containers were preserved.

The normal release build is reproducible with:

```powershell
python scripts/build-cats-release.py --scanner-base catscan-base:local --tag cats:container-vex-audit-final --cats-version 2026.10.20.2
```

## Remaining gaps

1. Positive exact VEX applicability is verified by focused exact-identity fixtures and existing vendor tests, but **not by these real image scans**. Obtain a publisher-supported exact image/package mapping with verifiable source/binary and containing-product relationships before claiming otherwise.
2. Ubuntu binary/source identity and Red Hat/SUSE enterprise edition/module context remain unresolved when publishers/scanners do not supply sufficient machine identifiers. Retain the mismatch, do not add approximate exemptions.
3. Run Trivy with an approved offline vulnerability database and add real Maven, NuGet and Cargo image samples. Current results for those ecosystems are implementation/test coverage only.
4. Benchmark positive high-fanout VEX queries and sustained durable queue scheduling separately. Concurrent evaluator/full materialization calls do not alone establish queue lease/retry throughput.
5. Retain the original scanner database and raw evidence alongside these hashes for independent reproduction. Updated databases, images or source freshness will change results; refresh assessments when intelligence changes.

No push, merge, rebase or modification of `main` or the OCI feature branch is part of this work.

After verification, the final staged whitespace check removed extra trailing blank lines from three files. [Formatting provenance](evidence/container-vex-scans/final-formatting.json) records the byte-identical substantive content and before/after hashes; test/build evidence retains the exact tested hashes.
