# SBOM-backed VEX correlation

## Problem and evidence boundary

A finding observation can lack a complete package URL even though the same scan retained the component's identity in its SBOM. That is a correlation problem before VEX lookup. A component recovered from the SBOM must belong to the observation's scan and immutable image scope; a shared package name, CVE, source package, or image label is insufficient.

The existing evaluator already separates observed identities, authoritative derived identities, exact VEX candidates, and accepted applicability. The correction carries retained scan components into that path. It preserves the scanner's original record and records the outcome of component binding. Existing publisher trust, freshness, version, architecture, distribution, containing-product, alias, and conflict checks still determine the result.

## Baseline inspected

Investigation used commit `22f35d50f4de6d834e3a0c9892dce6359343d461` from `origin/main`, independently of unrelated changes in the original checkout. Existing evidence is retained in:

- [`evidence/container-vex-scans/README.md`](evidence/container-vex-scans/README.md) and its manifest, per-image projections, and coverage report.
- [`evidence/authoritative-package-identity/README.md`](evidence/authoritative-package-identity/README.md), production evaluation details, root-cause reports, benchmarks, and vendor documents.

The primary corpus contains real scans of Ubuntu, Debian 12.9, Alpine 3.20.0, Red Hat UBI, SUSE, Python, and Node with image catalogers. Scans used Syft 1.31.0 and Grype 0.98.0 with an existing database built on 2026-10-03. The findings denominator is Grype `--only-fixed` matches. It is not an exhaustive count of all vulnerabilities.

| Retained primary workload | Count |
| --- | ---: |
| Component occurrences | 971 |
| Nonempty, syntax-valid PURLs | 957 |
| Scanner observations | 1,118 |
| Distinct CVE/package/version/PURL tuples | 1,069 |
| Unique service findings | 483 |
| Derived identities in the earlier identity audit | 595 |
| Observations with derived identities | 319 |
| Finding roots with derived identities | 119 |
| Direct or resolved VEX candidates | 0 |
| Applicable VEX statements | 0 |

These are historical results from the retained audit, not a new production measurement of this change. A CVE or alias occurred elsewhere in the VEX corpus for 482 of the 483 finding roots; that did not produce an applicable package match.

On 2026-10-25, the investigation independently checked all 35 raw files for the seven primary images against the baseline manifest. All SHA-256 hashes matched. The files are available in the manifest's external `raw_evidence_directory`:

```text
C:\Users\lil-j\.codex\visualizations\2026\10\19\01a1526b-954e-73b2-b46b-e7d15d435d2e\container-vex-raw-evidence
```

The earlier audit joined all 1,118 observations to exactly one raw Syft artifact by artifact ID plus exact name, version, type, and PURL, and to the exact Grype finding/artifact tuple. All 868 deb/RPM observations had installed-package database provenance in the raw capture that the older bounded projection omitted. This is evidence that preserving and retrieving the correct SBOM record matters; it is not evidence that all missing identities can be recovered or that a matching VEX statement exists.

## Traced evidence flow and verified gaps

| Stage | Implementation and evidence boundary |
| --- | --- |
| Generate inventory | [`generate-sboms.sh`](../scanning-main/scripts/generate-sboms.sh) writes native Syft JSON. The Docker path copies an unstarted container filesystem and uses Syft's image catalogers on the directory; the daemonless path uses the recorded registry/archive source. Directory inventories need independently verified image provenance. A config digest, multi-platform index digest, or mutable tag is not a platform-manifest binding. |
| Export formats | [`generate-sbom-formats.py`](../scanning-main/scripts/generate-sbom-formats.py) provides Syft JSON, CycloneDX JSON/XML, and SPDX JSON exports. The native Syft document remains Grype's input. [`extract-sbom-components.py`](../scanning-main/scripts/extract-sbom-components.py) accepts supported JSON inventories and retains available format-specific IDs and package evidence; a converted format cannot invent installed database authority that it lacks. |
| Scan packages and configuration | [`scan-sbom.py`](../scanning-main/scripts/scan-sbom.py) runs Grype with `--only-fixed` against a frozen copy of the native document and records the consumed SBOM and result hashes. [`scan-configurations.sh`](../scanning-main/scripts/scan-configurations.sh) uses Trivy configuration and image misconfiguration scanners plus Dockle evidence. Those configuration results do not supply the package vulnerability observations used by this correlation path. |
| Build the report | [`report-to-portal.sh`](../scanning-main/scripts/report-to-portal.sh) builds observations with the scanner component reference, original bounded artifact/distro/source records, and verified binding fields. It attaches native SBOM package metadata only for a unique exact artifact join in the document bound to the report. The component extractor adds a bounded inventory to the same execution payload. |
| Transfer and import | [`scan_worker.py`](../portal/app/scan_worker.py) packages generated evidence with job/attempt/input/service identity. [`scan_artifacts.py`](../portal/app/scan_artifacts.py) and [`scan_protocol.py`](../portal/app/scan_protocol.py) validate the envelope, file lengths/hashes, authorized paths, and fenced attempt before ingestion. The worker does not access the portal database. Direct execution ingestion and public-scan import converge on `ingest_payload` in [`main.py`](../portal/app/main.py). |
| Retain the scan | Ingestion validates `ExecutionPayload`, keeps `Execution.raw_payload`, inserts `FindingObservation` records, and writes the execution-owned [`SbomComponent`](../portal/app/models.py) lookup rows in the same transaction. The original observation is not replaced by the retained component. |
| Correlate and evaluate | [`observation_identities`](../portal/app/container_intelligence.py) leaves sufficient scanner identities on their existing path. Eligible incomplete identities use [`sbom_components.py`](../portal/app/sbom_components.py): exact execution ownership, image, component ID or exact PURL, platform-manifest digest, platform, and consumed-document digest must agree. Bounded lookup returns an explicit outcome. The shared package resolver and VEX evaluator still apply authority, version, distro, architecture, publisher, freshness, containing-product, and conflict rules. Dependency edges and source-name hints are not substitutes for those checks. |
| Persist and consume | [`native_vex.py`](../portal/app/native_vex.py) and [`risk_worker.py`](../portal/app/risk_worker.py) call the same batch identity path and retain its evidence. Findings queries/classification, [`service_posture.py`](../portal/app/service_posture.py), service/purpose exports, and [`remediation_jobs.py`](../portal/app/remediation_jobs.py) consume the shared current native disposition and generation tokens. An accepted statement for one observation cannot exclude a mixed finding whose other observations remain actionable. |

At the pinned baseline, `observation_identity` read the observation PURL and attached evidence only; it did not query retained execution components when identity was missing. The component projection retained useful flat inventory fields but omitted the original structured artifact record and the new document/platform binding. The reporter's exact-ID join read the current SBOM file without a scan-time input/output hash sidecar. Native disposition evidence also omitted the complete identity record that risk assessment could show. These are the verified correlation, provenance, and visibility gaps addressed here. The historical absence of applicable publisher statements remains a separate coverage limitation.

The new projection preserves bounded original artifact, distro, descriptor, and source records alongside exact component references, PURLs (including qualifiers), document digest/format, platform-manifest digest, and image platform. Source-package metadata and installed-database locations remain structured evidence for the existing authoritative resolver; flat source names do not acquire authority. Complete original scanner identities bypass recovery. Incomplete identities retain their original record beside the recovered identity and binding provenance. Scanner distro namespace must agree with retained distro identity, including when the scanner supplies only a name; the verified directional `redhat` to `rhel` representation pair is handled explicitly. Contradictory namespaces cannot produce an exclusion.

The stale-document guard is deliberately narrower than a package-ID match. The scan helper removes an older binding before scanning, freezes the input bytes, and writes the binding only after Grype succeeds. At report time, [`sbom_identity.py`](../scanning-main/scripts/sbom_identity.py) requires the current SBOM hash, scanner-result hash, image, and canonical image binding to match that scan-time record. Missing, stale, or conflicting records cannot attach SBOM authority to an otherwise valid scanner observation. This includes a replacement SBOM that happens to contain the same artifact ID.

## Publisher-backed evidence versus controlled cases

The baseline's exclusive root-cause counts are:

| Most specific verified barrier | Observations | Unique findings |
| --- | ---: | ---: |
| CVE absent from corpus | 1 | 1 |
| Vendor or ecosystem not covered | 497 | 205 |
| CVE absent from matching vendor statements | 491 | 194 |
| Containing-product context unverified | 58 | 47 |
| Package version mismatch | 71 | 36 |

The retained Canonical CVE-2026-53910 document contains fixed versions different from the scanned diffutils version. Red Hat's CVE-2025-11187 document contains versionless OpenSSL identities under distinct RHEL 7 and JBoss Core Services contexts; neither establishes applicability to the scanned UBI 9 package. The SUSE CVE-2006-2450 document is a publisher product-shape example outside the seven-image finding set.

The earlier controlled-positive benchmark inserts synthetic statements into a private transactional schema and rolls them back. Its positive, direct/derived conflict, 10,000-candidate, and overflow cases test evaluator behavior. They are not discovered vendor matches. New tests using controlled VEX statements must retain this distinction, even when their component metadata comes from a real SBOM capture.

## Operator evidence and shared consumers

The risk assessment and automatic VEX evidence views use the same identity renderer. They show:

- The original scanner PURL and installed version, including explicit missing values.
- SBOM binding outcome: matched, missing, ambiguous, conflicting, or missing scan/image scope; recorded failure reasons remain visible.
- The correlated component identity only after a successful binding.
- Scan execution, component reference, binding method, image digest, platform, SBOM digest, and retained original records.
- Authoritative derived identities and their existing provenance.
- CVE presence, exact candidate count, and the number of statements that passed applicability checks, without conflating them with effective exclusion.

Missing metrics in historical evaluations are labelled “Not recorded” or “Not established,” rather than zero. A successful SBOM binding establishes component identity only. Accepted statements can still disagree, and the effective disposition controls exclusion.

Native VEX findings, simplified views, service posture, exports, and remediation consume the shared current native disposition. They should not implement independent package matching. Mixed observations must remain actionable, and a changed scan or evidence generation must invalidate an older disposition.

## Measurement and reproduction limits

The existing [`scripts/audit-package-identity.py`](../scripts/audit-package-identity.py) is the strongest retained harness for corpus evaluation: it verifies raw input hashes, reconstructs exact joins, evaluates production logic, and can run scaling and controlled benchmarks. [`scripts/verify-container-intelligence.py`](../scripts/verify-container-intelligence.py) measures coverage and repeated observation workloads. [`scripts/verify-container-risk-worker.py`](../scripts/verify-container-risk-worker.py) exercises the worker in rollback-only staging.

These harnesses require an isolated loopback PostgreSQL database with the imported intelligence corpus. At initial investigation, the Docker CLI was available but the Docker Desktop Linux engine pipe was absent. The retained corpus-backed audit could not be rerun in that state. Existing measurements must remain labelled historical; an offline replay against selected documents or synthetic statements is a different workload.

The earlier authoritative-identity audit recorded the following sequential timings, including VEX, advisory, KEV, and EPSS work:

| Workload | Earlier baseline seconds | Identity audit seconds | SQL statements |
| --- | ---: | ---: | ---: |
| One observation | 0.009386 | 0.010459 | 7 |
| 1,000 observations | 0.385803 | 0.733479 | 28 |
| 10,000 observations | 4.348488 | 7.464165 | 280 |
| All seven images / 1,118 observations | 0.499515 | 1.021068 | 35 |

Those timings show added processing time with unchanged query counts. They were single warm/unknown-cache runs on a shared host, with concurrent release builds and no CPU reservation. They do not establish improved latency or a controlled before/after memory delta. Repeating observations creates load, not additional real findings. Coverage is deduplicated by service/CVE; image and ecosystem coverage can overlap.

## Verification of this change

Final verification on 2026-10-25 used the isolated branch and the project's existing Python environment:

| Check | Result |
| --- | --- |
| Combined backend suite: component correlation/ingestion/cross-format binding, identity ingestion/resolution, container intelligence, native VEX boundaries/consumers/workflows, retained scans, risk profiles/SQL, classification, and VEX repository | **673 passed, 22 skipped in 105.01 seconds** |
| Scanner suite: SBOM binding/components/formats, report generation, image identities, and SBOM identity; jq 1.8.1 available | **40 passed in 2.18 seconds**, no skips |
| Focused frontend tests: `native_vex.test.tsx` and `risk_coverage.test.tsx` | **25 passed** |
| TypeScript `tsc --noEmit`, scoped ESLint for the four changed frontend files, and Vite production build | **Passed** |
| Changed shell script syntax and final `git diff --check` | **Passed** |

Backend checks cover correctly bound recovery, complete-identity bypass, duplicate instances/versions, wrong image/platform/document/execution/service, missing scope, conflicting identities and distro namespaces, source/binary authority, rejection of dependency inheritance, generation invalidation, mixed observations, policy disabled/enabled, retained findings, and existing classification/risk/remediation/export consumers. They include ingestion transaction and duplicate-execution behavior, bounded indexed lookup, stale-document rejection, and publication fences. Frontend checks cover original versus recovered identity, unsuccessful binding outcomes, provenance, distinct CVE presence/candidate/applicability metrics, absent historical metrics, and native disposition review.

The 22 skipped checks require `CATS_TEST_POSTGRES_URL` (nine native VEX boundary cases and thirteen risk/VEX integration cases). No PostgreSQL test database or available Docker Linux daemon was present, so this change has not been integration-tested against PostgreSQL here. The build retains existing warnings about `runtime/static/app.css` and mixed static/dynamic imports of `risk_intelligence`; it completed successfully. These checks are focused regression coverage, not a claim that every repository test or a deployed worker/scanner environment was exercised. Real retained evidence and identity-only performance measurements are reported separately below; no new publisher-backed VEX coverage is claimed.

## Offline retained-scan audit

[`scripts/audit-sbom-correlation.py`](../scripts/audit-sbom-correlation.py) reads the manifest and seven capture projections directly from the pinned baseline commit, checks all 35 original raw files, and requires an exact, unique raw Grype finding and Syft artifact join for each of the 1,118 observations. It compares the original identity entry point with the new batch entry point using the same current package resolver and the same bounded raw-record reconstruction. This is a comparison of the lookup paths, not a rerun of the historical PostgreSQL/VEX evaluation.

The complete scanner path preserves all 1,118 identities and resolver results: 1,118 exact identity candidates and 595 derived identity candidates, with zero unresolved identities and zero SQL or SBOM lookups. Identity candidates are package lookup inputs, not matching VEX statements. The original observation records remain unchanged.

The separate missing-PURL perturbation removes the observation PURL, scanner-artifact PURL, and attached SBOM projection in memory while retaining the exact artifact reference. It supplies the hash-verified SBOM digest as a controlled assertion; the legacy scans did not retain the new scan-time consumed-document sidecar. All seven captures are directory SBOMs, including `node-image-catalogers`. Their old image records do not establish the platform-manifest binding required by the new scanner verifier. All 1,118 perturbed observations therefore remain unresolved with `scope_missing`; none is reported as real recovery.

A third workload uses the same real component records and exact references with explicitly artificial execution/image scope, a synthetic manifest digest, and a test platform. All 1,118 bindings succeed and reproduce the original package context. These are fixture results and cannot be counted as recovered real-image identities or trusted VEX matches. No VEX statements are created or evaluated by this audit.

This replay exposed real Grype/Syft representation differences: CPE strings versus CPE objects, package metadata type labels, and distribution display names/version strings. The comparison now handles the verified representation pairs without rewriting either original record or treating scanner labels as installed-package authority. Nested identity-bearing metadata contradictions remain conflicts. The audit reconstructs bounded raw records; it is not a byte-for-byte reporter replay. Reporter-created null placeholders have separate consumer regression coverage.

The final identity-only SQLite run used three warmed repetitions per workload:

| Workload | Observations | Resolved identities | Median seconds | SQL statements | SBOM lookup statements |
| --- | ---: | ---: | ---: | ---: | ---: |
| Complete real scanner records | 1,118 | 1,118 | 0.019893 | 0 | 0 |
| Real records with PURL removed; historical scope insufficient | 1,118 | 0 | 0.034641 | 2 | 0 |
| Artificial scope with real component records | 1,118 | 1,118 | 0.197218 | 7 | 5 |
| Repeated artificial-scope workload | 10,000 | 10,000 | 1.823918 | 7 | 5 |

Both artificial-scope workloads contain the same 190 distinct scoped component references. The lookup uses batches of 40 keys and at most 17 rows per exact key, including the overflow sentinel. SQLite's recorded query plan uses `ix_sbom_component_reference` on execution/image/reference. The two additional statements validate ownership. Repetition demonstrates bounded query count for this key distribution; it does not establish behavior for 10,000 distinct keys or a PostgreSQL latency improvement.

The machine-readable results, source hashes, per-image counts, query-plan evidence, and repeated timings are retained in [`offline-audit.json`](evidence/sbom-backed-vex-correlation/offline-audit.json). Reproduce from the repository root with a Python environment containing the portal dependencies:

```text
python scripts/audit-sbom-correlation.py --output docs/evidence/sbom-backed-vex-correlation/offline-audit.json
```

Use `--raw-evidence <directory>` when the verified raw files live elsewhere. The audit blocks network access, overrides the database URL to disposable in-memory SQLite, and does not touch an installed database. It fails if a raw hash, unique join, complete identity, original record, or source snapshot changes unexpectedly. Timings cover only identity recovery; they exclude inventory ingestion, package resolution, VEX/advisory evaluation, and network. They are warmed repeated runs on a shared host, not PostgreSQL production latency or throughput measurements.

## Existing scans and migration

New ingestion writes the bounded execution-owned component index. Assessment does not scan historical raw SBOM documents or implicitly rebuild inventory. After the portal schema update, [`scripts/index-retained-sbom-components.py`](../scripts/index-retained-sbom-components.py) can explicitly index existing retained `sbom_components` in bounded execution batches. Its `--limit` defaults to 50, and `--after-id` resumes after the printed checkpoint; run it in the intended portal database environment.

Indexing preserves the evidence already retained and cannot supply missing image-platform, platform-manifest, or consumed-SBOM hashes. Historical observations with complete scanner identities continue through their existing path. Historical observations that need recovery but lack the binding evidence require a new scan with verifiable scope; neither mutable image tags nor old index/config digests are promoted into a verified platform-manifest binding. A generic Docker-directory rescan is insufficient when Docker's inspect descriptor is absent or identifies a multi-platform index. Recovery requires verified native image evidence, such as the daemonless Syft OCI manifest/config path, or Docker provenance containing a platform-specific manifest descriptor, together with the matching platform and scan-time consumed-document binding.

Deployment and re-evaluation use the existing lifecycle:

1. Deploy the portal and scanner together, then start the portal so its existing additive `create_all` migration creates the component table/indexes and installs generation triggers. Startup does not enumerate historical SBOM inventories or reassess the corpus.
2. If existing retained inventories need indexing, run `python scripts/index-retained-sbom-components.py --limit 50` in the configured portal environment, then resume with the printed `--after-id`. The upper limit is 500 executions per invocation. The command validates and indexes one retained payload at a time; it does not search external raw files or strengthen missing provenance.
3. Rescan identities whose required scope or consumed-document evidence is absent using a source that establishes the verified platform-manifest scope described above. Repeating a Docker-directory scan whose descriptor is only an index or is missing will still leave recovery unresolved. Keep the new scan's generated SBOM, Grype result, and `.binding` record together. A complete scanner identity does not require this recovery migration.
4. Keep the durable risk/native VEX worker running. Resolver version `cats-package-identity/v2` is included in the native algorithm token; the existing worker discovers outdated algorithms and generations in bounded batches. Until a current evaluation exists, old dispositions do not qualify for exclusion. Changes to observations, executions, or component rows also invalidate the service generation.
5. Re-run an affected risk assessment through the existing assessment action after indexing or rescanning. Risk provenance includes the resolver version and identity source generation, and stale assessments expose `identity_resolver_changed` or `identity_source_changed`. The worker refuses to publish a current assessment if the source changes while it runs. Native exclusion need not be enabled for this identity source fence to apply.

A direct replacement of `Execution.raw_payload` removes its previous component projection in the same transaction. Re-index the replacement explicitly when appropriate; the old rows must not survive as authority for new payload bytes. Historical evaluations remain audit history rather than being edited in place.
