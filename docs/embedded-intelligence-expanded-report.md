# Expanded embedded intelligence release report

Completed 2026-10-20 UTC for release `2026.10.20.1`, sequence `2026102001`. The signed inventory, automatic offline import, exact baseline comparison and final normal-image runtime checks passed. Cold-import and final-runtime image measurements are attributed separately below.

## Signed inventory

The [manifest](../portal/app/embedded_intelligence_data/manifest.json) contains three VEX publishers and ten supplemental datasets from nine publishers: 13 sources. CISA contributes two supplemental datasets; SUSE contributes VEX and recommendations. Counts describe selected documents, normalized statements, or CVE-keyed supplemental records, as labeled. They are not additive counts of unique vulnerabilities, products, or currently usable matches.

| Source | Selected package contents | Scope | Data terms |
| --- | ---: | --- | --- |
| Canonical Ubuntu | 58,044 VEX documents; 23,252,990 normalized statements | 50,747 CVE-primary and 7,297 USN-primary documents with explicit CVE aliases | CC-BY-SA-4.0 |
| Red Hat | 59,417 VEX documents; 5,589,493 normalized statements | Original per-CVE CSAF archive; 1,481,906 statements have versioned PURLs | CC-BY-4.0 |
| SUSE VEX | 1,926 documents; 370,464 normalized statements | Selected recent CSAF cohort; 6,490 statements have versioned PURLs | CC-BY-4.0 |
| CISA KEV | 1,748 exploitation records | Entire acquired catalog | CC0-1.0 |
| Alpine SecDB | 10,094 advisory records | v3.24 main/community, CVE-linked fixes | CC-BY-SA-4.0 |
| GitHub reviewed advisories | 32,256 advisory records | Reviewed OSV entries with CVE aliases | CC-BY-4.0 |
| SUSE recommendations | 1,576 advisory records | Explicit recommended identities from the same SUSE cohort | CC-BY-4.0 |
| FIRST EPSS | 391,411 risk-enrichment records | Entire daily snapshot; scores published 2026-10-19 | FIRST express data-use terms |
| NIST NVD | 22,272 vulnerability records | Rolling modified feed; not full history | NIST public-service terms |
| CISA Vulnrichment | 200,751 risk-enrichment records | CISA-authored ADP containers only | CC0-1.0 |
| Go via OSV | 4,428 advisory records | `GO-` entries with CVE aliases | CC-BY-4.0 |
| PyPA via OSV | 7,667 advisory records | `PYSEC-` entries with CVE aliases | CC-BY-4.0 |
| RustSec via OSV | 607 advisory records | `RUSTSEC-` entries with CVE aliases | CC0; imported GitHub content CC-BY-4.0 |

The eight ordered payload parts contain **477,230,165 compressed bytes** and **8,070,632,870 decoded bytes**. The largest JSONL record is 5,437,773 bytes. These are transport/content dimensions, not PostgreSQL or image storage measurements. Limits are 2 GiB compressed, 8 GiB decoded and 8 MiB per record.

- Manifest SHA-256: `dcb38c60838d0ce5d07489f6b2cfa3630422cb1ef434922cf6a8eab9a25edf3c`.
- Complete payload SHA-256: `91235078016fa5245c98d9c651ae4dfa9e5fd0e55220cc221ad74b4c98e61a6e`.
- Acquisition-lock SHA-256: `dd96a697923f70961d82941a802f7d5544605e8ec3f6dea3312145cc0d5a8195`.

## Authority, selection and licensing boundaries

Only trusted, fresh VEX with exact package/version and required qualifiers can establish applicability. Red Hat and SUSE additionally require complete publisher-scoped containing-product context; a scanner distribution name/version cannot establish an enterprise product, module or edition. Versionless rows and missing context remain auditable evidence, not installed-product dispositions. Publication age is checked separately from acquisition health. Historical source-as-of demonstrations must not be presented as current fresh matches.

Supplemental advisories, NVD records, KEV exploitation and EPSS probabilities retain their own categories and provenance. They do not establish Not Affected or change scanner findings, compliance classifications, remediation policy or Cyber approval enforcement. SUSE `recommended` is not `fixed`. Current KEV/EPSS overlays require exact authenticated catalog membership; removed records remain history. The [read-only evidence API](supplemental-evidence-api.md) labels retained history and leaves current membership/applicability unevaluated.

Whole-document selection is explicit: Ubuntu uses a 512 KiB canonical cap and 10,000 expanded-statement limit; Red Hat uses 256 KiB; SUSE selects 2,048 recent available documents before its 1 MiB cap excludes 122. The manifest records technical exclusions, including Ubuntu's 19,830 oversized, 398 over-row-limit, 507 identifier/alias and 14 legacy-format exclusions; Red Hat's 12,003 oversized, 18 raw-member-bound and 411 duplicate-product-ID exclusions. These are adapter/resource limits, not vendor license restrictions. [Detailed Ubuntu cohort evidence](embedded-intelligence.md#bounds-and-ubuntu-size-decision) and the vendor reviews explain recoverable legacy formats and larger-cohort tradeoffs. No document is truncated to fit.

All selected inputs were acquired through public HTTPS without API credentials. [Access-path evidence](supplemental-source-research.md#access-paths-and-request-limit-evidence) distinguishes bulk archives, indexed downloads, unestablished numeric quotas and untested access for deferred providers. Acquisition locks retain original URLs, hashes, sizes and times. The release signature authenticates the CATS package; it does not claim independently verified signatures from every publisher.

[Attribution](../portal/app/embedded_intelligence_data/ATTRIBUTION.txt), pinned legal texts and [source-specific terms](../README.md#included-source-inventory) accompany the package; there is no common license over all sources. Share-alike obligations apply to covered Ubuntu/Alpine data and adaptations. FIRST permission and NIST conditions are recorded as named terms, not inferred open-source software licenses. The [RustSec clarification](supplemental-source-research.md#rustsec-license-file-clarification) records 15 CC-BY advisories/15 rows and 523 CC0 advisories/592 rows, including the upstream misfiled full-text discrepancy and the explicit declaration basis used for inclusion.

Deferred providers remain distinct from technical selection exclusions: [Microsoft MSRC](vendor-source-research.md#microsoft-msrc-deferred-no-records-bundled) needs an established feed-specific redistribution grant and reviewed product-ID mapping; [Chainguard/Wolfi](vendor-source-research.md#chainguardwolfi-conditional-data-licenses-no-records-bundled) has conditional OSV/SecDB terms whose eligibility/downstream rights for this bundle are unestablished, a separate current Libraries OpenVEX feed with an unestablished VEX redistribution grant, and exact identity/origin mapping work; [Debian](supplemental-source-research.md#debian-security-tracker-decision) lacks an established tracker-data grant in this review and needs source-to-binary mapping before applicability claims. None is described as having no feed or as universally prohibited. [Red Hat](redhat-csaf-evidence.md) and [SUSE](vendor-source-research.md#suse-included) reviews document official grants and exact product scopes.

## Reproduction and deployment

Use the normal portal dependencies plus `scripts/requirements-intelligence-build.txt`. Keep the exact acquisition cache and existing private signing key outside the checkout. From the repository root, replay the locked inputs into a review output directory:

```text
python scripts/build-embedded-intelligence.py --cache <external-cache> --private-key <external-private-key.pem> --output <review-output> --sequence 2026102001 --version 2026.10.20.1 --ubuntu-max-bytes 524288
```

Omitting `--refresh` uses verified cached bytes; adding it performs connected acquisition and requires renewed terms review if pinned evidence changes. Live URLs are mutable, so a fresh download does not reproduce this snapshot. Follow the [connected release procedure](embedded-intelligence.md#connected-release-procedure) to publish reviewed package output before building the normal image:

```text
python scripts/build-cats-release.py --scanner-base catscan-base:local --tag cats:<release-id> --cats-version <release-id>
```

For offline acceptance, use a disposable PostgreSQL 16 database with no external network, and the normal application image sharing its loopback network namespace. Configure `DATABASE_URL` explicitly with test-only credentials. Let the ordinary entrypoint import the embedded package into the empty database; do not mount intelligence data or manually perform the first import. Capture image identity, startup timestamps and peak container/process memory. After import, copy only the verifier into the test container and run:

```text
python /tmp/verify-embedded-intelligence.py --already-installed --report /tmp/expanded-acceptance.json
```

The verifier blocks non-loopback socket connections, measures repeat verification, queries exact database coverage/storage, and exercises real identities with wrong-context controls. Its output separates current freshness from historical diagnostics. See the [acceptance procedure](embedded-intelligence.md#reproducing-offline-acceptance); optional same-payload sequence-upgrade testing requires an external test signing key.

First import is synchronous and delays readiness. Plan timeout and disk headroom from measured database, index, WAL and temporary-storage behavior, not compressed size. Imports use one transaction; invalid/interrupted imports roll back while preserving prior committed evidence and administrator trust settings. Import failure is recorded but permits application startup to continue, so HTTP health alone does not prove successful intelligence installation, especially on a first deployment. Check Risk Intelligence package status. Reuse persistent database volumes; later signed sequences append/deduplicate history rather than resetting user data. Sources-page totals above its count bound are labeled lower bounds, separate from exact latest-package snapshot counts.

## Verification status and acceptance evidence

| Confirmed checks | Result |
| --- | --- |
| Broad Python suite, including classification | 412 passed; 10 PostgreSQL-dependent skips |
| Separate final PostgreSQL mixed suite, covering the skips | 33 passed |
| Risk Intelligence UI and TypeScript | 10 tests passed; TypeScript check passed |
| Scanner integration with real jq | 3 tests passed |
| Deployment topology / Compose checks | 6 passed |

These suites overlap; their counts must not be combined into a unique-test total. They do not replace full-corpus deployment measurements.

The cold-import benchmark and final hardened image contain the same signed payload. Both completed their stated checks; their separate image identities, timing scopes and limitations are recorded below.

## Exact coverage compared with the previous release

Historical performance figures are from the release report at commit `78a9012` and [retained baseline acceptance](evidence/embedded-intelligence-20261020/baseline-acceptance.json). The 600.28-second baseline was measured from startup-wait to startup-complete; the expanded cold measurement begins just before launching the container. No new baseline cold import or baseline memory measurement is claimed.

Both databases were counted with the same current verifier, at **2026-10-20T04:25:13.230656+00:00**. These are complete database counts, not samples. The baseline retains a same-payload sequence upgrade without duplicated evidence. Freshness is time-dependent; these numbers are a snapshot.

| Measurement | Previous release | Expanded release | Change |
| --- | ---: | ---: | ---: |
| VEX documents | 44,013 | 119,387 | +75,374 |
| VEX statements | 5,773,747 | 29,212,947 | +23,439,200 |
| Supplemental records | 44,098 | 672,810 | +628,712 |
| Unique VEX CVEs | 43,181 | 76,243 | +33,062 |
| Unique VEX product identities | 428,074 | 2,245,117 | +1,817,043 |
| Unique VEX CVE/product pairs | 5,773,747 | 25,631,947 | +19,858,200 |
| Unique CVEs across all categories | 71,599 | 397,207 | +325,608 |
| Unique product identifiers across all categories | 429,579 | 2,246,622 | +1,817,043 |
| Unique parsed package names | 17,254 | 198,764 | +181,510 |
| Versioned PURL statements | 5,773,747 | 24,741,386 | +18,967,639 |
| Rows satisfying freshness and identity preconditions | 2,905,511 | 10,501,630 | +7,596,119 |

The additional **7,596,119** rows satisfy source trust, verification, original publication freshness, nonwithdrawal and explicit-version preconditions. They are **potential applicability coverage, not unique resolved matches against deployed images**. Historical revisions and CVE/USN duplicates may overlap. Exact observed PURL/version, qualifiers and any containing-product context are still required; conflict handling can prevent a disposition. Only the real examples below establish actual evaluated matches. A `fixed` vendor statement is not proof that another installed version is fixed.

Unique package names count parsed PURL type/namespace/name, ignoring version, qualifiers and subpath. Supplemental names embedded inside original JSON without a normalized product PURL are not included. CVE/product pairs collapse repeated pairs, including rows with differing CSAF contexts; they do not count every distinct applicability condition. Supplemental records remain their original categories.

| VEX source | Unique CVEs | Unique product IDs | Package names | Versioned rows | Freshness/identity eligible rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| Canonical Ubuntu VEX | 57,981 | 2,002,561 | 176,360 | 23,252,990 | 10,379,724 |
| Red Hat CSAF VEX | 43,247 | 240,630 | 19,750 | 1,481,906 | 115,416 |
| SUSE CSAF VEX | 1,538 | 1,926 | 1,885 | 6,490 | 6,490 |

Red Hat contributes 115,416 currently eligible contextual rows; SUSE contributes 6,490. Those 121,906 rows require exact publisher-scoped CSAF containing-product evidence. Ordinary scanner distribution metadata alone cannot activate them. Ubuntu contributes 10,379,724 eligible rows. All 23,252,990 retained Ubuntu statements have explicit versions; Red Hat and SUSE also retain versionless evidence without treating it as an installed-version disposition.

| Status | Previous retained rows | Expanded retained rows | Previous eligible rows | Expanded eligible rows |
| --- | ---: | ---: | ---: | ---: |
| `affected` | 1,226,103 | 4,627,300 | 645,963 | 1,901,257 |
| `fixed` | 1,451,110 | 12,619,298 | 422,135 | 1,915,541 |
| `not_affected` | 2,170,970 | 9,979,355 | 981,466 | 4,783,680 |
| `under_investigation` | 925,564 | 1,986,994 | 855,947 | 1,901,152 |

Per-source status distributions, supplemental unique-CVE counts and all definitions are retained in [expanded-acceptance.json](evidence/embedded-intelligence-20261020/expanded-acceptance.json); comparison counts are in [baseline-coverage.json](evidence/embedded-intelligence-20261020/baseline-coverage.json). The full counting exercise took 995.24 seconds for the expanded database and 70.46 seconds for the baseline. These scans are acceptance work, not application request-path operations.

## Capacity, import and startup

| Measurement | Previous release | Expanded release |
| --- | ---: | ---: |
| Compressed intelligence payload | 69,661,506 B | 477,230,165 B |
| Decoded intelligence payload | 729,368,275 B | 8,070,632,870 B |
| Normal image size (local Docker inspect) | 1,254,131,741 B | 1,639,822,758 B (final) |
| PostgreSQL database size | 3,785,554,967 B | 24,329,468,951 B |
| Cold entrypoint-to-ready duration | 600.28 s | 2580.44 s (43.01 min) |
| Unchanged-package verification | 0.050 s | 0.548 s (final runtime) |
| Repeat normal-image startup to health | Not retained separately | 4.20 s |
| Portal cgroup peak memory | Not measured | 1,060,712,448 B |
| Portal PID 1 peak resident memory | Not measured | 1,048,168 KiB |
| PostgreSQL cgroup peak memory | Not measured | 3,223,199,744 B |

The expanded payload is 6.85 times the compressed baseline, database storage is 6.43 times, and cold startup is 4.30 times. Growth is not proportional to statement count. PostgreSQL database size includes retained application data and indexes, but excludes cluster WAL and transient sort/import disk peaks; these transient peaks were not measured. Allow additional disk headroom. Image sizes are local image sizes, not registry transfer sizes.

The environment was Docker Desktop 29.6.2 on x86_64, 28 visible CPUs and 16,618,557,440 bytes of Docker memory, PostgreSQL 16.15, a 4 GiB portal container and 3 GiB database container. PostgreSQL used 256 MiB shared buffers, 4 MiB work_mem and 64 MiB maintenance_work_mem; durability settings remained enabled. Cgroup memory includes cache and differs from process RSS; the PostgreSQL figure is not a measured database-server heap requirement. The shared host had other containers and some smaller checks running during import. The previous release did not retain memory measurements or a controlled identical-load experiment. These timings are observations, not production sizing guarantees.

The normal entrypoint automatically populated an empty PostgreSQL database with external networking disabled, no published ports and no intelligence mounts. The package state, exact installed rows and signed hashes were checked after HTTP health. No runtime download or manual first import occurred. The default Compose health-check start period is now 60 minutes, configurable with `CATS_INTELLIGENCE_START_PERIOD`, because the measured cold import exceeded the old 30-minute grace. Slower hosts may require a larger value. Readiness still waits for import; this change does not promise uninterrupted availability during first installation.

Image attribution is explicit:

- Cold import and full storage/count audit: `cats:embedded-vex-expanded-20261020`, `sha256:edd2993b80cf646690b83792476db1537dcdb44e984e7cb690e32718e33d303d`.
- Final hardened runtime and repeat startup: `cats:embedded-vex-expanded-final`, `sha256:9b001acbe697437fd6466e2ae568f2cb1633a08ca2ed8eaeb2d53760731525a8`.
- Both contain the identical signed payload above. The final image reused the imported database; no second cold-import measurement of the final image is claimed. Final changes include bounded runtime reads and package/worker identity hardening, covered by the automated and final runtime checks.

### Indexes and bounded execution

The 29.2-million-row statement table occupies 22,506,749,952 bytes including indexes/TOAST. Its four indexes total 1,796,988,928 bytes: primary key plus CVE, product ID and document ID. Exact lookup uses the existing indexed identity/CVE paths; installed definitions and an EXPLAIN plan are retained in the evidence. EXPLAIN estimates are not execution measurements. No speculative index was added solely to improve this one snapshot.

Import streams authenticated bounded payload parts and JSONL records, batches inserts, uses SQL-side document identity/counting instead of retaining every document ID in Python, and preserves one atomic transaction. Supplemental inserts use batches of 500; exact catalog membership queries use batches of 400 CVEs. Source/hash uniqueness and sequence checks preserve deduplication and revision history.

Assessment lookup binds exact CVE/product pairs, defers raw document text and fetches at most 10,001 candidates. Overflow returns `under_investigation` with `candidate_limit` rather than a partial exemption. The final smoke verified that behavior and restored its process-local diagnostic limit. The Sources handler uses bounded per-source probes and distinguishes exact counts from lower bounds. Package-status reads use JSON projections instead of loading full membership arrays.

## Real matching and final runtime verification

All three selected real vendor examples were fresh at the recorded evaluation time, including the SUSE example selected through the seeded fallback. The fallback selection label does not imply stale evidence: both current evaluation and the separately labeled source-publication-time diagnostic passed. These are exact package identities from vendor data, not assertions that those packages were scanned in the user deployment.

| Source | Real CVE and package | Required context | Current result | Final exact lookup |
| --- | --- | --- | --- | ---: |
| Canonical Ubuntu VEX | `CVE-2026-111458`; `pkg:deb/ubuntu/ssldump@1.3-2build1?arch=source&distro=jammy` | `distro=jammy`, `arch=source` | `under_investigation` | 11.13 ms |
| Red Hat CSAF VEX | `CVE-2026-73619`; `pkg:rpm/redhat/automation-controller@4.6.31-1.el9ap?arch=src` | Red Hat publisher; `cpe:/a:redhat:ansible_automation_platform:2` | `affected` | 7.04 ms |
| SUSE CSAF VEX | `CVE-2015-4588`; `pkg:rpm/suse/libwmf@0_2-7?upstream=libwmf-0:0_2-7.src.rpm` | SUSE publisher; `cpe:/o:suse:sled:15:sp5` | `not_affected` | 3.17 ms |

Wrong containing-product/distro context, wrong PURL and the worker wrong-version/package-digest controls returned `no_vex`. The worker test used real vendor package evidence with an explicitly synthetic containing-image digest, verifying that an OCI image digest is not substituted for a package digest. The final smoke calls the actual worker context helper/evaluator; it does not persist full assessment refreshes. Focused regression tests cover that refresh path.

Final snapshot examples also verified current authenticated KEV membership for `CVE-2026-102764` and EPSS 0.31392 for `CVE-1999-0077`; unknown CVEs remained unknown. These enrich risk display only. Source rules, freshness, membership, classification and enforcement boundaries were preserved.

Final package-status and Sources-handler calls took 290.3 ms and 295.6 ms; the catalog token took 40.2 ms. These are single local in-process handler timings after import, excluding HTTP transport/authentication middleware, not p95/p99 load tests. Exact lookup timings also exclude candidate discovery; discovery took 26-154 ms for these three examples. The old release's 19.15 ms lookup exercised stale evidence and is not an equivalent fresh-match benchmark.

The final runtime smoke passed, with no attempted prohibited outbound socket connections. Docker network isolation also prevented external egress. Its only database write was the expected unchanged-installer status timestamp. It verified the installed signed package, exact membership, bounded Sources responses, package-status projection, worker context, batch/single lookup agreement and conservative overflow. Python socket guards alone do not intercept every native-library call; the isolated container network is the deployment boundary.

## Evidence and remaining deployment validation

Raw sanitized measurements, SQL traces, retained test logs and reproduction helpers are in [the acceptance evidence directory](evidence/embedded-intelligence-20261020/README.md). No signing key, credentials or acquisition cache is committed. The build input lock and terms evidence support review/rebuild; live upstream URLs can change.

No automated failures remain in the reported final suites. The expanded signed payload was installed and read successfully offline; unchanged startup was verified with the final normal image. Corruption, rollback, downgrade, membership and ownership/compliance regressions are covered by tests; this final smoke did not perform another full-corpus sequence upgrade or a concurrent production scan workload. Validate deployment-specific disk/WAL headroom, cold startup budget, concurrency and observed SBOM product context in the disconnected environment. Preserve the database volume between releases. Main and the OCI feature branch were not changed; this work is committed only on `feature/risk-profiles-vex`, without push or merge.
