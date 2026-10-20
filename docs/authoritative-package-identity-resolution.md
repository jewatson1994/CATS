# Authoritative package identity resolution and VEX applicability

Implementation and audit date: 2026-10-20. Branch: `feature/risk-profiles-vex`; starting commit: `745ffd99172bd46ab2a67d2f5a6df54465e1b320`.

## Result

CATS now retains installed package-database provenance, derives bounded Debian/Ubuntu identities from that evidence, evaluates them alongside the original identity, and exposes the full relationship chain in Risk Intelligence. The seven-image rerun produces **595 eligible additional identities across 319 observations and 119 of 483 findings (24.6377%)**. It still produces **zero applicable VEX statements**. No scanner finding was suppressed, resolved, or rewritten to increase coverage.

The next limitation is the retained vendors' coverage of the actual installed products and versions. Package identity normalization alone cannot create those statements. The unchanged corpus has 119,387 VEX documents, 29,212,947 statements, 2,245,117 products and 13 total intelligence sources. No corpus rebuild or new feed was needed for this implementation.

## Audit method and denominators

The baseline is the committed [container audit](container-vex-applicability-audit.md) and its [evidence manifest](evidence/container-vex-scans/README.md). The new [reproducible evidence](evidence/authoritative-package-identity/README.md) includes per-observation classifications, per-finding unions, vendor statement identifiers, bounded raw-document examples, code/input hashes and query plans. `scripts/audit-package-identity.py` performs read-only analysis against the actual populated PostgreSQL repository.

The primary samples remain the same immutable Ubuntu, Debian, Alpine, UBI, SUSE, Python and Node images. They contain 971 component occurrences, 957 valid nonempty PURLs, 1,118 scanner observations, 1,069 distinct CVE/package/version/PURL tuples, and 483 distinct service finding IDs. A service finding is deduplicated by its scanner vulnerability ID; multiple packages and images can belong to it. Image and multi-cause totals overlap.

All 35 selected raw files were checked against retained hashes. Every one of the 1,118 observations joined the raw Syft/Grype artifact by the recorded artifact identity and exact package tuple. The new projection recovers existing evidence; it does not edit raw files or rescan changed images. The after evaluation uses the baseline's exact time, `2026-10-20T05:40:57.930104+00:00`, so source ageing is not mistaken for a resolver effect. A later deployment must apply its actual current freshness checks.

### Exclusive primary barriers

Each observation has one most-specific demonstrated barrier. Each finding receives the most-specific verified barrier among its observations. These are diagnostic categories, not applicability shortcuts. Percentages below use 1,118 observations and 483 findings respectively.

| Primary barrier | Observations | % | Findings | % |
| --- | ---: | ---: | ---: | ---: |
| CVE/verified alias absent from the entire corpus | 1 | 0.0894 | 1 | 0.2070 |
| Installed vendor/ecosystem has no covered publisher namespace | 497 | 44.4544 | 205 | 42.4431 |
| CVE absent from the matching vendor's retained statements | 491 | 43.9177 | 194 | 40.1656 |
| Required containing-product context unverified | 58 | 5.1878 | 47 | 9.7308 |
| Installed package/source version has no matching vendor version | 71 | 6.3506 | 36 | 7.4534 |
| **Total** | **1,118** | **100** | **483** | **100** |

There are zero exclusive cases attributed solely to source/binary naming, architecture, distribution/release, another PURL qualifier, an otherwise missing named vendor product, or another verified identity difference. This does not prove all such attributes match: a stronger verified coverage/version/context barrier takes precedence. The corpus-absent finding is `GHSA-3xgq-45jj-v275`, with alias `CVE-2024-21538`, for `cross-spawn@7.0.3`.

### Overlapping identity differences and provenance gaps

The evidence also preserves every demonstrated mismatch instead of forcing all failures into source/binary mapping. These rows overlap and must not be added together.

| Demonstrated difference | Observations | % of 1,118 | Findings | % of 483 |
| --- | ---: | ---: | ---: | ---: |
| Package version difference among named vendor candidates | 76 | 6.7979 | 41 | 8.4886 |
| Source/binary identity difference | 81 | 7.2451 | 50 | 10.3520 |
| Distribution qualifier representation difference | 125 | 11.1807 | 79 | 16.3561 |
| Upstream/source qualifier difference | 122 | 10.9123 | 80 | 16.5631 |
| Versionless product with unverified vendor context | 53 | 4.7406 | 42 | 8.6957 |

The matching-vendor CVE absence category touches 491 observations and 220 findings (45.5487%) when unioned without exclusive precedence; unsupported vendor/ecosystem coverage touches 497 observations and 285 findings (59.0062%). This explains why these union counts differ from the primary-barrier table.

All 868 Debian/RPM observations (77.6386%) lacked installed-database authority fields in the old bounded projection. Those fields were present in the hash-verified raw evidence for all 868. They were **present but discarded during projection**, not unavailable at the scanner. Separately, 53 Debian observations had an empty source name and 310 an empty source version. The retained Syft parser explicitly represents omitted Debian Source fields this way; Debian policy defines same-name/same-version defaults. These are not 53 missing source relationships.

For the 549 RPM observations (49.1055%), retained source-RPM relationships do not prove source epoch and the complete containing-product/module/edition context. They remain ineligible for derived VEX applicability. Source filenames omit epoch; the binary epoch cannot be copied to the source package. Missing publisher product evidence is reported explicitly.

No individual unmatched finding is attributed to a particular acquisition exclusion without a document-level proof. The existing build recorded Red Hat size/duplicate exclusions and SUSE size exclusions, but their aggregate counts do not establish the cause of any specific absent vendor/CVE relationship. Here, “absent from retained vendor statements” is the defensible result; “vendor has never published a statement” is not established.

## Authoritative sources and licensing

| Evidence source | Authority and use | Scope and redistribution |
| --- | --- | --- |
| Installed `/var/lib/dpkg/status`, observed by Syft's `dpkg-db-cataloger` | Binary package, version, architecture and explicit source package/version. [Debian Source policy](https://www.debian.org/doc/debian-policy/ch-controlfields.html#source) supplies omission semantics; [Syft 1.31.0 parser](https://github.com/anchore/syft/blob/v1.31.0/syft/pkg/cataloger/debian/parse_dpkg_db.go) establishes how the captured fields were emitted. | Local image evidence, not a newly redistributed vendor repository. Five bounded retained test records carry image digests, capture provenance and raw SHA-256. No Debian/Ubuntu index is acquired or bundled. |
| Installed OS release metadata and package PURL | Confirms namespace, release, codename and architecture already observed in the image. [Deb PURL definition](https://github.com/package-url/purl-spec/blob/main/types/deb-definition.json) documents qualifiers. | Never maps Debian to Ubuntu, enumerates security/ESM pockets, or invents a missing release. Known release facts are contradiction checks, not missing-data defaults. |
| [Canonical Ubuntu VEX](https://documentation.ubuntu.com/security/security-features/vex-sbom/) | Publishes both binary and source identities. For example, [CVE-2023-23916](https://github.com/canonical/ubuntu-security-notices/blob/main/vex/cve/2023/CVE-2023-23916.json) includes source `curl` with `arch=source` and binary curl/libcurl packages. Literal epoch and codename spelling are retained. | Existing data is [CC-BY-SA-4.0](https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE); existing original documents, notices and source attribution remain bundled. Documentation licensing is not substituted for data licensing. |
| Installed RPM metadata, source-RPM filename and NEVRA | Records a diagnostic binary-to-source relationship. [RPM tag documentation](https://rpm-software-management.github.io/rpm/manual/tags.html) distinguishes source RPM from epoch/version/release. | Does not prove a source epoch, RHEL module, subscription product, Ansible edition, SUSE service pack or containing-product identifier. No derived RPM exemption is emitted. |
| [Red Hat CSAF product relationships](https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/) and [SUSE CSAF](https://www.suse.com/support/security/csaf/) | Existing evaluator requires publisher-scoped product context in addition to exact package identity. | Existing Red Hat and SUSE security-data grants are CC-BY-4.0 with retained attribution/notices. This change introduces no new acquisition or redistribution source. |

A vendor PURL containing a package name is not proof that every installed package with that name belongs to the vendor product. UBI labels cannot establish an enterprise module or Ansible product. SUSE BCI distribution metadata cannot establish a different SLE product/service-pack context. Alpine, Wolfi and language ecosystems keep direct exact evaluation; unsupported derived resolution is explicit.

## Implementation

### Resolver and evidence chain

`portal/app/package_identity_resolution.py::resolve_package_identity` is a reusable, offline, deterministic resolver. Its version is `cats-package-identity/v1`. The original observed identity is copied intact into the resolution record, and derived candidates are separate objects. Each carries the method, publisher scope, eligibility, validity bound and provenance steps: source/path, scanner descriptor/version, observation time and supporting values. Reassessment recomputes candidates from observed evidence, never from an earlier resolution object.

The resolver requires an exact installed-record tuple, verified database metadata type/cataloger/primary location, image digest, architecture and distribution evidence. Each supplied artifact is bounded to 64 KiB. It preserves Debian/Ubuntu namespaces, binary/source version differences, epoch, rebuild suffixes and source-version qualifiers. Ubuntu codename representation comes from the installed OS record. Unknown qualifiers or pockets are not silently discarded.

An actual Debian `bash` binary `5.2.15-2+b7` retains source version `5.2.15-2`. An actual Ubuntu `bsdutils` binary `1:2.37.2-4ubuntu3.5` retains source `util-linux` version `2.37.2-4ubuntu3.5`; a binary epoch is not imposed on the source. Empty fields are accepted only when the verified parser supplied the documented omission representation. Conflicting source records, architecture, versions, namespaces or release metadata block the corresponding relationship.

The explicit outcomes are `exact_observed_identity`, `authoritatively_resolved_identity`, `multiple_valid_candidate_identities`, `insufficient_identity_evidence`, `conflicting_authoritative_metadata`, `unsupported_ecosystem`, `stale_mapping`, and `no_verified_relationship`. Multiple candidates are separately proven identities, not fuzzy alternatives. Candidate expansion is capped at eight total resolver identities. Incomplete relationship metadata alone does not invalidate an independently complete direct exact match; confirmed contradictions in the observed installed tuple retain uncertainty. Validation examines present fields independently across every supplied installed record before returning for missing source fields, stale metadata or other relationship-only gaps. Malformed location entries cannot hide a valid installed-database record, and missing fields are distinguished from contradictory values. These checks prevent a partial record or record ordering from hiding a later contradiction.

### Scanner ingestion

`scanning-main/scripts/report-to-portal.sh` retains bounded package database fields, metadata type, cataloger, primary location, scanner/SBOM descriptors, source relationships and original distribution metadata. `sbom_identity.py` preserves corresponding metadata through Syft, CycloneDX and SPDX extraction. `portal/app/schemas.py` allows the bounded ingestion fields. Scanner identity, aliases, original versions and fix information remain unchanged.

No missing Syft acquisition timestamp is fabricated. Recorded Grype timestamps and scan execution time are kept distinct. The risk worker supplies the execution's scan time and policy freshness deadline. The same retained metadata is verified with scanner tests for generated formats and report payloads. Real Trivy vulnerability scanning remains unverified because the retained offline environment lacked its vulnerability database; format tests do not claim otherwise.

### VEX evaluation and safeguards

`portal/app/container_intelligence.py::evaluate_container_batch` resolves observed evidence and passes eligible additional candidates to `portal/app/vex_intelligence.py::evaluate_batch`. The original direct identity remains included. Exact `(CVE, product_id)` lookups are grouped, indexed and bounded. Alias completeness, document revisions/withdrawals, publisher authority, freshness, product scope and status conflicts still apply.

Canonical-derived identities require a Canonical-scoped source URL and configured allowed host, including repository/path checks for GitHub. A generic GitHub hostname is insufficient. Debian-derived identities remain in the Debian namespace and cannot consume Canonical's Ubuntu statements. RPM diagnostics cannot become derived containing-product assertions.

Direct and derived accepted statuses are merged conservatively; disagreement is surfaced as a conflict. Expired/malformed mapping validity, withdrawn/stale evidence, incomplete aliases and overflow cannot manufacture a safe outcome. `Fixed` requires exact installed-version applicability and remains evidence; it does not resolve the scanner finding. Original findings and compliance/Cyber/OCI decisions are unchanged.

The internal evaluator also bounds extra candidates to eight, queries at most 1,000 pairs per statement fetch, limits materialized VEX rows to 10,000 plus an overflow sentinel, and batches revision lookups by 400 document keys. Original document bodies are deferred from assessment queries. Per-batch pair dictionaries prevent repeated full result scans. The resolver performs no database or external request; no persistent mapping cache is necessary for the bounded local transformations.

### Storage, invalidation and UI

No database schema or migration is added. Existing observation evidence and immutable assessment detail/provenance store the new fields. `risk_worker.py` records assessment algorithm 3 and the resolver version. `risk_profiles.py::latest_assessment` marks older/different resolver versions stale so users can reassess; historical assessments are not rewritten. Source/catalog/policy revisions and scan freshness continue to invalidate current results.

`portal/frontend/src/features/risk_coverage.tsx` shows original and derived identities, method, provenance source/version/time, supporting evidence, eligibility, rejection reasons and retained relationships. Coverage separates direct/derived candidate statements, eligible derived identities and accepted direct/derived statements. Candidate or identity counts are not labelled as applicable VEX. Historical assessments lacking these metrics show that they were not recorded. Risk Profiles remain visual-only.

## Before and after

| Metric | Baseline | After |
| --- | ---: | ---: |
| Distinct service findings | 483 | 483 |
| CVE/alias represented anywhere in corpus | 482 | 482 |
| Original direct exact VEX candidate rows | 0 | 0 |
| Eligible additional identity occurrences | Not implemented | 595 |
| Observations with eligible additional identities | Not implemented | 319 (28.5331%) |
| Findings with eligible additional identities | Not implemented | 119 (24.6377%) |
| Exact VEX candidate rows through derived identities | Not implemented | 0 |
| Applicable VEX / Not Affected / Affected / Fixed / Under Investigation | 0 each | 0 each |
| Stale/conflicting applicable evidence | 0 | 0 |
| Findings without applicable VEX | 483 | 483 |
| Current advisory-only findings | 111 | 111 |
| EPSS findings / affirmative KEV findings | 483 / 0 | 483 / 0 |

All 1,118 after observations have `no_vex`, not an invented Under Investigation statement. Resolver outcomes are 276 multiple-identity, 43 single-resolved, 250 unsupported-ecosystem and 549 no-verified-RPM-relationship. The new unresolved-relationship coverage flag affects 259 findings; the old zero did not measure these relationship gaps. That metric expansion is not a loss of previously applicable VEX.

All 71 Ubuntu observations still lack an exact vendor statement for the installed binary/source version after verified epoch/codename/source normalization. Debian relationships are useful, but the existing three-publisher corpus has no Debian VEX publisher. UBI/SUSE evidence is constrained by actual vendor-CVE coverage and complete product context. No intelligence was added, so any identity gains above come only from retaining and resolving existing scan evidence.

## Performance and verification

Final measurements, exact commands, test counts and release identity are recorded below and in the accompanying evidence. Real corpus workloads and controlled positive fixtures are kept separate; repeated observations are scale workloads, not additional scanned images. PostgreSQL plan evidence must show indexed pair/presence access; diagnostic near-product analysis is not part of normal assessment.

The real corpus benchmark includes VEX, advisory, KEV and EPSS evaluation, in batches of 250, with PostgreSQL-enforced read-only access. It uses the same retained observations; the 10,000-observation workload repeats those records. The resolver and evaluator source hashes match the final release. These are single warm/unknown-cache measurements on a shared host where background verification may affect latency, not cold-start or production capacity guarantees.

| Real-corpus workload | Observations | SQL statements | Wall time | Sampled Python RSS |
| --- | ---: | ---: | ---: | ---: |
| Single finding | 1 | 7 | 0.010459 s | 249.07 MiB |
| 1,000 observations | 1,000 | 28 | 0.733479 s | 255.96 MiB |
| 10,000 observations | 10,000 | 280 | 7.464165 s | 269.52 MiB |
| Seven images in one service | 1,118 | 35 | 1.021068 s | 270.30 MiB |
| Four concurrent assessment batches | 4 x 1,000 | 112 total | 3.043648 s total | 290.76 MiB shared |

RSS includes Python and previously materialized diagnostic/input data. Concurrent jobs share one process; RSS and process CPU cannot be summed per job. Database CPU and memory were not measured. These workloads measure the assessment evaluator, excluding complete worker persistence/classification and UI requests. Query counts scale by batch, not per finding. Real-corpus pair and CVE-presence plans use indexes and bounded limits, with zero VEX sequential scans. The prior audit's smaller projection/process and cache state differ; these timings do not establish a controlled before/after speedup or slowdown.

A separate, rolled-back PostgreSQL schema supplies **synthetic positive statements** for an actual retained Ubuntu identity. One derived positive took 0.006365 s (2 SQL statements). A 10,000-statement positive set took 0.958041 s (2 statements); 10,001 statements triggered `candidate_limit` and `under_investigation` in 0.847795 s (1 statement), with zero returned accepted statements. A direct/derived disagreement remained `conflicting` in 0.003493 s (2 statements). Indexed LIMIT query plans and schema-removal confirmation are retained. These cases validate positive behavior and limits; they are not claimed as real-image coverage.

Verification:

- Backend: **750 passed, 16 skipped**, including all **21 classification regressions**, 226 resolver/integration cases and 142 container-intelligence cases. The skips are opt-in PostgreSQL cases, handled separately below.
- Scanner: **20 passed** using retained package metadata and report/SBOM formats; shell syntax passed.
- Frontend: **49 files / 342 tests passed**; TypeScript and changed-file ESLint passed. Existing nonfatal jsdom `scrollTo` warnings remained. Full repository ESLint still reports the two unchanged unused variables `planning` / `setPlanning` at `remediations.tsx:242`; that file is identical to the starting commit.
- PostgreSQL 16.15: **30 passed**, covering risk/VEX, package membership/import/upgrade, concurrent durable-job leases, consistent export snapshots and six service-bundle cases. The same service-bundle cases also passed on SQLite (**6 passed**, separate run). Two raw-trigger fixture failures and one cyclic-foreign-key teardown error reproduced on extracted, unchanged `745ffd9` (13 passed, 2 failed, 1 error). Three test-only fixtures now use a schema-specific connection search path and reflected constraint names; assertions and production models are unchanged. Disposable databases were removed, with retained corpus counts unchanged. [Baseline and corrected evidence](evidence/authoritative-package-identity/verification/README.md) include the errors and commands.
- Release: built `cats:authoritative-identity-final`, CATS version `2026.10.20.3`, image ID `sha256:7a6a94e2c7d741d91b1dc7d6a5d3d40ca40de05a8aeb7ea840b60e8ffc013fc9`, on the existing offline scanner base. Network-disabled checks verified 12 packaged source hashes, five retained positive metadata cases, five rejection cases, signed intelligence, bundled tools/Grype database and Helm/Trivy configuration scanning (37 findings). Thirteen source files remained unchanged through the build/check window; 27 pre-existing containers remained unchanged and no temporary containers remained.

The signed embedded payload is unchanged: SHA-256 `91235078016fa5245c98d9c651ae4dfa9e5fd0e55220cc221ad74b4c98e61a6e`, sequence `2026102001`; manifest SHA-256 `dcb38c60838d0ce5d07489f6b2cfa3630422cb1ef434922cf6a8eab9a25edf3c`. A full 29.2-million-statement cold import was not repeated. The release uses embedded Trivy configuration checks; real Trivy vulnerability scanning remains outside the verified scope because its offline vulnerability database is absent.

[Verification evidence and commands](evidence/authoritative-package-identity/verification/README.md) record the separate test/build boundaries. Protected branch references and existing corpus/raw-evidence hashes are checked before commit. No production classification, Cyber approval, publication/remediation, or OCI gateway enforcement code was changed; the classification and risk regressions passed. This is preservation evidence, not a fresh disconnected Harbor/OCI end-to-end deployment test.


## Remaining coverage gaps and next steps

1. For Canonical, investigate whether the vendor provides exact historical installed-version statements beyond the retained document set. Do not reinterpret a statement for a fixed/newer version as covering an older installed binary.
2. For Red Hat and SUSE, obtain authoritative image/product membership, module/edition/service-pack and source-epoch evidence before adding containing-product resolution. A source RPM alone is insufficient.
3. Review Debian, Alpine/Wolfi and additional ecosystem-specific applicability sources and their data redistribution grants independently. A shared package name or CVE is not cross-distribution authority.
4. Trace excluded vendor documents to individual missing product/CVE tuples before changing corpus size limits. Preserve complete documents and existing signed import/rollback rules.
5. If external mapping indexes become necessary, acquire only the bounded official metadata required during the connected signed intelligence build, retain versions/hashes/license notices, and import through the existing PostgreSQL package mechanism. No separate runtime service or administrator download should be required.

The implementation makes authoritative relationships usable and reviewable offline. The measured real sample establishes improved identity coverage, not a positive VEX exemption rate. Controlled positive and negative regressions demonstrate the evaluator path without misrepresenting them as real scanner/vendor matches.
