# Embedded intelligence distribution

CATS embeds a signed, sharded intelligence snapshot in the normal portal and unified application images. Startup imports that snapshot into the existing PostgreSQL database. There is no additional intelligence service, runtime feed synchronization, or external download requirement.

## Authority and actual coverage

This release includes **three authoritative VEX publishers**: Canonical Ubuntu, Red Hat, and SUSE. It also includes **ten supplemental datasets from nine publishers**: CISA KEV, Alpine SecDB, GitHub-reviewed advisories, SUSE recommendations, FIRST EPSS, NIST NVD, CISA Vulnrichment, Go, PyPA, and RustSec. CISA supplies two supplemental datasets; SUSE supplies both VEX and supplemental recommendations. Counts refer to the selected signed snapshot, not entire publisher archives.

Only trusted, fresh, exact product-specific VEX can establish applicability. Supplemental advisories, vulnerability records, exploitation evidence, and predictive scores stay in separate record categories. A published fix is not evidence that an installed package contains it. Missing intelligence remains unknown. Risk Profiles remain informational and do not change classification, remediation, publication, or Cyber approval enforcement.

The README contains the source inventory. Detailed source evidence, primary documentation, redistribution conditions, and exact adapter boundaries are in:

- [Red Hat acquisition and identity evidence](redhat-csaf-evidence.md).
- [SUSE, Microsoft, and Chainguard research](vendor-source-research.md).
- [EPSS, NVD, Vulnrichment, OSV, and Debian research](supplemental-source-research.md).
- [Read-only supplemental evidence API](supplemental-evidence-api.md).

### Product matching

Ubuntu CVE-primary documents retain their original vulnerability identity. An Ubuntu USN-primary document is expanded only from explicitly declared CVE aliases, with verified Canonical authorship, official document/advisory identifiers, Ubuntu product identities, and the adapter's required status. CVE relationships are never guessed from prose or USN numbering. The complete original document object, aliases, references, and timestamps are retained.

Red Hat and SUSE CSAF trees resolve package helpers and supported relationships into exact component PURLs plus containing-product context. Publisher namespace, product CPE/PURL helpers, version, architecture, epoch, qualifiers, and nested relationships remain significant. Unsupported relationships, missing parents, ambiguous helpers, cycles, and duplicate product identifiers cannot fall back to an unscoped assertion. A bare RPM name or matching version alone is insufficient.

The scanner retains its original bounded Grype PURL and distribution evidence. A scanner distribution name/version does **not** prove a CSAF enterprise product, module, or edition; CATS does not invent that mapping. Red Hat/SUSE applicability therefore remains unknown when required product context is absent. Versionless statements remain auditable evidence but cannot establish an installed-version disposition. Reported normalized counts must not be confused with currently fresh, context-available matches.

## Bounds and Ubuntu size decision

The previous 64 KiB limit was a conservative whole-document selection policy, not a format requirement. Increasing it also increases normalized rows and database indexes. The new default is **512 KiB**, configurable with `--ubuntu-max-bytes` from 1 KiB through 4 MiB. Included documents are complete; statements are not truncated.

Measured Ubuntu CVE-primary cohorts before the small unsupported-format exclusions:

| Canonical cap | CVE documents | Canonical bytes | Expanded product statements |
| --- | ---: | ---: | ---: |
| 64 KiB, previous selection | 44,027 | 615,415,873 | 5,774,215 |
| 128 KiB | 48,465 | 1,034,215,551 | 9,989,246 |
| 256 KiB | 49,607 | 1,221,997,072 | 11,882,487 |
| 512 KiB, new selection | 50,761 | 1,576,603,002 | 15,256,728 |
| 1 MiB, before per-document row limit | 56,904 | 7,056,677,704 | 67,252,582 |
| 2 MiB, before per-document row limit | 70,577 | 21,845,483,820 | 207,546,741 |
| 4 MiB, before per-document row limit | 70,581 | 21,858,735,405 | 207,678,760 |

At 512 KiB, the USN alias cohort adds 7,297 complete documents and 7,996,730 product/CVE assertions within the 10,000-expanded-statements-per-document bound. These can overlap CVE-primary evidence, so the acceptance report separately counts distinct CVE/product pairs. The 1 MiB CVE cohort adds roughly 52 million rows and 5.48 GB of canonical document content over 512 KiB, before indexing; this release selects 512 KiB while retaining a configurable path to larger reviewed releases.

The 507 USN identifier/schema exclusions were audited individually: 423 have no explicit CVE aliases; 67 use Canonical's legacy nested metadata with timezone-less timestamps; and 17 exceed the 1,000-alias bound and also exceed 10,000 expanded rows. Of the 67 legacy documents, 63 fit the size/row bounds, including 62 nonempty documents with 55,138 rows. Canonical's [official VEX documentation](https://documentation.ubuntu.com/security/security-updates/vex/) recognizes the nested format but does not establish a timezone convention. CATS retains strict timestamp validation rather than assigning an undocumented timezone. Recovering these rows needs a documented vendor time convention or an explicitly reviewed conservative timestamp policy. Relaxing the alias cap alone adds no eligible documents. The 14 unsupported CVE-primary records use the same legacy schema and account for another 468 rows; the recoverable legacy cohort totals 55,606 rows within the other bounds. These are precise adapter limitations, not claims that the publisher's documents are illegitimate.

Release acquisition streams archives without extracting paths. Ubuntu and Red Hat archives have aggregate member/byte limits and 32 MiB raw-member limits; Red Hat additionally bounds its zstd window. Red Hat selects complete canonical documents up to 256 KiB. SUSE selects 2,048 recent indexed and available documents, with a 1 MiB canonical bound and 2 GiB acquisition cohort budget. Supplemental adapters have explicit download, decompression, member, line, and record bounds. Strict JSON decoding rejects duplicate keys and non-finite numbers before canonicalization. Shared TAR guards bound PAX/GNU extension metadata to 1 MiB per header and 64 MiB per archive, 32 nested extensions and 256 PAX fields, and reject sparse entries before standard-library expansion.

The final distribution is bounded to **2 GiB compressed, 8 GiB decoded, and 8 MiB per JSONL record**. Its gzip stream is split into ordered **64 MiB parts** when necessary. The signed manifest authenticates every part's exact name, size, digest, ordering, and the complete stream digest. The loader reads across part boundaries with bounded buffers; it does not concatenate or decompress the corpus in memory. Existing single-file signed packages remain supported.

## Installation, updates, and availability

`app.embedded_intelligence.install_package` verifies Ed25519 signatures against the application-pinned release public key, validates the payload, then imports under a PostgreSQL advisory lock and one transaction. The manifest cannot supply its own trusted key. Authentication covers the bytes actually consumed during import as well as preflight verification. The signature authenticates the CATS release process, not an independent vendor signature; application images still require a trusted distribution channel.

The loader bulk-inserts normalized statements and batches supplemental records. A temporary indexed table tracks imported document IDs; source product counts are computed in PostgreSQL instead of retaining millions of product strings in Python. Assessment queries use exact CVE/product pairs and do not retrieve raw vendor documents. A batch can load at most 10,001 candidate statements; exceeding the 10,000-candidate limit returns explicit under-investigation uncertainty instead of drawing a conclusion from truncated history. Latest-revision metadata queries are chunked to 400 document keys. Existing indexed CVE/product lookups remain in use. Current KEV/EPSS membership comes from hashes derived during authenticated installation; removed records remain history but cannot silently reappear as current enrichment.

Identical sequence/content is verified and skipped. Older sequences cannot downgrade installed intelligence, and conflicting content at an installed sequence is rejected. New sequences append immutable evidence and deduplicate existing documents/records. Administrator source trust settings, Risk Profiles, existing assessments, Cyber decisions, and scanner evidence are preserved. An interrupted or invalid import rolls back completely; a separate failure status remains visible, and the portal can start with previously committed evidence.

**Initial import delays portal readiness until completion.** It is not a background warmup. Plan storage and deployment readiness timeouts from the measured full-corpus results below. Both normal Compose definitions default `CATS_INTELLIGENCE_START_PERIOD` to `60m`, following the measured 43-minute cold import. Slower storage or constrained hosts may need a longer override; this is a healthcheck grace period, not a guaranteed import deadline. Subsequent unchanged starts verify compressed bytes and skip normalization. Do not reset the PostgreSQL volume to update intelligence. Workers continue to use committed evidence; changed vendor data must arrive through a newer signed application release, not runtime Internet access.

The Sources page keeps latest-package snapshot counts separate from retained repository history, which includes earlier revisions and manual uploads. Retained statement totals are exact through 10,000 per source; larger sources show a lower bound of 10,001 and explicitly leave the total uncounted. Each count query stops at 10,001 rows instead of scanning millions of statements. Document totals remain exact. Status metadata is projected in the database so large KEV/EPSS membership hash arrays are not transferred or decoded for this page.

Freshness uses original document and score publication dates plus acquisition metadata, never deployment time. Downloading an old vendor document today does not make its applicability fresh. The source summary is acquisition health; individual assessment results also enforce original evidence age.

## Connected release procedure

Install normal portal dependencies plus `scripts/requirements-intelligence-build.txt` in the connected build environment. The latter provides bounded zstd archive decoding for Red Hat; the deployed loader consumes canonical gzip JSONL and does not download or decode provider archives.

Keep the acquisition cache and private release signing key outside the checkout. Reuse the existing release key; `--generate-key` is only for a first key, and replacing the public pin requires a reviewed rotation.

```text
python scripts/build-embedded-intelligence.py --cache <external-cache> --private-key <external-private-key.pem> --sequence <increasing-integer> --version <release-id> --ubuntu-max-bytes 524288 --refresh
python scripts/build-cats-release.py --scanner-base catscan-base:local --tag cats:<release-id> --cats-version <release-id>
```

Omit `--refresh` to rebuild entirely from the verified cache. The acquisition lock pins original input hashes, byte counts, URLs, retrieval dates, and available publication metadata. Retain that cache because live publisher URLs change. Canonical JSON, fixed gzip timestamps, deterministic signatures, and deterministic source selection make identical locked inputs/options reproducible. Reviewed licensing evidence is byte-pinned; changed terms or changed presentation require review rather than assumed permission. The builder publishes staged output only after success, with the manifest last. Build images only after it exits successfully.

Both normal Dockerfiles verify the signed package. The release private key must never be copied into the repository, package, or image. Source license texts and attribution notices accompany the data. Their obligations apply to the corresponding data and adaptations, not an invented common license over all sources.

## Reproducing offline acceptance

Use a disposable PostgreSQL 16 database container with networking `none`; start the normal CATS image sharing only that container's loopback network namespace. Use test-only credentials, no published ports, and no mounted intelligence files. The ordinary application entrypoint must populate the empty database without a manual import. Capture startup timestamps and container/process memory during the import, then verify `/health` and repeat startup against the same volume.

After automatic import, run the verifier inside the same offline image:

```text
python /tmp/verify-embedded-intelligence.py --already-installed --report /tmp/expanded-acceptance.json
```

Its `DATABASE_URL` must name the disposable loopback database. It blocks non-loopback socket connections, performs exact database aggregate counts, records storage/index sizes, tests each included VEX publisher with exact and wrong contexts, distinguishes current-time results from explicitly historical source-as-of diagnostics, measures KEV/EPSS lookup, and repeats package verification. A historical diagnostic is not evidence that a stale statement is currently usable. The optional `--upgrade-signing-key` exercise re-signs the same payload at a newer sequence and verifies deduplication and downgrade prevention; keep that private key outside production images.

## Measured release results

The signed manifest and the acceptance report provide the final measured inventory and performance for this release. Source-specific pre-package measurements above are not substitutes for the full database measurements. Historical baseline: 69,661,506 compressed payload bytes, 3,785,554,967 PostgreSQL bytes after a same-payload sequence upgrade, 600.28 seconds initial startup import, and 0.050 seconds unchanged-package verification. The earlier release did not measure peak memory. Hardware, Docker contention, dataset expansion, and indexing can make growth nonlinear.

The expanded release contains **119,387 VEX documents and 29,212,947 statements from three vendors**, plus 672,810 supplemental records. Exact counts found 76,243 unique VEX CVEs and 2,245,117 VEX product identities. At the audit time, 10,501,630 rows met trust/freshness/version preconditions; these are potential coverage, not resolved applicability to deployed images.

Measured offline cold startup was 2,580.44 seconds, PostgreSQL storage was 24,329,468,951 bytes and portal cgroup peak memory was 1,060,712,448 bytes. The final normal image restarted against that database in 4.20 seconds and verified the unchanged signed package in 0.548 seconds. Real current scoped Ubuntu, Red Hat and SUSE examples passed, with wrong-context rejection. See the [complete expansion report](embedded-intelligence-expanded-report.md) for baseline comparisons, image attribution, terms, exact source counts, memory/storage caveats and [reproducible evidence](evidence/embedded-intelligence-20261020/README.md).