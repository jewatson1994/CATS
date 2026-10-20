# Red Hat CSAF VEX acquisition and applicability evidence

Research date: 2026-10-19. This records the measured Red Hat input and adapter behavior; the signed release manifest remains the authority for the actual packaged cohort.

## Official data and redistribution terms

[Red Hat Security Data](https://access.redhat.com/security/data) explicitly licenses the linked security resources and alternate Security Data API representations under **CC BY 4.0**. Redistribution requires attribution to Red Hat and a link to the original. This is the security **data** grant, not a license inferred from software source code. The selected CSAF documents also contain the same explicit CC BY 4.0 legal disclaimer. The builder verifies the exact disclaimer before retaining each document, ships the downloaded licensing evidence and [full CC BY 4.0 legal code](https://creativecommons.org/licenses/by/4.0/legalcode.txt), and preserves each document's original URL. A changed licensing page or disclaimer requires review before the build continues. Attribution: Red Hat, Inc.; publication does not imply Red Hat endorsement of CATS.

Pinned downloaded evidence:

| Evidence | SHA-256 |
| --- | --- |
| `LICENSE-redhat.html` (Security Data page) | `a1fd756f9ebd470a2e197bf43357f28c67a4970e6953791716bbd53558e8bda5` |
| `LICENSE-redhat-CC-BY-4.0.txt` | `9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411` |

## Acquisition and measured limits

The [official original per-CVE VEX directory](https://security.access.redhat.com/data/csaf/v2/vex/) publishes `archive_latest.txt`, a dated tar.zst archive and its SHA-256 checksum. The downloaded locator selected `csaf_vex_2026-10-18.tar.zst`: **373,262,380 compressed bytes**, SHA-256 `50e6aa3cd24430a5e60c9f9ff7ada312e85375a43a112e73a884a509b0aeb7de`. The published checksum matched. The archive contains **71,849 documents, 22,159,788,284 original uncompressed bytes**. The separate [newer binary-RPM-aware VEX feed](https://security.access.redhat.com/data/csaf/v2/vex-feed/) advertised an approximately 825.9 MB archive at research time, exceeding this builder's 512 MiB acquisition bound. It is not silently substituted for the original feed.

The selected locator, archive and checksum were downloaded anonymously over HTTPS; no Red Hat account or API token was used. A numeric request quota for this static archive route was not established from the reviewed material. This is not a claim of unlimited capacity: refresh makes bounded release-time downloads, transport/throttling errors fail acquisition, and offline replay makes no network requests.

The acquisition lock retains the exact URL, SHA-256, byte count and acquisition timestamp of the locator, archive, checksum and license evidence. Reproduction uses those cached bytes. The adapter streams tar members without extraction, bounds the zstd window to 128 MiB, bounds archive members to 200,000 and declared decompressed member bytes to 64 GiB, and skips individual original members above 32 MiB. Only exact `year/cve-year-number.json` members are eligible. Duplicate JSON keys and malformed/ambiguous CSAF identities are rejected.

Measured canonical whole-document cohorts, before parser exclusions:

| Canonical cap per document | Documents | Canonical bytes |
| --- | ---: | ---: |
| 64 KiB | 36,789 | 470,378,806 |
| 256 KiB | 59,828 | 3,984,161,424 |
| 1 MiB | 69,148 | 8,562,755,015 |
| 4 MiB | 71,438 | 13,078,756,249 |

The 256 KiB adapter measurement retained **59,417 complete documents**, **3,936,932,742 canonical bytes**, and **5,589,493 normalized statements**. Of these, **1,481,906 statements** have versioned PURLs, across **15,912 documents**. All normalized statements require CSAF product context. The normalized subset covers **43,247 CVEs** and **240,630 distinct package PURLs**; 16,170 retained documents have no supported normalizable statement. Exclusions were 12,003 documents above the canonical cap, 18 original members above 32 MiB, and 411 documents with duplicate CSAF product IDs. No document's statements are truncated to make it fit. Canonical JSON retains the complete original object, while `upstream_sha256` records the original byte hash; whitespace is not preserved in the packaged object. The measured cohorts exclude the 18 members skipped before canonicalization. A future signed release may choose a different documented cap to stay within its overall package bound.

## Exact product context

The [official Red Hat CSAF VEX guide](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/docs/csaf-vex.md) describes component PURLs, product CPEs and relationships. A `default_component_of` relationship binds the component in `product_reference` to the containing product in `relates_to_product_reference`. A relationship's full product ID is publisher-local metadata, not a component PURL. Source RPM, binary RPM, architecture, epoch, release, module and product distinctions are retained; no equivalence is inferred.

`app.csaf_identity.csaf_products` resolves machine-readable helpers through branches and supported relationships, preserving parent and nested product helpers in `csaf_product_context`. The context includes the publisher namespace and a deterministic list of exact helper dictionaries. Missing parent helpers, contradictory composite helpers, unknown relationships, missing publisher context, cycles and duplicate product IDs cannot fall back to an unscoped component assertion. CPE-only products constrain relationships but do not become executable package identities.

Applicability requires the exact original PURL, exact version and exact complete contextual dictionary. The trusted authority scope is only `pkg:rpm/redhat/`; Red Hat assertions are not granted authority over another distribution, generic package names, Maven packages or OCI images by this adapter. Versionless assertions remain retained evidence and cannot establish an installed-version disposition. Missing or mismatched context remains `no_vex`; original document dates still determine stale evidence even when the archive was acquired recently.

Real samples downloaded and inspected:

- [CVE-2024-3094](https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-3094.json): versionless xz component identities demonstrate why product context and installed version cannot be assumed.
- [CVE-1999-0710](https://security.access.redhat.com/data/csaf/v2/vex/1999/cve-1999-0710.json): fixed relationship for `pkg:rpm/redhat/squid@2.5.STABLE3-6.3E.13?arch=i386&epoch=7`, constrained to publisher `https://www.redhat.com` and CPE `cpe:/o:redhat:enterprise_linux:3::as`. The document's current release date is 2026-01-08, so the default 30-day policy treats it as stale at the research date. It is suitable for exact-context tests at a historical evaluation time, not evidence of present freshness.

## Scanner evidence and verification

The portal report retains Grype's original package PURL when it is a `pkg:` string no longer than 1,500 UTF-8 bytes, and retains the original distribution object as `scanner_distro` when its JSON representation is at most 4 KiB. Over-limit or invalid values become null instead of being truncated into another identity. `scanner_distro` is deliberately distinct from an exact PURL `distro` qualifier. A distribution name/version does not establish a Red Hat product CPE or module identity, so the scanner does not fabricate `csaf_product_context`.

Focused tests cover contextual isolation, wrong vendor/product/version, nested product context, unsupported and ambiguous identities, exact raw document retention at ingestion, whole-document size selection, changed licensing terms, unsafe tar names, archive limits and actual scanner JSON transformation. The real downloaded archive was decoded with the configured window bound and an original versioned example was parsed successfully. Offline normal-image installation and final runtime verification passed; the [release report](embedded-intelligence-expanded-report.md) records exact coverage, image identities and evidence. The current fresh Red Hat example is CVE-2026-73619 / automation-controller 4.6.31-1.el9ap with the exact Ansible Automation Platform 2 containing-product context. The older squid example above remains a historical diagnostic; it is not used as proof of current freshness.
