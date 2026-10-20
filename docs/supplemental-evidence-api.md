# Supplemental evidence browsing

Authenticated users with service-view access, or configuration-management access, can read retained supplemental intelligence. These endpoints do not mutate evidence or assessments. Sign-in and permission checks follow the existing risk API.

`GET /api/risk/records?cve=CVE-2026-12345` searches an exact uppercase CVE. Optional `kind` is one of `advisory`, `vulnerability`, `exploitation`, or `risk_enrichment`; `source_id` selects the numeric source ID. `limit` defaults to 50 and is restricted to 1–100. `cursor` defaults to 0 and selects record IDs greater than that value. Use the returned `next_cursor` with the same filters for the next page; null means no additional matching row was present. No wildcard or all-record search is exposed.

Each result contains its kind, supplemental category, source ID/name/enabled state, publisher record ID, product, acquisition time, source URL, hash, and `first_import_package_version`. Lists never load the publisher data object. Long summary fields are capped at 512 characters for the record ID, 2,048 for the product, and 4,096 for the source URL, with affected names explicitly listed in `truncated_summary_fields`.

`GET /api/risk/records/{id}` returns the same summary plus the retained `data` object, including original publisher content where the adapter stores it. Detail is restricted to an 8 MiB JSON response. A database byte-size predicate prevents loading oversized data; the complete encoded response is checked again. Oversized detail returns HTTP 413, a missing record returns 404, and invalid filters or bounds return 422.

All records are labeled `retained_history: true`, `current_package_membership: not_evaluated`, and `applicability: not_evaluated`. A record's package version identifies its first import, not proof of membership in the latest package. Earlier and disabled-source evidence remains available for provenance review. The assessment overlays separately verify exact current KEV/EPSS membership and freshness. Generic advisories never establish applicability or a VEX NotAffected decision; any publisher status under `data` remains supplemental source content.
