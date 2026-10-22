# Artifact catalog loading repair

Baseline: origin/main `825b75cd30b4a22138bf29480741faa66f9ae008`.
Repair branch: `fix/artifact-catalog-loading`.

## Root cause and repair

The deployed catalog request raised `jinja2.exceptions.TemplateNotFound: artifact_catalog.html` through `catalog_page` and `FrontendTemplates.TemplateResponse`. React implements this page, but the backend migrated-page registry omitted it. The request failed before catalog queries. The same omission affected artifact recommendations and patch campaigns; commit 339fbd4 also contains the omission, so source inspection establishes that it predates enterprise UI modernization.

Register all three existing React pages in `portal/app/frontend.py`. Project only public service and registry fields needed by recommendations and campaigns. No database schema, authorization, eligibility, or lifecycle engine changes are required.

## Verification

- Backend targeted regressions: 116 passed, 1 skipped. Includes frontend bootstrap, artifact catalog, patch catalog integration, PostgreSQL catalog, release revisions/signing and OCI lifecycle tests.
- The skipped encrypted-key test requires a locally installed Cosign executable (`CATS_TEST_COSIGN`).
- Dedicated real PostgreSQL test uses separate temporary application and intelligence databases: empty catalog, 27 unique artifacts, one artifact shared across two services, pagination, search escaping, service scoping and conservative eligibility passed. Other targeted tests use their existing fixtures; these are not all PostgreSQL tests.
- Frontend: 418 tests passed across 61 files; typecheck and production build passed.
- HTML and page-JSON response tests cover all three repaired pages without legacy templates, including credential exclusion and required bootstrap context.

Reproduce backend checks with the project's Python environment, `PYTHONPATH=portal`, and `CATS_TEST_SPLIT_POSTGRES_URL` pointing to an isolated PostgreSQL server:

```powershell
python -m pytest portal/tests/test_frontend.py portal/tests/test_artifact_catalog.py portal/tests/test_patch_catalog_integration.py portal/tests/test_catalog_loading_postgres.py portal/tests/test_release_revisions.py portal/tests/test_release_signing.py portal/tests/test_oci_lifecycle.py -q -rs
```

## Limits

The original browser failure and server traceback were observed. Fixed rendering was verified by response tests; an authenticated post-fix browser walkthrough was not completed. The catalog uses cards, so table resizing, sorting and autofit were not verified. This repair does not add a complete lineage/signature/release detail browser to the catalog. Existing lifecycle regression checks do not constitute a new real patch/sign/publish acceptance run. No production deployment, push or merge was performed.
