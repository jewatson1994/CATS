# React frontend: development and acceptance checks

## Architecture

The 43 portal page types now render native React components, sharing the existing CATS stylesheet and branding. Legacy Jinja page templates and page-specific imperative scripts are removed. FastAPI continues to own URLs, authentication, permissions, forms, jobs, evidence, exports, and persistence. No database migration is required.

Page GET requests with `Accept: application/vnd.cats.page+json` return a versioned envelope (`schemaVersion`, `page`, `data`). Normal GET requests receive the same safe data in an escaped bootstrap script and load the locally built assets. Explicit Python projections allowlist fields; ORM objects, credentials, raw HTML and arbitrary audit metadata are not serialized. Responses are private/no-store and vary by Accept.

Cookies remain HttpOnly. Native POST forms preserve server-issued CSRF tokens and backend validation, redirects, multipart uploads and permission checks. React controls are conveniences, not authorization. Export, artifact and authentication links retain native navigation. Page and job requests abort when their scope changes. Architecture polling accepts a selected `view_version`, and the server rejects unknown releases and isolates their execution/revision evidence.

## Build and checks

Use Node 24.19 and pnpm 11.19. From `portal/frontend`:

```text
pnpm install --frozen-lockfile
pnpm exec tsc --noEmit
pnpm exec eslint src vite.config.ts --max-warnings 0
pnpm exec vitest run
pnpm build
```

Assets are generated in `portal/app/static/frontend` and are ignored by Git. Start the Python portal only after building. If assets are missing, the portal gives an explicit 503 build message. Both Dockerfiles build the frozen frontend dependency tree in a separate Node stage; the final Python image contains assets but no Node runtime. Existing branding and `app.css` remain separate local assets. For an offline build, populate the pnpm store beforehand and use `pnpm install --offline --frozen-lockfile`; a fresh offline machine still needs that dependency cache or a prebuilt image.

Run the backend suite from the repository root:

```text
.venv/Scripts/python -m pytest portal/tests -q
```

On Linux, replace `.venv/Scripts/python` with `.venv/bin/python`.

## Verification handoff (2026-09-30)

- Frontend: 57 tests across 17 files pass; TypeScript and ESLint pass; production Vite build passes (125.70 kB gzipped application bundle).
- Backend: the complete portal suite passes with 667 passed, 1 skipped and two FastAPI lifecycle deprecation warnings.
- Frozen offline dependency installation passed with the populated local pnpm store.
- Browser checks on a disposable local database covered authenticated dashboard, scan, SBOM and patch rendering, direct reload, back/forward navigation and a clean console. No real scan or patch job was submitted.
- Docker is unavailable on this PC; container builds, real registry scanning and Kind acceptance remain unverified.

## Manual acceptance checklist

Use a disposable database and test services; do not test destructive actions against production evidence.

- [ ] Build the image, start it without frontend internet access, and verify all fonts, scripts, styles and branding load locally.
- [ ] Sign in/out; verify required password change, expired sessions, failed sign-in and direct URL refresh.
- [ ] Compare administrator, manager and restricted accounts: invisible controls, direct forbidden URLs and forged POSTs must remain forbidden.
- [ ] Create/edit a service, search/filter/sort/paginate the dashboard, and verify archive approval and service/group scope.
- [ ] Verify `Version:` stays static, the configured number opens historical versions, and unconfigured services show `Unknown`.
- [ ] Open two services and releases in succession; use back/forward and refresh. Findings, graphs, validation, artifacts and polling must never retain another scope's evidence.
- [ ] Compare simplified/raw findings; request an exception, POA&M and mitigation for the intended CVE. Review, revoke and close records with approved roles.
- [ ] Download individual POA&M, PPSM, assets, findings, mitigation, SBOM, diagrams, all-workbook and authorized portable bundle exports; inspect contents and service/version scope.
- [ ] Exercise public image, Docker archive, Helm archive/repository/OCI and service-definition scans; inspect partial acquisition failures, cancellation, elapsed time, completion and result downloads.
- [ ] Exercise SBOM and patch workflows, queued/running/error/cancelled states, and missing or expired jobs. Confirm refresh and temporary result retention behavior.
- [ ] Remove missing evidence, then retry from a stale page; verify the warning and that newer evidence is not removed.
- [ ] Verify static scan completion is independent of runtime validation. Test disabled Kind, queued validation, success, partial verification, failure and immutable historical runs.
- [ ] Exercise architecture zoom/pan/fit, node keyboard focus, details, differences, declared/runtime tabs, resizing and layout persistence. Confirm selected-release isolation.
- [ ] Import/edit/export service definitions and chart catalogs; test spreadsheet exchange, preview errors, designer controls and purpose-specific templates.
- [ ] Run a remediation and inspect before/after comparisons, stages, logs, validation, candidate downloads and retry behavior.
- [ ] Exercise admin users/groups/services, staging, requests, audit, configuration, policy, compliance, framework and dependency-watchlist pages with allowed/denied roles.
- [ ] Check desktop/mobile layouts, keyboard navigation, dialogs, empty/error/loading states and browser console; verify no external frontend resources or credential leakage.

Automated tests cover component behavior, page projection security, scope cancellation and backend workflows. Real registry downloads, image scanning, Kind clusters and complete container acceptance require the worker tools and Docker; unit tests do not replace those checks.
