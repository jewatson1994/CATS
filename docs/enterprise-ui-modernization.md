# CATS Enterprise UI/UX Modernization

Branch: `feature/enterprise-ui-modernization` (based on `main` at `339fbd4`).
Scope: frontend presentation only (`portal/frontend`). No backend route, API parameter, schema, worker,
authorization, compliance, VEX, risk, approval, publication or export behaviour was changed.

## 1. Initial UX audit

The audit covered every routed page in `portal/frontend/src` (Services, service workspace tabs, Raw and
Simplified Findings, Service Security Matrix, Discovery, Scan, SBOM, Patch and patch campaigns,
Remediations, Cybersecurity, Risk Intelligence, Approvals, Approved Releases, Artifact catalog, OCI
destinations, Jobs, Requests, Configuration and the administration pages). Baseline screenshots were taken
from a locally running CATS backend (SQLite, 42 seeded services) before any change.

Prioritized findings:

| Priority | Finding | Where |
| --- | --- | --- |
| P1 | Filter forms consume a large part of the first screen. The Service Security Matrix spends three permanent rows (about 230 px of form) on eight fields before the first row of data. | Service Security Matrix |
| P1 | Tables have no professional grid behaviour: no resizing, no column choice, no density, no sticky header, and long tables lose their header while scrolling. | All data tables |
| P1 | The header crowds the full product name next to navigation; at tablet width (768 px) the account menu is clipped off-screen and the header wraps unpredictably below 850 px. | Global header |
| P2 | Inconsistent table construction: about 50 hand-written tables with different empty states (plain text, `td.empty`, paragraph after the table), different pagination markup and different status presentation (raw enums such as `NOT_ATTEMPTED`, plain text statuses, badges). | Matrix, Jobs, Requests, Remediations, Approvals |
| P2 | Several numeric columns are hard to scan: zero and non-zero counts look identical, and "Medium / Low" shares one column so neither can be read or sorted on its own. | Matrix |
| P2 | Missing loading and empty states: Jobs shows "Loading jobs…" in a table cell, the Services page shows a spinner with no layout, lists show plain paragraphs. | Services, Jobs, Approvals, Releases |
| P2 | The Remediations filter is hidden in a `<details>` disclosure with eleven fields and no indication of which filters are active. | Remediations |
| P2 | Approved Releases are cards that cannot be compared; current authorization (validity) and publication are not visible together. | Approved Releases |
| P2 | The Cyber approval detail does not visually separate the automated technical assessment (frozen snapshot) from the human Cyber decision and from publication. | Approval detail |
| P3 | Secondary navigation is an unlabelled flat list (Artifact catalog, Remediate, SBOM, Jobs, Requests). | "More" menu |
| P3 | Discovery shows its workflow as a static "Discover → Review → Confirm → Scan" badge that never reflects progress. | Discovery |
| P3 | Service pages have no direct route to related workflows that are not tabs (scan this service, patch its images, its POA&M entries, jobs). | Service overview |
| P3 | No skip link; menus have no arrow-key movement; several menus can be open at once. | Header |
| P3 | Lists that are server-paginated are not sortable, but nothing signals why; lists that are complete are not sortable either. | All tables |

## 2. Design principles

1. **The data is the page.** Controls collapse into toolbars, drawers and menus; tables take the space.
2. **Presentation only.** Every form keeps its method, action, field names and values. Every link keeps its
   destination. Status values are shown exactly as the backend computed them; the grid maps a value to a
   tone and never derives a new state.
3. **Honest sorting.** A table sorts only the scope the user can see in full (see section 5).
4. **Never colour alone.** Badges carry text and an icon; severity carries pips; non-compliant and KEV
   rows carry an edge marker in addition to the badge.
5. **Keyboard parity.** Everything the mouse can do (resize, reorder, sort, open menus, filter) has a
   keyboard path.
6. **Refine, not replace.** The dark CATS palette, accent and themes (cats, blue, red, gray, light) are
   unchanged; the new layer uses only existing design tokens. No gradients, glows or decorative motion
   were added.
7. **No new dependencies.** Everything is built on React 19 and the existing CSS token system.

## 3. New reusable components

| Component | File | Purpose |
| --- | --- | --- |
| `DataGrid` | `components/DataGrid.tsx` | Semantic `<table>` grid: drag/keyboard resize, double-click auto-fit, drag and menu reordering, show/hide, density, sticky header, pinned identifier column, client/server/none sorting, loading skeleton, empty state, row detail slot, toolbar slots. |
| `gridPreferences` | `components/gridPreferences.ts` | Versioned, per-table layout persistence (widths, order, hidden, density, pinning) with validation and graceful failure. |
| `FilterDrawer` | `components/FilterDrawer.tsx` | Slide-out modal filter form wrapping a page's existing GET form, with Apply, Reset, Cancel, active-count badge, focus loop and focus restoration. |
| `FilterChips` | `components/FilterDrawer.tsx` | Active-filter chips, each a link to the same URL without that filter, plus Clear all. |
| `QuickSearch` | `components/FilterDrawer.tsx` | Toolbar search box that belongs to the drawer's form (`form` attribute), so one request carries every filter. |
| `hrefWithout` | `components/FilterDrawer.tsx` | Builds "this view without filter X" URLs (single or one value of a repeated parameter) and resets `page`. |
| `Popover` | `components/Popover.tsx` | Accessible non-modal menu (Columns, Density): `aria-expanded`, focus moves in, Escape returns focus, closes on outside focus/pointer. |
| `Pager` | `components/Pager.tsx` | Compact pagination: range, rows-per-page, previous/next icon links with accessible names. |
| `RelatedWorkflows` | `components/ServiceHeader.tsx` | Service quick links to existing routes that are not tabs. |
| New icons | `components/ui.tsx` | sort, sortAsc, sortDesc, filter, columns, rows, search, menu, download, grip, chevrons, external. |
| `enterprise.css` | `styles/enterprise.css` | Header, grid, drawer, chips, popover, pager, skeleton and responsive rules, loaded after `design-system.css`. |

## 4. Navigation changes

* **Compact identity.** `CATS` wordmark and icon; the deployed version is a small monospace pill (hidden
  below 1100 px). The full product name is in the brand tooltip, in screen-reader text, and in a new
  **About CATS** dialog in the account menu (product name and deployed version).
* **Primary destinations unchanged:** Services | Discovery | Scan | Patch | Cybersecurity ▾ | More ▾.
* **More is grouped** into labelled sections: Governance (Remediate, Requests), Inventory (Artifact catalog,
  SBOM), Operations (Jobs). Every route, label and permission check is unchanged.
* **Utilities right-aligned:** notifications (count capped at 99+, header with pending count), administration
  gear (now marked current on `/admin` pages, same permission logic and destination), account menu with
  initials avatar (name hidden below 1280 px but kept in the accessible name).
* **Active state** for links and groups uses an accent underline in addition to the highlighted background.
* **Keyboard:** skip link to `#main-content`; ArrowDown on a menu button opens it and focuses the first item;
  ArrowUp/ArrowDown/Home/End move within a menu; Escape closes and returns focus; only one header menu is
  open at a time.
* **Responsive:** single 56 px row from 1920 px down to 768 px (verified); below 700 px the destinations move
  to a second row while brand and account utilities share the first.

![Grouped More menu, opened from the keyboard](enterprise-ui-modernization/after/nav-more-open.png)

## 5. Table improvements

### Column resizing and auto-fit
* Drag the boundary at the right edge of any header. Widths are clamped (56–720 px; 520 px for wrapping
  columns, or per-column limits).
* Double-click the boundary (or focus it and press Enter/Space) to fit the column to its header and the
  rendered rows. Measurement reads at most 200 rendered rows: never the unbounded dataset.
* The boundary is a focusable `role="separator"` with `aria-valuenow/min/max`; ArrowLeft/Right resize by
  16 px (64 px with Shift), Home/End jump to the limits. Changes are announced in a live region.
* Before any resize, natural widths are measured from the rendered content and the grid switches to a fixed
  layout, so resizing one column never moves the others.

### Column management
* **Columns** menu: show/hide per column, move left/right buttons, pin identifier column, Reset column layout.
* Headers can also be dragged to reorder.
* Security-critical columns are marked **Required** and cannot be hidden (for example Service, Status,
  Critical, High and KEV in the matrix; Finding, Severity, State and KEV in findings; Cyber decision in the
  approval queue; Authorization and Publication in Approved Releases).
* **Density:** Compact, Comfortable (default), Spacious.
* **Sticky header** inside a scroll frame sized to the viewport; **pinned identifier** column while
  scrolling horizontally (verified in the browser).

### Persistence
* Stored in `localStorage` under `cats.grid.<table-id>.v1`, per table identity.
* Only layout is stored: column keys, pixel widths, density and the pin flag. No row values, filter values,
  identifiers or user data (a unit test asserts this).
* Malformed or obsolete entries are ignored; new columns take their natural position; blocked storage
  (private windows) is tolerated.

### Sorting
Sorting follows the real scope of the dataset:

| Mode | Used when | Behaviour |
| --- | --- | --- |
| `client` | Every row of the dataset is on screen (Jobs, Requests, Approved Releases, Accounts, service non-compliance and warnings; matrix and findings when the result fits on one page; approvals when the API returned every match) | Stable sort; numbers, ISO dates and severities sort by value; missing values always sort last; third click restores the server order. First click is descending for numeric, date and severity columns and ascending for text. |
| `server` | The backend already exposes ordering parameters (Remediations POA&M and Mitigations views: `sort=due\|status`, `direction=asc\|desc`) | Headers are links to the same route with those parameters; `aria-sort` reflects the server's order. |
| `none` | The dataset is paginated and the backend offers no sort parameter (matrix and findings with more than one page, audit log) | Headers are not sortable, so one page is never presented as a sorted dataset. |

Columns that only have a display-formatted date (for example finding due dates and audit times) are not
client-sortable, because sorting formatted text would misorder them.

## 6. Filter drawer behaviour

* A **Filters** button (with an active-filter count) opens a right-hand drawer containing the page's
  existing fields. **Apply filters** submits the same GET form to the same URL; **Reset** goes to the page's
  existing reset URL; **Cancel**, the close button, Escape and a backdrop click close it without changes.
* The drawer is a native modal `<dialog>`: the page behind is inert, Tab cycles inside the drawer, and focus
  returns to the Filters button on close (verified in the browser).
* **Active filter chips** appear above the table; each chip removes only its filter; **Clear all** resets.
* Applied to: Service Security Matrix (CVE, component, scanned since, status, severity, attention, with the
  search box in the toolbar) and Remediations (service, identifier, title, owner, severity, status, date
  range, sort, page size).
* Deliberately left inline: service findings (five compact fields in one row), Approved Releases and the
  approval queue (one or two fields), Artifact catalog (one field), Accounts (one field). Inline is faster
  there.

![Filter drawer](enterprise-ui-modernization/after/matrix-drawer.png)

## 7. Service Security Matrix redesign

| Before | After |
| --- | --- |
| ![Before](enterprise-ui-modernization/before/services-1440x900.png) | ![After](enterprise-ui-modernization/after/services-1440x900.png) |

* Toolbar: **Service Security Matrix | Search | Filters | Columns | Density | Export Excel**. The first data row
  moved up by about 270 px at 1440×900.
* Active/Staged/Archived moved to the page header, because it changes the page title and totals, not just
  the table.
* Status badge and warning indicator unchanged (`GREEN`/`YELLOW` → Compliant, `RED` → Non-compliant; raw
  value kept in `data-value`). Non-compliant rows also get a red edge marker.
* Counts are right-aligned with tabular numerals; zeros are muted; non-zero Critical, KEV and Overdue use the
  danger colour; High uses the warning colour. Medium and Low are separate columns (same values).
* Kind (deployment validation) shows a status badge (`NOT_ATTEMPTED` → "Not attempted") linking to the same
  validation view; Missing Evidence and SBOM keep Yes/No text.
* Compact pager with rows-per-page (10/25/50/100, the backend's existing `page_size`).
* Loading shows skeleton metrics and rows; empty and filtered-empty states offer Clear filters.
* Filters, compliance semantics, counts and links are byte-for-byte the same requests as before.

Further views: [chips](enterprise-ui-modernization/after/matrix-chips.png),
[column chooser](enterprise-ui-modernization/after/matrix-columns.png),
[compact density](enterprise-ui-modernization/after/matrix-compact.png),
[sticky header and pinned column while scrolled](enterprise-ui-modernization/after/matrix-scrolled.png).

## 8. Other pages

| Page | Change |
| --- | --- |
| Service findings (Raw, Simplified, Non-compliance, Warnings) | Data grid with required columns, KEV row marker, compact pager. Simplified groups expand into a full-width detail row; their member pages are cached for the page's lifetime so collapsing and re-expanding does not request them again. Inline filters kept. |
| Remediations | Page header, selectable summary cards, tabs with a Filters drawer, chips, data grid; POA&M/Mitigation Status and Due date headers use the existing server `sort`/`direction` parameters. |
| Requests | Data grid; status badges; review dialog unchanged. |
| Jobs | Page header, status count badges, data grid with status badges, progress bars and errors, skeleton loading, selected-job summary panel. Polling unchanged. |
| Approvals | Data grid (Cyber decision and Publication as separate columns). Detail view adds a stage track: **Technical assessment** (frozen snapshot) → **Cyber decision** (human) → **Publication**. |
| Approved Releases | Cards replaced by a comparable table: Authorization (validity or Revoked), Publication, Expires, Scan date and Destination side by side; revoked rows marked. Release detail and revision history unchanged. |
| Discovery | The static workflow badge became a live stage indicator (Discover → Review → Confirm → Scan) driven by the existing job, inventory and confirmation state, with a direct link to the scan once started. |
| Service overview | Related workflows: Scan this service, Patch service images, POA&M entries, Jobs and exports. |
| Patch campaigns | Per-status image counts above the campaign items. |
| Accounts, Audit | Data grid (accounts keep the dialog-based detail; audit keeps server order). |

| Before | After |
| --- | --- |
| ![Findings before](enterprise-ui-modernization/before/service-1440x900.png) | ![Findings after](enterprise-ui-modernization/after/service-1440x900.png) |
| ![Remediations before](enterprise-ui-modernization/before/remediations-1440x900.png) | ![Remediations after](enterprise-ui-modernization/after/remediations-1440x900.png) |
| ![Jobs before](enterprise-ui-modernization/before/jobs-1440x900.png) | ![Jobs after](enterprise-ui-modernization/after/jobs-1440x900.png) |
| ![Releases before](enterprise-ui-modernization/before/releases-1440x900.png) | ![Releases after](enterprise-ui-modernization/after/releases-1440x900.png) |
| ![Discovery before](enterprise-ui-modernization/before/discovery-1440x900.png) | ![Discovery after](enterprise-ui-modernization/after/discovery-1440x900.png) |

## 9. Responsive behaviour

Verified with a headless Chromium against the running application at 1920×1080, 1440×900, 1366×768,
1024×768, 768×1024 and 480×900 on Services, Remediations and Findings:

* No horizontal page overflow at any size (`scrollWidth − innerWidth = 0`).
* Header is one 56 px row from 1920 down to 768 px with the account controls fully visible (previously clipped
  at 768 px); two rows at 480 px.
* Wide tables scroll horizontally inside their frame with the identifier column pinned; the page does not.
* The filter drawer is `min(420px, 100vw)` and fits at every size.
* Toolbars wrap; the search box takes a full row below 700 px.

| 768×1024 before | 768×1024 after | 480×900 after |
| --- | --- | --- |
| ![](enterprise-ui-modernization/before/services-768x1024.png) | ![](enterprise-ui-modernization/after/services-768x1024.png) | ![](enterprise-ui-modernization/after/services-480x900.png) |

## 10. Accessibility improvements

* Skip link; `main` is focusable as its target.
* Visible 2 px focus outline on grid sort buttons, resize handles, menus and drawer controls.
* Header menus: disclosure pattern with arrow keys, Home/End, Escape with focus return.
* Grid: `<caption>`, `scope="col"`, `aria-sort` on sortable headers, keyboard-operable resize separators,
  live-region announcements for sort, resize, fit, move and reset; the scroll frame is a labelled, focusable
  region so keyboard users can scroll it.
* Drawer: labelled modal dialog, focus moves to the first field, Tab loop, Escape/cancel, focus restoration;
  the form has `role="search"`.
* Column chooser and density use real checkboxes and a radio group with legends.
* Status is never colour-only (badge text and icon, severity pips, row edge markers paired with badges).
* `prefers-reduced-motion`: drawer animation, skeleton shimmer and menu transitions are disabled (verified:
  computed `animation-name: none`).
* No hover-only actions were introduced.

## 11. Performance

* No new runtime dependencies. Main bundle 393.9 kB → 423.9 kB (124.3 kB gzip); route chunks unchanged in
  structure.
* The grid memoizes column maps, visible-column order and sorted rows; sorting is O(n log n) on the rows
  already loaded.
* Width measurement happens once per column set (after rows exist) and on explicit auto-fit; resizing updates
  only column widths.
* Simplified-finding groups cache their member pages, removing repeat requests when a group is re-expanded.
* Virtualization was intentionally not added: every grid shows one server page (at most 250 rows), and
  virtualization would break auto-fit, keyboard traversal and accessibility.

## 12. Test results

All commands run in `portal/frontend` on the feature branch:

| Check | Result |
| --- | --- |
| `pnpm typecheck` | Pass |
| `pnpm lint` | Pass (0 problems) |
| `pnpm build` | Pass |
| `pnpm test` | **60 files, 415 tests passed** (baseline on `main`: 58 files, 385 tests) |
| Backend tests that inspect frontend sources (`test_scan_definition_ui.py`, `test_elapsed_time.py`, two navigation tests in `test_portal.py`) | 19 passed |

New tests: `components/DataGrid.test.tsx` (sorting semantics, server and none modes, drag resize, clamping,
keyboard resize, auto-fit, reordering by menu and drag, visibility and required columns, reset, persistence
scoping and validation, density, menu focus, pinning, skeleton and empty states, blocked storage),
`components/FilterDrawer.test.tsx` (dialog semantics, focus, Escape/backdrop, form contract, quick search,
chips, URL removal, focus loop), four new header tests (brand/About/skip link, grouped sections and arrow
keys, single open menu, avatar), and three new matrix tests (chips and counts, dataset-only sorting and
pager, lifecycle/export/required columns).

Existing tests changed only where markup changed, with the behaviour assertions kept: the matrix filter form
is now opened from the drawer (same action, method and fields), the empty-state cell spans 15 columns (Medium
and Low are separate), the Kind link's accessible name is the badge label ("Failed") with `data-value`
`FAILED`, a findings pager link is named "Next page", and one accounts selector targets the grid cell.

One existing test (`cyber_approvals.test.tsx` › "selects the retained candidate directly in the variant
selector", untouched code) timed out once in a full parallel run and passed on every re-run, in isolation and
in the full suite; it relies on a 1 s `waitFor` and is timing-sensitive under load.

Browser verification (headless Chromium against the running app, seeded SQLite data): drag resize
(215 → 335 px), double-click auto-fit (→ 206 px), keyboard resize, sort order, persistence across reload,
drawer open/Escape/focus restore and Tab loop, menu arrow keys, sticky header, pinned column, reduced motion,
and the responsive sweep in section 9. The Artifact catalog page rendered its error page in the local demo
both before and after this change (a local SQLite environment issue, not related to the frontend), so it was
not visually verified.

## 13. Remaining UX opportunities (frontend only)

* Convert the remaining small configuration and evidence tables (Configuration, Risk Intelligence, policy
  pages, validation evidence) to `DataGrid` where they grow beyond a handful of rows.
* Artifact catalog cards could gain a table view once its local error is resolved and it can be verified.
* A shared toast for asynchronous confirmations (existing pages use inline notices and `role="status"`
  messages, which were kept).
* Saved views (named filter + column layouts) per table, stored locally.
* Row selection with bulk actions where the backend already supports batch operations.

## 14. Recommendations requiring backend changes (not implemented)

1. **Matrix sorting:** add a `sort`/`direction` parameter to the Services portfolio query (the route accepts
   `sort` but the portfolio ignores it). The grid's `server` mode is ready to use it.
2. **Findings sorting:** server-side sort for Raw findings (severity, EPSS, KEV, due date) so paginated
   results can be sorted across all pages.
3. **Approval queue paging and sorting:** expose `page`, `page_size`, `sort` on `/api/cyber-approvals` so large
   queues do not depend on one response.
4. **Raw dates in page data:** provide ISO timestamps alongside display strings (for example finding due
   dates, last seen, audit times) so those columns can sort correctly.
5. **Exceptions ordering:** accept `sort`/`direction` on the Exceptions tab (currently created-at only).
6. **Server-side layout preferences** if users need their column layouts across browsers (today they are
   local per browser, by design).

---

# Phase 2: menus and remaining pages

Branch: `feature/ui-modernization-phase-2`, based on `main` at `22f35d5`. Same rules as phase 1: presentation
only. Every form keeps its method, action, field names and field order; every link keeps its destination;
every permission check is unchanged.

## What changed

| Area | Change |
| --- | --- |
| Header menus | Cybersecurity and More items show an icon and a one-line description. The destination stays the link's accessible name; the description is its accessible description. Popovers share one style and a short entrance animation (off with reduced motion). The More menu right-aligns on narrow screens so it never runs off-screen. |
| Account menu | Icon rows for Appearance, Change password, About and Sign out. The theme picker expands inline as swatches instead of a 720 px flyout. |
| Notifications and in-page menus | Notification items show a status dot with the service beneath. Service Actions, Export and version menus use the same row style; destructive actions are separated and red. |
| Administration | One grouped console sidebar (Access, Platform, Policy, Delivery) on every admin page, replacing tab strips that differed from page to page. Policy pages keep their own permission flags. Save and error messages are callouts. Below 1000 px the sidebar becomes a scrollable strip. |
| Account pages | Change password and Appearance share an Account sidebar. Without a session the password page keeps the focused sign-in card. |
| Scan, SBOM, Patch | Standard page header; form split into labelled sections (images, Helm charts, Docker Compose, service definition, ingest); a side panel explaining the workflow steps with links to related pages. The back link to the public overview appears only when signed out. |
| Cybersecurity dashboard | Thousands separators (164,372), left-aligned cards with a "View details" cue, tighter charts and consistent panel styling. |
| Artifact catalog | Toolbar-style search, two-column card grid, identity blocks and service chips. |
| POA&M overview | Totals row (entries, active, pending, overdue) and the shared data grid with muted zeros and an overdue row marker. |
| Browser tab titles | Readable titles such as "Scan · CATS", "Hardening Policy · CATS" and "Dependencies · Payments Service · CATS" instead of internal page keys ("self service · CATS"). |

New files: `components/WorkspaceGuide.tsx`, `features/account_shared.tsx`, `styles/console.css`, and tests in
`features/admin_shared.test.tsx` (plus additions to `App.test.tsx` and `components/Shell.test.tsx`).

## Verification

| Check | Result |
| --- | --- |
| `pnpm typecheck`, `pnpm lint`, `pnpm build` | Pass |
| `pnpm test` | 62 files, 424 tests passed |
| Browser (Chromium, demo data) | No horizontal page overflow on Settings, Scan, Patch, POA&M and Change password at 1920, 1366, 1024, 768 and 480 px; the More menu fits the viewport at every size. |

The admin console layout uses the CSS `:has()` selector. Browsers without it (Firefox before 121) show the
navigation stacked above the content instead of beside it; nothing is lost.

## Before and after

| Before | After |
| --- | --- |
| ![](enterprise-ui-modernization/phase-2/configuration-before.png) | ![](enterprise-ui-modernization/phase-2/configuration-after.png) |
| ![](enterprise-ui-modernization/phase-2/scan-before.png) | ![](enterprise-ui-modernization/phase-2/scan-after.png) |
| ![](enterprise-ui-modernization/phase-2/patch-before.png) | ![](enterprise-ui-modernization/phase-2/patch-after.png) |
| ![](enterprise-ui-modernization/phase-2/cybersecurity-before.png) | ![](enterprise-ui-modernization/phase-2/cybersecurity-after.png) |
| ![](enterprise-ui-modernization/phase-2/poam-before.png) | ![](enterprise-ui-modernization/phase-2/poam-after.png) |
| ![](enterprise-ui-modernization/phase-2/password-before.png) | ![](enterprise-ui-modernization/phase-2/password-after.png) |

Menus: ![](enterprise-ui-modernization/phase-2/menus-after.png)
![](enterprise-ui-modernization/phase-2/account-menu-after.png)

## Still not modernized

Addressed in phase 3 below.

---

# Phase 3: service views and remaining pages

Branch: `feature/ui-modernization-phase-3`, built on phase 2. Presentation only, as before.

| Area | Change |
| --- | --- |
| Service views | Architecture, Artifacts, Dependencies and Deployment Validation now use the same service header as Overview, Findings, Remediations and Activity: service name, compliance badge, version, owner, latest evidence and the Request approval, Export and Actions controls. Each view's own title, explanation and actions sit in a band under the tabs. The header data comes from the same `service_view` the Overview page uses, so the compliance badge is the real computed value on every view. |
| Finding detail | Standard page header with an Active/Resolved badge and the Remediate action; remediation classification as a callout; risk cards with a severity badge and a "Known exploited" badge for KEV. |
| Watchlist match | Standard header with a back link to the service's warnings and a "Watchlist match" badge. |
| Discovery | Wider source column (340 px) that stays in view while reviewing, standard panel radius and spacing, dashed upload fields. |
| Validators | Breadcrumb back to Settings · Integrations, the dedicated-VM notice as a standard warning callout, status badges for validators, clearer selected state. |
| Risk Policy | Hard-coded greens and ambers replaced with theme tokens, so the tabs and notices follow every theme (checked in the light theme). |
| Encoding fix | `discovery.tsx` on `main` (commit `22f35d5`) contained two Windows-1252 characters, which rendered as a replacement character and broke `test_internal_login_navigation_stays_in_current_tab`. Fixed in its own commit. |

## Verification

| Check | Result |
| --- | --- |
| `pnpm typecheck`, `pnpm lint`, `pnpm build` | Pass |
| `pnpm test` | 62 files, 424 tests passed |
| Backend tests that read frontend sources | 19 passed (one was failing on `main` before the encoding fix) |
| Browser | All six service views, finding detail, Discovery, Validators and Risk Policy rendered against demo data; light theme checked for menus, admin and service pages. |

## Before and after

| Before | After |
| --- | --- |
| ![](enterprise-ui-modernization/phase-3/svc-deps-before.png) | ![](enterprise-ui-modernization/phase-3/svc-deps-after.png) |
| ![](enterprise-ui-modernization/phase-3/svc-validation-before.png) | ![](enterprise-ui-modernization/phase-3/svc-validation-after.png) |
| ![](enterprise-ui-modernization/phase-3/finding-before.png) | ![](enterprise-ui-modernization/phase-3/finding-after.png) |
| ![](enterprise-ui-modernization/phase-3/validators-before.png) | ![](enterprise-ui-modernization/phase-3/validators-after.png) |

Light theme: ![](enterprise-ui-modernization/phase-3/light-theme-after.png)

## Final polish (phase 3, continued)

| Area | Change |
| --- | --- |
| Tables in Settings and policy pages | Every hand-built table inside the admin console (OIDC claim mappings, OCI registries, trusted CA certificates, OS package mirrors, vulnerability due-date and EPSS rules, Dependency Watchlist entries, release destinations, upstream registries and mappings) shares one bordered style: header band, compact rows, compact in-row fields and buttons, row actions on one line. These tables stay hand-built rather than using the data grid because their rows contain editable fields and forms. |
| Empty lists | OCI registries, registry destinations and upstream registries/mappings show "None configured" rows instead of bare column headers. |
| Status cells | Watchlist entries, OIDC claim mappings and OCI registries show standard status badges (same text as before). |
| Risk Policy group picker | A scope bar with the Owning group field, an "Editing <group>" indicator and one-click group chips (up to 12 groups); a proper empty state before a group is chosen. The Risk Profiles / Assessments switch is a segmented control (it previously looked inverted). |
| Remediation report | Standard page header (back link, status badge, the Retry or Review-a-new-plan action as a button), elapsed time as "7m 36s" instead of "456s", a current-state badge, changed files as cards with change counts, and images as cards showing original → candidate with the classification badge. All wording is unchanged. |

Verification: typecheck, lint and build pass; 62 files and 426 frontend tests pass (new tests cover the group quick picks and elapsed formatting); 19 backend tests that read frontend sources pass. The remediation report was checked in the browser with fixture data from the existing tests, because the demo database has no remediation jobs.

| Before | After |
| --- | --- |
| ![](enterprise-ui-modernization/phase-3/table-cfg-integrations-before.png) | ![](enterprise-ui-modernization/phase-3/table-cfg-integrations-after.png) |
| ![](enterprise-ui-modernization/phase-3/table-vuln-before.png) | ![](enterprise-ui-modernization/phase-3/table-vuln-after.png) |
| ![](enterprise-ui-modernization/phase-3/report-before.png) | ![](enterprise-ui-modernization/phase-3/report-after.png) |

Risk Policy picker: ![](enterprise-ui-modernization/phase-3/risk-picker-after.png)
Report images and artifacts: ![](enterprise-ui-modernization/phase-3/report-images-after.png)
