# Retained Helm remediation continuation report

Repository: `C:\Users\lil-j\Projects\Cyber Hygiene`
Branch: `feature/schrodinger-validation-offline-bundles`
Status: implementation and local checks complete; changes remain uncommitted and unpushed. Existing unrelated working-tree changes were preserved. Next step: rebuild/redeploy and perform the user's completely fresh disconnected remediation-gauntlet scan.

## 1. KSV-0016 mapping failure

The code investigation found a chain of defects: equivalent rendered resources from different scan routes were treated as conflicting because their scanner artifact/document locations differed; Helm source comments could be lost at YAML document boundaries; and the retained-source mapper rejected every source containing Helm expressions, even when the exact container and mutation branch were literal YAML. Consequently the planner could lose an authoritative template link or reject a valid linked template. Missing memory requests intentionally have no default proposal; that is separate from this mapping failure. The real gauntlet chart and failed scan payload were not available locally, so the exact combination encountered by that particular run cannot be conclusively reconstructed. These are confirmed code defects and regression reproductions, not a claim of inspecting its runtime payload.

## 2. KSV-0106 mapping failure

The same cross-render join and blanket-template rejection defects affected capabilities mapping. The graph render route also previously ignored entry-specific release/namespace settings used by the configuration render route, allowing inconsistent identities. A typed `["ALL"]` proposal existed, but a proposal alone could not establish an exact editable source. As above, the exact historical gauntlet payload was unavailable; the corrected failure paths are covered by synthetic retained-source and cross-render tests.

## 3. Multiple render/scan paths

Yes. `extract-helm-images.sh` renders graph artifacts for image discovery; the default source configuration scan can encounter those artifacts when scanning the source tree. `scan-configurations.sh` independently renders and scans charts. Both paths remain enabled.

## 4. Different evidence filenames

`remediation-gauntlet-<digest>.yaml` is produced by the chart configuration-render route. `helm-image-rendered/graph-1.yaml` is produced by graph image discovery and can be encountered by source scanning. These are scanner evidence locations, not authoritative files to edit. Which route emits an individual rule depends on the scanned artifacts and Trivy results; no rule-specific filename assumption is used.

## 5. Where provenance was lost

The scanner's source-comment extraction used prior YAML node end marks, which can include the next document's source comment. Ingestion required evidence filename/document index equality when joining otherwise equivalent retained resources. Input-file fallback could select an unrelated rendered input, and stale enriched evidence could persist. Physical chart discovery paths were also mixed with chart-instance identifiers. These locations have been corrected.

## 6. Render provenance

Both render routes now honor entry release and namespace settings, share deterministic instance identity semantics, and retain separate chart instance, source path, template, rendered artifact, document and resource/container provenance. An existing graph chart ID is preferred; fallback identity incorporates source, release, namespace, values inputs and set arguments. Source-comment association uses document boundaries. Physical paths remain physical paths.

## 7. Persisted finding lineage

Existing lineage enrichment now joins equivalent render evidence only with affirmative instance/template/resource/execution provenance. `_cats_resource_lineage_evidence` retains alternate evidence locations without replacing the authoritative source. Stale enrichment is cleared before recalculation. The existing retained scan/finding persistence carries these additive fields; no new database table is introduced.

## 8. Resource/container identity

Matching uses Kubernetes API version, kind, namespace and name together with chart instance and source template. Container name and group (`containers`, `initContainers`, or `ephemeralContainers`) remain exact selectors. Missing resource fields do not erase a known container identity. Container position is not used to guess the target.

## 9. Render-to-source mapping

Different evidence artifact/document locations may match when affirmative chart-instance and template lineage proves equivalence. Conflicting chart instances/templates or duplicate documents in the same artifact remain blocked. The planner resolves a retained values mapping first where proven; otherwise it can resolve an exact literal YAML branch in the retained template. Scanner artifacts are displayed as evidence and are never promoted to authoritative source merely because their filename resembles the chart.

## 10. Chart-instance isolation

Instances with the same chart/resource/container names but different release, namespace, source, values or set context are not merged merely by name. A cross-render join requires affirmative matching instance identity. Ambiguous instances remain unresolved or require an explicit uniquely addressable Guided target selection.

## 11. Absent YAML fields

Typed SET/upsert can insert absent `resources.requests.memory`, `resources.requests.cpu`, `securityContext.capabilities.drop`, and related registered fields into an exact literal container mapping. Empty `{}` parents and entirely absent parents are supported. Sibling containers and scalar Helm expressions are preserved. Missing, null, false, numeric zero, empty string and arrays remain distinct in the mutation engine. Literal branch serialization may normalize formatting/comments within that branch.

## 12. Values mapping

Proven retained values mappings remain preferred. Mapping is constrained to a unique template/document/container and simple supported expressions. Direct `toYaml .Values... | indent/nindent` object mappings can address missing nested leaves when the retained values object exists. Arbitrary transforms, control flow, multi-container sharing and unproven defaults are rejected rather than guessed. This does not invent a new values structure or alter chart architecture.

## 13. Literal Helm templates

Scalar expressions such as an included resource name or templated image are masked as opaque values solely for parsing literal structure, then restored byte-for-byte. Dynamic resource identity requires affirmative source lineage and a unique matching kind/API document. The chosen container name and edited branch must be literal. Standalone structural expressions, conditional/range/with blocks, dynamic YAML keys and dynamic target values remain unsupported for literal editing; they require a proven values mapping or remain unresolved.

## 14. Guided target selection

Guided shows each uniquely addressable editable resource/container/source option when selection is required. Selection is validated server-side by target ID before an accepted edit. A known rendered target with unavailable source is reported as source unavailable, not incorrectly described as an unknown target. No valid options means unresolved only. Explicit target selection does not authorize an otherwise ambiguous source edit.

## 15. CPU/memory input

Sizing rules intentionally have no proposed quantity. Guided offers `Configure value` for an editable sizing target, followed by a required blank `Resource quantity` input. The placeholder is an example, not a submitted value. `256Mi` is preserved as explicit user input, with actor/approval and input provenance recorded. Automated mode does not invent sizing values.

## 16. Quantity validation

Validation requires a string with supported Kubernetes decimal, binary or exponent quantity syntax and a positive value. Zero—including `0e3`—negative, malformed, empty, excessively long or out-of-range values are rejected. Lowercase decimal `k` is supported; invalid uppercase decimal `K` is rejected. CPU must have no finer precision than `1m`; values are never silently rounded. Bounded input/exponent handling is a deliberate application safety limit. Syntax reference: [Kubernetes Quantity](https://kubernetes.io/docs/reference/kubernetes-api/definitions/quantity-resource/); CPU precision: [Kubernetes resource management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

## 17. KSV-0016 final behavior

With affirmative retained lineage and an editable literal branch or proven values mapping, memory is classified as requiring custom input. Guided can accept `256Mi` and mutate only the exact authoritative container path. It is not reported verified merely because the source edit succeeds. Missing/ambiguous provenance remains safely unresolved.

## 18. KSV-0106 final behavior

With the same exact source/target prerequisites, Guided exposes `Apply proposed value (["ALL"])`; the candidate contains an array, not a string. Automated can accept it only when classified safe and fully resolved. Cross-render evidence filenames no longer independently make the mapping ambiguous.

## 19. KSV-0017 regression

The exact-container `securityContext.privileged: false` path remains covered. New parameterized cases exercise false alongside memory and capabilities across absent and empty parents, while preserving the sibling container. Typed false remains distinct from numeric zero. Real gauntlet KSV-0017 execution still requires the fresh environment scan.

## 20. Actionability model

Target resolution, source resolution and actionability are separate fields. States distinguish automatic resolution, selection required, editable source, unavailable source, actionable proposal and required custom input. The UI reports a known target even if its source cannot be edited. Selection state no longer collapses valid candidates into manual-only/unresolved behavior.

## 21. Automated safety

Automated only accepts fully editable, exact, safe proposed changes. It never chooses an ambiguous resource/container, manufactures a CPU/memory quantity or bypasses source verification. Typed proposals remain validated. Unsupported and review-required changes remain unresolved.

## 22. Old scans

Older payloads without affirmative instance/template provenance do not gain cross-render equivalence by guessing. Existing unambiguous literal mappings can still work; incomplete/conflicting retained lineage remains unavailable or requires a supported explicit target selection. A fresh scan is needed to obtain the new provenance reliably.

## 23. Summary of Changes

Summary readback now parses opaque scalar Helm expressions to retrieve the actual typed literal after-value. Tests verify `256Mi`, `["ALL"]` and false, including nested flow mappings. Existing acceptance, actor, source-modified, hashes/diff and final-scan evidence remain integrated. A proposed value is not substituted for observed actual content. Sensitive diff redaction remains in place.

## 24. Final verification

The existing final render checks exact typed accepted values and expected mutation scope. The final configuration scan remains authoritative for finding resolution; source edits or successful rendering alone do not establish success. Missing final scan evidence remains unverified. This continuation does not add a Schrödinger dependency or substitute deployment validation for the final configuration scan.

## 25. Frontend changes

Guided displays independent target/source/actionability states and editable target choices, retains a blank quantity field, preserves typed capabilities proposals, and labels known absent fields `Not specified` and sizing proposals `User input required`. Actual controls remain named `Configure value` and `Resource quantity`. A governance test now selects the failure alert explicitly because the page can display the same failure text in multiple locations.

## 26. Backend/API changes

Changes are within existing scanner ingestion, retained-source mapping/mutation, plan/decision and summary paths. Additive plan fields and existing target IDs are passed through the frontend API. Accepted custom quantities are validated centrally before candidate generation. No endpoint redesign, external dependency or architecture replacement was introduced.

## 27. Files touched by this continuation

These are continuation-specific edits; the repository also contains substantial preexisting modifications/untracked files, which are not attributed to this task:

- `scanning-main/scripts/configuration-lineage.py`
- `scanning-main/scripts/extract-helm-images.sh`
- `scanning-main/scripts/scan-configurations.sh`
- `portal/app/main.py`
- `portal/app/remediation.py`
- `portal/app/remediation_sources.py`
- `portal/app/remediation_mutations.py`
- `portal/app/remediation_summary.py`
- `portal/app/frontend_remediations.py`
- `portal/frontend/src/features/remediations.tsx`
- `portal/frontend/src/features/remediations-decisions.test.tsx`
- `portal/frontend/src/features/governance.test.tsx`
- `portal/tests/test_configuration_lineage.py`
- `portal/tests/test_remediation_lineage.py`
- `portal/tests/test_remediation_cross_render.py`
- `portal/tests/test_remediation_sources.py`
- `docs/retained-helm-lineage-continuation-report.md`

## 28. Tests added/updated

Coverage includes multi-document source comments, strict input matching/stale evidence removal, physical chart paths, matching and conflicting chart instances, equivalent cross-render artifacts, same-artifact duplicate-document rejection, conservative scalar/object values mapping, explicit Guided resource/container selection, unavailable-source messaging, blank quantity input, three typed literal mutations across three missing/empty-parent layouts, summary actual-value readback, dynamic/control-flow rejection and twelve quantity cases. Existing ambiguous-target expectations were updated to selection-required where a uniquely addressable editable choice exists.

## 29. Test/build results

- Backend selection covering remediation unit/integration/workflow, classic Helm/render/source mapping, Helm ingestion/downloads, configuration lineage, shell lifecycle, frontend governance and patching: **412 passed**, one expected warning from a deliberately duplicate ZIP-entry fixture.
- Quantity/source suite after the final precision adjustment: **28 passed**.
- Entire frontend: **25 test files / 117 tests passed**, rerun after the final UI wording edit.
- TypeScript checking: passed.
- Frontend production build: passed, 75 modules; Vite reported the existing runtime-resolved `app.css` warning.
- Frontend ESLint: passed.
- Python compilation of application/scanner scripts: passed.
- Bash syntax for both changed render shell scripts: passed.
- `git diff --check`: passed.
- Tracked Linux `.sh` files: no CRLF bytes found.

The backend selection is focused, not a claim that every unrelated backend test was executed. An initial whole-directory collection without the required repository import path failed; the reported backend selection used both repository and portal import paths.

## 30. Migration/schema impact

No database migration or relational schema change. Existing JSON payloads gain optional lineage evidence/actionability fields; source mapping retains its existing form. Missing fields on older scans remain supported conservatively. No new Python/npm dependency was added.

## 31. Remaining limitations

Structural Helm control flow and unproven transforms remain intentionally unsupported for literal mutation. Shared values across containers are not guessed. Formatting/comments inside a rewritten literal branch can normalize. Definitive diagnosis of the two historical findings requires their original retained chart/render/scan payload. No claim is made that every Helm chart can be reverse-mapped. A fresh scan is required to assess the actual gauntlet source shape and new lineage.

## 32. Linux/disconnected coverage

The real Linux scanner image, disconnected registry/bundle workflow, actual Helm/Trivy execution and user gauntlet chart were not exercised locally. Shell syntax and fixture/mocked integration behavior passed on Windows. Rebuild/redeploy and fresh disconnected testing remain the user's next step.

## 33. Expected KSV-0016 UI after the fresh scan

If the actual retained source meets the proven mapping prerequisites, Guided should show `KSV-0016`, its memory-request finding title, rendered `Deployment/remediation-gauntlet` with namespace and exact container, the scanner evidence filename separately from `Authoritative source: templates/deployment.yaml` (or its actual retained path), and `resources.requests.memory`. For an absent literal field, Before is `Not specified`; Proposed is `User input required`. Decision offers `Configure value` plus `Leave unresolved`; choosing Configure opens a blank required `Resource quantity` input accepting `256Mi`. If several exact editable candidates exist, select the explicit resource/container first. If proven values mapping applies, that retained values file/key is shown instead. Unsupported source structure is reported honestly as unavailable.

## 34. Expected KSV-0106 UI after the fresh scan

With the same mapping prerequisites, Guided should show `KSV-0106`, the capabilities-drop title, exact rendered resource/container, scanner evidence `helm-image-rendered/graph-1.yaml` or the actual fresh artifact, authoritative retained template/values path, and `securityContext.capabilities.drop`. For an absent literal field, Before is `Not specified`; Proposed is `["ALL"]`. Decision offers `Apply proposed value (["ALL"])`, supported custom capabilities, and `Leave unresolved`. Multiple exact editable candidates require explicit selection. After execution, Summary of Changes must distinguish accepted/source-modified from verified; verified requires successful final evidence.

Work stops here for the user's fresh rebuild/deployment and disconnected gauntlet scan. No commit, push or additional architecture change was performed.
