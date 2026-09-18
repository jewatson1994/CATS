# CATS Deployment Validation Capability Expansion Report

Date: 2026-09-16

This report records the implementation and static/unit verification for the
explainable classification and capability expansion request. A new live
Helm/kind acceptance was intentionally not run in this pass because the
operator will perform that validation.

## 1. Original classification cause

The observed `PARTIALLY_VERIFIED` run had expected resources in
`comparison.declared_only`. The old finalization fallback assigned
`FailureCategory.UNKNOWN` with a generic “some declared resources were not
observed” message. That made a normal missing-expected-resource condition look
unexplained.

## 2. Resources responsible

The persisted comparison identifies the exact kind/namespace/name identities in
`declared_only`; the new reason record copies those identities into bounded
`EXPECTED_RESOURCE_NOT_OBSERVED` evidence. Runtime-generated controller objects
remain in `defaulted`/`runtime_generated` counts.

## 3. Correct semantics

CronJobs are validated as accepted workload configuration; a future schedule is
not a readiness failure. Generated Jobs, EndpointSlices, and other controller
objects are not treated as missing declarations. Required capabilities and
required workload evidence are distinct from optional diagnostics.

## 4. Classification changes

`finish()` now derives classification reasons and totals before persistence.
`VERIFIED`, `PARTIALLY_VERIFIED`, and `COULD_NOT_VALIDATE` retain their
deterministic meanings; cleanup failure remains a separate diagnostic.

## 5. UNKNOWN fix

The declared-only branch now leaves the category unset so the structured
reason code becomes `EXPECTED_RESOURCE_NOT_OBSERVED`. `UNKNOWN` is no longer a
fallback for that ordinary comparison outcome.

## 6. Explainability model

Runs persist `classification_reasons` and a `classification_summary` inside
diagnostics. Each reason includes a stable code, resource identity, expected
state, observed state, and explanation. The summary contains expected,
observed-expected, expected-only, runtime-generated, and failed totals.

## 7. Capability categories

Preflight and runtime correlation include Kubernetes, scheduling, DNS/Service
Discovery, ServiceAccount/RBAC, NetworkPolicy, HPA/Metrics, CRDs/custom
resources, admission webhooks, TLS/Certificate dependencies, LoadBalancer,
Ingress, Storage, configuration, GPU/extended resources, cloud/provider
signals, and operator/external dependency evidence.

## 8. DNS

Explicit Service FQDN references in rendered container environment values create
a required DNS capability. When a ready workload Pod exists, CATS probes the
Service FQDN with `getent` and a bounded `nslookup` fallback. Only names and
boolean outcomes are retained; arbitrary command output is discarded.

## 9. RBAC

ServiceAccounts, Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings are
matched by exact namespace/name identity. Binding role references and
ServiceAccount subjects are checked separately and reported as evidence.

## 10. NetworkPolicy

Policy objects are verified as accepted configuration. Enforcement is explicitly
recorded as `enforcement_tested: false`; the status does not claim traffic
isolation that this CNI sandbox did not exercise.

## 11. HPA/Metrics

HPA objects and their Deployment/StatefulSet targets are correlated. No scale
event is required for acceptance and metrics delivery is recorded as not
observed, avoiding a false claim of autoscaling behavior.

## 12. CRDs/operators

CRD `Established` state and observed custom resources are recorded. External
operator reconciliation is not inferred from object creation and remains
explicitly unverified.

## 13. Webhooks/TLS

Admission webhook configuration, referenced Services, and EndpointSlices are
correlated without reading certificate values. TLS Secret references are
checked by metadata/type only; private key and certificate contents are never
persisted.

## 14. Configuration aggregation

Repeated configuration-dependency rows remain available as detailed evidence,
while `capability_assessment` groups them into one summary with required,
verified, available, and failed counts.

## 15. UI

The validation page adds a prominent **Why this result?** section with totals,
resource-level reason rows, a stable anchor, and a clickable status badge. The
capability section shows grouped totals above the detailed technical evidence.
The live endpoint updates both sections during polling.

## 16. Tests

Focused validation, capability-evidence, Ingress, and LoadBalancer tests pass
after the changes. Added coverage checks advanced capability detection,
deterministic classification totals/reasons, grouped capability counts, the
explicit DNS dependency rule, and bounded DNS probe evidence.

## 17. Live torture result

No new live Helm/kind run was performed for this request, per operator
direction. Earlier retained acceptance artifacts are historical context only
and do not claim to validate these latest changes.

## 18. Evidence supporting the result

The implementation is covered by unit tests and source-level review of the
classification finalizer, API persistence path, worker field mapping, live
JSON rendering, and template anchor. The existing Helm release-name fix remains
in the LoadBalancer path: render/install/status all use the same
`cats-validation-N` release identity, with regression coverage in the
LoadBalancer integration tests.

## 19. Remaining limitations

The validator still does not prove external DNS, NetworkPolicy packet
enforcement, HPA metric freshness or scaling, certificate validity, service
mesh behavior, cloud-controller semantics, or arbitrary operator convergence.
Those boundaries are intentionally visible in capability evidence rather than
silently promoted to `VERIFIED`. The operator should perform the live Helm
acceptance and inspect the persisted reason table after deployment.
