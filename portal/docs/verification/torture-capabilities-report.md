# CATS generalized capability providers — implementation report

## Acceptance boundary

The retained torture-chart baseline and the completed pre-review acceptance run
are preserved as JSON evidence. The final adversarial-review fixes were rebuilt
successfully as `cats:1.2.9`, including offline bundle validation. At the
operator's request, the post-review live torture-chart rerun is intentionally
left for operator confirmation. The interrupted rerun's exact kind cluster and
Docker network were deleted, and `kind get clusters` reported no clusters.

## 1. Existing architecture discovered

Deployment Validation already rendered Helm, created one disposable kind
cluster/network per run, installed the release, collected Kubernetes evidence,
persisted the result, and deleted the environment in `finally`. MetalLB 0.16.1
was a working one-off bootstrap path. The architecture lacked a common provider
lifecycle, an offline Ingress provider, exact StatefulSet claim detection, and
provider-neutral evidence in the UI.

## 2. Capability-provider architecture implemented

`CapabilityRequirement`, provider inventory/specification, deterministic
dependency planning, bootstrap, readiness, artifact reconciliation, redacted
evidence, and reverse-order cleanup are implemented in
`app/capability_providers.py`. Deployment Validation now invokes the manager for
bootstrap, reconciliation, and cleanup. Readiness alone never produces
`VERIFIED`.

## 3. Providers implemented

- `metallb`: MetalLB 0.16.1, CATS-provisioned, offline and digest pinned.
- `ingress-nginx`: ingress-nginx 1.15.1 plus kube-webhook-certgen 1.6.9,
  CATS-provisioned, offline and digest pinned; explicitly depends on MetalLB.
- `kind-local-path`: discovers and uses the real compatible/default
  StorageClass already supplied by kind; it does not install unnecessary
  storage infrastructure.

Only providers required by rendered resources are planned. GPU and cloud/vendor
requirements remain unsupported/provider-specific unless meaningful runtime
support really exists.

## 4. LoadBalancer / MetalLB regression results

The exact MetalLB path is preserved: controller health, exact address pool,
exact Service namespace/name, provider-assigned address, Service UID-owned
EndpointSlices, and ready endpoints are required. Helm template and install now
use the same `cats-validation-N` release name; the regression suite proves the
rendered and installed Service identity is the same. Provider-specific classes
and annotations never become generic `VERIFIED`.

## 5. Ingress / ingress-nginx results

The provider validates the bundled manifest and image archives, imports images
into kind, applies the pinned manifest, waits for admission jobs and controller
readiness, and performs a server-side dry-run admission probe. Artifact
verification requires the current Ingress UID to have status or a matching Sync
event, every exact backend Service and referenced port to exist, exact
Service-UID-owned EndpointSlices with ready addresses, and ready backend Pods.
Network reachability is explicitly recorded as not tested.

## 6. Storage results

StatefulSet `volumeClaimTemplates` and direct PVC references are detected. A
claim verifies only when the exact PVC is Bound, names an observed Bound PV, the
PV claimRef matches namespace/name/UID, and the observed StorageClass uses the
selected local provisioner. Where a workload consumes the claim, its exact Pod
must be scheduled and Ready. No equivalence to cloud disks, CSI products, Ceph,
or production storage is claimed.

## 7. Workload-type verification results

Kind-specific evidence covers Deployment, StatefulSet, DaemonSet, Job, CronJob,
Pod, init containers, and native sidecars. Deployment/StatefulSet replicas,
DaemonSet desired/ready counts, Job completion, Pod readiness/success,
init-container exit state, and sidecar readiness are evaluated separately. A
CronJob is verified as an API-accepted exact configuration without waiting for
a future schedule; owned Job execution is retained separately when observed.
Node scheduling constraints are not weakened.

## 8. Offline asset strategy

The central inventory pins provider versions, manifest SHA-256 values, image
index digests, platform config digests, and Docker archive layer identities.
Builds may create verified archives ahead of time, while validation itself never
downloads a provider manifest or arbitrary `latest` image. Missing or invalid
offline assets yield provider/environment evidence, not application findings.
The `cats:1.2.9` build passed both offline bundle self-checks.

## 9. Security-boundary verification

Existing host-boundary preflight remains the execution gate. Capability
providers do not grant arbitrary hostPath, Docker/container-runtime sockets,
host PID/IPC, arbitrary devices, dangerous host capabilities, or host
credentials. Provider infrastructure is labeled and excluded from application
workload/drift evidence. Resource guardrail failures remain best-effort warnings
when kind and Kubernetes can safely continue.

## 10. Capability Assessment UI changes

Capability rows render provider, version, provisioned-by-CATS state, bootstrap,
readiness, reconciliation, verification method, failure reason, evidence, and
cleanup. Live updates use the same generalized backend payload. Configuration
and Secret dependencies expose only kind/name/existence/provenance; Secret data
and values are not collected or rendered.

## 11. Tests and results

- Full portal suite after adversarial-review fixes: **341 passed, 1 skipped**.
- Focused provider/reconciliation/deployment suite: **94 passed**.
- Deployment Validation live JavaScript test: passed.
- MetalLB offline bundle tests: **4 passed**.
- ingress-nginx offline bundle tests: **3 passed**.
- `git diff --check`: passed (only expected LF-to-CRLF notices).
- Persisted final JSON scan: no Secret object containing `data` or
  `stringData`.

## 12. Torture-chart end-to-end results

Baseline (`torture-capabilities-before.json`): `PARTIALLY_VERIFIED`; Helm
template/install passed; release `cats-validation-1` was deployed; LoadBalancer
was `VERIFIED`; Ingress was `UNAVAILABLE`; cleanup was complete.

Completed pre-review acceptance (`torture-capabilities-final.json`): `VERIFIED`;
16 rendered objects; Helm template 109 ms, install 731 ms, total 840 ms; provider
order MetalLB → ingress-nginx → kind local-path; LoadBalancer, Ingress, and
Storage were `VERIFIED`; 6/6 Deployment replicas, 1/1 StatefulSet replicas, 1/1
DaemonSet pods, 9/9 Pods, 1/1 Job, and 1/1 PVC were ready/bound; cleanup was
complete in 139 seconds.

That acceptance predates the final port/PV/lifecycle hardening. The post-review
live rerun is deliberately not claimed here and is the remaining operator test.

## 13. Cleanup verification

Cleanup remains independent from validation outcome and verifies both exact
kind cluster absence and exact Docker network absence. Provider cleanup flows
through `ProviderManager.cleanup`; an environment teardown failure makes the
provider lifecycle cleanup result fail instead of being blindly stamped
complete. The interrupted operator-deferred rerun was cleaned explicitly and no
kind clusters remained.

## 14. Persisted evidence verification

Provider identity/version, bootstrap/readiness/reconciliation, resource
identity, runtime observation, failure reason, timing, and cleanup are JSON-safe
and survive cluster destruction. Before/final evidence files are retained next
to this report. Static scan and finding state remain independent from Deployment
Validation environment outcomes.

## 15. Adversarial review findings and fixes

The fresh review found and the implementation fixed:

- Ingress false-positive acceptance of a nonexistent backend Service port.
- Same-name replacement Ingress inheriting an old UID's Sync event.
- Bound PVC false positive without an exact PV claimRef and local
  StorageClass/provider correlation.
- CronJob evidence being diagnostic-only instead of explicitly participating in
  the final decision with configuration-vs-execution semantics.
- Provider manager reconciliation/cleanup not being invoked by orchestration.
- Duplicate environment examples that enabled and then disabled Ingress.

The reviewer found no actionable release-name regression, Secret-value leak,
unpinned/offline-provider regression, infrastructure/application evidence mix,
host-boundary weakening, or static-scan coupling.

## 16. Capabilities CATS still cannot meaningfully emulate

CATS intentionally does not fake GPUs or hardware extended resources;
AWS/Azure/GCP APIs and IAM; cloud load-balancer controllers; cloud CSI behavior;
production SAN/Ceph behavior; metadata services; or vendor-specific Ingress and
LoadBalancer semantics. These remain `REQUIRED` plus
`UNSUPPORTED`/`COULD_NOT_VALIDATE`/`PROVIDER_SPECIFIC`, with exact requirement
provenance, rather than fabricated success or application vulnerability
findings.
