# LoadBalancer implementation and acceptance report

Verified on 2026-09-16 using the real `helm-test` Service (ID 11), retained
Helm source Execution 13, and the existing Docker Desktop runtime. Stored
validation history was read, not rewritten. The test harness ran isolated
copies of the modified modules in the existing portal container; it did not
replace the running application's files or restart services.

## Before and after

| Evidence | Real baseline | Real new implementation |
| --- | --- | --- |
| Overall result | PARTIALLY_VERIFIED | VERIFIED |
| Helm template/install | PASS / PASS | PASS / PASS |
| Helm installed release | candidate-1 (render used cats-validation-1) | cats-validation-1 for both |
| LoadBalancer | UNAVAILABLE | VERIFIED |
| Bootstrap | 0 ms | 33,225 ms |
| Actual Service | requirement: cats-validation-1-nginx | cats-validation-1-nginx observed |
| Assigned address | no verified address | 172.19.255.239, from CATS pool |
| Ready backend endpoints | not verified | 1, UID-associated EndpointSlice |
| Node scheduling | PENDING | VERIFIED |
| Ingress/storage/GPU/cloud | Ingress incorrectly UNAVAILABLE | all NOT_REQUIRED |
| Cleanup | COMPLETE | COMPLETE |
| Total run duration | 35 seconds | 79 seconds |

Full retained evidence: [baseline](loadbalancer-before.json) and
[after](loadbalancer-after.json). After cleanup, Docker container/network
listings for the acceptance run names were empty. The stopped bundle-export
helper was also removed. No provider host daemon, proxy container, route or
port is created by this implementation.

## Root cause and timing

`capability_preflight` correctly detected `Service.spec.type=LoadBalancer`.
`provision_validation_capabilities` then required both an enabled flag
(default false) and a configured local manifest (default empty). Normal
Compose did not provide them. That branch emitted both reported strings and
returned without executing a provider command. Rounded elapsed time was
therefore 0 ms; the bootstrap path was called, but performed no provisioning.

The separate render/install naming mismatch used `cats-validation-N` for
render and `candidate-N` for install. Both now use `cats-validation-N`, and
tests require matching names and reject a Service under the old install name.
The live run also exposed invalid `kubectl rollout status --all` usage; waits
now target the actual rendered controllers. PDB collection was added because
the actual chart includes one and omitting it falsely yielded declared-only.

## Selected provider and packaging

MetalLB **0.16.1 native/L2** was selected. The repository pins kind **0.33.0**,
kubectl/node **1.37.0**, and Helm **4.2.3**; those pins were retained and used
in live acceptance. The existing node digest starts `a1ed56cfb0e7`.

[Cloud Provider KIND](https://kind.sigs.k8s.io/docs/user/loadbalancer/) is the
kind-documented option, but runs outside Kubernetes with container-runtime
access and creates host-side load-balancer containers. Its default
cross-cluster discovery and host-helper cleanup add isolation complexity.
[MetalLB native installation](https://metallb.io/installation/) keeps the
controller, speaker, pool and advertisement inside each disposable cluster.
No existing bundled provider was present, only the optional manifest hook.
Only MetalLB was installed.

The scanner build adds a dedicated bundle stage. It fetches only at **build
time**, validates the upstream manifest SHA-256 and pinned linux/amd64 image
manifest/config digests, checks every uncompressed archive layer, and records
manifest/archive hashes in `bundle.json`. Supplied offline build artifacts use
the same validation. The complete bundle at
`/opt/cats/validation/loadbalancer` is inherited by the all-in-one image and
travels with normal image save/load distribution. The release checker verifies
its contents. The bundle stage was actually built successfully.
The all-in-one build rejects older scanner bases missing the bundle instead
of producing another image that cannot supply its default capability.

Validation verifies local hashes, imports `controller.tar` and `speaker.tar`
with `kind load image-archive`, and applies local files. Provider images use
`imagePullPolicy: Never`; there is no runtime URL apply, curl, registry pull or
Helm repository dependency in the provider path.

## Lifecycle, evidence and status

Render → detect → create isolated kind cluster → verify bundle → import images
→ apply labeled native resources → wait CRDs and controller/speaker rollout
→ create run-network address pool and L2Advertisement → install Helm
→ wait actual workloads and Service reconciliation → recheck provider health
→ collect exact Service, EndpointSlices and events → classify → cleanup.

Bootstrap has an aggregate deadline, reserved time for Helm, per-stage status
and elapsed time, and bounded sanitized failures. Failure continues to Helm
and Kubernetes evidence collection when the cluster remains usable.

`AVAILABLE` is provider readiness before exercise. `VERIFIED` requires the
exact namespaced LoadBalancer Service, an address belonging to the recorded
CATS pool, healthy current controller/speaker and unchanged pool/advertisement,
and ready UID-owned backend EndpointSlices when the Service has a selector.
`UNEXERCISED` means an available provider did not demonstrate Service/backend
success. `UNAVAILABLE` means provider readiness was not established/retained.
Vendor classes/annotations remain provider-specific and cannot become fully
verified through generic emulation. Optional connectivity is explicitly
`attempted: false`; no HTTP/TCP reachability is claimed.

Technical evidence includes versions, image digests, integrity hashes, stages,
timing, pool, provider status, Service identity/status, endpoint ownership,
events and cleanup. The UI presents compact provider/reconciliation status
with expandable technical evidence. Existing JSON persistence carries this
data without mutating earlier runs or static findings.

## Infrastructure, cleanup and security

Provider objects and pod templates carry the CATS infrastructure and run
labels. They are excluded from workload counts and artifact drift, retained
in diagnostics, and destroyed with kind. The node exclusion label is removed
only inside the run's cluster. Address allocation uses inspected free addresses
on that run's network and excludes gateway/node allocations; each cluster has
its own provider API namespace and no shared host controller.

The known speaker uses host networking and NET_RAW **inside the kind node**.
It receives no Docker socket, host process or host route access. Existing
untrusted-artifact security checks are unchanged. User-provided controller
manifests are not promoted to trusted built-in infrastructure. Bootstrap
commands use argument arrays and a run-specific kubeconfig.

Finally-based cleanup remains active on success, failure, timeout and
cancellation. Cluster and network deletion are verified separately from the
workload verdict; a cleanup failure stays visible rather than silently
converting validation evidence. Stale-run cluster cleanup naturally also
removes in-cluster MetalLB components.

## Configuration and deployment

`CATS_DEPLOYMENT_LOAD_BALANCER_PROVIDER_ENABLED` defaults to **true** in code,
examples and Compose, implementing automatic provisioning only when required.
Explicit false is supported. `CATS_DEPLOYMENT_LOAD_BALANCER_BUNDLE_DIR` defaults
to the packaged path and `CATS_DEPLOYMENT_LOAD_BALANCER_TIMEOUT` to 90 seconds.
The legacy manifest field remains accepted but is no longer executed for LB.
Ingress configuration is unchanged. No administrator manifest is needed.

Rebuild the scanner base and all-in-one image through the existing build
workflow, then recreate the portal service to activate these changes in the
UI. The currently running application was deliberately left unchanged; only
the isolated acceptance copy used the new implementation.

## Tests and fresh review

- Final portal full suite: **303 passed, 1 skipped**.
- Final focused validator/provider/integration suite: **70 passed**.
- Packaging integrity tests: **4 passed**.
- Built bundle integrity verified in a real `--network none --pull=never`
  container: MetalLB 0.16.1, manifest and both image archives passed.
- Python compilation checks passed.
- Compose configuration validation passed; targeted whitespace checks passed.
- Real baseline plus two successful provider executions; final full artifact
  result VERIFIED with complete cleanup.

Coverage includes detection, no-op without LB, automatic selection, bootstrap
order/success/failure/timeout, Helm continuation, missing/corrupt dependencies,
provider-specific semantics, exact release/Service correlation, namespace/UID
ownership, unready backends, foreign pool addresses, provider health,
infrastructure labels, explicit disable, cleanup failure visibility, per-run
isolation, offline command behavior and existing historical-run tests.

Fresh independent backend review identified four issues, all corrected:
failed commands labeled PASS in stage evidence; acceptance of foreign LB
addresses; readiness ignoring pool/advertisement presence; missing Service
events for chart-explicit namespaces. Corresponding runtime checks and tests
were added. A requested second review pass hit the subagent account quota;
the first fresh review completed and its concrete findings were fixed.

## Known limitations

The real test used the deployment's already-enabled egress setting. An actual
`--offline` run was attempted first: the pinned kind node failed before
Kubernetes because its entrypoint computed an empty DNS gateway on Docker's
internal network (`iptables-restore: host/network '' not found`). CATS does
not silently relax that isolation. Provider dependency loading is offline,
but a fully disconnected end-to-end run on this Docker Desktop host is **not
claimed**; the pre-existing kind/network issue remains.

The host also reported an optional Docker memory-update failure and a local
multi-platform nginx image import failure. Both remained warnings, and nginx
became ready using the deployment's existing network-enabled behavior. These
are not suppressed or represented as successful controls. MetalLB does not
provide public routing, provider-specific cloud behavior or proven Windows
host reachability. This distribution currently supports linux/amd64 and IPv4
kind bridge networks. General workload network reachability was not tested.
