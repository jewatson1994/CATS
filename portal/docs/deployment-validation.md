# Deployment Validation

Deployment Validation is CATS runtime evidence for Helm artifacts. It is a
second, asynchronous pass after static ingestion: CATS renders the retained
chart, creates a uniquely named disposable Kubernetes cluster with `kind`,
installs the chart, observes workload health and Kubernetes events, captures an
Observed topology, compares it with the Declared topology, and destroys the
cluster.

Static analysis remains authoritative. A missing tool, unavailable image,
unsupported dependency, validation timeout, rejected workload, or failed kind
cluster does not fail, roll back, or invalidate a completed CATS scan. Runtime
results do not create POA&M findings by themselves.

## States

- `VERIFIED` — Helm installed and expected workloads reached an acceptable
  Ready state in the CATS ephemeral environment.
- `PARTIALLY_VERIFIED` — Helm installed and meaningful Kubernetes evidence was
  collected, but an environmental capability (for example generic LoadBalancer,
  Ingress, or provider-specific storage) could not be fully reproduced.
- `COULD_NOT_VALIDATE` — an environmental dependency, security restriction,
  unavailable image, Helm/kind failure, or API failure prevented meaningful
  validation.
- `NOT_ATTEMPTED` — validation is disabled, was not requested, or the scan did
  not retain source files that can be submitted to the validator.

`VERIFIED` does not certify that an artifact will deploy successfully in every
production Kubernetes environment. kind does not reproduce cloud controllers,
CSI drivers, admission controllers, operators, service meshes, external secret
providers, or production networking unless they are deliberately supplied.

## Capability preflight

After Helm rendering, CATS records the environmental capabilities requested by
the artifact: LoadBalancer Services, Ingress classes, PVC and StorageClass
requirements, custom resources/operators, scheduling constraints, host
networking, extended resources/GPU requests, and recognizable cloud-provider
APIs. This evidence is stored with the immutable validation run.

CATS plans providers only for generic capabilities required by the rendered
artifact. MetalLB supplies generic LoadBalancer behavior and ingress-nginx
supplies generic Ingress behavior from bundled, SHA-verified manifests and
digest-pinned image archives. The provider order is explicit: ingress-nginx
depends on MetalLB so its controller Service can reconcile without adding a
host process or weakening the sandbox. Existing usable local/default kind
storage is discovered rather than replaced. No controller or provider is
downloaded during validation. Provider-specific classes and storage drivers
are never silently mapped to a generic implementation. If Helm installs and
Kubernetes evidence is collected while a capability remains unavailable, the
result is `PARTIALLY_VERIFIED`.
Objects supplied by CATS are labeled `cats.clanhq.io/validation-infrastructure`
and retained as raw evidence, but excluded from normal artifact reconciliation.

## Security boundary

Submitted Helm and Kubernetes content is untrusted. Before kind is created,
CATS inspects the exact `helm template` output, but ordinary Kubernetes scope,
RBAC, namespaces, hooks, host ports, image pull policy, and custom resources
are not preflight gates. The boundary policy blocks only requests that can
reach the Docker host or kind-node control surface: sensitive `hostPath`
targets and runtime sockets, privileged containers, sandbox-sensitive Linux
capabilities, device mounts, and host-networking when egress is enabled.
Host PID and IPC namespace sharing are also blocked because they expose the
disposable kind node's namespaces.
Object/pod capacity observations are
  warning-level governance metadata; Kubernetes is still allowed to evaluate
  the rendered workload. ResourceQuota and LimitRange remain applied
  inside the disposable namespace when the API accepts them. Each run also gets a dedicated Docker network
that is internal by default; a namespace NetworkPolicy adds defense in depth.
External egress requires an explicit configuration change. Child tools receive
a minimal environment rather than portal/database credentials. Persisted
diagnostics contain bounded metadata and command hashes, and Secret values are
removed before evidence is persisted.
The Docker network is the primary isolation control; the Kubernetes egress
policy is defense in depth and should not be treated as a substitute for a
policy-capable CNI.

## Resource isolation

CATS attempts CPU, memory, and process limits independently on the ephemeral
kind control-plane container. The result persists each control's configured
value and status (`ENFORCED`, `UNSUPPORTED`, or `FAILED`) plus an overall
`ENFORCED`/`BEST_EFFORT` state. A runtime that cannot configure or verify a
defense-in-depth limit produces an environmental warning and validation
continues inside the bounded kind sandbox. `RESOURCE_LIMIT_EXCEEDED` is
reserved for explicit Docker node exhaustion evidence; Kubernetes scheduling
failures and large Pod resource requests remain runtime workload evidence,
classified as `INSUFFICIENT_CPU`, `INSUFFICIENT_MEMORY`, or `UNSCHEDULABLE`
when Kubernetes reports those conditions. Application `OOMKilled` events are
captured as `OOM_KILLED` runtime evidence.

kind itself requires Docker-socket-equivalent privileges and creates privileged
node containers. These controls reduce what a submitted chart may request; they
do not turn the Docker socket into a hostile-code sandbox. Run Deployment
Validation on a dedicated, disposable Docker host or VM, not on a multi-tenant
host. The normal CATS portal already requires Docker access for scanner
workflows, but operators should treat enabling runtime validation as an explicit
trust-boundary decision.

## Helm timing evidence

Each run persists measured Helm template and install stages in its
`helm_result` JSON: start/completion timestamps, per-stage durations, and the
combined `helm_total_duration_ms`. Failed stages retain the time they ran;
stages that were never reached have no fabricated duration. The aggregate
validation duration remains on the Validation run; the Helm panel shows only
template/install timing.

For that reason, canonical configuration defaults Deployment Validation to
disabled. Enabling it is an explicit operator decision and should be done only
on a dedicated disposable Docker host or VM. The Kubernetes API binds to
`127.0.0.1` by default. A containerized portal that must reach the host API
requires an explicitly chosen validator-only host address; using `0.0.0.0`
expands the host-network attack surface and is not the safe default.

## Offline operation

When preflight blocks a chart, the result also persists
`security_policy_violations`: one bounded object per rejected policy check.
Each object identifies the rule, reason, kind/name/namespace, container and
manifest field, plus a value and scanner-retained template, line, or Helm
values path only when attribution is reliable. The Deployment Validation page
renders the complete list. Older runs with only an aggregate count remain
readable and say that detailed evidence was not retained. The aggregate message
uses “violation(s)”; these are policy checks, not HTTP requests.

The release image pins kind, kubectl, Helm, and a digest-qualified kind node
image. A disconnected environment must preload the pinned `kindest/node` image
into the Docker daemon, or mount a reviewed `docker save` archive and set
`CATS_DEPLOYMENT_KIND_NODE_ARCHIVE`. Workload images are loaded directly into
kind when available, but a local inspection or image-load failure is only a
warning. Helm and Kubernetes still receive the chart so `ImagePullBackOff`,
`ErrImagePull`, and registry-auth failures become runtime evidence. Registry
credentials are not copied into the ephemeral cluster.

If administrators explicitly enable network egress, images absent from the
local daemon are left for Kubernetes to pull. Registry authentication is not
copied automatically; private images still need an approved, environment-
specific integration. The local-image requirement remains useful as a signal in
the UI, but it is not an early-exit gate for a safe chart.

## Configuration

The canonical defaults are one concurrent worker, 180 seconds each for cluster
creation and Helm installation, 120 seconds for readiness, 60 seconds each for
collection and cleanup, and 600 seconds total. The environment variables are
listed in `.env.example`:

- `CATS_DEPLOYMENT_VALIDATION_ENABLED`
- `CATS_DEPLOYMENT_VALIDATION_WORKERS`
- `CATS_PIPELINE_MAX_REQUEST_BYTES`, `CATS_DEPLOYMENT_MAX_SOURCE_BYTES`
- `CATS_DEPLOYMENT_*_TIMEOUT`
- `CATS_DEPLOYMENT_MAX_PODS`, `CATS_DEPLOYMENT_MAX_OBJECTS`, `CATS_DEPLOYMENT_MAX_COMMAND_OUTPUT_BYTES`

Repository file and root-chart counts are recorded as workload scale, not used
as validation gates. Every discovered root chart is linted, rendered, and
installed within the aggregate byte and total-time budgets.

## Sandbox trust boundary

Deployment Validation protects the boundary between a disposable kind node
and Docker Desktop/the real host/CATS. Local inspection of the supported kind
runtime established that the node has a separate PID and network namespace and
does not inherit CATS environment variables, database storage, signing keys,
registry credentials, or the Docker socket. It is, however, a privileged
Docker container with unconfined seccomp/AppArmor, a writable ephemeral `/var`
volume, and a read-only `/lib/modules` host bind. Compromise of the node is
therefore not treated as safely contained.

Each run uses a dedicated Docker bridge and does not attach its node to the
CATS application network. With egress disabled the bridge is internal.
`hostNetwork` is allowed only in that internal mode. Host gateway isolation is
not claimed when egress is enabled.

Preflight decisions are behavioral rather than chart-name based:

- read-only node `/proc` and `/sys` telemetry is sandbox-sensitive but allowed;
- Docker/containerd/CRI sockets, root hostPath, devices, `hostPID`, `hostIPC`,
  privileged containers, and node-takeover capabilities remain hard blocks;
- writable or otherwise unproven host paths remain blocked;
- allowed-sensitive decisions and blocking boundary violations are persisted
  separately. Neither creates a static finding or POA&M record.
- `CATS_DEPLOYMENT_MAX_CPU`, `CATS_DEPLOYMENT_MAX_MEMORY`,
  `CATS_DEPLOYMENT_MAX_STORAGE`
- `CATS_DEPLOYMENT_NODE_CPUS`, `CATS_DEPLOYMENT_NODE_MEMORY`,
  `CATS_DEPLOYMENT_NODE_PIDS`
- `CATS_DEPLOYMENT_KIND_NODE_IMAGE`, `CATS_DEPLOYMENT_KIND_NODE_ARCHIVE`
- `CATS_DEPLOYMENT_API_ADDRESS`, `CATS_DEPLOYMENT_API_HOST`
- `CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS`
- `CATS_DEPLOYMENT_LOAD_BALANCER_PROVIDER_ENABLED`,
  `CATS_DEPLOYMENT_LOAD_BALANCER_BUNDLE_DIR`, `CATS_DEPLOYMENT_LOAD_BALANCER_TIMEOUT`
- `CATS_DEPLOYMENT_INGRESS_CONTROLLER_ENABLED`,
  `CATS_DEPLOYMENT_INGRESS_BUNDLE_DIR`, `CATS_DEPLOYMENT_INGRESS_TIMEOUT`

Every attempt gets a run ID, cluster name, namespace, job-local kubeconfig, and
durable evidence record. Cleanup is attempted in `finally` even when creation,
install, readiness, or collection fails. Startup recovery only targets exact
cluster names owned by expired database runs; it never deletes clusters merely
because their names share a prefix.

## Re-running and future remediation

Users with remediation-execution permission can select **Re-run Validation**.
This creates a new run and retains the earlier evidence. The worker accepts a
generic `ValidationArtifact` with an artifact type and reference, rather than
assuming the original upload. A future Remediate workflow can therefore submit
the remediated candidate through the same validator and compare its result with
the original baseline without changing this execution contract.

Pipeline producers that render with non-default Helm values must include the
exact ordered artifact-relative paths in `helm_values_files` and retain those
files in `helm_source_files`. Validation passes the same files to Helm lint,
template, and install. Producers should materialize `--set` overrides as an
additional values file so validation remains reproducible without putting
sensitive values on a process command line.

## Automatic generic LoadBalancer capability

Ordinary `Service.type: LoadBalancer` selects the built-in MetalLB 0.16.1
native/L2 provider automatically. The scanner image bundles its SHA-verified
manifest and digest-pinned controller/speaker image archives; the all-in-one
image inherits them. Validation verifies local integrity and imports archives
directly into its own kind cluster. It never fetches provider dependencies.
See `cats-scanner/tool-archives/README.md` for disconnected build inputs.

MetalLB was selected over Cloud Provider KIND because all provider resources
stay inside the per-run cluster: no host process, Docker socket, host proxy
container discovery, host port, or host route is needed by this provider.
The trusted speaker uses host networking and NET_RAW inside the disposable
kind node, not the Docker host. Existing artifact security checks are unchanged.
This does not emulate AWS/Azure/GCP or vendor-specific LoadBalancer classes.

After render and cluster creation, CATS loads images, installs and waits for
the controller/speaker and CRDs, then creates a pool from unallocated addresses
on that run's Docker network. Helm template and install use the identical
`cats-validation-N` release name. After workload readiness, CATS rechecks the
provider, pool and advertisement, and correlates the exact Service namespace,
name, assigned pool address and UID-owned ready EndpointSlices. Only this
evidence permits `VERIFIED`; no HTTP/TCP reachability is claimed.

Bootstrap failure remains non-blocking for Helm, with real bounded failure
evidence and timings. `AVAILABLE` means provider ready before exercise;
`UNEXERCISED` means the Service/backends did not demonstrate success;
`UNAVAILABLE` means provider readiness failed; provider-specific semantics
remain `PROVIDER_SPECIFIC`. Nonrequired capabilities remain `NOT_REQUIRED`.
Provider objects carry CATS infrastructure labels and are excluded from
workload counts/drift while their technical evidence is retained.

Default `CATS_DEPLOYMENT_LOAD_BALANCER_PROVIDER_ENABLED=true` implements AUTO
behavior (no work when not needed). Explicit false disables it. The default
bundle directory is `/opt/cats/validation/loadbalancer`; bootstrap budget is
90 seconds, additionally bounded to reserve time for Helm. The legacy LB
manifest variable is accepted but no longer executed: arbitrary controller
manifests cannot replace CATS-owned trusted infrastructure.

Cleanup removes the complete kind cluster and its per-run Docker network in
`finally`, including cancellation/failure. No separate provider host resources
are created. Cleanup confirmation is independent of validation success.

## General capability providers

Deployment Validation uses a provider-neutral lifecycle: requirement detection,
dependency planning, offline bootstrap, provider readiness, artifact runtime
reconciliation, evidence persistence, and reverse-order cleanup. Provider
readiness never proves that an artifact exercised a capability. Each capability
row retains provider identity/version, bootstrap/readiness status, verification
method, reconciliation result, failure reason, and cleanup outcome.

Generic Ingress uses ingress-nginx 1.15.1 and kube-webhook-certgen 1.6.9. CATS
verifies and loads their archives before applying the pinned kind manifest. An
artifact Ingress is `VERIFIED` only when the exact namespace/name is accepted,
either by status or a Sync event for the current Ingress UID, every referenced
Service and exact named/numeric backend port exists, EndpointSlices are owned
by those exact Service UIDs and expose ready endpoints, and the corresponding
Pods are Ready.
This is control-plane evidence; CATS records that network reachability was not
tested. Cloud-specific Ingress classes and annotations remain
`PROVIDER_SPECIFIC`.

Storage evidence is resource-specific. Standalone PVCs and every PVC name
generated by StatefulSet `volumeClaimTemplates` must be observed Bound in the
correct namespace. Each PVC must identify an observed Bound PV whose claimRef
matches the PVC namespace/name/UID, and its observed StorageClass must use the
selected local provisioner. When a workload consumes the claim, its exact Pod
must be scheduled and Ready. ConfigMap and Secret dependencies retain only object kind/name,
existence, and reference provenance; values and Secret key contents are never
collected. Workload evidence covers Deployment, StatefulSet, DaemonSet, Job,
CronJob, Pod, init containers, and native sidecars using namespace and UID
ownership rather than same-name correlation. A CronJob is verified as an exact
API-accepted configuration without waiting for a future schedule; whether an
owned Job executed successfully is recorded separately.

The acceptance harness `scripts/verify-loadbalancer.py` can run a retained
execution against isolated modified modules without updating historical DB
records. `--offline` also enforces an internal Docker network. On the tested
Docker Desktop host, the pinned kind 0.33/node 1.37 entrypoint fails before
Kubernetes on that internal network (empty DNS gateway in iptables-restore).
This existing kind/network incompatibility is not bypassed by enabling egress
automatically; the provider bundle remains offline, while the real acceptance
uses the deployment's already-enabled egress setting.

## Live run status

The Deployment Validation page treats the persisted run record as authoritative.
While a run is active, the page polls its run-scoped JSON endpoint approximately
every two seconds and updates the phase badge, summary fields, anchored elapsed
timer, Helm timings, capability assessment, resource readiness, conditions,
dependencies, topology, comparison, policy evidence, warnings, events,
diagnostics, and cleanup state in place. Polling continues through cleanup and
stops only when the status is terminal, the phase is `COMPLETE`, and cleanup is
terminal. A failed poll preserves the last evidence and announces a retry.

Re-running submits for a new run, switches the page to that run immediately,
and rejects responses from the previous run. Historical terminal runs do not
poll. The JSON rerun response is encoded with the same authoritative view as
the GET endpoint so timestamps and the initial `QUEUED` state are safe for the
browser to consume.

## Explainable classification and expanded capabilities

Every completed run persists `classification` (the same value as `status`),
`classification_reasons`, and a `classification_summary`. Reasons are bounded,
machine-readable records with a stable code, resource identity, expected and
observed state, and a human explanation. The summary counts expected resources,
observed expected resources, expected-only resources, runtime-generated
resources, and failed resources. The page renders these records in **Why this
result?**, and the status badge links to that section. Cleanup is intentionally
reported separately and never changes a successful classification.

The deterministic rule is: `VERIFIED` requires Helm success, no unhealthy
required workload, and no unmet required capability; `PARTIALLY_VERIFIED`
means Helm and meaningful runtime evidence exist but a required capability or
expected resource remains incomplete; `COULD_NOT_VALIDATE` means the run could
not collect meaningful evidence. A CronJob is not downgraded merely because its
future schedule has not created a Job. Controller-generated resources are
classified as `defaulted`/`runtime_generated`, not as missing declared objects.
An absent expected object uses `EXPECTED_RESOURCE_NOT_OBSERVED`; the generic
`UNKNOWN` category is reserved for genuinely unclassified failures and is no
longer used as a fallback for an ordinary declared-only comparison.

The capability preflight and runtime evidence now cover node scheduling, DNS /
Service Discovery, ServiceAccount/RBAC references, NetworkPolicy configuration,
HPA target resolution, CRD/custom-resource acceptance, admission webhook
Service/EndpointSlice references, TLS Secret metadata, and the existing
LoadBalancer, Ingress, Storage, configuration, GPU, cloud/provider, and
operator signals. Explicit Service DNS dependencies are probed from a ready
workload Pod with `getent`/`nslookup`; values and Secret contents are never
persisted. NetworkPolicy enforcement, metrics delivery, certificate validity,
and external operator behavior remain explicitly marked as not tested rather
than being represented as verified.

Repeated configuration-dependency rows are retained as technical evidence but
are grouped into one capability summary with required, verified, available,
and failed totals. This preserves traceability while keeping the primary page
readable.
