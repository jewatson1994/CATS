# Schrodinger v2 validation core

Base: `3d1d8c88de15900d995a02e7a4560e85dfeeb5ce`.

Main already provides the Kind engine, Helm rendering and installation,
readiness observation, restricted sandbox policy, resource limits, network
isolation, cleanup, mTLS transport, asynchronous jobs, polling, cancellation,
and restart recovery. This change extends those components rather than
introducing another runtime or host provisioning system.

## Contract and adapters

`cats.validation/v2` declares a 32-character hexadecimal request ID, validation
type, service ID/version, artifact reference and SHA-256 digest, and Helm
deployment configuration. The server assigns a separate job ID. Submission,
polling, and terminal evidence bind both IDs to the exact type, service version,
reference, and digest; the client rejects mismatches. Existing v1 remains.

Binary archives use streamed uploads and bounded declaration headers. OCI uses
JSON declarations. Four adapters prepare inputs for the same Kind engine:

- `helm-chart`: verified archive with a concrete chart and ordered values files.
- `oci`: immutable digest reference, explicit registry allowlist and CA trust;
  Helm must report the expected digest before extraction.
- `standard-bundle`: exact manifest/content inventories and digest verification.
- `offline-bundle`: the same integrity checks plus vendored dependencies and
  verified image archives, isolated networking, and runtime image loading.

`require_helm_lifecycle=True` opts v2 into actual `helm upgrade --install` and
release-status observation after every strict sandbox gate has passed. It
changes deployment technique only: failed CPU/memory/PID or namespace resource
policy enforcement remains fatal. V1 strict manifest-apply behavior remains.
Verified requires successful installation and a deployed release plus the
existing runtime observation checks. Rendering or applying manifests alone
cannot produce a v2 Verified result. Values ordering and namespace are retained.

## Integrity and safety

The generic bundle helpers provide deterministic archives, canonical paths,
exact inventories, SHA-256 checks, bounded files/bytes/metadata, dependency
inspection, and workload/image inventories. Traversal, absolute paths,
case-folded duplicate paths, links, special files, and undeclared content are
rejected. Docker-save image config/layer identity is checked separately from
registry manifest digest identity.

OfflineVerified requires verified internal network isolation, complete image
inventory loading, vendored dependencies, zero external chart fetches/image
pulls, and successful real Helm/runtime validation. Unperformed checks remain
null; missing evidence cannot imply offline verification. Pull policies that
require registry access are rejected. Strict resource and restricted-pod
policies remain mandatory. mTLS and client ownership checks are preserved.

Job-owned uploads, preparation directories, Kind clusters and networks are
cleaned on completion/failure/cancellation. Restart recovery also removes
owned uploads and preparation directories; cleanup failures remain explicit.

## Validation and acceptance boundary

Focused tests exercise contract rejection, identity mismatches, concurrent job
separation, archive safety, adapter preparation, values preservation, actual
Helm command selection, install/status/readiness failures, sandbox enforcement,
and cleanup. Runtime command tests use mocked Docker/Kind/Helm responses.
The full backend suite is run on this reconstructed branch.

Docker, Kind and Helm are unavailable on this development machine. A real
chart installation and runtime observation on the dedicated validator VM remain
required acceptance evidence; unit tests are not that proof. The next phase
must supply managed deployment onto a Docker-ready host and HQ wiring. OCI
requires configured registry trust; offline execution requires local node and
workload images and supported strict network enforcement.

No managed host provisioning, payload/release assets, Ubuntu package closure,
remediation integration, user-facing Offline Bundle generation, frontend,
Docker/Compose, or dependency-manifest changes belong to this phase.
