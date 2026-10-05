# CATSchrödinger delivery validation

This describes the implemented contract, not production certification. Use the
dedicated disposable Linux validator and PKI described in
[setup](schrodinger-setup.md) and review the [security audit](schrodinger-security-audit.md).
`VERIFIED` means the tested Helm deployment installed and expected workloads
became ready under the sandbox restrictions; it is not a security approval.

## Artifact modes and identity

The v2 validator accepts four explicit `validation_type` values:

| Type | Submitted artifact | Identity checked |
| --- | --- | --- |
| `helm-chart` | Streamed retained Helm archive | SHA-256 of archive bytes; service/version in its manifest |
| `oci` | JSON declaration with `oci://registry/path@sha256:…` | Immutable digest confirmed by Helm pull |
| `standard-bundle` | Streamed deployment ZIP | SHA-256 of ZIP bytes plus manifest/file/dependency inventories |
| `offline-bundle` | Streamed self-contained deployment ZIP | Same checks, complete rendered image archives, then isolated runtime verification |

The remediation wizard's `bundle` choice is a **legacy retained candidate**,
not a new final Standard/Offline Bundle and not evidence of final verification.
Original deployment, remediated candidate, and final delivery results are
independent. Never reuse an earlier result for rewritten Helm values, a new
render, a mutable tag, or a regenerated ZIP.

Standard/Offline Bundle delivery is asynchronous. CATS materializes the final
bytes once, sends that file to the independent validator, and releases it only
after `VERIFIED` with matching artifact digest, service/version and validation
type. Offline delivery additionally requires `offlineVerified: true`. The
download handler rechecks the retained bytes; failed, changed, or unverified
artifacts are not downloadable as final bundles. The attempt-specific route is
`/services/{service}/remediations/{job}/deliveries/{attempt_id}/bundle.zip`.
An OCI publication can exist even if its subsequent verification fails; inspect
the delivery and verification statuses separately before promotion.

## API and evidence

Submit to `POST /api/v2/validations`. For archive/ZIP artifacts send
`Content-Type: application/octet-stream`, an explicit `Content-Length`, and
`X-CATS-Declaration` containing URL-safe base64-encoded JSON. OCI submission uses
`application/json` with the same declaration:

```json
{
  "schema_version": "cats.validation/v2",
  "validation_type": "offline-bundle",
  "service": {"id": "service-key", "version": "revision-2"},
  "artifact": {"reference": "delivery.zip", "digest": "sha256:<64 lowercase hex characters>"},
  "deployment": {"type": "helm", "namespace": "validation"},
  "validation_profile": "default"
}
```

Replace the digest placeholder; it is not valid wire data. Unknown fields,
duplicate JSON keys, unsupported profiles, invalid paths and size-limit breaches
are rejected. `namespace` and `validation_profile` are optional. Acceptance is
HTTP 202 with `validation_id`, v2 `schema_version` and `status: QUEUED`. Poll
`GET /api/v1/validations/{validation_id}`; cancellation uses
`POST /api/v1/validations/{validation_id}/cancel`. These shared lifecycle routes
retain v2 schema/identity for v2 jobs. `/health` retains the legacy v1 health
schema; health alone does not prove a workload can deploy.

Terminal states include `VERIFIED`, `PARTIALLY_VERIFIED`, `COULD_NOT_VALIDATE`,
`FAILED`, `ERROR`, `CANCELLED`, and `TIMED_OUT`. Results carry `validation_type`,
`service`, `artifact`, `artifact_digest`, `deployment`, `helm`, `network`, and
`offlineVerified`, alongside lifecycle/resource evidence. `network` reports
`isolated`, `external_chart_fetches`, and `external_image_pulls`; unavailable
measurements remain null, not an inferred zero. Offline results also report
required/provided/loaded images. Retain the full result with the delivery digest.

## Offline prerequisites and limits

An offline bundle needs retained root chart/values, vendored declared Helm
dependencies and matching lock provenance, exact rendered manifests, checksummed
files, and an archive with verified image identity for **every rendered image**.
The bundle manifest uses `schemaVersion: "1.0"` (distinct from the v2 API schema),
`validationType`, `service`, `deployment`, `files`, `helmDependencies`, `images`,
and `requiredImages`. Unsafe ZIP paths, symlinks, undeclared entries, missing
dependencies/images and checksum or image-identity mismatch fail closed.

Provision the validator's approved digest-pinned Kind node image locally before
closing provisioning egress. Offline execution forces strict sandbox policy,
no network egress and local images. It loads bundle image archives into Kind,
checks node image inventory, and requires proven isolated node networking and
zero external chart fetches/image pulls before `offlineVerified` can be true.
See setup for Docker Engine 28+ isolated bridge requirements and VM preflight.
This is an inventory/runtime check, not a general packet-capture claim about all
application traffic. VM-level firewall restrictions remain necessary.

Disconnected verification cannot supply absent CRDs/operators, production
storage classes, cloud load balancers, ingress infrastructure, secrets or
external services. Missing capabilities must remain partial/unavailable/failure
evidence. Neither mocked regression tests nor this Windows development host
certify live Linux isolation or production readiness; run the documented VM
preflight and a representative end-to-end deployment before enabling delivery.

## Trust and OCI configuration

Keep the existing mTLS boundary: CATS uses the configured explicit server CA,
client certificate and encrypted client key; redirects, embedded URL credentials
and insecure TLS bypass are not supported. The validator requires its client CA
and `CATS_VALIDATOR_CLIENT_FINGERPRINTS` authorization allowlist of DER leaf
certificate SHA-256 fingerprints. Rotate certificates/fingerprints as described
in setup. Registry CA trust is separate from validator-server trust.

OCI resolution requires `CATS_VALIDATOR_OCI_ALLOWED_REGISTRIES` (comma-separated
exact host/port authorities), `CATS_VALIDATOR_OCI_CA_FILE` (or explicit
`SSL_CERT_FILE` / configured trusted CA certificates), and, for authentication,
`CATS_VALIDATOR_OCI_REGISTRY_CONFIG` pointing to an existing Helm registry config.
Protect these files and restrict the worker's destinations/egress. This OCI
allowlist controls chart resolution, not arbitrary workload egress.

Tool subprocesses receive only PATH/home/temp/system paths, Docker connection
settings, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, Helm cache/config/data paths and
`XDG_RUNTIME_DIR`; arbitrary credential environment variables are not inherited.
The OCI adapter explicitly sets `HELM_REGISTRY_CONFIG` and its selected CA.
Do not rely on a shell's ambient registry login or unrelated cloud credentials.
