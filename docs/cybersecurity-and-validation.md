# Cybersecurity configuration and deployment validation

All endpoints, registries, certificate authorities, and data sources are explicit
configuration. CATS can use internal mirrors and private trust in disconnected
deployments; no public network service is needed for these runtime features.

## Dependency Watchlist

Global configuration administrators manage entries at **Configuration →
Dependency Watchlist**. A match is a warning, never a vulnerability, compliance
failure, scan failure, or publishing gate. CATS matches the component inventory
from newly ingested Syft SBOMs. Older scans without `sbom_components` have no
watchlist evidence until rescanned.

TXT files contain one exact component name or PURL per line. Blank lines and
lines beginning with `#` are ignored. CSV columns are
`purl,ecosystem,name,version_constraint`. YAML contains an `entries` list:

```yaml
entries:
  - purl: pkg:pypi/requests
    version_constraint: ">=2.30"
  - ecosystem: python
    name: cryptography
    version_constraint: "<45.0"
```

PURL takes precedence over ecosystem and name. Names match after case and
separator normalization; substring matching is never used. Version constraints
support `==`, `>=`, `<=`, `>`, and `<` for dotted numeric versions. Other version
schemes support exact equality. Unsupported constraints are rejected. Matching
records retain the watchlist entry, component, image, PURL, version, and scan.

## Cybersecurity page

The top navigation **Cybersecurity** page summarizes current, service-scoped
evidence. Green means compliant with no current warning; yellow means compliant
with one or more warnings requiring attention; red means noncompliant under the
existing CATS service policy. Watchlist matches alone can make a compliant
service yellow. Deep inspection links back to service, finding, POA&M, warning,
and deployment validation views. The page does not infer historical trends from
missing history.

## OIDC claim mapping

The existing OIDC authorization-code login uses a same-window redirect and
returns to the requested local route. Administrators configure a standards-based
issuer, client, and trusted CA, then create mappings under **Configuration →
OIDC Claim Mapping**. Each mapping names a dotted claim path, exact expected
string value, existing CATS role, and explicit global, service, or group scope.
String and array claims work, including nested objects. Disabled or unmatched
mappings grant no OIDC role. Existing CATS permissions still decide access on
the server. Local role assignments remain independent. Changing mappings is
audited; raw tokens and private keys are not displayed.

Legacy environment-variable role maps remain available when no configured
claim mappings exist. Existing assignments created before assignment-source
tracking cannot be distinguished automatically from manual assignments and
should be reviewed when switching from legacy maps to configured mappings.

## CATSchrödinger validator

The validator is a separate Linux service that runs the existing bounded Kind
engine. Prepare a Linux VM with Docker or a compatible container runtime,
Kind, kubectl, Helm, the CATS Python environment, sufficient disk/memory, and
explicitly supplied Kind node images and workload images or approved internal
OCI sources. Give the validator a dedicated state directory and resource limits.
It creates temporary Kind clusters and workspaces; it does not host persistent
applications. The engine attempts cleanup after every result and recovers
interrupted jobs on startup.

Launch from the `portal` directory through `validator_server.py` with:

```text
CATS_VALIDATOR_SERVER_CERT=/path/to/server.pem
CATS_VALIDATOR_SERVER_KEY=/path/to/server-key.pem
CATS_VALIDATOR_CLIENT_CA=/path/to/client-ca.pem
CATS_VALIDATOR_STATE_DIR=/var/lib/cats-validator
CATS_VALIDATOR_PORT=8443
```

The launcher refuses to start without all three TLS files and requires a
trusted client certificate during the TLS handshake. Configure CATS with the
validator HTTPS endpoint, client certificate, encrypted client key, and
validator CA under **Configuration → Deployment Validation Sandbox**. Test
Connection reports readiness and capacity. Install the same package and
explicit artifact sources on a connected or disconnected VM; no cloud API is
part of the protocol.

`POST /api/v1/validations` accepts a versioned JSON package and returns a job
ID promptly. `GET /api/v1/validations/{id}` returns phase, terminal status,
cleanup status, and structured result. `POST /api/v1/validations/{id}/cancel`
requests cancellation. `GET /health` reports tool readiness and capacity.
The package uses `schema_version: cats.validation/v1`, a manifest with
`service_key` and `timeout_seconds`, and an artifact with bounded `source_files`,
`values_files`, and `declared_resources`. Paths are validated before scheduling;
there is no shell-command field or archive extraction. Source files are held
only for the active job and are not saved in result files. Result fields are
restricted to structured, nonsensitive status and resource summaries. A
deployment problem is `FAILED`; infrastructure/preflight failure is `ERROR`.

The existing local Kind path remains available when no remote endpoint is
configured for backward compatibility. A deployment using the remote validator
does not require Kind in the CATS portal. Other existing portal scan and patch
features may still require their own container-runtime access.

## Security data sources

Configure each source under **Configuration → Security Data Sources**. KEV uses
the CISA JSON feed format; EPSS uses CSV or gzip CSV. Grype accepts a native
database archive through `grype db import`, including offline upload. Trivy
refreshes from an explicitly configured OCI DB repository using its native
download command. Trivy offline upload is not offered because the repository
does not define a safe portable upload format for its native DB. KEV and EPSS
also accept offline uploads. Private HTTPS sources use the configured trusted
CA bundle. Redirects are rejected, so an internal source cannot silently fall
back to another host. Source URLs cannot include credentials, query strings,
or fragments. Configure an internal mirror with endpoint-level authentication
instead of a signed URL.

Candidates are checked before activation. Feed files use atomic replacement;
scanner databases are imported/downloaded into staging, checked, then swapped
with rollback of the previous directory on activation failure. The Compose
deployment mounts persistent volumes for the policy feeds and scanner caches.
Only global configuration administrators can change sources or refresh data;
attempts, successes, and failures are audited without credentials.

## Current validation limits

The validator health endpoint checks installed tools, the container runtime,
and free disk. It does not run a controlled Kind deployment as a VM smoke test;
operators should run a real validation after installation. Remote validation
currently returns structured result evidence only. Raw Helm output and pod logs
are withheld because they may contain secrets; an evidence retrieval API needs
redaction and per-artifact access control. The separate VM and TLS trust chain
must be supplied by the deployment operator.
