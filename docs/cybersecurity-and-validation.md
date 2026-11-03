# Cybersecurity configuration and deployment validation

For the remote CATSchrödinger security boundary, provisioning and executable
transport/workload/cleanup checks, see [operator setup](schrodinger-setup.md)
and [security audit](schrodinger-security-audit.md). Remote execution enforces
strict policy and applies the exact inspected Helm rendering; it does not run
Helm hooks or full release-install semantics. Local legacy validation behavior
described elsewhere is not authorization to expose that engine remotely.

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

For Keycloak, select **Discover groups and roles** to read existing realm groups,
realm roles, and roles belonging to the configured CATS client. Filter the list
and select **Map to CATS** to populate the claim fields, then choose the CATS role
and scope and save. Discovery uses the saved OIDC connection, requires global
administration, and does not grant access by itself. The client must have service
accounts enabled and read access to the Keycloak directory and client settings.
Only supported membership mappers enabled in the ID token on the client, its
default scopes, or explicitly requested optional scopes produce suggestions.
Missing permissions or mappers produce setup guidance. Custom mappers and other
OIDC providers can still use manual claim mappings. Membership changes take
effect on the user's next login.

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

Under **Settings → Data → Security Data Sources**, **Refresh all four sources daily**
is enabled by default. The Compose `security-data-worker` checks each source once
per UTC day. With a blank source, CATS uses CISA's KEV feed, FIRST's daily EPSS
scores, Anchore's Grype v6 listing, or Aqua's Trivy DB repository. A saved mirror
takes precedence for both daily and manual refreshes. Failed downloads or
validation leave the installed data available. Each card shows the last attempt,
last success, installed version and any failure.

For an offline deployment, clear the daily refresh checkbox and save. Manual
refresh and offline uploads remain available. KEV accepts CISA JSON and EPSS
accepts CSV or gzip CSV. For Trivy, save the mirror's OCI database repository
and select **Refresh**. Private HTTPS sources use the configured trusted CA
bundle. The FIRST public feed can redirect to its dated file on the same host.
Configure other HTTP sources with their final URL, without credentials, query
strings or fragments.

Current finding views use the installed KEV catalog and available EPSS scores
when evaluating existing findings. A new scanner database takes effect on the
next scan. Original scan evidence and approved snapshots retain their recorded values.

To refresh Grype from a mirror, serve the v6 `latest.json` and the archive it
names in the same directory on the mirror. Open **Grype DB → Configure and upload offline data**.
Enter the mirror’s v6 listing URL (for example, `https://mirror.example/grype/v6/latest.json`)
in **Configured source** and select **Save source**. Select **Refresh** on the
Grype DB card. CATS downloads the archive named in the listing, verifies its
SHA-256 checksum, then imports it. To pin a specific archive, save its direct
`.tar.zst` URL in the same field.

To update Grype offline, open **Grype DB → Configure and upload offline data**.
Select the `.tar.zst` database archive. You can upload it alone or add the matching
`latest.json` from the same release. Select **Upload offline data**. When you
include the listing, CATS checks the archive against its checksum before running
`grype db import`. A mismatch leaves the installed database in place. Check
**Status** and **Installed** on the Grype DB card for the result.

CATS validates each update before activating it. It replaces the KEV and EPSS
files atomically and switches Grype and Trivy to a validated database version.
Scans already running keep their own copy. Both Compose configurations persist
the feeds and scanner databases.
Global configuration administrators manage sources, manual updates and the
daily refresh preference. CATS audits update attempts and outcomes.

## Current validation limits

The validator health endpoint checks installed tools, the container runtime,
and free disk. It does not run a controlled Kind deployment as a VM smoke test;
operators should run a real validation after installation. Remote validation
currently returns structured result evidence only. Raw Helm output and pod logs
are withheld because they may contain secrets; an evidence retrieval API needs
redaction and per-artifact access control. The separate VM and TLS trust chain
must be supplied by the deployment operator.
