# Service Remediation

Remediation is **disabled by default**. A global configuration administrator
enables it under **Configuration → Remediation** after verifying the patch
worker, configured OCI registry, mirrors, certificates, and validator. A
toggle is audited. Disabling it rejects new service and finding remediation
requests; existing jobs finish, and all prior reports remain visible.

Execution requires the existing scoped `remediation.execute` permission.
Reports require `service.view`; bundle downloads require `service.export`.
The existing public Patch workspace is a separate workflow.

## What the job does

The job snapshots the latest service assessment, rendered workload images,
active canonical service images, findings, and retained Helm source. It uses
the existing Copa patch worker once per distinct image. That worker applies
configured package mirrors and CAs, produces a new image archive, compares
fixable Grype findings, and, for OCI output, pushes and optionally signs the
new image using configured registry credentials. Remediation also requests
new Syft, Trivy, and Dockle evidence from the patched artifact. Unsupported
images and individual patch failures remain visible without erasing other
successful images. Original images, charts, and assessment history remain
unchanged.

Only exact source mappings are rewritten. An ambiguous Helm values mapping
requires review. The candidate render must contain every remediated image
and no original image before OCI chart publication or deployment validation.
Each retained chart gets a job-specific SemVer version, is packaged with
`helm package`, and can be pushed with Helm's standard OCI support. Chart
publishing uses the registry marked for remediation and an isolated Helm
credential file. No public registry or CA is assumed.

Existing deterministic Kubernetes security-context rules can change values
only when CATS has an exact source mapping. Dockle findings are rescanned but
are not automatically edited: an image hardening change can alter application
behavior and requires an explicit safe rule and source evidence. Other
unmapped findings remain manual remediation.

## Output modes

**Publish to configured OCI** stages patched images in the configured
registry, packages and pushes charts, and submits the exact remediated chart
and image references to CATSchrödinger when its mTLS endpoint is configured.
Publication and validation have separate result states. A deployment failure
does not erase published images, charts, scans, or the candidate bundle.
Only a `VERIFIED` validator result is shown as validated.

**Downloadable bundle** uses the same patch worker in download mode. The ZIP
contains `manifest.json` (`cats.remediation/v1`), image archives, Helm
packages where packaging succeeded, new SBOMs, Grype reports, Trivy/Dockle
completion status, the before/after summary, and candidate source files. Raw
Trivy/Dockle output stays out of transferable bundles because scanner
messages can contain image configuration values. The bundle
contains no registry credentials, signing keys, or patch logs. Source files
with recognizable secret-bearing material are rejected for either output mode.
manifest gives each archive's loaded Docker tag and its intended remediated registry
reference. An operator must load, tag, and publish these images to the
configured target registry before deploying the bundled chart. Offline
bundles are not marked Kind Verified before that transfer and validation.

The bundle does not include signatures for images that have not been
published; the existing signing path applies only to pushed image digests.
The job requires one configured remediation registry even in bundle mode so
the chart can carry the intended target image references.

## Status and evidence

Service Remediations shows stage history, image mapping, configuration
changes, chart version/package state, measured fixable Grype counts, full
Grype severity/KEV totals and highest EPSS score where every patched image
received a fresh full scan, and deployment validation. Full totals remain
unknown when any full scan is unavailable; the UI does not reuse old totals
as new evidence. The report's downloadable artifact is
separate from the original scan evidence. A read-only status endpoint is
`GET /api/v1/services/{service_key}/remediations/{job_key}`.
Service policy remains **Not Evaluated** for a patched candidate until CATS
ingests a complete new service assessment. Candidate static checks and new
scanner files do not silently replace governance findings or exceptions.

New states include `bundle_ready`, `bundle_partial`, `publication_partial`,
`evidence_partial`, `validation_failed`, and `validation_unavailable`. They
show what completed rather than collapsing every stage into one pass/fail.
Image, chart, validation, bundle, and terminal events are audited without
credential material.
Terminal jobs can be retried as a new job. The new record points to its prior
attempt and receives new image tags and a new chart version; existing evidence
is not overwritten. A service row lock and active-job check prevent concurrent
requests for the same service.

## Deployment requirements and limits

The patch worker still needs a container runtime and the existing Copa,
Grype, Syft, Trivy, and Dockle tools. Configured per-OS mirrors and local
scanner databases support disconnected use; failed private sources do not
fall back to the public Internet. Remediation uses CATSchrödinger for remote
Kind validation and does not run a privileged local Kind deployment.

Actual OCI and VM integration requires a configured registry, trust chain,
patch worker, and validator. Bundle mode does not automatically import or
publish artifacts at the destination. Secret detection for chart source is
conservative but cannot prove that a container image contains no embedded
secrets; operators should treat image archives as sensitive artifacts.
