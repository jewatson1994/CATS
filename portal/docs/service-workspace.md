# Service workspace

Each service uses one navigation model: Overview, Architecture, Artifacts,
Deployment Validation, Findings, Remediations, and Activity. Raw and
Simplified Findings are views within Findings; the selected view and filters
remain in the URL for refreshes and deep links.

## Artifact revisions

The Artifacts workspace keeps the original scan source immutable. Authorized
Service Managers can add manifests and images, create working Helm revisions,
and directly replace or remove image inventory entries. Each edit is
attributable and historical scan or validation evidence remains tied to its
original execution/revision.

Container images are shown by canonical digest/reference identity while all
references remain available through **Referenced by**. Row **Scan** starts the
existing scanner for that image; **Scan All Images** queues one job per unique
identity through the existing worker pool. Scan results are ingested through
the normal findings pipeline.

## Expected empty states

Missing architecture evidence, artifacts, findings, validation runs, and
activity are normal service states and render inside the CATS shell. Unexpected
failures remain visible as technical errors rather than being converted into
misleading empty data.
