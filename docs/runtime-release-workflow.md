# From a Kubernetes deployment to an active CATS release

A complete cluster observation can start assessment and prepare a draft. A Service Manager submits that draft. An independent Cyber reviewer makes the decision. Signed publication and activation establish which release is authorized in production.

## Architecture assessment

The starting point was the runtime monitoring branch at `9ebe3cd`. The implementation extends the following components.

| Area | Existing capability at assessment | Integration needed |
| --- | --- | --- |
| Runtime agent and portal | Functional one-use linking, token revocation, HTTPS reports, durable sequence numbers, bounded paging, Pod and container inventory, freshness and digest checks. Kubernetes controller discovery was partial. | Add ownership traversal, desired templates, watches with periodic lists, cluster UID pinning, bounded offline replay and a complete-discovery protocol marker. |
| Discovery and OCI | The discovery-worker and adapters resolve retained deployment sources, charts, values and dependencies. The registry gateway already has service-scoped repository mappings and manifest verification. | Associate cluster observations with approved sources. An observed Helm label cannot provide original chart bytes. |
| Service catalog and Unified Artifact Lifecycle | Functional owning groups, service grants, artifact registration and service-to-artifact assignments. | Retain unassigned applications, confidence evidence and manager-authorized workload mappings. |
| Assessment | The scan-worker, durable scan jobs, project ingestion and evidence store support immutable inputs, image scanning, SBOMs and Helm assessment. VEX, KEV, EPSS and Risk Profiles already exist. | Schedule assessment for mapped runtime artifacts, reuse valid digest-bound receipts and assemble evidence for this exact candidate inventory. |
| Approved Releases | Readiness, programmatic Cyber submission, return of blockers, immutable release revisions, signing, publication and active revision selection already exist. A current-service request or amendment requires an existing evidence set. There was no programmatic runtime draft that followed deployment changes before submission. | Add a versioned preparation record and submit its frozen evidence through the existing Cyber API. |
| Authorization, jobs and notifications | Service-scoped grants separate request, export and decision permissions. The portal already has an action center, audit events, worker admission, retries and publication jobs. | Bind observations to an authorized service, enforce an independent reviewer, and surface role-specific pending actions in the existing center. |
| Interface | Clusters & agents, Services, Cyber approvals and Approved Releases already have operator entry points. | Extend those screens with cluster roles, assignment, assessment comparison, submission, return for changes and runtime component findings. |

Implementation order was collector and storage compatibility, then assignment, scanner integration and draft preparation, followed by frozen Cyber submission, activation and production reporting. The database upgrade adds `cluster_role`, `discovery_group_id` and `discovery_observed_at` to runtime environments, and adds `runtime_applications` and `runtime_release_candidates`. Submitted approvals still use the existing Cyber approval and release revision tables. Existing environments start with the `unspecified` role. Existing collectors can continue reporting.

## Configure the cluster

Upgrade the portal and scan-worker deployment to the same revision and install the discovery-capable collector chart. In **Clusters & agents**, configure the environment's service scope, cluster role and discovery group. Use one linked collector and a dedicated persistent volume per Kubernetes environment. The discovery group controls who can review otherwise unowned observations in that environment. For an environment with selected services and no discovery group, a manager must manage the entire selection to review unassigned observations. [Agent installation, image mirroring and rollback](../runtime-agent/README.md)

| Cluster role | Behavior |
| --- | --- |
| Development | Discover applications and prepare assessments and drafts after assignment. Unapproved workloads can run and are shown as observations. |
| Test / Validation | Prepare candidates from the assigned workloads and update the assessment as the deployment changes. |
| Production | Compare running artifacts and components with the service's active signed release and report findings. |
| Unspecified | Collect inventory and preserve existing monitoring behavior. Draft preparation starts when an administrator selects Development or Test / Validation. |

Roles are mutually exclusive and centrally configured. For example, a runtime administrator can send this body to `PUT /api/runtime/environments/12` to designate a validation cluster and its discovery group.

```json
{"cluster_role":"validation","discovery_group_id":7,"service_scope":"selected","service_ids":[18,23]}
```

## Assign applications and prepare evidence

1. In **Services**, open **Discovered applications and release candidates**. Expand an unassigned application to inspect its source, controllers, containers, desired images, observed digests, Helm metadata and suggested services. Suggestions explain their evidence. The matching order considers a CATS service annotation, an established mapping, Helm identity and namespace, application labels, workload relationships and existing artifact associations.
2. Select an active service that you manage, or choose **Create a new service** in an all-services environment with a configured discovery group that you manage. CATS creates and assigns the service in one transaction. A conflicting service key or changed inventory requires a fresh selection.
3. A confirmed mapping follows the namespace and controller UIDs through Pod restarts. A newly created controller requires review before it can join an already assigned service. Multiple workload or chart groups can be assigned to the same service. A draft aggregates their components within one source environment and namespace. A second cluster retains its own observation history.
4. The scan-worker coordinator checks for reusable receipts and admits jobs for missing evidence. Configure a service-owned OCI mapping for each image origin, or supply service-scoped project CI evidence. CATS checks immutable references, source and ownership, receipt integrity and evidence age. Each verified image or chart receipt shows matching artifact catalog entries already assigned to the service, including their media type, platform and service roles. [Artifact lifecycle](unified-artifact-lifecycle.md)

   For Helm, the collector reads the chart name and version from workload metadata. Set `cats.io/chart-digest` to the SHA-256 of the original compressed chart archive. Supply that archive through project CI, or upload the single packaged chart (`.tgz` or `.tar.gz`) to Discovery and confirm its rendered chart root for the same service. The Discovery path checks the service's owning group and inventory checksum, authenticates the encrypted upload and compares its bytes to the reported digest. The candidate retains Discovery's recursive dependency versions, digests and reported enablement alongside the scanner receipt. The release validator checks exact vendored dependencies, including packaged subcharts, against the original archive. Once the chart reaches the scanner, its retained copy supports rescans after the Discovery upload expires. A label, an expanded tree checksum, a repository snapshot or a worker-local mirror cache alone leaves the chart blocked until a matching original is available. [Source discovery and offline mirrors](discovery-workflow.md)

   For private images, configure the worker's existing `CATS_SCAN_REGISTRY_AUTH_SOURCE` with an entry for the mapped upstream registry hostname. CATS revalidates that the job requests the exact service-mapped immutable image before allowing the worker to use this credential. Portal credentials for manifest resolution are configured on the OCI upstream. Chart scans and unmapped project-source rescans use the public worker policy.

   In **Cyber approvals**, a failed registry lookup identifies the image reference and suggests what to check. Reasons distinguish a missing service mapping, denied pull access, a missing tag or digest, a TLS or connectivity failure, and invalid manifest content. Correct the mapping, credentials, trusted CA or upstream image and keep the scan worker polling. A verified retry clears that reference's diagnostic on the current draft. CATS retains the 64 most recent unresolved lookup diagnostics per revision.

   Pin the reviewed platform manifest in the validation deployment. A fully qualified requested tag must refer to the same repository as the running image. A desired multi-platform index and a running child digest remain distinct inventory entries and block review. A matching runtime digest also blocks review when service registry, catalog or scanner evidence identifies an index. For disconnected scans where the source type was unknown during review, publication checks the digest-verified source manifest before copying or signing it. Runtime releases require a single platform manifest because the scanner assesses one platform per image input.
5. Inspect the candidate in **Cyber approvals**. It shows source, component inventory, artifact receipts, SBOM and vulnerability evidence, VEX, KEV, EPSS, Risk Profile results, and changes against the active release when comparable evidence exists. Missing sources, incomplete scans and unresolved rollouts remain visible as blockers. The existing readiness checks and service policies apply. Risk authority decisions retain their existing permissions and records. [Risk policies and authority](risk-model.md)

The coordinator runs during existing scan-worker polling. A worker must poll even if the collector has disconnected. Admission is bounded, failed work is retried and unchanged valid inputs can be shared across revisions for the same service. Assessment failures and review-ready drafts appear in the existing notification center. Network access is needed only where the configured internal services, workers and mirrors communicate. Air-gapped sites can mirror images and scanner data and supply retained chart inputs locally.

## Submit, review and activate

Select **Submit for Cyber Review** after reviewing a ready candidate. CATS checks the manager's service permissions and verifies the reviewed inventory and evidence again. Submission records the actor and time, creates a pending entry in **Cyber approvals**, and retains a checksum-bound snapshot and evidence bundle. Later observations can create a separate draft. The reviewer can still decide the submitted inventory. From **Services**, managers can open a superseded draft to inspect the original inventory, its fingerprint and the events recorded for that revision.

The built-in Service Manager role grants `runtime.prepare_release` for assignment and submission. The Cybersecurity role grants `runtime.review_release` for decision and activation. Both permissions follow service or group scope and work with the existing release permissions. A custom role needs the applicable grant. The built-in Administrator role alone grants neither.

In a production environment, a Service Manager with `runtime.map_import` and `service.view` can associate a local observation with an existing publisher-managed service, including on a replica. The environment's discovery and service scopes also apply. This association is local reporting data. Release evidence, assessment, approval and activation remain with the publisher.

Cyber can approve, deny or return the submission with a rationale. Returning it allows the manager to supply additional evidence and request a fresh review. The prior submission and decision remain available. The submitter cannot decide that submission even if they also hold a Cyber role. An approval queues the existing publication worker. Verify publication and activate the signed revision through **Approved Releases**. The active-pointer version check prevents a stale activation from replacing a newer release. Service Managers and Cyber see the actions for their authorized services in the existing notification center. [Cyber approval, publication and expiry](cyber-approved-releases.md)

## HTTP integration

Use a signed-in account and the portal's CSRF header for user writes. A linked agent bearer credential is limited to the reporting protocol. The portal OpenAPI document includes request schemas for environments, reports, assignment, Cyber submission and decisions.

| Operation | Request |
| --- | --- |
| Register an environment and enroll the collector | `POST /api/runtime/environments`, `POST /api/runtime/environments/{id}/link-tokens`, `POST /api/runtime/link` |
| Report observations | `POST /api/runtime/reports` or `POST /api/runtime/reports/pages`. Use `discovery_version: 1` for complete controller inventories. Only the final verified, complete snapshot reconciles absence. |
| List observations, suggestions and candidate links | `GET /api/runtime/applications?offset=0&limit=50` |
| Assign the inventory that a manager reviewed | `POST /api/runtime/applications/{id}/assignment` with `expected_fingerprint`, nullable `expected_service_id` and exactly one of `service_id` or `new_service_key` |
| Inspect release readiness | `GET /api/services/{service_key}/cyber-approval-readiness?runtime_candidate_id={id}`. Read `blockers`, `runtime_evidence` and `review_digest`. |
| Submit to existing Cyber queue | `POST /api/cyber-approvals` with `service_key`, `runtime_candidate_id` and the latest `review_digest`. A stale review returns HTTP 409. |
| Inspect or decide | `GET /api/cyber-approvals/{id}` and `POST /api/cyber-approvals/{id}/decision`. Supply `decision` (`approved`, `denied` or `returned`), `rationale` and the eligible `destination_id` when required. |
| Activate a published revision | Read `GET /api/approved-releases/{approval_id}/revision`, then `POST /api/approved-releases/{approval_id}/revision/activate` with the active pointer's `expected_version`. |

## Investigate production findings

Open **Clusters & agents → Issues** and filter by cluster, namespace or issue type. Use the observation time, service, workload, container, requested image, actual digest and release reason to trace a decision. CATS distinguishes an unassigned workload, an unverified digest, an unexpected or missing approved component and a denied, expired, revoked or inactive release. Older signed releases can establish image membership where their evidence predates component inventory. Missing-component checks require a fresh complete discovery report. An incomplete or disconnected collector produces a coverage warning and retains the last complete inventory. Historical changes beyond the collector's bounded offline buffer can be coalesced.

Kubernetes permissions are limited to listing and watching selected metadata. Changes to cluster workloads and registry admission remain under their existing controls. [Collector permissions](../runtime-agent/README.md) · [OCI gateway policies](oci-proxy.md)

## Verify the integration

From `portal`, run the discovery, assignment, candidate, approval and production reporting suites together.

```shell
python -m pytest -q tests/test_runtime_discovery_collector.py tests/test_runtime_applications.py tests/test_runtime_candidates.py tests/test_runtime_assessment_catalog.py tests/test_runtime_resolution_diagnostics.py tests/test_runtime_release_review.py tests/test_runtime_production_components.py ../runtime-agent/tests/test_chart.py
```

Two additional suites exercise real services.

- Set `CATS_TEST_POSTGRES_URL` to a disposable PostgreSQL database and run `python -m pytest -q tests/test_runtime_applications_postgres.py`. This checks that upgrades preserve legacy service scopes and submitted inventory, and that an assignment racing a collector update receives a conflict on stale data.
- With Docker available and `registry:2.8.3` cached locally, set `CATS_TEST_RUNTIME_REGISTRY=1` and run `python -m pytest -q tests/test_runtime_registry_integration.py`. It starts a temporary loopback TLS registry and verifies tag resolution, a matching manifest digest, a conflicting config digest and an unavailable tag.

The runtime-agent CI job installs the chart in a disposable kind cluster. Its live smoke test checks that a standalone Pod and a Deployment appear as unassigned applications, and that replacing the collector Pod preserves the agent identity, application records and artifact fingerprints. [Runtime-agent packaging and verification](../.github/workflows/publish-runtime-agent.yml)
