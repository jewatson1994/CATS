# Deployment Discovery

Open **Discovery** next to Scan. Discovery inspects deployment configuration and preserves evidence; starting discovery does not start a vulnerability scan.

1. Select an owning group and choose a source. You can upload a deployment file or repository archive, import an approved GitLab project, or enter an OCI image or versioned chart reference. Supported configuration includes Helm, Kubernetes, Kustomize, Compose, GitOps definitions and image lists.
2. Optionally name the environment and enter relative values-file paths, one per line in override order. Use non-secret configuration. Later files override earlier files.
3. Review each deployment root, its components, image references, completeness and diagnostics. Expand **Source evidence** to inspect provenance or **Complete inventory and relationships** for the full graph. Discovery treats inputs as untrusted and does not execute application scripts, build images or deploy workloads.
4. Select the roots belonging to one service. Choose an existing service, or **Stage a new service** if your group staging authority permits it. New services receive exactly the selected owning group. Only services in the owning group for which you have scan permission appear. Explicitly acknowledge a partial inventory after reviewing its gaps. Blocked or invalid inventories cannot be confirmed.
5. Choose **Confirm inventory**. This records the reviewed service association without scanning. Choose **Start scan** separately when ready, then follow **View scan progress**.

Leaving Discovery keeps the job running. Reopen it under **Ongoing** to check progress or cancel it. **New discovery** opens a fresh form while other jobs continue. A queued cancellation takes effect immediately. A running job shows **Cancellation requested** until the worker stops. Completed discoveries remain available under **Recent discoveries**.

Retry or **Rediscover as new version** preserves prior evidence. Under **Compare immutable versions**, select an earlier completed discovery from the same group to inspect added, removed and changed component IDs.

If discovery is incomplete, review diagnostics and candidate environment paths. In **Resolution assistance**, adjust non-secret options (including ordered files or a `source_map` from Flux source identity to an uploaded directory), then retry as a new version. This reruns discovery and preserves earlier evidence. To add missing source files, submit a corrected archive. Administrators can also supply exact-version, SHA-256-verified archives through the optional [offline mirror](universal-deployment-discovery.md#follow-up-implementation-2026-10-20). The page never silently treats an unknown or partial result as a complete deployment.

## Import a GitLab repository

Choose **GitLab repository** and enter the project's HTTPS URL, such as `https://gitlab.example.com/platform/payments`. Leave **Access token** blank for a public project. For a private project, use a read-only GitLab token with the `read_api` scope and access to that project. Submit the token through an HTTPS connection to the portal. [GitLab access token scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/)

Choose **Load branches and tags** to browse available refs and filter them by name. You can also enter a branch, tag or commit SHA directly, or leave the ref blank to use the default branch.

The portal resolves the ref to a commit and downloads that commit's archive into encrypted Discovery storage. The archive excludes the contents of separately hosted Git submodules. You can see the resolved commit under **GitLab source**. Specify values files relative to the repository root, for example `deploy/values-prod.yaml`. The token is used only for the current project's ref lookup and import. Retrying the job reuses its retained snapshot. To pick up new commits on a branch, submit the project again. Other Git hosts and disconnected installations can use a source archive.

### Allow projects in Compose

GitLab imports are disabled until an administrator sets `CATS_DISCOVERY_GITLAB_SOURCES` in the deployment's environment file. An exact project URL approves one project, including a project in a subgroup. An exact instance origin approves all projects on that instance that the submitted credentials or anonymous access can read. Separate entries with commas or whitespace, or use a JSON array. This example approves one public project and a whole internal instance.

```dotenv
CATS_DISCOVERY_GITLAB_SOURCES=https://gitlab.com/gitlab-org/charts/gitlab,https://gitlab.example.com
```

Recreate the full portal and its GitLab workers after changing the allowlist. The local stack uses the following command. For the main HTTPS stack, substitute `--env-file /secure/cats.env -f templates/compose.main.yaml` for `--project-directory . --env-file .env -f templates/compose.local.yaml`.

```sh
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml up -d --wait portal polling-worker discovery-worker
```

GitLab clients use system trust and certificates saved under **Administration → Trusted CA certificates**. For file-based trust, set `CATS_DISCOVERY_GITLAB_CA_FILE` to the absolute host path of the public PEM CA bundle and include the overlay below on each Compose update. It mounts the certificate read-only in all three containers. The Discovery worker, which runs as UID 10003, must be able to read the file.

```sh
docker compose --project-directory . --env-file .env -f templates/compose.local.yaml -f deploy/compose.discovery-gitlab-ca.yaml up -d --wait portal polling-worker discovery-worker
```

### Poll projects by GitLab topic

A full CATS deployment can discover and scan the current default-branch commit of each matching project, including projects in subgroups. A publisher can add a GitLab project topic once and push subsequent revisions using its own script or CI pipeline. Repeated polls of the same project ID and commit SHA reuse the existing intake record.

1. On the full CATS host, add the exact GitLab HTTPS **origin** (for example `https://gitlab.example.com`) to `CATS_DISCOVERY_GITLAB_SOURCES`. A project-only allowlist entry works for a manual import. Topic polling needs origin approval to list projects under a GitLab namespace. Apply the Compose configuration above.
2. Using an account with global configuration permission, open **Administration → GitLab topic polling** at `/admin/topic-polling`. Enter a source name, the approved origin, and an exact GitLab project topic such as `cats-scan`. Choose a group search to include a single GitLab group and its subgroups, with one CATS claim group. Choose an instance search for independent group trees. For example, map GitLab namespace `platform/services` to the Platform claim group and `mission/apps` to Mission. Both can use the same topic. Only projects under a configured namespace qualify for intake.
3. Supply a read-only GitLab token with `read_api` access to the target projects if private repositories are involved. CATS encrypts the credential with `CATS_CONFIG_ENCRYPTION_KEY`. Save the source and choose **Preview matches** to check the project paths, default branches and claim destinations using the polling worker. A preview works with automatic polling disabled. It reads GitLab metadata without creating services, downloading repository archives or queuing scans. When the matches look right, enable the source and choose **Poll now** or wait for the configured interval (default 300 seconds).
4. In GitLab, apply the configured topic to a project in that namespace. The default branch should contain the deployment manifests or charts that identify its runnable images. Publish the referenced images to a registry reachable by the CATS scan worker. For private images, configure the scan worker's registry access as described below. The publisher or custom script controls what it writes to GitLab and the registry. CATS reads the repository archive and inspects the declared configuration.
5. In **Administration → GitLab topic polling**, open the source's **Projects** view to follow each commit through Discovery, Scan and evidence ingestion. The polling worker downloads the selected commit into encrypted Discovery storage. The Discovery worker renders it, and a complete inventory with eligible images can enter the scan queue.
6. Once CATS has ingested complete scan evidence for the project's latest revision, authorized members of the target group can see and claim the service under **Unclaimed Services** at `/unclaimed-services`. If a newer commit arrives before the claim, the project leaves that queue while the new revision is processed. The admin **Projects** view continues to show the revision and its status. Later observed commits remain attached to the same GitLab project and service.

A successful poll removes a project from consideration if it loses the topic, moves outside the configured namespace, or is archived in GitLab. CATS retains its evidence and any existing owner. A partial poll can hold a project when it finds a routing conflict. It only withdraws projects for absence after the entire search succeeds. If the account that authorized a source loses global configuration access, another global configuration administrator can open **Edit source** and save it to resume polling under their authorization.

The latest preview and latest poll have separate results. Open the match details to see each sampled project's branch, commit, claim group and outcome. Totals cover the whole run. For an instance search, the excluded count can identify topic matches outside your namespace mappings without listing those projects.

If rules assign different claim groups to one project, CATS holds intake until the routes agree. Edit the instance mappings or disable the competing rule, then poll the intended source. If the result says **Already tracked by** another source, that named source owns the binding and must be enabled to pick up future revisions. Each GitLab project keeps one service and its scan history.

The scanner's `CATS_PUBLIC_MAX_IMAGES` setting defaults to 50 distinct images per scan. If a project exceeds this limit, set the intended limit for the full deployment, recreate the portal and polling worker, and retry the revision from **Projects**.

**Private image registries.** Topic image scans pull anonymously by default. To allow a private pull, place a read-only pull credential in the scan worker's existing registry-auth mount (`CATS_SCAN_REGISTRY_AUTH_SOURCE`). Set `CATS_TOPIC_SCAN_REGISTRY_PREFIXES` in the full deployment environment to explicit registry/repository paths, such as `registry.example.com/team-a,registry.internal:5000/platform/payments`, then recreate `scan-worker`. Each prefix covers that exact repository and its descendants. A credential scoped at the registry to those same repositories limits what the account can read.

Docker associates credentials with a registry host. CATS only supplies a host's credential when **every** image from that host in the verified topic scan belongs to an allowed repository. For example, a job containing both `registry.example.com/team-a/api` and `registry.example.com/team-b/db` uses anonymous pulls for that registry if only `team-a` is allowed. Other eligible hosts are evaluated independently. The GitLab read token is used only for the GitLab source. [Scan worker registry configuration](dedicated-scan-worker.md)

The full polling worker has separate processing slots for GitLab intake and signed OCI synchronization. With multiple polling workers, CATS runs one intake poll at a time per GitLab origin so overlapping sources see project changes in order. A free worker can still run a preview or poll another origin. `CATS_REPLICA_SYNC_ENABLED` controls the OCI slot. GitLab sources each have an **Enable automatic polling** setting. Replica deployments run the OCI slot only.

| Symptom | Check |
| --- | --- |
| A project never appears | Preview the saved source. Check the exact project topic, namespace mapping and GitLab token access. For a routing conflict, inspect the matching sources and their claim groups. If the project matches, open **Projects** to see whether deployment discovery or scanning needs attention. A commit pushed only to another branch does not change the polled branch tip. |
| GitLab TLS or permission errors | Verify the CA from the polling worker's perspective and the read token's access to the project and its archive. The public CA override requires the overlay when the stack is recreated. |
| A revision is waiting for Discovery or Scan | Open **GitLab topic polling → Projects** for the source and check the latest revision. Check `polling-worker`, `discovery-worker`, `portal-control`, and `scan-worker` and their job statuses. Durable Discovery/intake and scan queues use `CATS_JOB_QUEUE_CAPACITY` and `CATS_SCAN_QUEUE_CAPACITY`. Preserve `discovery_uploads` and `public_jobs` on upgrades. |
| Discovery is incomplete or the scan cannot pull an image | Inspect the revision error and Discovery diagnostics. Supply missing chart dependencies, correct the deployment image references, or configure registry trust and pull access. After repairing a transient failure, retry the failed revision from the source's **Projects** view. A changed deployment is picked up at the next default-branch commit. |
| A project is missing from Unclaimed Services | In **GitLab topic polling → Projects**, check the latest revision for pending or failed processing. Confirm that its scan has complete, ingested evidence, that the service is still unclaimed and that the user may manage services in its configured claim group. |


## Helm charts declared in values.yaml

A parent `Chart.yaml` can contain only chart metadata while its sibling `values.yaml` declares child charts under `services`. For example, `services.prometheus.helmRepo` can declare the chart `kube-prometheus-stack`, its repository and its version. Discovery follows recognized Helm and OCI entries, including entries with `enabled: false`, so the inventory covers every declared component. When a resolved child's values also declare services, Discovery follows that catalog in turn. [Example catalog](../scanning-main/examples/services-values.yml)

For offline discovery, place each child under the parent's `charts/` directory as an unpacked chart or a `<chart>-<version>.tgz` package. Discovery checks the name and version against the catalog. You can also use a local `chart_map` for another uploaded directory or an administrator-configured mirror for the exact version. Direct retrieval requires `HELM_ALLOW_NETWORK=true` and a repository or registry namespace permitted by the administrator's source policy. That policy can list individual sources or allow all valid sources as described below. [Worker source and registry configuration](universal-deployment-discovery.md#helm-network-retrieval-and-live-archive-acceptance-2026-10-21)

Each child starts with its own chart defaults. Discovery applies its `valuesFiles` (also spelled `values_files`) in declaration order, using paths relative to the source root. The entry's inline `values` mapping overrides those files. Files selected for that child in **Resolution assistance** apply last. Catalog `postRenderers` supports declarative Kustomize image changes and inline patches. A nonempty catalog `valuesFrom` or `postRenders` leaves the chart unresolved and blocks its inclusion in a distribution.

Review each child under **Complete inventory and relationships**. A successfully rendered workload provides image evidence. If a chart or a required values file is unavailable, the inventory retains the child and its diagnostic while Discovery continues with its siblings. Supply the missing input and retry as a new version to verify the rendered images.

For example, `services.dokuwiki.enabled: false` sets the initial distribution choice for DokuWiki. Discovery still attempts to resolve the declared chart and identifies the source file, version and result. The same rules apply to GitLab imports and uploaded archives. Allowing a GitLab project lets Discovery read that project. An administrator separately chooses which external chart sources the worker may contact.

If you intend to use `oci://oci.trueforge.org/truecharts/dokuwiki` directly with an individual source policy, enable `HELM_ALLOW_NETWORK=true` and add that exact chart URL to the JSON list in `CATS_DISCOVERY_HELM_SOURCES` in your Compose environment. Preserve any existing entries. Recreate the Discovery worker and retry Discovery. For offline use, supply the exact chart archive locally or through the configured mirror.

### Allow all chart sources for Discovery

To permit Discovery to retrieve charts from all valid HTTPS Helm repositories and OCI registry sources, set both values in the deployment's environment file:

```dotenv
HELM_ALLOW_NETWORK=true
CATS_DISCOVERY_HELM_SOURCES=["*"]
```

The wildcard also permits HTTPS chart downloads, CDN redirects and public anonymous OCI bearer-token services without listing each origin. TLS certificate and hostname verification, exact chart versions, checksum verification and resource limits still apply. This controls Discovery retrieval only; it does not grant Cyber approval or authorize publication. Network retrieval remains disabled by default.

Private OCI registry credentials remain limited to their configured namespaces. To send those credentials to a separate bearer-token service, explicitly list its HTTPS origin in `CATS_DISCOVERY_HELM_TOKEN_ORIGINS`, for example `["https://auth.registry.example"]`. An unlisted token service may be contacted anonymously; the wildcard does not authorize forwarding private registry credentials to it.

After editing the environment file, recreate the worker and retry Discovery. For the local stack, run `docker compose --project-directory . --env-file .env -f templates/compose.local.yaml up -d --no-deps --force-recreate discovery-worker`. For the main deployment template, run `docker compose --env-file /secure/cats.env -f templates/compose.main.yaml up -d --no-deps --force-recreate discovery-worker`.

### Release a service distribution

1. Confirm the inventory for the service. Open the service's **Artifacts** tab, expand **Service distributions**, and choose **Create distribution**.
2. Give the distribution a name such as `Production without wiki`. Review the enabled and disabled chart list. You can enable a rendered catalog chart even when its source default was off. Save the selection and choose **Scan distribution**. An image shared by multiple charts is included once if any included component uses it.
3. Once the scan finishes, choose **Request Cyber approval for this distribution**. Cyber sees both lists, the chart identities, and the retained image digests from that scan. Publication delivers the selected container images. The signed release records the distribution and its exact inventory. Other selections for the service have their own approvals.
4. To reassess the same distribution, return to **Service distributions**, scan it again and submit the new evidence for Cyber review. To change the selection, choose **Edit as new distribution**, save, scan and submit it. The earlier release remains bound to its original selection.

Disabling a catalog service also excludes its nested releases unless another enabled service supplies them. Enabling a service restores the declared defaults for children that become available.

For a native dependency declared inside `Chart.yaml`, Helm evaluates conditions and values in the parent chart's render. CATS records these dependencies under the parent. To change one, select the corresponding parent values file in Discovery, confirm the new rendering, and use that inventory for the distribution.

An ordinary Helm service can be discovered without Kustomize. If Discovery reports a Kustomize problem, the diagnostic points to a detected overlay. Inspect that directory and supply any referenced bases or patches if the overlay belongs in the deployment.

## Native rendering isolation

The dedicated Linux worker runs as UID 10003. Bubblewrap exposes only the selected static renderer binary and the job source directory (read-only), creates fresh user, network, process and mount namespaces, clears the environment, drops capabilities, and supplies private temporary storage. Plugins, executable post-renderers and Kustomize exec extensions are rejected. A child seccomp filter blocks subsequent namespace creation/entry and mount changes, checks the syscall architecture, and fails closed on unsupported architectures. The worker records trusted build-time Helm, Kustomize and Compose versions. Wall-clock limits apply to every render. Combined output limits are optional and default to unlimited (see the resource settings below).

Docker's built-in seccomp policy can prevent Bubblewrap namespace setup. The implementation fails closed in that case. Compose applies the explicitly approved `deploy/discovery-seccomp.json` profile only to the Discovery worker, permitting Bubblewrap setup; no privileged mode, unconfined profile or writable host `/proc` is supported. The container policy is separate from the stricter child filter applied after namespace setup.

Acceptance on Docker Desktop Linux used an ephemeral default-derived policy with `unshare`, `clone` constrained to `CLONE_NEWUSER`, and `mount`, `umount2`, `pivot_root` additions. The worker retained no network, a read-only root, all capabilities dropped, no-new-privileges, process/memory/CPU limits and private `/tmp`. Helm 4.2.3, Kustomize 5.8.1 and Compose 2.39.4 rendered fixtures successfully. A parent Helm chart generating Flux configuration, ConfigMap `valuesFrom`, a local child chart and a declarative Kustomize image post-renderer produced the expected complete inventory. A Helm write to `/source` failed; private `/tmp` output succeeded. Source ownership and worker identity were UID 10003. These results do not establish compatibility with every Linux host security policy.

## Singularity acceptance in the isolated environment

The real project is available only to the operator. Upload the complete source archive with local chart dependencies, select the intended root values files in deployment order, and compare the reviewed image inventory against the previous all-but-two-chart result. Inspect each generated Flux release, effective ConfigMap values, downstream chart and image provenance. For the two previously unresolved charts, retain the exact missing-reference diagnostics and check whether their required values exist in the source archive. Missing external artifacts remain unresolved. Record the archive hash, selected configuration, tool versions, inventory ID, component/image counts and unresolved diagnostics. Confirm service boundaries and use the existing Scan handoff only after review. Synthetic renderer tests are not Singularity acceptance.

The installed worker-only profile was also verified with Compose configuration validation, all 11 renderer regression tests, and an offline non-root Helm smoke render using the committed profile path.


### Discovery input capacity

Discovery defaults to unlimited upload bytes, per-file bytes, extracted bytes,
file counts, and renderer output bytes. Operators can set positive values for
`CATS_DISCOVERY_MAX_UPLOAD_BYTES`, `CATS_DISCOVERY_MAX_FILE_BYTES`,
`CATS_DISCOVERY_MAX_EXTRACTED_BYTES`, `CATS_DISCOVERY_MAX_FILES`, and
`CATS_DISCOVERY_MAX_RENDERED_BYTES`; zero disables the respective budget. There
is no hidden upper clamp. Direct Compose ingestion retains its separate budgets.
Supplemental inputs use the Discovery budgets and have no fixed chain-count cap.

Uploads and supplemental copies stream in chunks. Native renderer output spools
to disk before parsing; parsing still requires memory proportional to document
size. The Discovery worker uses the `discovery_scratch` disk volume for temporary
inputs instead of a 512 MiB tmpfs. Provision and monitor that volume and the
upload volume for source, decrypted, extracted and rendered data. Container
memory (`CATS_DISCOVERY_MEMORY`, default 1 GiB), CPU, process and execution-time
budgets still apply. A process killed by the operating system cannot emit its own
resource diagnostic; inspect worker/container logs in that case. Configure any
external reverse proxy request-body limit and request timeout for the intended
upload sizes; application settings cannot override an external proxy rejection.

Archive extraction, repository hashing, and approved mirror/Helm artifact downloads
use file-backed streaming. Archive buffers do not grow with the combined archive
and extracted payload. ZIP directory metadata, inventory data, parsed documents,
and final renderer text still occupy memory. Structural YAML protections and
inventory complexity limits remain; these are distinct from uploaded file-count
budgets. Helm metadata and administrator mirror manifests remain bounded. Network
socket/deadline limits remain in force. Render input scoping and encrypted cache
size thresholds only skip optimizations; they do not reject larger sources.
