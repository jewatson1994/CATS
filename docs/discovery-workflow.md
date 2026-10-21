# Deployment Discovery

Open **Discovery** next to Scan. Discovery inspects deployment configuration and preserves evidence; starting discovery does not start a vulnerability scan.

1. Select an owning group and upload a deployment file or repository archive. Supported configuration includes Helm, Kubernetes, Kustomize, Compose, GitOps definitions and image lists. Direct Git repository fetching is not enabled. An OCI image reference can also be inspected; remote chart references may require an uploaded local chart and will report unresolved input explicitly.
2. Optionally name the environment and enter relative values-file paths, one per line in override order. Use non-secret configuration. Later files override earlier files.
3. Review each deployment root, its components, image references, completeness and diagnostics. Expand **Source evidence** to inspect provenance or **Complete inventory and relationships** for the full graph. Discovery treats inputs as untrusted and does not execute application scripts, build images or deploy workloads.
4. Select the roots belonging to one existing service. Only services in the owning group for which you have scan permission appear. Explicitly acknowledge a partial inventory after reviewing its gaps. Blocked or invalid inventories cannot be confirmed.
5. Choose **Confirm inventory**. This records the reviewed service association without scanning. Choose **Start scan** separately when ready, then follow **View scan progress**.

Running work can be cancelled. Retry or **Rediscover as new version** preserves prior evidence. Under **Compare immutable versions**, select an earlier completed discovery from the same group to inspect added, removed and changed component IDs. Comparison reports inventory changes, not vulnerability changes.

If discovery is incomplete, review diagnostics, correct or include missing local dependencies/configuration, and submit the corrected input. The page never silently treats an unknown or partial result as a complete deployment.

## Native rendering isolation

The dedicated Linux worker runs as UID 10003. Bubblewrap exposes only the selected static renderer binary and the job source directory (read-only), creates fresh user, network, process and mount namespaces, clears the environment, drops capabilities, and supplies private temporary storage. Plugins, executable post-renderers and Kustomize exec extensions are rejected. A child seccomp filter blocks subsequent namespace creation/entry and mount changes, checks the syscall architecture, and fails closed on unsupported architectures. The worker records trusted build-time Helm, Kustomize and Compose versions. Wall-clock and combined output limits apply to every render.

Docker's built-in seccomp policy can prevent Bubblewrap namespace setup. The implementation fails closed in that case. Deployment requires explicit operator review of a default-derived container policy permitting Bubblewrap setup; no privileged mode, unconfined profile or writable host `/proc` is supported. The container policy is separate from the stricter child filter applied after namespace setup.

Acceptance on Docker Desktop Linux used an ephemeral default-derived policy with `unshare`, `clone` constrained to `CLONE_NEWUSER`, and `mount`, `umount2`, `pivot_root` additions. The worker retained no network, a read-only root, all capabilities dropped, no-new-privileges, process/memory/CPU limits and private `/tmp`. Helm 4.2.3, Kustomize 5.8.1 and Compose 2.39.4 rendered fixtures successfully. A parent Helm chart generating Flux configuration, ConfigMap `valuesFrom`, a local child chart and a declarative Kustomize image post-renderer produced the expected complete inventory. A Helm write to `/source` failed; private `/tmp` output succeeded. Source ownership and worker identity were UID 10003. These results do not establish compatibility with every Linux host security policy.
