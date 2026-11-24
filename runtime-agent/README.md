# CATS runtime agent

This collector reports Kubernetes Pod/container or Linux Docker inventory to a CATS portal over verified HTTPS. Create an environment and generate a linking key on the **receiving** instance first. The key binds one installation to that environment. It expires after one hour, so request it when the target is ready. [Portal setup and interpreting findings](../docs/runtime-agents.md)

## Kubernetes

The chart accepts an HTTPS portal URL or a bare hostname or IP address with optional port. A bare address uses HTTPS. The portal certificate must cover the address you supply.

The cluster needs a working persistent volume, outbound HTTPS to the CATS portal, and access to the in-cluster Kubernetes API. The installer needs permission to create a namespace, Deployment, service account, cluster-scoped Pod reader role and binding, Secret and PVC. The collector's ClusterRole grants `list` and `watch` on Namespaces, Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs. It opens no inbound port and mounts no node runtime socket. The kubelet must be able to obtain the collector image on the node that runs it.

### Connected install with two settings

Use Bash on a machine with Helm, kubectl and a kubeconfig for the target cluster. The `cats-runtime` chart runs `ghcr.io/jewatson1994/cats-tool` with `CATS_ROLE=runtime-agent`. The published chart pins the release image by digest. Linux amd64 nodes use the same image layers as the portal and workers. Linux arm64 nodes use the runtime collector from the same multi-platform image. [CATS image and chart publishing](../.github/workflows/build-cats-tool.yml)

```bash
kubectl config current-context
CATS_URL=https://cats.example.org
CHART=oci://ghcr.io/jewatson1994/charts/cats-runtime
umask 077
keyfile=$(mktemp)
trap 'rm -f "$keyfile"' EXIT
read -rsp 'Paste the CATS linking key: ' key
printf '\n'
printf '%s' "$key" > "$keyfile"
unset key
helm upgrade --install cats-runtime "$CHART" --version 0.2.1 \
  --namespace cats-runtime --create-namespace \
  --set-string catsUrl="$CATS_URL" --set-file linkingKey="$keyfile"
```

The published chart needs the portal URL and linking key. The portal’s **Link agent** panel includes its configured image reference when available. To use that same release from an internal registry, pass `--set-string image.reference="$CATS_IMAGE"` with the pullable reference used by the portal. The source chart at `runtime-agent/helm/cats-runtime` defaults to `cats-tool:latest` when no image reference is supplied. After enrollment, the Deployment retains its reporting identity on the PVC and reports under the environment name you chose in CATS.

The `--set-file` form keeps the key out of shell arguments, but Helm stores the supplied value in release history. To keep it outside Helm values, have your secret manager provision a Secret in the release namespace with data key `linking-key`. Use `--set-string linkingKeySecret=NAME` **in place of** `--set-file linkingKey=...`. To create the Secret from the protected key file, run the following commands.

```bash
kubectl create namespace cats-runtime --dry-run=client -o yaml | kubectl apply -f -
kubectl -n cats-runtime create secret generic cats-runtime-link \
  --from-file=linking-key="$keyfile"
helm upgrade --install cats-runtime "$CHART" --version 0.2.1 --namespace cats-runtime \
  --set-string catsUrl="$CATS_URL" --set-string linkingKeySecret=cats-runtime-link
```

### Disconnected install

Transfer the packaged chart and the same CATS release image used by the portal. If that release is already in a registry the cluster can read, transfer only the chart. To carry a published multi-platform image across a disconnected boundary, run the following on a connected machine with Helm and Skopeo. Set `SOURCE_IMAGE` to the full release image reference, preferably its index digest.

```bash
mkdir -p dist
helm pull oci://ghcr.io/jewatson1994/charts/cats-runtime --version 0.2.1 --destination dist
skopeo copy --all "docker://${SOURCE_IMAGE:?Set SOURCE_IMAGE to the CATS release image}" oci:dist/cats-tool:release
```

Transfer `dist` to the disconnected side. Copy the image into the internal registry, then use the destination digest for both Compose and Helm. For a locally built amd64 release, the existing CATS image can also be loaded and pushed to that registry. [Build and export the shared image](../README.md#build-from-source)

```bash
INTERNAL_REPOSITORY=registry.internal.example.org/platform/cats-tool
skopeo copy --all --digestfile dist/cats-tool.digest oci:dist/cats-tool:release "docker://$INTERNAL_REPOSITORY:release"
export CATS_IMAGE="$INTERNAL_REPOSITORY@$(cat dist/cats-tool.digest)"
```

Use that `CATS_IMAGE` in your deployment environment. Create the namespace and bootstrap Secret as above. For a private portal CA and an authenticated registry, provide the CA Secret and a registry pull Secret available in that namespace.

```bash
kubectl -n cats-runtime create secret generic cats-runtime-ca --from-file=ca.crt=site-ca.pem
helm upgrade --install cats-runtime ./dist/cats-runtime-0.2.1.tgz --namespace cats-runtime \
  --set-string catsUrl=https://cats.internal.example.org \
  --set-string linkingKeySecret=cats-runtime-link \
  --set-string caSecret=cats-runtime-ca \
  --set-string image.reference="$CATS_IMAGE" \
  --set-string 'imagePullSecrets[0].name=internal-registry'
```

The node’s container runtime must trust the internal registry CA. The chart’s `caSecret` supplies the CA for HTTPS to the CATS portal. The collector uses the Kubernetes service account’s CA and token for the cluster API.

### Verify enrollment and the first report

```bash
kubectl -n cats-runtime get pods,pvc
kubectl -n cats-runtime rollout status deployment/cats-runtime --timeout=180s
kubectl -n cats-runtime logs deployment/cats-runtime --tail=40
```

Check the logs for `linked` and `report_accepted`. The Deployment's readiness probe checks for a persisted agent ID. In **Clusters & agents**, open the environment, verify that its agent shows fresh coverage and an observation time, then inspect a reported namespace and workload to confirm CATS has accepted inventory.

The chart uses one nonroot replica, a read-only root filesystem, dropped capabilities and a PVC. The storage driver must support POSIX ownership and `fsGroup: 10001`. To select a storage class use `persistence.storageClass`. For an existing suitable claim use `persistence.existingClaim`. The chart retains its PVC on uninstall. To reinstall the same collector in the same namespace, set `persistence.existingClaim=cats-runtime-state` (substitute the original release's claim name), keep the same portal URL, and omit both bootstrap settings. Upgrades also reuse the persisted reporting identity. Each active collector needs its own source identity and writable state.

### Discovery, upgrades and interrupted connectivity

Upgrade the portal to a unified release that contains the runtime agent before installing chart 0.2.1. If an earlier installation set a custom collector image, supply the new CATS image with `image.reference` during the upgrade. Keep the same release, namespace, endpoint and persistent volume. The chart updates the existing read-only role and reuses the enrolled credential. Use `helm history cats-runtime -n cats-runtime` to find the previous revision. If a rollback is needed, first allow queued reports to drain, then run `helm rollback cats-runtime REVISION -n cats-runtime`. A previous Pod-only collector can report container inventory to the upgraded portal. It cannot confirm removal of a discovered controller.

The collector watches Kubernetes metadata for changes, coalesces bursts, then lists fresh snapshots. Its regular reporting interval also triggers a full reconciliation. A watch failure falls back to periodic lists. An expired resource version starts another list. Snapshot collection projects only names, identities, ownership, selected app/Helm labels, release annotations, the numeric `cats.io/service-id` hint, an optional lowercase SHA-256 `cats.io/chart-digest` annotation, requested images and runtime status. Namespaced owner UIDs connect ReplicaSets to Deployments and Jobs to CronJobs. Template components remain visible at zero replicas. An empty namespace contributes no application.

At startup the collector lists the `kube-system` namespace by name and pins its UID in the private agent state. A copied PVC with a different cluster UID stops before enrollment or replay. An upgrade from a Pod-only collector pins the cluster on its first discovery-capable startup. For a replacement cluster, provision a new agent PVC and linking key. Each installation retains its own source UUID.

If CATS becomes unreachable, the collector keeps the exact pending report on its volume. While disconnected it observes further distinct application/component changes and queues up to eight additional snapshots, within a 64 MiB total buffer. Pod UID, replica and node churn alone do not enqueue a change. At capacity the collector coalesces unsent tail entries and logs `offline_buffer_coalesced`. On reconnect it replays the queue in order and continues reconciling. Very short-lived workloads between reconciliations or changes beyond the buffer may be missed. A denied or failed list reports incomplete coverage and preserves the last complete inventory.

## Linux Docker host

On a monitored Linux Docker host, run the collector from the same `CATS_IMAGE` as the portal. The Compose file starts `CATS_ROLE=runtime-agent` with the Docker inventory source. It gives the process access to the host Docker socket. The collector issues read-only inventory requests, but access to this socket carries host-level privileges.

Set `CATS_IMAGE` to your pullable or preloaded shared release image. From the repository root, prepare the state directory and the protected linking key for a **Docker** environment. Run the commands as an operator with Docker access.

```sh
export CATS_IMAGE="${CATS_IMAGE:?Set CATS_IMAGE to the portal release tag or digest}"
export CATS_URL=https://cats.example.org
export CATS_AGENT_NAME="$(hostname)"
export CATS_DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
sudo install -d -m 0700 -o 10001 -g 10001 /var/lib/cats-runtime
sudo install -d -m 0750 -o root -g 10001 /etc/cats-runtime
sudo sh -c 'umask 077; cat > /etc/cats-runtime/linking-key'
# Paste the new linking key, press Enter, then Ctrl-D.
sudo chown 10001:10001 /etc/cats-runtime/linking-key
docker compose -f runtime-agent/compose.docker.yaml up -d
docker compose -f runtime-agent/compose.docker.yaml logs --tail=40 runtime-agent
```

For an existing systemd installation, stop and disable the old unit before switching. Keep its state and key directory ownership, set `CATS_AGENT_UID` and `CATS_AGENT_GID` to the numeric IDs of the existing `cats-runtime` account, and start Compose with the same portal URL. Its enrolled identity stays in `/var/lib/cats-runtime/state`. For a private portal CA, place its public CA bundle in `/etc/cats-runtime/ca.crt` and set `CATS_CA_FILE=/etc/cats-runtime/ca.crt`. For a rootless engine, set `CATS_DOCKER_SOCKET` to the socket path and use its numeric group ID.

## Troubleshooting and recovery

| Symptom | Checks and recovery |
| --- | --- |
| `ImagePullBackOff` before a collector log exists | Inspect `kubectl -n cats-runtime describe pod POD`. Check registry address, tag or digest, node platform, node registry CA and the pull Secret in this namespace. These are kubelet operations and happen before the agent can contact CATS. |
| Pending Pod or unwritable state | Check PVC binding, storage class, mount, `fsGroup` and free space. Keep the PVC when restarting or upgrading so the collector can reuse its identity and sequence. |
| Agent starts but never links | Use the receiving portal's HTTPS address, validate DNS, certificate chain, key Secret name and key `linking-key`. Check that the key is current and for the right source type on this instance. Replacing an unused key invalidates the older one. |
| Network outage or lost acknowledgment | Restore the same portal URL and TLS trust. Restart with the same state. An interrupted initial enrollment can replay the same key and pending credential during its validity window. Reports retry the same persisted sequence and body. Check the next accepted observation time for freshness. |
| Pod list denied or coverage incomplete | Check the service account's cluster-scoped list/watch permissions for every resource listed above, Kubernetes API reachability and the error reported by CATS. The collector pages snapshots larger than 2,000 containers or 2 MiB. The total snapshot limit is 20,000 observations or 16 MiB. A failed or incomplete collection preserves the last complete snapshot. |
| Agent revoked, state lost or state restored to an old sequence | Stop the affected collector. In CATS revoke the old agent for that environment if still active. Issue a new key. Deploy using a fresh state directory or fresh PVC and the new key. Keep any existing volume separate during recovery. Verify one fresh reporting agent before retiring the old installation. |
| Cluster healthy but an image is unverified | Compare the running container's actual image ID to its CATS repository mapping, environment service scope and retained release. A desired image tag or spec digest alone cannot verify what is running. [Finding interpretation](../docs/runtime-agents.md#investigate-a-namespace) |

To revoke, select the linked agent in CATS and confirm revocation. Its credential immediately stops authorizing reports. Revocation preserves its previous observations for investigation. Stop or scale down the collector if it is no longer needed. Changing the CATS instance requires enrollment with that instance and separate state. Avoid sharing a state volume, inspecting its credential in logs, or using an old snapshot as a second running agent.

## What the collector observes

- Kubernetes paginates cluster-wide Pods and reads regular, init and ephemeral container status. Pod UID, container kind and name identify an observation. The direct controller, namespace, node and selected Helm labels add context. For a running container, the agent uses the qualified repository and digest from status when available. A runtime that returns only `sha256:…` can still be matched when the Pod explicitly requests `registry.example.org/team/web@sha256:…` and the two digests are identical. CATS independently checks manifest membership for that repository and service before it can establish release approval. A mutable tag, a runtime-scheme-prefixed ID such as `containerd://sha256:…`, or a digest present only in the Pod spec leaves the running identity unverified. Waiting and terminated containers retain their observed states.
- Docker lists running and stopped containers. It looks up metadata by the inspected immutable image configuration ID. One unambiguous repository digest can supply manifest identity. Missing or conflicting digests leave the image unverified.
- Collection failures, limits, or a race with container removal can make a snapshot incomplete. The default interval is 60 seconds with a 120-second collection budget. Short-lived containers can start and stop between observations. For a one-shot check on a Docker host, stop the running collector and use `docker compose -f runtime-agent/compose.docker.yaml run --rm runtime-agent run --source docker --once` with the same environment and state directory.
- Reports contain inventory metadata. The collector does not fetch workload logs, application environment variables, Kubernetes Secret contents, CPU/memory metrics or admission events. Kubernetes returns whole Pod objects when listed. The collector selects the inventory fields it sends to CATS.
