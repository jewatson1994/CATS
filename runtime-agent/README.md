# CATS runtime agent

This collector reports Kubernetes Pod/container or Linux Docker inventory to a CATS portal over verified HTTPS. Create an environment and generate a linking key on the **receiving** instance first. The key binds one installation to that environment. It expires after one hour, so request it when the target is ready. [Portal setup and interpreting findings](../docs/runtime-agents.md)

## Kubernetes

The chart accepts an HTTPS portal URL or a bare hostname or IP address with optional port. A bare address uses HTTPS. The portal certificate must cover the address you supply.

The cluster needs a working persistent volume, outbound HTTPS to the CATS portal, and access to the in-cluster Kubernetes API. The installer needs permission to create a namespace, Deployment, service account, cluster-scoped Pod reader role and binding, Secret and PVC. The collector's ClusterRole grants only `list` on Pods across namespaces. It opens no inbound port and mounts no node runtime socket. The kubelet must be able to obtain the collector image on the node that runs it.

### Connected install with two settings

Use Bash on a machine with Helm, kubectl and a kubeconfig for the target cluster. From the source tree the chart is `runtime-agent/helm/cats-runtime`. For a published release it is `oci://ghcr.io/jewatson1994/charts/cats-runtime`. The default collector image is `ghcr.io/jewatson1994/cats-runtime:0.1.0`. Check that the publishing run for your version succeeded and that the operator can read the chart and the cluster nodes can pull the image. The workflow packages the chart and builds collector images for Linux amd64 and arm64. The disconnected procedure also works with a locally built collector. [Runtime agent packaging workflow](../.github/workflows/publish-runtime-agent.yml)

```bash
kubectl config current-context
CATS_URL=https://cats.example.org
CHART=runtime-agent/helm/cats-runtime
umask 077
keyfile=$(mktemp)
trap 'rm -f "$keyfile"' EXIT
read -rsp 'Paste the CATS linking key: ' key
printf '\n'
printf '%s' "$key" > "$keyfile"
unset key
helm upgrade --install cats-runtime "$CHART" \
  --namespace cats-runtime --create-namespace \
  --set-string catsUrl="$CATS_URL" --set-file linkingKey="$keyfile"
```

The only required settings for a new standard installation are the portal URL and the linking key. With a published chart, set `CHART=oci://ghcr.io/jewatson1994/charts/cats-runtime` and add `--version 0.1.0` to the Helm command. The Deployment enrolls itself, receives its environment assignment, persists its reporting identity, and starts submitting inventory. The portal uses the environment name you chose, even if the Helm release or Kubernetes context has a different name.

The `--set-file` form keeps the key out of shell arguments, but Helm stores the supplied value in release history. To keep it outside Helm values, have your secret manager provision a Secret in the release namespace with data key `linking-key`. Use `--set-string linkingKeySecret=NAME` **in place of** `--set-file linkingKey=...`. To create the Secret from the protected key file, run the following commands.

```bash
kubectl create namespace cats-runtime --dry-run=client -o yaml | kubectl apply -f -
kubectl -n cats-runtime create secret generic cats-runtime-link \
  --from-file=linking-key="$keyfile"
helm upgrade --install cats-runtime "$CHART" --namespace cats-runtime \
  --set-string catsUrl="$CATS_URL" --set-string linkingKeySecret=cats-runtime-link
```

### Disconnected install

Transfer a packaged chart and the collector image for the **target node architecture**. On a build machine with the source checkout and access to the Dockerfile's base image, prepare the two artifacts:

```bash
mkdir -p dist
helm package runtime-agent/helm/cats-runtime --destination dist
docker build --tag cats-runtime:0.1.0 runtime-agent
docker save --output dist/cats-runtime-image.tar cats-runtime:0.1.0
```

If using a published release, the matching packaged chart and collector image can be mirrored instead. On a machine with access to the internal registry, load the image and push it to a repository the cluster nodes can read:

```bash
INTERNAL_IMAGE=registry.internal.example.org/platform/cats-runtime
docker load --input dist/cats-runtime-image.tar
docker tag cats-runtime:0.1.0 "$INTERNAL_IMAGE:0.1.0"
docker push "$INTERNAL_IMAGE:0.1.0"
```

Use your internal chart package and image repository when installing. Create the namespace and bootstrap Secret using the previous section. For a portal signed by a private CA, create a Secret containing its public CA bundle and add `caSecret`. The following example assumes the registry pull Secret `internal-registry` already exists in the same namespace. Omit the option for a registry the kubelet can already read.

```bash
kubectl -n cats-runtime create secret generic cats-runtime-ca --from-file=ca.crt=site-ca.pem
helm upgrade --install cats-runtime ./dist/cats-runtime-0.1.0.tgz --namespace cats-runtime \
  --set-string catsUrl=https://cats.internal.example.org \
  --set-string linkingKeySecret=cats-runtime-link \
  --set-string caSecret=cats-runtime-ca \
  --set-string image.repository="$INTERNAL_IMAGE" --set-string image.tag=0.1.0 \
  --set-string 'imagePullSecrets[0].name=internal-registry'
```

Pin the collector to the actual manifest digest from your internal registry using `image.digest=sha256:...`. The chart gives the digest precedence over `image.tag`. For a registry with a private CA, configure trust in the **node's container runtime** so the kubelet can pull the agent image. The chart's `caSecret` configures the collector's HTTPS connection to **CATS**. The Kubernetes API uses the service account's own CA and token. A disconnected deployment needs only local DNS, the local source of the collector image, the cluster API and the receiving CATS instance.

### Verify enrollment and the first report

```bash
kubectl -n cats-runtime get pods,pvc
kubectl -n cats-runtime rollout status deployment/cats-runtime --timeout=180s
kubectl -n cats-runtime logs deployment/cats-runtime --tail=40
```

Check the logs for `linked` and `report_accepted`. The Deployment's readiness probe checks for a persisted agent ID. In **Clusters & agents**, open the environment, verify that its agent shows fresh coverage and an observation time, then inspect a reported namespace and workload to confirm CATS has accepted inventory.

The chart uses one nonroot replica, a read-only root filesystem, dropped capabilities and a PVC. The storage driver must support POSIX ownership and `fsGroup: 10001`. To select a storage class use `persistence.storageClass`. For an existing suitable claim use `persistence.existingClaim`. The chart retains its PVC on uninstall. To reinstall the same collector in the same namespace, set `persistence.existingClaim=cats-runtime-state` (substitute the original release's claim name), keep the same portal URL, and omit both bootstrap settings. Upgrades also reuse the persisted reporting identity. Each active collector needs its own source identity and writable state.

## Linux Docker host

From the repository root on the target host, install the collector and service. The supplied unit runs `python3` and expects the system Docker socket and `docker` group. Use Python 3.12 and a supported Linux host. Adjust `--docker-socket` and service account permissions for a rootless daemon. Docker socket access grants host-level privileges even though the collector uses read-only API calls.

```sh
sudo useradd --system --home /var/lib/cats-runtime --shell /usr/sbin/nologin cats-runtime
sudo install -d -m 0755 /opt/cats-runtime
sudo cp -R runtime-agent/cats_runtime /opt/cats-runtime/
sudo install -d -m 0700 -o cats-runtime -g cats-runtime /var/lib/cats-runtime
sudo install -d -m 0750 -o root -g cats-runtime /etc/cats-runtime
sudo install -m 0644 runtime-agent/systemd/cats-runtime.service /etc/systemd/system/
sudo tee /etc/cats-runtime/agent.env >/dev/null <<'EOF'
CATS_URL=https://cats.example.org
CATS_AGENT_NAME="Production Docker host"
CATS_LINKING_KEY_FILE=/etc/cats-runtime/linking-key
EOF
sudo chmod 0640 /etc/cats-runtime/agent.env
sudo chown root:cats-runtime /etc/cats-runtime/agent.env
sudo sh -c 'umask 077; cat > /etc/cats-runtime/linking-key'
# Paste a fresh Docker environment linking key, press Enter, then Ctrl-D.
sudo chown cats-runtime:cats-runtime /etc/cats-runtime/linking-key
sudo systemctl daemon-reload
sudo systemctl enable --now cats-runtime
sudo journalctl -u cats-runtime -n 40
```

For a private portal CA, install the readable public CA bundle and add `CATS_CA_FILE=/etc/cats-runtime/ca.crt` to `agent.env` before starting the unit. After the first successful report the agent uses its protected state under `/var/lib/cats-runtime/state`. The used bootstrap key file can then be removed.

## Troubleshooting and recovery

| Symptom | Checks and recovery |
| --- | --- |
| `ImagePullBackOff` before a collector log exists | Inspect `kubectl -n cats-runtime describe pod POD`. Check registry address, tag or digest, node platform, node registry CA and the pull Secret in this namespace. These are kubelet operations and happen before the agent can contact CATS. |
| Pending Pod or unwritable state | Check PVC binding, storage class, mount, `fsGroup` and free space. Keep the PVC when restarting or upgrading so the collector can reuse its identity and sequence. |
| Agent starts but never links | Use the receiving portal's HTTPS address, validate DNS, certificate chain, key Secret name and key `linking-key`. Check that the key is current and for the right source type on this instance. Replacing an unused key invalidates the older one. |
| Network outage or lost acknowledgment | Restore the same portal URL and TLS trust. Restart with the same state. An interrupted initial enrollment can replay the same key and pending credential during its validity window. Reports retry the same persisted sequence and body. Check the next accepted observation time for freshness. |
| Pod list denied or coverage incomplete | Check the service account's cluster-scoped Pod list permission, Kubernetes API reachability and the error reported by CATS. The collector pages snapshots larger than 2,000 containers or 2 MiB. The total snapshot limit is 20,000 observations or 16 MiB. A failed or incomplete collection preserves the last complete snapshot. |
| Agent revoked, state lost or state restored to an old sequence | Stop the affected collector. In CATS revoke the old agent for that environment if still active. Issue a new key. Deploy using a fresh state directory or fresh PVC and the new key. Keep any existing volume separate during recovery. Verify one fresh reporting agent before retiring the old installation. |
| Cluster healthy but an image is unverified | Compare the running container's actual image ID to its CATS repository mapping, environment service scope and retained release. A desired image tag or spec digest alone cannot verify what is running. [Finding interpretation](../docs/runtime-agents.md#investigate-a-namespace) |

To revoke, select the linked agent in CATS and confirm revocation. Its credential immediately stops authorizing reports. Revocation preserves its previous observations for investigation. Stop or scale down the collector if it is no longer needed. Changing the CATS instance requires enrollment with that instance and separate state. Avoid sharing a state volume, inspecting its credential in logs, or using an old snapshot as a second running agent.

## What the collector observes

- Kubernetes paginates cluster-wide Pods and reads regular, init and ephemeral container status. Pod UID, container kind and name identify an observation. The direct controller, namespace, node and selected Helm labels add context. For a running container, the agent uses the qualified repository and digest from status when available. A runtime that returns only `sha256:…` can still be matched when the Pod explicitly requests `registry.example.org/team/web@sha256:…` and the two digests are identical. CATS independently checks manifest membership for that repository and service before it can establish release approval. A mutable tag, a runtime-scheme-prefixed ID such as `containerd://sha256:…`, or a digest present only in the Pod spec leaves the running identity unverified. Waiting and terminated containers retain their observed states.
- Docker lists running and stopped containers. It looks up metadata by the inspected immutable image configuration ID. One unambiguous repository digest can supply manifest identity. Missing or conflicting digests leave the image unverified.
- Collection failures, limits, or a race with container removal can make a snapshot incomplete. The default interval is 60 seconds with a 120-second collection budget. Short-lived containers can start and stop between observations. For a one-shot check on a Docker host, stop the unit first and run the collector as its service account with the same URL, CA, state directory and `run --source docker --once`.
- Reports contain inventory metadata. The collector does not fetch workload logs, application environment variables, Kubernetes Secret contents, CPU/memory metrics or admission events. Kubernetes returns whole Pod objects when listed. The collector selects the inventory fields it sends to CATS.
