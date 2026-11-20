# Monitor clusters and agents

Open **Clusters & agents** (`/runtime`) on the CATS portal to see which clusters are reporting, which namespaces need attention, and which running images still have current Approved Release evidence. A Kubernetes collector reports Pod inventory to a CATS main or replica over HTTPS. A Linux Docker collector can report container inventory to the same view.

## Connect a cluster

1. On the CATS instance the cluster can reach, choose **New environment**. Give it a recognizable cluster name and choose **Kubernetes**. The default **All active CATS services** includes services that become active later. Choose **Selected services** and pick at least one to limit release matching. Older environments retain their selected scope. Select a scope in the portal before linking another agent to an older environment with an empty selection. Save the environment and use one collector per cluster to avoid counting the same Pods twice. Collection includes Pods across namespaces. The service scope controls which release evidence CATS considers.
2. Open that environment and choose **Link agent**. The key identifies the receiving environment. It expires after one hour. Issuing another key invalidates an earlier unused key for this environment. Give the key and the **HTTPS portal URL** to the cluster operator.
3. Install the Helm chart with the portal URL and the linking key. The Pod enrolls automatically on first startup and stores its agent identity on a persistent volume. Registry, private CA and storage settings depend on the target cluster. [Connected and disconnected installation](../runtime-agent/README.md#kubernetes)
4. Confirm the Deployment is available, then open the environment in **Clusters & agents**. Look for the new agent, a first accepted report and a fresh observation time. The default reporting interval is 60 seconds. After the first complete report, select a namespace and inspect a running container's actual image identity and release decision.

Environment creation, scope changes, linking and revocation require application-wide `runtime.manage`. Viewing requires `runtime.view`. Administrators have both by default. The CATS environment ID and persisted collector source UUID establish identity. Operators can rename the environment without relinking. Choose **Docker** for a host running Docker Engine. [Docker host installation](../runtime-agent/README.md#linux-docker-host)

## Investigate a namespace

In **Clusters and hosts**, open a cluster and choose **View issues for** that cluster. **All agents** shows reporting status and last contact across the installation. In **Issues**, filter by **Cluster or host** and **Namespace**. **Issue type** separates confirmed policy failures, unverified observations and coverage gaps. For example, to find images that need a release review in the `payments` namespace, select that namespace and **Confirmed policy failure**, then read the reason beside the affected Pod, container, repository and digest. Inspect **Unverified observation** separately to find containers that lack sufficient evidence for an approval decision.

Open the cluster detail to compare a container's state, requested image, runtime-reported identity and CATS decision. Kubernetes ownership metadata identifies the Pod's direct controller where available. Chart and Helm release labels provide attribution hints.

| What you see | What it means and what to check |
| --- | --- |
| Approved | A current service-scoped release permits the observed repository and immutable manifest digest. A verified cached parent/child manifest relationship can establish membership for a multi-platform image. |
| Excepted | A current local replica override permits the image. Review the exception and its lifetime on that replica. |
| No matching Approved Release | CATS saw the running repository and digest and found no matching release in this cluster’s service scope. The issue shows its namespace and Pod. Check the service association and release inventory. |
| Expired, revoked or otherwise noncompliant | CATS has enough evidence to identify the image and determine that current release authorization denies it. A running digest for an identified service can also fall outside its current approved inventory. Inspect the reason and release details. For an expired release, locate a current approved replacement or follow the service's release-review process. |
| Container not running | CATS retains observed waiting, terminated or stopped state. It cannot confirm a currently running deployment for this container. |
| Unknown or unverified image identity | Check the running container's status `imageID` for a repository and manifest digest. If the runtime reports only a SHA-256, it must exactly match the digest of the Pod's explicitly pinned, fully qualified image. CATS must then independently verify that manifest's membership in release evidence for the same repository and an in-scope service. A tag-only image, mismatched digest, or runtime-scheme-prefixed config or container ID remains unverified. |
| Outside the configured service scope, missing mapping or unknown release membership | Check the environment's selected services, the proxy hostname, the service's OCI repository mapping, and its retained release inventory. A matching tag, digest on an unrelated repository, or missing mapping cannot establish approval. Edit the service scope only when the service belongs in this environment. |
| Stale or incomplete report | The rows may come from an earlier complete snapshot. Restore reporting or fix the collection error, then wait for a new complete report before using the counts to assess current workloads. |

For example, a Pod can continue running an image after its release expires. A refreshed dashboard can flag that container even if it has stayed on the same node since its original pull. **Runtime reports observations.** Kubernetes decides when the node pulls or reuses image bytes. The collector does not intercept registry requests, admit or terminate Pods, or remediate findings. A group policy that permits an OCI pull on scan compliance alone does not establish Approved Release membership for runtime reporting. [OCI gateway policy](oci-proxy.md)

CATS can match a fully qualified upstream repository and manifest digest directly to unique retained source or publication evidence for an in-scope service. For a CATS gateway path, set `CATS_OCI_HOSTNAME` to the public gateway host, including any nondefault port, and check that `<project>/<service-id>/<image>` resolves to the service. A private host that merely mirrors the same digest needs an established repository identity or mapping.

The receiving portal keeps its own observations and reevaluates them against current local or verified imported releases. Local exceptions remain attributable to the instance that issued them. After a release change, confirm the receiving instance has the expected evidence and refresh the page.

## Interpret coverage

| Agent state | Inventory interpretation |
| --- | --- |
| Never reported | The agent enrolled. CATS has no accepted report yet. Check the agent logs and its reachability to CATS and the inventory source. |
| Fresh | CATS received a recent complete report with a recent observation time. Check the container states and results in the reported inventory. |
| Incomplete | Collection failed or exceeded a limit. CATS retains the last complete inventory as unverified. An empty **complete** snapshot removes previous rows. |
| Stale | The last contact or observation is older than five minutes. Check connectivity, clocks and the collector's state volume. Replaying a prior report does not refresh its observation time. |
| Revoked | CATS rejects this agent's credential. Its last contact and retained observation count remain visible on the agent. Its observations are excluded from current cluster and namespace totals. |

When two enabled collectors report the same Kubernetes container UID in one cluster, CATS counts it once and prefers the freshest complete inventory. This keeps a collector replacement from doubling the reported workload count.

The agent sends up to 2,000 observations and 2 MiB in one request. Larger inventories use multiple pages, up to 20,000 observations and 16 MiB in one snapshot. CATS validates the whole snapshot before replacing retained inventory. A collection beyond the limit reports incomplete coverage. Cluster and namespace issue counts cover the entire retained inventory. The Issues and Inventory views page independently, so a violation on a later inventory page still appears under Issues. Periodic collection can miss short-lived containers. For installation, recovery and revocation procedures, see the [agent runbook](../runtime-agent/README.md#troubleshooting-and-recovery).
