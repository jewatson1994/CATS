# OCI replica staging qualification — 2026-11-05

This run extends the [completion audit](oci-replica-completion-audit-2026-11-05.md) with an actual 100-image Harbor inventory and a newly scanned and patched nginx service. It uses an isolated local staging environment on branch `codex/oci-approved-release-replicas`, based on `40f1af0c13c5aed78e35a63609daa6e65b69f122`. It does not qualify an unspecified external production deployment.

## Scope and evidence

The inventory comprises 123 runnable Linux/amd64 images derived from the immutable nginx base. Each has a distinct filesystem marker layer, configuration and image digest. Release 1 contains indices 0–99; release 2 contains indices 23–122: exactly 77 retained, 23 retired and 23 new images. Shared base layers remain shared. Inventory assessment records are explicitly synthesized test evidence; production capture, signing, publication, verification, reconciliation and proxy authorization execute normally. The separate nginx workflow uses fresh actual assessments and approvals.

Only source Harbor receives publication writes. Harbor `v2.15.4-d8841742` copies the complete service subtrees with its actual `harbor` adapter and jobservice, verified TLS, manual rules, preserved namespaces and deletion replication disabled. Replica trust pins the signer independently. Fresh PostgreSQL replicas use only portal, proxy and database services, with separate evidence and cache volumes. Scoped public test projects allow anonymous target reads; this run does not validate a private target robot configuration.

Private credentials, keys, databases, receipts and detailed logs remain outside the repository under the task's `staging-qualification` workspace. The sanitized machine-readable record links results to raw evidence with SHA-256 hashes.

## Results

The qualification passed. The [machine-readable evidence record](staging-qualification-2026-11-05.json) contains release identities, all 123 image digests, actual Harbor executions, source-outage probes, override results, cleanup and hashes of retained raw evidence.

| Check | Observed result |
| --- | --- |
| Actual Harbor replication | Executions 12–15 and all repository transfer tasks succeeded for the fresh nginx and inventory baseline/successor releases. |
| Baseline inventory | 100 complete image graphs downloaded and hash-verified: 2,101,456,490 bytes. |
| Incomplete successor | Removing one successor-only target layer caused synchronization to fail without replacing the baseline. Restoring that layer allowed recovery with the source still stopped. |
| Disconnected successor | All 100 graphs downloaded and hash-verified from a newly empty blob cache: 2,101,456,523 bytes. Source Harbor remained unavailable before and after the complete phase. These totals include shared layers downloaded for each graph; they are not unique storage size. |
| Replacement and history | Exactly 77 retained, 23 new and 23 retired images; all 23 retired roots denied. One service, 100 active images and both release histories remained intact. |
| Local overrides | Fixed and indefinite exact-scope grants allowed the selected retired image and recorded usage. The other 22 retired roots remained denied. Both grants were revoked, immediately denying the selected root despite cached content; administrator creation was denied. |
| Runnable corpus | All 123 published OCI identities executed successfully by validated immutable Docker ID, with exact marker output, networking disabled and read-only filesystems. |
| Imported evidence | Both signed inventory evidence bundles matched the source receipts. The successor retained 123 historical image records while exposing 100 active images. |
| Fresh nginx | Actual scan, patch, independent rescan, approvals and Harbor replication completed. Package vulnerability observations fell from 194 to 0; seven configuration findings remained. The patched image's disconnected cold pull verified 63,708,035 bytes; override/revocation and replica restart checks passed. |
| Regression checks | 129 passed; zero failures, errors or skips across the five focused suites. |

Failures found in the qualification drivers were corrected and the affected live phases repeated. The final complete inventory phase reran all 100 pulls from another newly empty blob cache after correcting the override URL; the earlier failed attempt remains in the evidence. No production application failure remained in these scenarios.

All owned qualification services were stopped after verification, retaining volumes and logs. The quarantined target layer was independently rechecked for its exact original hash and size, with no held copy remaining. Changes are committed locally only; nothing was pushed or merged.

## Corrections made during qualification

- Added literal service-subtree Harbor policies, validation before execution, and safe recovery when a policy exists but its local checkpoint is missing. Harbor omits optional false values; an omitted `replicate_deletion` now means false while true remains rejected.
- Added an explicit nginx service key so a fresh run cannot accidentally reuse a previous service's identity. Malformed, empty and conflicting identities fail before login or state changes.
- Added source-only runnable inventory publication, atomic checkpoints, immutable workspace binding, resumable frozen evidence capture, and runtime verification bound to the published OCI configurations and manifests.
- Preserved the original OCI manifests and compressed layers in the runtime archive. Docker's containerd image store reports the manifest digest as the image ID; verification now accepts only the exact published manifest or configuration digest, supporting both Docker storage modes. The initial identity-check failure and the successful offline run are retained separately.
- Execute the already verified immutable Docker image ID, avoiding a race if a tag changes between inspection and execution. A regression simulates retagging; the complete runtime check is repeated after this correction.
- Added live HTTP inventory checks with exact release lineage, full graph hashes, independently established missing-content failures, cold blob-cache proof and fixed/indefinite override cleanup.
- Corrected the source availability probe to preserve `/v2/` exactly. The initial probe failed before synchronization because stripping its trailing slash returned a redirect; that failed attempt is retained separately.
- Made the actual source registry probe mandatory even when extra publisher URLs are supplied. Override cleanup captures the returned grant ID before validating its scope, so a malformed response with a usable ID still triggers revocation.
- Corrected the inventory driver's override URL to the existing `/api/services/{service_key}/local-overrides` route. Its first complete attempt downloaded all 100 graphs but then used an incorrect `/api/replica/services/...` route, which the replica boundary correctly rejected. A regression now exercises the production router through that boundary. The failed attempt is retained; both override durations are checked live before the entire final phase is repeated with a newly empty blob cache.
- Limited target fault injection to one successor-only marker with no references outside the owned namespace. Quarantine verifies exact bytes and records ownership before renaming; restoration runs in a cleanup path.

## Repeating the qualification

Use a new private workspace and disposable, explicitly owned Harbor source/target subtrees. Start with the [Harbor setup procedure](portable-approved-releases.md#repeating-the-isolated-harbor-qualification) and a fresh worker-free replica from `compose.replica.yaml`. Preserve its actual project name and API/proxy/bootstrap settings in the private `stack.json` used by the verifier. Supply a unique `--service-key` to the existing fresh nginx workflow; execute its scan, patch, independent rescan, approvals and publication before the Harbor nginx phases.

The new drivers have the following responsibilities:

| Driver | Role |
| --- | --- |
| `portal/tests/harbor_inventory_qualification.py` | Publish real image graphs and signed releases to source only; export and execute the complete 123-image corpus |
| `portal/tests/harbor_inventory_http.py` | Configure the live replica, verify baseline, reject incomplete successor, recover, then verify disconnected pulls and overrides |
| `portal/tests/harbor_inventory_fault.py` | Reversibly quarantine/restore one owned successor-only target blob |
| `portal/tests/harbor_replication_qualification.py` | Configure exact subtree policies and retain actual Harbor executions and configuration |

Run the phases in this order; do not publish the successor before completing baseline pulls:

1. Configure `setup-scoped --namespace <alias> --repository-prefix qualification/<unique-subtree>` on the Harbor controller. The prefix is literal, without a wildcard; the driver adds `/**`.
2. Run corpus `publish-first` with `--workspace`, `--namespace`, `--service-key`, an immutable runnable `--base-image` already in source Harbor, explicit `--source`/`--target`, `--ca` and `--docker-config`. Run in a container on the Harbor network with the repository mounted read-only and private workspace mounted separately.
3. Run controller `replicate --namespace <alias> --label <baseline-label>`. Run HTTP `--phase setup`, then `--phase baseline` with its `--workspace`, `--replica-workspace`, CA, actual API/proxy URLs and the exact source `/v2/` URL. Every image graph must be downloaded and hash-checked.
4. Run corpus `publish-successor` with the same identity parameters; replicate again. Run host-side `verify-runtime --workspace <inventory-workspace>` to load the exported archive and execute all 123 images with networking disabled, read-only filesystems, no capabilities and bounded resources.
5. Capture controller `inspect`; stop the owned source Harbor services and original CATS/publisher services. Preserve target Harbor and the replicas. The verifier must observe connection failure against the same previously reachable source endpoints; authentication and TLS failures do not count as disconnection.
6. Mount only the disposable target registry volume into the fault helper. Run `quarantine --registry-storage <mount> --confirm-target <exact-target>`, then HTTP `--phase incomplete --require-source-offline`, and always `restore` in a `finally` cleanup path. The parent must remain reachable, the exact referenced marker must be unavailable/corrupt, production verification must reject that content, and the baseline must remain active.
7. Run HTTP `--phase recover --require-source-offline`. Preserve PostgreSQL and evidence, replace only this replica's blob-cache mount with a new named empty volume, and verify both portal/proxy mounts and the empty directory. Retain the previous volume. Record the exact `cats-inventory-cold-cache-v1` proof fields required by the verifier, after recovery and before any successor pull.
8. Run HTTP `--phase complete --cold-cache-proof <proof>`. It downloads all 100 successor graphs, checks all 23 retired images, exercises fixed and indefinite exact overrides, checks the other 22 remain denied, verifies audit usage, revokes in cleanup, and checks immediate denial despite cached content. Repeat the nginx Harbor driver's disconnected, override and restart phases separately.
9. Retain sanitized evidence and hashes. Stop only the owned test containers; retain volumes and logs. Do not prune unrelated Docker resources.

The cold inventory proof concerns blob storage. PostgreSQL's manifest cache remains intact and can serve the 77 previously pulled roots; the report must not describe this as an entirely empty replica. This corpus is a correctness test, not a capacity or concurrency benchmark for 100 unrelated production applications.

Runtime execution loads a local archive whose OCI objects match the published corpus; it does not pull through target Harbor. The separate HTTP phases download and hash-check every target-served graph. These two checks establish distinct properties and are recorded separately.

Focused regression command from the repository root:

```powershell
$env:PYTHONPATH = 'portal'
$env:PYTHONDONTWRITEBYTECODE = '1'
.\.venv\Scripts\python.exe -m pytest portal/tests/test_harbor_replication_qualification.py portal/tests/test_harbor_inventory_qualification.py portal/tests/test_harbor_inventory_http.py portal/tests/test_harbor_inventory_fault.py portal/tests/test_nginx_workflow_integration.py -q -p no:cacheprovider --basetemp <new-external-test-directory>
```

No production application code changed in this qualification. Existing broad application/frontend results remain historical evidence from the completion audit; they are not counted as rerun here.
