# nginx hardening qualification — 2026-11-05

The nginx runtime, local replica and actual Harbor qualification passed. The fresh scan reduced package vulnerability observations from **194 to 0** and configuration findings from **7 to 3**. Four configuration findings were resolved by an explicit derivative of the real package-patched image. The requested removal of all seven raw findings is **incomplete**: the three remaining findings are retained below, with their evidence and dispositions. Approval and successful runtime checks do not make those findings disappear.

This run covers nginx only, using service key `nginx-hardening-20261105` in a fresh private workspace on branch `codex/oci-approved-release-replicas`. The [earlier staging qualification](staging-qualification-2026-11-05.md), including its 100-image inventory and 23-image replacement scenario, remains historical evidence and was not rerun here. Earlier qualification workspaces and results remain intact.

## Immutable lineage and fresh assessments

| Stage | Immutable reference |
| --- | --- |
| Original nginx | `docker.io/library/nginx@sha256:09ab424a8c788f8d0fe3a64429f6d19dfa526885c8609b748d0943a75dcb9f8c` |
| Actual package patch | `publisher.test:5000/patched/nginx@sha256:eb007132ae918972f2de3ba02e45bc330460058472b13ba5fe4aa3e838c13663` |
| Final hardened derivative | `publisher.test:5000/hardened/nginx@sha256:2dd3835ed3850194293bc9191b8a66504f66c069580b7c08dbe3e18200c33fa2` |

The retained package-patch result reports `PATCHED`, 194 vulnerabilities removed, none remaining, and `image_changed: true`. The hardening step follows that result; it does not manufacture package-remediation counts or treat an already clean image as a successful package patch.

| Assessment | Scan ID | Package observations | Configuration findings | Approval |
| --- | --- | ---: | ---: | --- |
| Original source | `64ca7b425b704f7384c3da376f1791b8` | 194 | 7 | 1 |
| Final hardened digest | `f423df809f5548cd8ad057adc5d61821` | 0 | 3 | 2 |

Both scans completed with no skipped images or charts. The final scan ran after runtime verification, finishing at `2026-11-05T22:50:58.573163-05:00`. Both approval publications report verified signatures and verification status. Source snapshot digest: `sha256:b057666a987dce72264028247410ad0987d7be52b1edb1ce8a5c5350f9a39797`; final snapshot digest: `sha256:e8cb7c45ed4172110e5fec81085b65942f5ccdeb4a003b19d3046b6184f6425d`.

## Recipe and observed runtime

The opt-in [Dockerfile](../portal/tests/nginx-hardening/Dockerfile), [nginx.conf](../portal/tests/nginx-hardening/nginx.conf), and [default.conf](../portal/tests/nginx-hardening/default.conf) use the immutable package patch as their base. Their combined recipe identity is `sha256:bd286366360d5a8f59581d9d11b9a67b3f4730ab51f62d82c77b3d0830b2ab20`.

The image runs as UID/GID `101:101`, listens on **8080**, and starts `nginx -g 'daemon off;'` directly. It bypasses the inherited root-oriented `/docker-entrypoint.sh` startup scripts. PID and temporary paths are under `/tmp`; logs go to standard output/error. Existing deployments must map their service port to container port 8080 and cannot assume the bypassed startup scripts still apply environment substitutions. The inherited image's exposed-port metadata is not evidence of an active port-80 listener.

The health check fetches `http://127.0.0.1:8080/` every five seconds, with a three-second timeout, three-second start period and two retries. The derivative preserves the inherited static content, image layers and history; it neither squashes the image nor rewrites history to remove scanner findings.

The [runtime verifier](../portal/tests/nginx_hardening_qualification.py) completed on the host from `22:49:22` to `22:49:58` at UTC−05:00. Its receipt has `complete: true`, all nine required checks true, and `cleanup_complete: true`:

| Check | Observed result |
| --- | --- |
| Immutable identity | Executed inspected Docker ID `sha256:2dd3835ed3850194293bc9191b8a66504f66c069580b7c08dbe3e18200c33fa2`; final config digest `sha256:2617b62548847039f4f4bf12d515232a76bd73299e0c06dab7dd4d357aca8b25` |
| Patch ancestry | All 12 inherited layer descriptors and the complete 23-entry inherited history prefix preserved; equivalent OCI/Docker media-type names are recorded explicitly |
| Non-root and restrictions | UID 101, read-only root filesystem, all capabilities dropped, `no-new-privileges`, networking disabled, 16 MiB `/tmp` tmpfs, 128 MiB memory, 64-process limit |
| HTTP content | Served all 615 bytes of the inherited index page; SHA-256 `fb47468a2cd3953c7131431991afcc6a2703f14640520102eea0a685a7e8d6de` |
| Health behavior | Healthy initially; stopping nginx processes with `SIGSTOP` made Docker report unhealthy while the container remained running; `SIGCONT` restored healthy status |
| Cleanup | Owned runtime container removed successfully |

The initial verifier rejected equivalent OCI/Docker layer media-type names; validation was corrected to accept equivalent encoding while preserving digest, size and other descriptor checks. A subsequent nested-Docker launch failed because of the available cgroup environment. Neither attempt qualified runtime behavior. The successful attempt used `--offline-input` with exported source/final archives on the host. Raw registry manifests were hash-bound to their immutable references, configs and layer bytes were validated, and loaded filesystem identities were checked before the same runtime tests ran. All 12 source and 15 final layers in this run had `exact_published_blob: true`; the decompressed-export fallback was not needed.

These checks qualify the included static HTTP configuration under the stated restrictions. They do not establish behavior for separately mounted application configuration or TLS termination.

## Disposition of all seven configuration findings

| Scanner / finding | Source severity | Final disposition |
| --- | --- | --- |
| Dockle `CIS-DI-0001` — create a user | High | Resolved: explicit `USER 101:101`; actual process identity verified |
| Trivy `DS-0002` — root image user | High | Resolved: same recipe and runtime identity proof |
| Dockle `CIS-DI-0006` — add health check | Low | Resolved: image health check plus observed healthy → unhealthy → healthy transitions |
| Trivy `DS-0026` — missing health check | Low | Resolved: same image configuration and live outage proof |
| Dockle `CIS-DI-0010` — credential heuristic | Critical | Remains raw; the exact `KEY_SHA512` match is a public checksum, as detailed below |
| Trivy `DS-0013` — inherited `RUN cd` | Medium | Remains raw; inherited module-install history is preserved |
| Dockle `CIS-DI-0005` — Docker Content Trust | Low | Remains raw; scanner-environment assessment is distinct from this workflow's signed release verification |

The exact `KEY_SHA512` value in both actual source and final histories is:

```text
e09fa32f0a0eab2b879ccbbc4d0e4fb9751486eedda75e35fac65802cc9faa266425edf83e261137a2f4d16281ce2c1a5f4502930fe75154723da014214f0655
```

It matches the public-key checksum in the [official nginx Dockerfile at immutable commit `4b9f658`](https://github.com/nginx/docker-nginx/blob/4b9f658be76820b24e4ef4605413a5c08707a512/stable/alpine-slim/Dockerfile#L29). That instruction verifies the downloaded public signing key; this exact match supports classifying this occurrence as a credential-heuristic false positive. It does not justify ignoring other credential findings. The matched actual `CreatedBy` text has SHA-256 `7050b2bdb40162ad480c263215031635badff707d73f606ac73be75f5dab7729`. An independent download and hash of the public key was not completed because DNS resolution failed; no such independent verification is claimed.

The `RUN cd` finding comes from a separate inherited module-install instruction, not the `KEY_SHA512` instruction. Its retained evidence file has SHA-256 `7795231588d7c632639663caa355e97a6ba71950a2830741341375189dfe365a`. Removing the history entry would conceal provenance rather than change the running server, so it remains visible.

Dockle's [content-trust assessor](https://github.com/goodwithtech/dockle/blob/v0.4.15/pkg/assessor/contentTrust/contentTrust.go#L16) checks the scanner environment, and its [archive scan path](https://github.com/goodwithtech/dockle/blob/v0.4.15/pkg/scanner/scan.go#L37) still invokes assessments. Verified CATS release signatures do not satisfy or erase that separate finding. No scanner suppression or acceptance rule was added for any of the three remaining findings.

## Local replica qualification

The fresh local replica acceptance completed at `2026-11-05T22:52:22.711829-05:00`. With the publisher unavailable, its first proxy request for the final root downloaded and hash-verified one manifest and 16 blobs totaling 63,712,607 bytes. The root was exactly `sha256:2dd3835ed3850194293bc9191b8a66504f66c069580b7c08dbe3e18200c33fa2`.

The original release became superseded and was denied. Exact local override 1 changed from active to revoked; the next request was denied with `release_superseded` despite cached content. The final release remained allowed, the administrator-only override attempt was denied, and publisher statuses remained source superseded / final active. Both imported evidence archives were read-only and byte-equal to the original signed evidence. The final archive retained both scan executions and the real package-patch execution.

## Actual Harbor qualification

Harbor replication executions **16** (source) and **17** (final) each completed with status `Succeed` and two successful tasks. The fresh Harbor replica established its source baseline before the final successor was seeded and replicated. Its acceptance completed at `2026-11-05T22:56:11.125743-05:00`.

With source Harbor, the original registry and original CATS unavailable, the first request for the hardened root downloaded and hash-verified the same final graph: one manifest, 16 blobs and 63,712,607 bytes. Source-image pulls had already warmed shared base blobs. This proves the first hardened-root request, not an entirely empty blob cache.

The source release was denied as superseded, exact override 1 was created and revoked, and the immediate warm-cache request was denied with `release_superseded`. Both signed imported evidence archives matched their originals. Restart verification completed at `2026-11-05T22:56:40.034890-05:00`: reconciliation found two unchanged releases with zero failures, revoked override 1 remained ineffective, the superseded source remained denied, and the final graph still passed. Original first-pull evidence remained preserved. Post-restart probes again found all three original sources unreachable and target Harbor reachable.

## Repeatable procedure

1. Follow the [isolated nginx setup](portable-approved-releases.md#repeating-the-real-nginx-acceptance-workflow) using `nginx_acceptance_stack.py` and a new private workspace, Compose project and service key. Preserve prior workspaces. Run `nginx_workflow_integration.py` phases `setup`, `source`, then `patch` against the original immutable nginx reference. Require a real successful package-patch result.
2. Build `portal/tests/nginx-hardening` with `BASE_IMAGE` set to the exact immutable reference returned by that patch. Publish the derivative to the owned registry and resolve its final immutable reference. Retain the original patch result separately.
3. Run the runtime verifier with those exact references and a new evidence directory. Use host-side offline mode when the registry is reachable only inside the qualification network: export the raw platform manifests as `source-manifest.json` and `hardened-manifest.json`, plus matching Docker archives `source.tar` and `hardened.tar`, into the private offline-input directory. Do not reconstruct registry manifest JSON or substitute a mutable tag.

   ```text
   python portal/tests/nginx_hardening_qualification.py --source-image <immutable-package-patch> --hardened-image <immutable-final-image> --workspace <new-runtime-directory> --offline-input <private-export-directory>
   python portal/tests/nginx_workflow_integration.py patched --workspace <nginx-workspace> --hardened-receipt <new-runtime-directory>/hardening-runtime.json
   ```

4. The patched-phase preflight binds the successful runtime receipt to the actual package patch and final digest before any API action. It rejects malformed identities, failed checks and conflicting retained evidence; it saves `hardening-result.json` and a separate validation binding in workflow state. The final image receives its own fresh scan, approval and publication. The ordinary workflow without a hardening receipt remains available.
5. Copy actual signed publication receipts with `nginx_replica_acceptance.py copy`. Use `nginx_replica_workflow.py` to sync/pull the source first, then sync the final successor and verify it with the original publisher unavailable. Preserve raw findings and imported history throughout the override/revocation checks.
6. Follow the [isolated Harbor procedure](portable-approved-releases.md#repeating-the-isolated-harbor-qualification) with a fresh owned namespace and `harbor_nginx_qualification.py`. Replicate source alone and establish the baseline before publishing/replicating the final successor. Then run disconnected verification and `restart-check`. Retain failed attempts and successful evidence separately; stop only owned test services when finished.

The [sanitized evidence index](nginx-hardening-qualification-2026-11-05.json) records the qualification identities and retained evidence hashes. Private retained evidence includes source/final scans and approvals, the original patch result, workflow state, the runtime receipt and offline archive identities, local replica acceptance, Harbor replication and disconnected/restart proof. Credentials, signing private keys and raw private outputs remain outside the repository.

The focused hardening/workflow unit suite passed **121 tests in 2.41 seconds** after the final archive-descriptor validation change. The existing regression suite passed **174 tests in 7.41 seconds**; these suites overlap and their counts are not additive. The narrow routing regression also passed independently. The broader suite required rerunning unchanged outside the restricted test environment after diagnosing its socket-pair limitation.

Cleanup completed at `2026-11-06T03:58:02.7793202Z`: all three owned qualification projects reported zero running containers, with their volumes retained. Runtime containers were already removed by the successful verifier; retained workspaces, logs and prior qualification history were preserved.
