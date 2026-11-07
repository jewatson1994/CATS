# OCI replica attestation and signing-key continuity completion

**R13 integrated attestation routing and R16 authenticated signing-key continuity are complete for the supported CATS release format.** This report supersedes those two Partial implementation findings in the [November 6 qualification](oci-replica-final-qualification-2026-11-06.md). That historical report remains unchanged.

The changes were qualified on branch `codex/oci-approved-release-replicas`, starting at `c2f80eb48ad60bcf04cadafcf817c7f50688ca62`. The [machine-readable report](oci-replica-feature-completion-2026-11-07.json) records the actual image ID, releases, audit evidence, test counts and SHA-256 hashes for 58 retained evidence files.

## Completed behavior

| Requirement | Implementation and evidence |
| --- | --- |
| R13: integrated attestations | Publication creates native Cosign approval attestations for images and charts, binding the artifact, approval snapshot and evidence archive. Signed inventories pin exact manifests and DSSE envelopes. Import verifies their complete graphs and signatures. Proxy tags, cold digest requests, blobs and referrers use the granting release's inventory and live authorization, including Local Cyber overrides and revocation. Relocation preserves the original signed subject. |
| Repeated artifact approvals | Digest-derived immutable retention tags preserve both signature and attestation graphs when native tags move. Two approvals of the same image were published before their first Harbor replication. Both releases then imported successfully with the source stopped. The proxy exposed only the active approval's attestation and excluded the superseded one from referrers. |
| R16: signing-key continuity | Normal administrator key replacement creates a bounded transition signed by both keys. Releases carry the complete authenticated chain, per-service cutovers and original publisher root. Replicas retain sealed trust, stable service identity and actual signer metadata. Two successive rotations succeeded using only the unchanged original pin. |
| Rotation enforcement | Conflicting chains, invalid signatures, old-key events outside cutovers, lost/tampered trust state and stale concurrent configuration changes fail closed. Reserved publications block premature replacement. PostgreSQL and SQLite serialization prevent trust or active-release regression. Historical releases within authenticated intervals and legacy upgrades remain supported. |
| Disconnected recovery | A fresh isolated importer authenticated the second successor from the original pin alone. The delivered standalone verifier accepted the same original pin. The current successor signed a revocation of an original-key release without using the old key for that operation. |

## Real Harbor qualification

The opt-in [qualification driver](../portal/tests/harbor_continuity_qualification.py) uses explicitly **synthetic** multi-platform image, Helm chart and approval evidence fixtures. Cosign 2.6.1, Harbor `v2.15.4-d8841742`, registry replication, the deployed replica HTTP APIs, PostgreSQL and TLS are real. Source-to-target transfers are exclusively Harbor replication jobs; the driver does not copy into the target registry or write the deployed replica database.

| Harbor execution | Scenario | Result |
| --- | --- | --- |
| 22 | Original signing key | 4/4 tasks succeeded |
| 23 | First authenticated replacement | 4/4 tasks succeeded |
| 24 | Second authenticated replacement | 4/4 tasks succeeded |
| 25 | Delayed replication after two same-image approvals | 4/4 tasks succeeded |
| 26 | Successor-signed original-release revocation | 4/4 tasks succeeded |

Five releases retained one local service identity and the original publisher pin. All nine source-Harbor services were stopped before disconnected import and pull checks. Complete image/index, chart and attestation graphs passed target-only verification, including digest-first attestation access, original subject/signature verification and referrers.

Two exact-root, indefinite Local Cyber overrides allowed superseded original-key attestations; administrator-only creation was denied. Uses were audited, and revocation immediately denied tags, manifests, unique envelope blobs and referrers even after caching. A later signed publisher revocation changed only the intended original release. Restarting the complete replica stack preserved release IDs/history, original trust, revoked overrides and their audit. Disconnected pulls and revocation denial passed again after restart.

The final portal and proxy used the same verified `cats-replica:continuity-completion` image. All 22 qualification containers were stopped after verification; database, evidence, cache and registry volumes were preserved.

## Regression results

Counts below describe separate runs and overlap; they must not be added as unique coverage.

| Run | Result |
| --- | --- |
| Broad backend regression | 1,283 passed, 4 skipped |
| Final affected-feature regression after the last fixes | 347 passed, 1 skipped |
| Real PostgreSQL upgrade/import/concurrency checks | 17 passed |
| Native Cosign encrypted key roundtrip and upload/password validation | 2 passed |
| Frontend | 496 passed across 66 files; TypeScript/Vite build passed |

The broad skips were two unrelated PostgreSQL cybersecurity evidence cases and two Windows-host native-Cosign cases. Both native-Cosign cases subsequently passed in Linux; this also covers the final focused run's single skip. The two unrelated PostgreSQL cases were not rerun. Final runs have zero failures or errors. Native test-container dependency gaps were resolved before its successful run.

Evidence is retained outside Git at `C:\Users\lil-j\.codex\visualizations\2026\11\05\01a1ada8-46fc-7ae1-895c-a315b48a238b\completion-20261107`. Private signing material, registry credentials and test account secrets are excluded from this report and the commit.

## Operational scope

Use the updated [deployment runbook](oci-replica-deployment-runbook.md), [portable release guide](portable-approved-releases.md) and [proxy guide](oci-proxy.md). Preserve the original pin through authenticated rotation. Replicate and retain both native attachment tags and the immutable `cats-signature-*` / `cats-attestation-*` tags. Older publication graphs and embedded import scripts require explicit backfill or the current importer; they are not rewritten automatically.

Rotation requires the current private key and supports at most 32 transitions with 10,000 service cutovers per certificate. Lost-key recovery requires an authorized backup or separately planned trust migration. Other registry versions, arbitrary third-party attestation formats and production infrastructure still require deployment-specific qualification.

This completion run does not repeat the earlier real nginx scan-and-patch workflow or 100-image/23-replacement test. Its synthetic content is not evidence of a new nginx scan, production readiness or broader registry compatibility.
