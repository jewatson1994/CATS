# Retained live container scan evidence

These files were captured on 2026-10-20 from actual Docker images, using Syft 1.31.0 and Grype 0.98.0 from `cats:1.67`. The scanner image ID is `sha256:3108a4cc12d98dda53f59747064898fb2dafd7d6f0a7a897ed968baed3040346`. Grype used the existing database built `2026-10-03T06:31:58Z`, schema `6.1.10`. Full database origin, scanner versions, image registry digests, timestamps, raw file hashes and original commands are in `manifest.json`.

Target images were created and exported without execution. Scanning ran with network disabled; the existing Grype database volume was mounted read-only. No findings or package identities were invented. Only the capture's own temporary containers and root filesystem archives were removed.

| Capture key | Components | Nonempty, syntax-valid PURLs | Grype findings |
| --- | ---: | ---: | ---: |
| ubuntu | 101 | 101 | 71 |
| debian | 88 | 88 | 0 |
| alpine | 42 | 42 | 0 |
| redhat-ubi | 206 | 206 | 291 |
| suse | 146 | 146 | 334 |
| python | 123 | 109 | 181 |
| node | 89 | 89 | 58 |
| debian-12-9 | 88 | 88 | 79 |
| alpine-3-20-0 | 14 | 14 | 69 |
| node-image-catalogers | 293 | 293 | 93 |

The findings denominator is **Grype `--only-fixed` matches**, matching the existing scanner pipeline. These counts are not an exhaustive all-vulnerability count. The latest Debian and Alpine samples genuinely returned zero under that filter and are retained. The older images add nonempty, genuine examples for those families.

`node` records the original directory catalog defaults. `node-image-catalogers` scans the same immutable image using `--override-default-catalogers image`; it finds 204 npm packages and 35 npm vulnerability matches that the directory defaults omitted. This is a scanner integration correction, not a change to the target image. See the [official Syft cataloger documentation](https://oss.anchore.com/docs/guides/sbom/catalogers/) and [CLI reference](https://oss.anchore.com/docs/reference/syft/cli/). Other samples retain their original directory catalog results.

The Python sample includes three Python packages and ten Python findings; the SUSE sample includes two Go packages and 76 Go findings. Maven, NuGet and Cargo are not represented by live scanner findings in this sample set.

Every finding retains the scanner's original PURL, installed version, aliases, fix information and matching details. `evidence.sbom_artifact` joins only a unique Syft artifact ID with exactly matching name, version and type. The metadata retains source/binary distinctions but does not establish equivalence between them. Image labels, distribution metadata and CPEs are raw evidence; they are not promoted into publisher-scoped containing-product context.

The PURL count uses conservative syntax checks (scheme, ecosystem, package/version structure, percent escapes and nonempty unique qualifiers). It does not assert applicability or identity equivalence. Fourteen Python-image binary artifacts have no PURL.

Full Syft/Grype outputs are retained outside Git at the absolute `raw_evidence_directory` recorded in the manifest. The bounded projections in this directory retain all component identities and all findings. SHA-256 and byte counts for each raw output allow verification; the raw files are required to independently rederive the projections. All 50 per-image raw files and the recorded Trivy attempt log were verified against their hashes.

Trivy 0.69.3 was available, but its vulnerability database was absent. The actual offline attempt failed with “The first run cannot skip downloading DB.” The failure is retained in the manifest. No completed Trivy vulnerability scan is claimed; the existing production pipeline uses Trivy for misconfiguration scanning.

## Reproduction

Explicitly pull each immutable `image_digest` from the manifest into Docker, and provide the scanner image and the recorded Grype database in the target environment. To capture one image:

```sh
python scripts/capture-container-vex-scans.py \
  --output /absolute/path/to/raw-evidence \
  --summary-dir /absolute/path/to/bounded-evidence \
  --scanner-image cats:1.67 \
  --grype-db-volume cats_security_grype_db \
  --image-ref 'sample=registry/repository@sha256:actual-digest-from-manifest' \
  --image-key sample --cataloger-mode image
```

Use `--cataloger-mode default` to reproduce the original directory defaults. The script does not pull images or update intelligence. A later database produces different findings; retain database provenance with any rerun.

For coverage and performance, run `scripts/verify-container-intelligence.py` using the application's Python environment, a read-only workspace mount, and the isolated imported PostgreSQL database. The verifier requires an explicit loopback `DATABASE_URL` and enforces read-only transactions. It uses the application evaluator, advisory enrichment, KEV/EPSS overlays and coverage aggregator in batches of 250:

```sh
python scripts/verify-container-intelligence.py \
  --app-path /workspace/portal \
  --evidence /workspace/docs/evidence/container-vex-scans \
  --report /output/intelligence-final.json \
  --details /output/intelligence-final-details.json \
  --summary /output/intelligence-final-summary.json
```

Its primary seven-family service uses `ubuntu`, `debian-12-9`, `alpine-3-20-0`, `redhat-ubi`, `suse`, `python` and `node-image-catalogers`. The other three captures remain separate comparisons. The 1,000- and 10,000-observation performance workloads repeat actual captured observations and are explicitly distinguished from additional live scans. Per-image scanner counts are occurrence counts. Service coverage deduplicates the scanner CVE IDs across packages and images, matching the portal's `unique(service_id, cve)` constraint, and unions enrichment flags. Distinct package identities and scanner observation counts are also reported; they are not the coverage denominator. Image and ecosystem coverage totals overlap.

The recorded runtime image is `sha256:9b001acbe697437fd6466e2ae568f2cb1633a08ca2ed8eaeb2d53760731525a8`. The audit database container is `cats-vex-expanded-db-20261020`, whose Docker network mode is `none`. The verification client shares only that network namespace, skips normal application startup and mounts current application source read-only. For example, after supplying a file containing the audit database's loopback `DATABASE_URL`:

```sh
docker run --rm \
  --network container:cats-vex-expanded-db-20261020 \
  --entrypoint python \
  --mount type=bind,src=/absolute/path/to/worktree,dst=/workspace,readonly \
  --mount type=bind,src=/absolute/path/to/output,dst=/evidence \
  --env-file /absolute/path/to/audit-database.env \
  --env PYTHONDONTWRITEBYTECODE=1 \
  sha256:9b001acbe697437fd6466e2ae568f2cb1633a08ca2ed8eaeb2d53760731525a8 \
  -B /workspace/scripts/verify-container-intelligence.py \
  --evidence /workspace/docs/evidence/container-vex-scans \
  --report /evidence/intelligence-final.json \
  --details /evidence/intelligence-final-details.json \
  --summary /evidence/intelligence-final-summary.json
```

## Measured coverage

`coverage-and-benchmark.json` is the bounded final report. It retains measured timings, query counts, process-memory counters, compact PostgreSQL query plans, code/input hashes, per-image and per-ecosystem coverage, and selected actual rejected identities. Full per-observation results and query plans are retained beside the original scans outside Git; the summary records their SHA-256 values and byte counts. `coverage-runtime.json` records the isolated runtime and database image IDs. The existing signed package contains 29,212,947 VEX statements and 2,245,117 products. The additive advisory membership backfill completed before this measurement.

| Primary image | Components | Valid PURLs | Scanner observations | Unique findings in image | Current advisory findings | EPSS findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `ubuntu:jammy-20260731.1` | 101 | 101 | 71 | 36 | 0 | 36 |
| `debian:12.9-slim` | 88 | 88 | 79 | 55 | 0 | 55 |
| `alpine:3.20.0` | 14 | 14 | 69 | 33 | 0 | 33 |
| `registry.access.redhat.com/ubi9/ubi:9.6` | 206 | 206 | 291 | 191 | 0 | 191 |
| `registry.suse.com/bci/bci-base:15.6` | 146 | 146 | 334 | 208 | 66 | 208 |
| `python:3.11.13-slim-bookworm` | 123 | 109 | 181 | 128 | 10 | 128 |
| `node:20-bookworm-slim`, image catalogers | 293 | 293 | 93 | 83 | 35 | 83 |

The seven images contain 971 component occurrences, 957 valid nonempty PURLs, 1,118 scanner observations and 1,069 distinct CVE/package/version/PURL tuples. Coverage uses **483 unique service findings**, with these measured results:

- Exact VEX candidates: 0; applicable VEX: 0 (0%). This sample does not establish positive real-image VEX applicability.
- CVE or alias present under a different product identity: 482 (99.793%); absent from VEX: 1 (0.207%). The absence is the scanner ID `GHSA-3xgq-45jj-v275`, alias `CVE-2024-21538`, for `cross-spawn@7.0.3`; it still has a current GitHub advisory and EPSS.
- Current advisory references: 111 (22.981%): 66 Go, 10 PyPI and 35 npm findings. These are package references; retained version ranges are not re-evaluated as a second scanner and cannot establish Not Affected.
- EPSS: 483 (100%); affirmative KEV: 0. No current intelligence: 0 because every finding has EPSS. These enrichment rates do not imply VEX coverage.
- Unresolved scanner identity: 0 after preserving and reconciling 109 explicit RPM epoch representations and 76 exact Go standard-library artifact versions. This does not establish enterprise product context.

The authenticated advisory catalogs contain Alpine SecDB 10,094 records, GitHub Reviewed 32,256, Go 4,428, PyPA 7,667, RustSec 607 and SUSE CVRF 1,576. Current KEV contains 1,748 and EPSS 391,411 members. Actual references in this sample come from Go/PyPA/GitHub package records. Alpine SecDB's strict package/release comparison produced zero references for the captured Alpine findings; SUSE CVRF did not create an RPM advisory match. Maven, NuGet and Cargo have implementation/test coverage but no live scanner observations in this sample.

| Workload | Observations | Unique service findings | SQL statements | Wall time |
| --- | ---: | ---: | ---: | ---: |
| One finding | 1 | 1 | 7 | 0.009386 s |
| One batch | 250 | 144 | 7 | 0.061261 s |
| 1,000 observations | 1,000 | 427 | 28 | 0.385803 s |
| 10,000 observations | 10,000 | 483 | 280 | 4.348488 s |
| Seven images, one service | 1,118 | 483 | 35 | 0.499515 s |
| Four concurrent jobs | 1,000 per job | 427 per job | 112 total | 1.877344 s |

The process reached 107.65 MiB in sampled resident memory and 107.22 MiB in the independently reported lifetime peak. The large VEX, intelligence-record and package-membership lookups used indexes. The only sequential scan in the captured plans was the eight-row catalog table. Separate KEV and EPSS plans are retained; the EPSS plan used `ix_intelligence_records_cve` and `intelligence_package_members_pkey` and executed in 0.585 ms. The exact VEX-pair plan executed in 3.764 ms, with 11.684 ms planning time and no returned candidates.

The measurements include actual VEX diagnostics, advisory references and KEV/EPSS overlays in batches of 250. Because no exact VEX candidate matched these real images, these timings measure the unmatched-identity path; high-fanout positive VEX applicability is not benchmarked. PostgreSQL and OS caches are warm, and the host was not reserved exclusively for the audit. Memory covers the Python verification process, not the PostgreSQL server. The report retains separate `/proc` samples and `getrusage` lifetime peaks; concurrent job memory and process CPU counters overlap and must not be added.

## Real worker verification

The real worker was measured separately against the same populated corpus. Retained scanner observations were staged through the model, followed by real classification and `refresh_assessment`. Each service had one owning group and produced 483 findings from 1,118 observations, with 111 findings having current advisory references and no applicable VEX. No fixture VEX was injected. Classification and original scan rows remained unchanged during assessment, and all staged rows were rolled back; PostgreSQL sequences may advance.

| Full assessment materialization | Worker SQL statements | Worker call time | Total including staging/classification/verification | Process peak RSS |
| --- | ---: | ---: | ---: | ---: |
| One service | 77 | 1.767262 s | 4.235054 s | 270.512 MiB |
| Four concurrent services | 308 total | 14.647940-15.944247 s per call | 33.127568 s | 430.914 MiB shared process |

The single-service classification took 0.784752 s before the measured worker call. Concurrent calls synchronize after evidence staging and classification. Their elapsed times include contention on this shared host and are not additive. This check exercises full materialization but does not submit HTTP ingestion requests or run durable queue lease/retry scheduling. Reports: [single worker](worker-final.json), [concurrent workers](worker-concurrent.json).

To reproduce the worker measurement in the same isolated database/runtime described above, substitute this command for the evaluator command. The workspace remains read-only; the database user must allow temporary audit rows and DDL within rollback-only transactions. Use a disposable audit database, not a production database.

```sh
python -B /workspace/scripts/verify-container-risk-worker.py \
  --evidence /workspace/docs/evidence/container-vex-scans \
  --report /evidence/worker-final.json \
  --details /evidence/worker-final-details.json --jobs 1
```

Use `--jobs 4` with separate report/detail filenames for the concurrent check. `worker-final-runtime.json` and `worker-concurrent-runtime.json` retain the isolated runtime details. Full per-observation worker reports remain beside the raw scans outside Git, with hashes in the bounded reports.

## Final regression checks

The complete backend command and source hashes are retained in `backend-final.json`. From the feature worktree, using the same Python environment and dependencies:

```powershell
$env:PYTHONPATH = 'portal'
$suites = @(
  'test_container_intelligence.py', 'test_container_intelligence_identity.py',
  'test_sbom_identity_ingest.py', 'test_risk_profiles.py', 'test_risk_routes.py',
  'test_vex_repository.py', 'test_scan_intelligence.py', 'test_risk_worker_vex_identity.py',
  'test_risk_sql.py', 'test_risk_sources_api.py', 'test_risk_records_api.py',
  'test_embedded_intelligence.py', 'test_embedded_intelligence_build.py',
  'test_intelligence_membership.py', 'test_intelligence_projections.py',
  'test_intelligence_catalogs.py', 'test_packaged_risk_intelligence.py',
  'test_verify_embedded_intelligence.py', 'test_risk_worker_retained_scans.py'
) | ForEach-Object { "portal/tests/$_" }
$auditTestTemp = Join-Path $env:TEMP ('cats-container-' + [guid]::NewGuid().ToString('N'))
python -m pytest -q @suites --basetemp $auditTestTemp --junitxml backend-final.xml
```

This run uses SQLite and no `CATS_TEST_POSTGRES_URL` or `CATS_TEST_DATABASE_URL`; it reports 463 passed and 10 opt-in PostgreSQL skips. Separate PostgreSQL runs passed all opt-in cases. Their exact commands, isolated schema settings and dialect counts are recorded in `postgres-*-final.json` and summarized by `postgres-final-summary.json` (80 passed, including seven SQLite projection variants). The expiry-specific recheck is not counted twice. `frontend-final.json` contains the exact 22-test, typecheck and lint commands. `scanner-final.xml` and `classification-final.xml` record 15 and 21 passing tests respectively. The final audit document records build/offline limits and remaining live-sample gaps.

The final staged whitespace check removed extra trailing blank lines from three files after verification. [Formatting provenance](final-formatting.json) records before/after hashes; all preceding bytes and both Python syntax trees are identical. The test and build records retain their original hashes.
