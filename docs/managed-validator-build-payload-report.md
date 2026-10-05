# Build Payload completion report

2026-10-04 · Cyber Hygiene · `feature/hq-managed-validator-provisioning`.

The local build workflow is implemented. No real release payload was materialized:
the required qualified vendor package, wheel and image inputs are unavailable in
this development environment. No downloads, image builds, VM provisioning,
commits or pushes were performed. Synthetic test assets are confined to temporary
test fixtures and must never be deployed. The previous first-payload inspection
report describes the pre-change inventory; this report supersedes its manual
runtime assembly instructions.

1. **Why the button was absent:** the implementation accepted externally staged
   payloads with deployment-pinned digests. It had a CLI assembler and verifier,
   but no release asset contract, runtime assembly service or persistent local
   trust record.
2. **Previously present:** current validator application and launcher, pinned
   portal requirements, existing payload builder/verifier/installer, scanner tool
   acquisition and archive build logic. The scanner caches and legacy standalone
   validator appliance do not establish qualified managed host assets.
3. **Image additions:** current launcher, existing assembler, new release seal
   script and a mandatory named build context containing qualified managed assets.
   This wires assets into future images; it does not fabricate missing binaries.
4. **Layout:** `/opt/cats/validator-assets/release.json`, platform directories
   `ubuntu-22.04-amd64` and `ubuntu-24.04-amd64`, their `validator-assets.json`,
   binaries, offline packages, wheels, image archives and self-test chart. The
   separate image seal is `/opt/cats/validator-assets.sha256`.
5. **Release manifest:** format 1 catalog with exact CATS identity and platform
   manifest digests. Each platform declares exact asset paths, packages, wheels,
   versions, native Python version, pinned image references, size/SHA256/provenance
   for every file, Docker runtime version and completed qualification flags.
   See `managed-validator-release-inputs.md` for the full contract.
6. **Pins:** no new production versions or hashes were invented. Actual approved
   pins must be supplied in qualified release manifests. Validation enforces
   Docker Engine 28+, Python 3.10 on Ubuntu 22.04 and 3.12 on Ubuntu 24.04,
   digest-pinned images and explicit component versions. The legacy appliance's
   Docker CLI 27.5.1, Kind 0.27.0, kubectl 1.32.2 and Helm 3.17.1 were not reused.
7. **Integrity:** reviewed acquisition provenance and offline qualification are
   release inputs. Image construction verifies every declared size/hash and seals
   the catalog; trust in that seal comes from the trusted HQ image. Runtime checks
   the seal, platform manifest, every asset and the final format 1 output.
8. **Docker closure:** platform-specific qualified `.deb` inventory is copied
   from the image to staging and final payload; installer retains `--no-download`.
   Release qualification must prove a clean native host installs the entire closure.
9. **Wheels:** separately qualified native Python wheel closures are included in
   the generated application tar; the installer retains `--no-index`. Runtime
   performs no dependency resolution or acquisition.
10. **Kind:** qualified versioned local binary, copied and hashed.
11. **kubectl:** qualified versioned local binary, copied and hashed.
12. **Helm:** qualified versioned local binary, copied and hashed.
13. **Node image:** qualified local archive with digest-pinned reference; release
    qualification must demonstrate compatibility and loaded digest retention.
14. **Self-test:** local digest-pinned image archive and dependency-free chart tar
    with root `Chart.yaml`; release qualification must prove the disconnected test.
15. **Application tar:** generated from this running HQ release's launcher,
    requirements and Python application modules, plus the native wheel closure.
    It excludes mutable data, environment files and key files. Identity combines
    CATS release identity with the actual source content hash, including dirty
    source content; no Git command, public fetch or application image is used.
16. **Backend:** provision permission + CSRF → database-exclusive queued job →
    background claim → verify sealed platform assets → package current source →
    stage local assets → invoke unchanged assembler → invoke unchanged verifier →
    recheck source assets → make output read-only → persist verified digest and
    metadata → atomically activate. Failures retain the previous active payload.
17. **UI:** existing Installation payload card has Build/Rebuild Payload, a
    platform selector when appropriate, asynchronous stage polling, exact safe
    failure details, build metadata, previous builds, Verify and Activate controls.
    Completion refreshes validator inventory/readiness. Permissions govern controls.
18. **Storage:** immutable unique build directories under
    `/app/data/validator-payloads`, backed by the new named `validator_payloads`
    compose volume. Database stores metadata and digests, never payload bytes.
19. **Local trust:** successful assembly originates only from image-sealed assets
    and current application source; its verified manifest digest is persisted in HQ.
    Imported/external payloads still require their independent environment pin.
20. **Manifest digest:** computed by the existing assembler, reverified before
    persisting, displayed in UI and checked again on activation/provisioning.
21. **Activation:** one active verified build per exact OS/version/architecture,
    enforced with a database unique index. Successful builds autoactivate visibly;
    older verified builds remain available for explicit activation.
22. **Discovery:** live persisted records are checked without restart or env edits.
    An already authorized installation resolves its retained original digest even
    after another build is activated. Existing externally pinned payloads remain
    usable when no matching local active build exists.
23. **Build network:** assembly code has no network acquisition, subprocess
    downloads, pip install, package resolver or vendor executable invocation.
    Tests exercise the assembler while network connection attempts are prohibited.
24. **Target acquisition:** existing bootstrap installer uses offline apt and pip
    flags and local Docker loads. No changes introduce public acquisition.
    Real disconnected target acceptance has not been run here.
25. **Frontend:** `portal/frontend/src/features/validators.tsx`, `validators.css`
    and `validators.test.tsx`.
26. **Backend:** new `portal/app/validator_payload_builds.py`; integrations in
    `validator_management.py`, `models.py`, `main.py`.
27. **Release:** `cats-image/Dockerfile.all-in-one`, `portal/Dockerfile`, new
    `scripts/seal-managed-validator-release.py`, both compose volume definitions,
    and `docs/managed-validator-release-inputs.md`. Existing assembler unchanged.
28. **Tests:** payload assembly/selection/activation/history/retained trust,
    missing components, integrity and qualification failures, source exclusions,
    runtime connection guard, unsafe paths, database concurrency, interruption,
    API permissions/CSRF/input boundary; release sealing and frontend build flow.
29. **Backend results:** 98 passed across payload builds, release seal, managed
    management, provisioning readiness, bootstrap and operations. Existing
    FastAPI lifespan deprecation warnings remain.
30. **Frontend results:** 18 validator tests passed; TypeScript check and Vite
    production build passed. Build warns about an existing large output chunk and
    runtime-resolved `/static/app.css`. No Docker image build or browser screenshot
    acceptance was performed.
31. **Schema:** new metadata-only `validator_payload_builds` table and partial
    unique indexes. Existing startup `Base.metadata.create_all` creates them on
    upgrade; no alterations to existing tables or standalone migration required.
    SQLite and PostgreSQL partial-index definitions are provided; PostgreSQL was
    not exercised here.
32. **Unavailable inputs:** qualified Docker 28+ package closures for both native
    Ubuntu releases; Python wheel closures for current requirements; approved
    Kind/kubectl/Helm binaries; compatible node image; deterministic self-test
    image/chart; independently reviewed provenance, actual pins and qualification
    evidence. Neither a real usable manifest digest nor VERIFIED production
    artifact exists yet. The normal image build fails without these inputs.
33. **Operator steps:** release preparation must first produce and qualify the
    inputs described in `managed-validator-release-inputs.md`, then build/redeploy
    the sealed HQ image with its persistent volume. As an operator, open Settings
    → Validation → Validators; select Ubuntu 22.04 amd64; click Build Payload;
    wait for VERIFIED and Active. Manage CATSchrodinger-Dev-01, confirm the SSH
    fingerprint, enter temporary SSH/sudo credentials, Test Connection if needed,
    acknowledge warnings, re-enter cleared credentials and click Provision
    Validator. Do not provision until the actual release assets are qualified.

## Handoff

Objective: one-click offline payload assembly from a self-contained HQ release.
Repository/branch: Cyber Hygiene / feature/hq-managed-validator-provisioning.
Completed: runtime jobs, local trust/activation, UI, image input/seal contract,
persistence and focused verification. Remaining release acceptance: acquire and
qualify real inputs, build the HQ image, then explicitly provision the Ubuntu
22.04 target and prove the disconnected self-test. No real VM was modified.
