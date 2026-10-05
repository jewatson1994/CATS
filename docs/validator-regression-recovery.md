# Validator regression recovery

## Cause

The consolidated project retained the older native Ubuntu package validator implementation while the working Docker validator implementation remained in the sibling `Cyber Hygiene-validator-docker-host` directory. Earlier changes switched `build.ps1` and the release builder back to the release profile, activating the retired `prepare-managed-validator-release.py` package download pipeline. The build and validator management code consequently belonged to different implementation generations.

The Windows build shortcut was already correct: it launches `C:\Users\lil-j\Projects\Cyber Hygiene\build.ps1` with that directory as its working directory. Changing the shortcut to the sibling checkout would lose the current project's remediation changes.

## Recovery

- Restored the Docker validator release, provisioning, management, protocol, and runtime implementation in the consolidated project.
- Updated the active build chain to build the unified image and export verified Docker validator release archives.
- Removed native Ubuntu package asset requirements from the active Dockerfiles and build chain. Direct execution of the retired preparation script now fails with a migration message before downloading packages.
- Restored selection of an available healthy managed validator, including health, capacity, certificate, and self-test checks, without a local fallback.
- Preserved the current remediation implementation and checked its decision, delivery, and workflow tests.

## Verification

347 backend tests passed across the focused validator, runtime, transport security, deployment, capability, and remediation suites. Frontend type checking passed, and 35 tests passed across three relevant frontend suites. Build script parsing, compose parity, and release image verification logic were checked.

Docker is unavailable on the development host, so a complete image build and validation on the remote VM remain unverified. Run the existing build shortcut to create the corrected release, then re-provision the validator using that release and run validation again. Existing containers and previously generated release archives do not acquire these source changes automatically.
