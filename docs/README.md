# CATS documentation

Start with the [project README](../README.md) for an overview. The guides below are the main entry points; dated reports and files under `evidence/` preserve verification of specific revisions and environments rather than a blanket qualification of the current release.

## Install and operate

- [Guided main and replica setup](guided-setup.md): small installer bundles, local images, TLS, registry setup, and offline ingress.
- [Deployment templates](../templates/README.md): HTTPS main/replica, local development, external-ingress replica, and validator configuration.
- [Nginx ingress](nginx-ingress.md): hostnames, certificates, and migration.
- [Database backups](database-backups.md): scheduled backup configuration and restore procedures.
- [Durable workers](durable-workers.md), [scan worker](dedicated-scan-worker.md), and [worker isolation](../deploy/worker-isolation.md): service responsibilities, upgrades, and host acceptance.
- [OIDC integration](KEYCLOAK-INTEGRATION.md) and [trusted CAs](trusted-ca-and-repository-policies.md): identity-provider and repository trust configuration.
- [Validator appliance](validator-appliance.md): dedicated runtime-validation hosts.

## Use CATS

- [Role training](training/README.md): administrator, assessor, service-manager, and cybersecurity walkthroughs.
- [Discovery workflow](discovery-workflow.md) and [universal deployment discovery](universal-deployment-discovery.md): approved GitLab sources, deployment archives, review, and offline inputs.
- [Docker Compose ingestion](compose-ingestion.md): ordered inputs, profiles, previews, and image associations.
- [Remediation](remediation.md) and [remediation wizard](remediation-wizard.md): planning, patching, review, validation, and delivery.
- [Cyber approvals and approved releases](cyber-approved-releases.md): review authority, publication, expiry, offline import, and revocation.
- [Unified artifact lifecycle](unified-artifact-lifecycle.md): artifact catalogs, proposed adoption, campaigns, and governed revisions.
- [Deployment validation](../portal/docs/deployment-validation.md) and [architecture layout](../portal/docs/architecture-layout.md): runtime evidence and service topology.
- [Standalone scanner](../cats-image/STANDALONE-SCAN.md): scanner usage outside the portal.

## Distribute and verify releases

- [OCI proxy operations](oci-proxy.md): access policy, verified caches, and registry behavior.
- [Replica deployment runbook](oci-replica-deployment-runbook.md): separate replica setup, evidence synchronization, and release graphs.
- [Signed release documentation](signed-release-documentation.md) and [signing](../portal/SIGNING.md): immutable attachments, verification, and recovery.
- [Portable approved releases](portable-approved-releases.md): signed bundles and disconnected use.
- [Schrödinger deliveries](schrodinger-deliveries.md): runtime validation and disconnected-delivery limits.

## Risk and security intelligence

- [Cybersecurity and validation](cybersecurity-and-validation.md) and [risk model](risk-model.md): assessment meaning and evidence boundaries.
- [Risk Policy and VEX training](training/risk-policy-and-vex.md): scoped profiles, effective disposition, and operational review.
- [Embedded intelligence](embedded-intelligence.md) and [source inventory](security-data-sources.md): signed packages, readiness, provenance, licenses, and recorded coverage.
- [Native VEX disposition](native-vex-disposition.md): lifecycle, exclusions, configuration, and evidence limits.
- [Authoritative package identity](authoritative-package-identity-resolution.md) and [SBOM-backed correlation](sbom-backed-vex-correlation.md): package matching and applicability safeguards.
- [Service ownership and signing policy](service-ownership-and-signing-policy.md): ownership and trust boundaries.

## Develop and investigate

- [Contributing](../CONTRIBUTING.md): repository layout, environment setup, tests, and review practices.
- [React frontend](react-frontend.md): page architecture, local assets, and acceptance checks.
- [Scanner/CLI](../scanning-main/README.md), [scanner image](../cats-scanner/README.md), and [unified image](../cats-image/README.md): tool and image responsibilities.
- [Lifecycle integration fixture](../tests/lifecycle/README.md): isolated signing, registry, and authorization checks.
- [Historical implementation records](archive/README.md): preserved workbook, portability, service-definition, and Helm-transfer handoffs.

Keep current operating instructions in the relevant guide. Label reports with the tested revision, date, environment, and unresolved limitations; preserve reproducible evidence without confusing it with current deployment instructions.
