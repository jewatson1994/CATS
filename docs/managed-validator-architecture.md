# Managed validator architecture

The existing validator is a standalone FastAPI worker launched by `portal/validator_server.py`. Its TLS transport requires client certificates and explicitly pins authorized HQ client leaf fingerprints. `validator_client.py` supplies encrypted client keys, checks HTTPS, blocks redirects, streams v2 artifacts, and polls existing persisted validation jobs. The Kind and SchrÃƒÆ’Ã‚Â¶dinger engines implement Helm, OCI, standard bundle, and isolated offline bundle validation; their evidence and cleanup semantics remain authoritative.

HQ currently stores one manually configured endpoint in the global `validator_configuration` PortalSetting. Managed identities extend that same configuration shape (`endpoint`, `ca_certificate`, `client_certificate`, encrypted `client_key`). The manual endpoint remains supported. Managed records provide identity, lifecycle, certificates and provisioning history that the single setting cannot represent. Additive tables use the repository's existing serialized `Base.metadata.create_all` migration mechanism; existing tables and evidence are retained.

Existing reuse: `AuthContext` global permissions, `AuditEvent`, Fernet secrets with `CATS_CONFIG_ENCRYPTION_KEY`, SQLAlchemy persistence/session factory, React page envelopes/CSRF, bounded worker executors, and the existing operational mTLS transport. Bootstrap credentials never enter page DTOs or audit metadata. Provisioning uses a pinned SSH bootstrap plane; subsequent health, self-test, rotation and validation use mTLS.

The managed payload is an explicit versioned, hash-verified directory owned by HQ. It must contain the actual architecture-specific binaries, offline package closure, validator application and Python environment, local node/test images, and self-test chart. Missing assets block provisioning. Installer assets never fetch public packages or images. Build-time acquisition is separate from VM provisioning.

READY requires authorized CSR enrollment, verified validator identity/protocol, runtime checks, complete Kind/Helm self-test, verified cleanup, and bootstrap credential retirement. Service startup is insufficient. Interrupted attempts require explicit retry with fresh credentials; completed/failing attempts retain only safe stage history.

## Review handoff

Objective: HQ-managed Ubuntu Server 22.04/24.04 validator provisioning and operational lifecycle in Cyber Hygiene, branch `feature/hq-managed-validator-provisioning`. Implementation and automated verification are complete: backend 1183 passed/1 skipped, frontend 123 passed; compilation, type checking, lint and production build passed. Existing dirty work is preserved; no commit, push or deployment was performed.

Next step: prepare and qualify the offline payload, rebuild/redeploy HQ, and perform the first clean Ubuntu Server 22.04 LTS VM acceptance and disconnected test. Real Linux/systemd/Docker/Kind behavior remains unverified. See the [68-topic completion report](managed-validator-completion-report.md) for test evidence, prerequisites, exact acceptance steps and limitations.

Offline releases are selected by exact detected Ubuntu version and architecture through an externally pinned catalog (or a matching single-release manifest). Packages and wheels are acquired separately for each platform. Both HQ and the remote installer reject mismatches before installation.
