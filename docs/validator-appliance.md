# Validator appliance

Run this appliance on a dedicated, disposable Linux amd64 VM with Docker Engine and Docker Compose. It combines the mTLS validation API on 8443 and the HTTPS local administrator service on 8444. If either listener exits, the supervisor stops the other and exits unsuccessfully; Compose restarts the appliance. State and administrator records persist in the `validator-state` volume at `/var/lib/cats-validator`.

The Docker socket grants root authority over this VM. Host networking is required so the worker can reach Kind's localhost Kubernetes API. Do not install this appliance on the production host or place production credentials, managed identities, cloud credentials, or sensitive workloads on the VM. Do not mount production kubeconfig files. Delete the disposable VM when its purpose is complete.

## Prepare and launch

Use a host directory containing `server.crt`, `server.key`, and `client-ca.crt`. The server certificate must cover the hostname used by both clients. Set the private key's mode to `0600`. The directory is mounted read-only. Provide a separate PEM CA bundle containing the roots needed for outbound HTTPS; this also supports private enterprise roots through `SSL_CERT_FILE`.

Supply these environment variables through your deployment secret mechanism or a protected, untracked environment file:

- `CATS_VALIDATOR_TLS_DIR`: absolute host TLS directory.
- `CATS_VALIDATOR_CA_BUNDLE`: absolute host CA bundle file.
- `CATS_DEPLOYMENT_KIND_NODE_IMAGE`: an approved Kind-compatible image with an actual verified `@sha256:` digest. Match its Kubernetes version to the bundled kubectl; do not use the engine's placeholder default. Preload it on the VM for strict/offline operation.
- `CATS_VALIDATOR_CLIENT_FINGERPRINTS`: comma-separated SHA256 fingerprints of explicitly trusted production client certificates, each 64 hexadecimal characters.
- `CATS_VALIDATOR_ADMIN_USERNAME` and `CATS_VALIDATOR_ADMIN_PASSWORD`: local bootstrap credentials required on first startup; use a unique password of at least 14 characters. The administrator listener uses HTTPS and local password authentication, without requiring a client certificate. Credentials are passed through the environment, never command arguments. Docker administrators can inspect container environments. Account password hashes persist in the state volume; this Compose file requires the bootstrap values to remain supplied on subsequent launches.
- `CATS_VALIDATOR_DOCKER_SHA256`: independently verified SHA256 of the Docker 27.5.1 amd64 static archive from `https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz`. The build fails if it is missing or mismatched. Verify this artifact against your approved supply-chain source before deployment.

Build and launch from the repository root:

```sh
docker compose --env-file /secure/validator.env -f compose.validator.yml up -d --build
```

The image pins Docker CLI 27.5.1, Kind 0.27.0, kubectl 1.32.2, and Helm 3.17.1. All downloads undergo SHA256 verification; Kind, Kubernetes, and Helm checksums come from their official release endpoints. Build-time internet access is needed for these tools, OS packages, and Python dependencies. Review and update version pins as part of appliance maintenance.

## Network boundaries

Configure the VM's NSG/firewall explicitly: permit production-initiated TCP 8443 only from the production worker's private source addresses, and administrator-initiated TCP 8444 only from the administrative VPN or bastion. Keep both listeners off the public internet. Host networking means Compose port mappings provide no filtering. Deny validator-initiated traffic to production; the production worker submits jobs and polls results. Permit DNS and outbound artifact/image downloads only to deliberately approved destinations. Restrict SSH to the management path if it is needed. No production credential is required on this appliance.

Default execution is strict. `CATS_VALIDATOR_EXECUTION_MODE=permissive` is an optional explicit choice for this disposable VM: it bypasses workload security preflight while retaining bounded input and cleanup. VM integrity and trustworthy results are not guaranteed in permissive mode. The administrator interface can persist fingerprint allowlists, execution mode, network egress, local-image requirements, and the Kind node image; saved settings supersede bootstrap environment defaults. Enable network access consciously. For offline operation, pre-stage approved images and artifacts, require local images, and deny outbound traffic at the VM firewall.

An uploaded administrator CA bundle persists as `ca-bundle.pem` in the state volume and is used for worker subprocess HTTPS trust. Neither this bundle nor `SSL_CERT_FILE` installs trust into the host Docker daemon or workload images; configure those trust stores separately when required.

## Connect and operate

1. Open `https://<validator-hostname>:8444` through your management network and sign in using the bootstrap local account. Change its password in **Local credentials**.
2. Upload the same shared CA bundle used in CATS if it differs from the mounted bundle. Set your approved digest-pinned Kind image. Select **Permissive** only on the disposable project VM; allow project egress and disable the preloaded-image requirement if you intend to download images. These changes affect subsequent jobs.
3. In main CATS, open Administration settings and **Deployment Validation Sandbox**. Set the endpoint to `https://<validator-hostname>:8443`, supply the production client certificate and private key, and supply the CA that validates the appliance server certificate. Save, then select **Test Connection**. The client certificate fingerprint must match the appliance allowlist.
4. On the appliance page, select **Test appliance readiness** to check local tooling, Docker and disk capacity. Main CATS tests the connection in the production-to-project direction; no reverse production connection is attempted.
5. Submit a small deployment validation from a service in CATS. Confirm the job appears under **Recent jobs**, completes, and reports successful cleanup. Validate your NSG rules independently; a readiness test does not prove network isolation.

Check both HTTPS services after startup using the provisioned trust roots; validation API requests must include an allowlisted client certificate. Confirm the administrator bootstrap and persisted account work, then submit a small test job from production and verify its result. `docker compose -f compose.validator.yml logs` reports startup failures. Removing the named state volume deletes job and administrator state; preserve it when updating the image.
