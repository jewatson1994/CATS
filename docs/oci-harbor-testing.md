# Local Harbor interoperability and offline fixture

This development fixture runs real Harbor v2.15.4 in its own `cats-harbor-test` Compose project. It exposes only `https://localhost:18443`, uses a generated TLS certificate and random administrator/database passwords, and stores all generated configuration, secrets, data and image archives in ignored `.test-temp/harbor-local/`. It does not mount the Docker socket or change existing CATS services. It is a local testing installation, not a production Harbor deployment.

Use Docker Desktop with Linux containers, Compose v2, and Python with the repository dependencies (`requests`, `PyYAML`, `cryptography`). Allow several GB for downloaded images, the offline archive and registry data. Harbor's [official prerequisites](https://goharbor.io/docs/edge/install-config/installation-prereqs/) specify at least 2 CPUs, 4 GB RAM and 40 GB disk. This fixture pins the [v2.15.4 release](https://github.com/goharbor/harbor/releases/tag/v2.15.4), verifies its online installer SHA-256, and runs the official prepare image by digest. `tests/harbor/images.lock.json` pins all service image digests (Linux amd64); offline startup uses their verified image IDs. Configuration follows [Harbor's configuration documentation](https://goharbor.io/docs/edge/install-config/configure-yml-file/).

Run from the repository root using its Python environment:

```powershell
python tests/harbor/prepare_harbor.py
docker compose -f .test-temp/harbor-local/compose.harbor.yml up -d
python tests/harbor/smoke_harbor.py
```

Initial database initialization can briefly restart jobservice. The smoke script waits for Harbor health before testing. Inspect only this project's status with `docker compose -f .test-temp/harbor-local/compose.harbor.yml ps`. Credentials are in `credentials.json` under the fixture root; the login is `admin`. Trust `harbor/tls/server.crt` explicitly in the test client; do not disable certificate validation. Windows filesystem ACLs, rather than Python chmod alone, determine access to the secrets. Never commit or share credentials, TLS private keys, or generated Harbor configuration.

The smoke script creates private project `cats-fixture`, uploads a synthetic OCI image to `cats-fixture/image:stable`, and verifies real TLS with the custom CA, Bearer authentication, byte-for-byte manifest identity, digest-addressed reads, streamed blob integrity, anonymous rejection and the referrers endpoint. Its layer is a valid tar archive with a matching image rootfs digest. Re-running resets this synthetic tag. `smoke-results.json` records non-secret results and digests. This administrator seeding credential is test-only; production proxy upstream access should use a pull-only Harbor robot account.

## Offline reuse

While images are available locally:

```powershell
python tests/harbor/export_offline.py
```

This creates `harbor-images.tar` and `offline-images.json`, containing ten image references, the archive SHA-256 and the prepare image identity. The image archive contains vendor images only, without fixture credentials or uploaded artifacts. Preserve `installer.tgz` too. On an offline machine with Docker, Python and the required packages already installed, copy these three files into the fixture root, verify the archive against the SHA-256 in the trusted metadata, and run:

```powershell
docker image load -i .test-temp/harbor-local/harbor-images.tar
python tests/harbor/prepare_harbor.py --offline
docker compose -f .test-temp/harbor-local/compose.harbor.yml up -d --pull never
python tests/harbor/smoke_harbor.py
```

Offline prepare checks the imported prepare image identity and forbids image pulls. Fresh setup generates fresh secrets; regenerating an existing fixture preserves them. Generated Compose files contain absolute host paths, so regenerate instead of copying them between computers. The archive is not a backup of Harbor data: preserving existing artifacts requires separately protecting the entire fixture data and secrets. This test verifies cached-image startup with pulls forbidden; disconnected clean-machine installation and recovery have not been tested.

## Proxy test connection and cleanup

Host-side proxy tests can use upstream endpoint `https://localhost:18443`, the generated CA PEM and local administrator credential. Harbor's token realm uses localhost, so a proxy container cannot consume this fixture unchanged: configure a resolvable hostname and matching trusted certificate when testing across container boundaries. The localhost-only setup intentionally stays private to this machine.

Stop only the fixture:

```powershell
docker compose -f .test-temp/harbor-local/compose.harbor.yml down
```

This preserves bind-mounted data for restart. Delete generated files only when the test installation and its data are no longer needed. Avoid broad Docker cleanup commands, which could remove unrelated project data.

## Recorded validation

On 2026-10-19, Docker Desktop ran all nine Harbor services and the real Harbor smoke passed using a 2,631,680-byte tar layer. An archive of all ten required images was exported, configuration was regenerated with `--offline`, and the services restarted with `--pull never`. The separate `tests/harbor/smoke_proxy.py` exercises actual proxy authorization against this Harbor and writes `proxy-results.json`. These transport smoke checks concern Harbor and the shared registry transport; proxy authorization, Helm/multiplatform acceptance and independent Distribution interoperability are separate tests, not implied by this smoke result.
