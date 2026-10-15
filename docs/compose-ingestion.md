# Assess a Docker Compose application

CATS can discover image references and configuration evidence from a Docker Compose application, then assess each unique image through the existing scan worker. It associates shared images with every declaring service and retains incomplete evidence explicitly. It does not build images, start containers, run application commands, or perform Compose runtime validation.

## Submit and preview

1. Open **Scan** and use **Docker Compose files and companions** to upload the Compose YAML files and any required `.env` or service `env_file` files. A ZIP, TAR, TAR.GZ, or TGZ bundle preserves the relative directory structure. Do not upload an entire source repository when a small bundle is sufficient.
2. Enter the bundle-relative YAML paths under **Compose file order**, one per line, with the base file first and overrides after it. Leave the field blank only when the bundle contains one unambiguous standard Compose entry file; a single standard override beside it is then included automatically. Use explicit ordering for all other combinations.
3. Enter the desired **Compose profiles**, separated by commas or newlines. Services without profiles are included by default; profiled services are included only when their profile is selected. Inactive profile services are omitted from discovery, so verify the selected profiles cover the intended application.
4. Select **Preview Compose** to inspect services, effective images, source files, configuration, and discovery issues. Preview does not pull or scan images and cannot be ingested as a security assessment.
5. Select **Start scan** to assess the discovered images. To retain the assessment on a service, choose the existing service ingestion options and the intended service version. The existing scan permissions apply.

For example, upload a bundle containing:

```text
compose.yaml
compose.production.yaml
.env
```

`compose.yaml`:

```yaml
services:
  api:
    image: harbor.example.org/team/api:${APP_TAG}
    ports: ["8080:8080"]
  worker:
    image: harbor.example.org/team/api:${APP_TAG}
  metrics:
    image: harbor.example.org/team/metrics:1
    profiles: [observability]
```

`compose.production.yaml`:

```yaml
services:
  api:
    read_only: true
```

`.env`:

```dotenv
APP_TAG=1.2.3
```

Set the file order to `compose.yaml`, then `compose.production.yaml`. Select `observability` to include `metrics`. The API and worker share one image scan, while the evidence retains their separate service associations.

## Interpretation and limitations

Compose ingestion uses a restricted, non-executing YAML parser. It supports YAML anchors, ordered overrides, `!reset`/`!override`, common unique-resource merges, profile selection, bundled interpolation inputs, and selected service configuration evidence; it is not a replacement for the complete Docker Compose implementation. Includes, extends, provider/model services, unresolved profiles, and explicit platform selection can prevent CATS from determining the applicable images or scanning them correctly and remain blocking. Unsupported runtime features such as develop settings, lifecycle hooks, and label files are retained as review notes. Review every issue before relying on the inventory.

Interpolation uses the uploaded bundle's `.env` data and supported Compose variable/default syntax. It does not read the portal or worker process environment. Service `env_file` inputs supply service environment metadata; they do not implicitly become interpolation variables for image references. Relative references resolve against the directory of the first selected Compose file. Keep referenced paths inside the uploaded bundle. Missing selected Compose files, unresolved image references, and unreadable or unsafe Compose/archive inputs prevent complete image discovery. Missing runtime variables (including required passwords and tokens), service env files, and deployment configuration files are review notes when image discovery can proceed. Do not supply production secrets just to scan resolved images.

External networks/volumes, unavailable bind mounts, and external secrets/configs are listed as review notes about unverifiable deployment prerequisites. CATS never inspects host paths to resolve them. Supplied sensitive values used in structural fields are withheld and reported as unresolved; an affected image reference still blocks scanning that image. Uploads are limited to 500 files, 4 MiB per extracted file, and 32 MiB total; the existing `CATS_PUBLIC_MAX_IMAGES` limit still applies.

Empty named-resource declarations such as `volumes: {data: null}` or `networks: {egress: {}}` are valid and do not count as missing inputs. Unresolved-variable messages identify the variable name without displaying its value or custom error text. Review notes remain visible in inventory, review, and exported Compose evidence; they do not populate blocking missing evidence or make a successful image scan incomplete. A complete image assessment does not establish that all deployment configuration was supplied or that the deployment is ready to run.

A service with both `image` and `build` scans the declared image; missing build inputs are review notes. This does not establish that the image matches its build context. A build-only service has no image to assess and remains missing evidence; build and publish the intended image separately, then declare that reference and rescan. Inactive profile services are outside the assessment inventory. An unreachable image or unavailable scanner evidence also prevents an otherwise clean result from proving coverage.

Published ports, selected security settings, image associations, and discovery issues appear in the Compose evidence and service overview. Configuration findings describe declared settings, not observed runtime behavior. Existing image scanning and image configuration checks still run; there is no Docker Compose deployment or runtime-validation stage.

## Private registries and sensitive inputs

For private Harbor images, use fully qualified image references such as `harbor.example.org/team/api:1.2.3` or a digest. Configure registry credentials and trusted CAs through the existing CATS administration and worker setup. A service-scoped scan passes only credentials for registries referenced by the discovered images. Preview cannot validate pull authorization or image availability.

CATS treats Compose files as untrusted input. Uploaded archives are bounded and checked; references cannot escape the bundle. Discovery never invokes Docker Compose, shell expansion, builds, application commands, or remote includes. Only sanitized image references and discovery metadata reach the scanner. Raw Compose files, `.env` values, service environment values, commands, and registry credentials are not included in returned Compose evidence. Upload only the companions needed for discovery and avoid embedding credentials in image references.

## Architecture from retained Compose evidence

The service Architecture tab uses the retained Compose inventory automatically, including scans ingested before this feature was deployed. It shows services, shared images, startup dependencies, networks, published host ports, internal ports, volumes/bind mounts, and config/secret references. Select a node or connection for its source and supporting details; use the existing graph layers to focus on workloads, networking, configuration, or storage.

Compose architecture is labeled **Declared**. Startup dependencies and shared networks do not prove observed traffic, and Compose evidence does not claim Kubernetes deployment validation. Secret contents and environment values are excluded. Partial discovery still displays the known topology with its issues; unresolved images are not invented. Only services retained from the selected profiles appear. Mixed Helm/Compose evidence keeps both sources in the same graph. No rescan, database migration, or additional environment setting is required when the saved scan already contains Compose inventory.

## Deploy the feature

This feature uses the existing **portal**, **portal-control**, and **scan-worker** services and the shared CATS image. No new environment variables, service containers, or external Compose parser are required. Rebuild the image from this checkout and deploy the same version across portal, portal-control, and all existing workers using the [normal upgrade instructions](../README.md#3-start-and-verify). Existing scanner databases, registry access, trust configuration, and disconnected-operation prerequisites still apply.

The automated flow tests exercise actual bundle discovery, durable worker transfer, image deduplication, service ingestion, scoped registry authentication, sanitized result artifacts, and preview without scanner execution. Scanner binaries are simulated; these tests do not prove live Harbor connectivity or vulnerability-database availability.
