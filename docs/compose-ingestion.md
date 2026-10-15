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

Compose ingestion uses a restricted, non-executing YAML parser. It supports YAML anchors, ordered overrides, `!reset`/`!override`, common unique-resource merges, profile selection, bundled interpolation inputs, and selected service configuration evidence; it is not a replacement for the complete Docker Compose implementation. Includes, extends, remote inputs, multiline dotenv, provider/develop features, lifecycle hooks, label files, model services, and explicit platform selection require a supported, explicitly resolved input before CATS can claim complete coverage. Discovery reports unsupported or unresolved features rather than silently treating the application as fully assessed. Review every issue before relying on the inventory.

Interpolation uses the uploaded bundle's `.env` data and supported Compose variable/default syntax. It does not read the portal or worker process environment. Service `env_file` inputs supply service environment metadata; they do not implicitly become interpolation variables for image references. Relative references resolve against the directory of the first selected Compose file. Keep referenced paths inside the uploaded bundle. Missing files, unresolved required values, unsafe paths, and unsupported composition features prevent a complete assessment.

External networks/volumes, unavailable bind mounts, and external secrets/configs are listed as unverifiable prerequisites. CATS never inspects host paths to resolve them. Supplied sensitive values used in structural fields are withheld and reported as unresolved. Uploads are limited to 500 files, 4 MiB per extracted file, and 32 MiB total; the existing `CATS_PUBLIC_MAX_IMAGES` limit still applies.

A service with both `image` and `build` scans the declared image. This does not establish that the image matches its build context. A build-only service has no image to assess and remains missing evidence; build and publish the intended image separately, then declare that reference and rescan. Inactive profile services are outside the assessment inventory. An unreachable image or unavailable scanner evidence also prevents an otherwise clean result from proving coverage.

Published ports, selected security settings, image associations, and discovery issues appear in the Compose evidence and service overview. Configuration findings describe declared settings, not observed runtime behavior. Existing image scanning and image configuration checks still run; there is no Docker Compose deployment or runtime-validation stage.

## Private registries and sensitive inputs

For private Harbor images, use fully qualified image references such as `harbor.example.org/team/api:1.2.3` or a digest. Configure registry credentials and trusted CAs through the existing CATS administration and worker setup. A service-scoped scan passes only credentials for registries referenced by the discovered images. Preview cannot validate pull authorization or image availability.

CATS treats Compose files as untrusted input. Uploaded archives are bounded and checked; references cannot escape the bundle. Discovery never invokes Docker Compose, shell expansion, builds, application commands, or remote includes. Only sanitized image references and discovery metadata reach the scanner. Raw Compose files, `.env` values, service environment values, commands, and registry credentials are not included in returned Compose evidence. Upload only the companions needed for discovery and avoid embedding credentials in image references.

## Deploy the feature

This feature uses the existing **portal**, **portal-control**, and **scan-worker** services and the shared CATS image. No new environment variables, service containers, or external Compose parser are required. Rebuild the image from this checkout and deploy the same version across portal, portal-control, and all existing workers using the [normal upgrade instructions](../README.md#3-start-and-verify). Existing scanner databases, registry access, trust configuration, and disconnected-operation prerequisites still apply.

The automated flow tests exercise actual bundle discovery, durable worker transfer, image deduplication, service ingestion, scoped registry authentication, sanitized result artifacts, and preview without scanner execution. Scanner binaries are simulated; these tests do not prove live Harbor connectivity or vulnerability-database availability.
