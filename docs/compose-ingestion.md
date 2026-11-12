# Assess a Docker Compose application

CATS can discover image references and configuration evidence from a Docker Compose application, then assess each unique image through the existing scan worker. It associates shared images with every declaring service and retains incomplete evidence explicitly. It does not build images, start containers, run application commands, or perform Compose runtime validation.

## Submit and preview

1. Open **Scan** and use **Docker Compose files and companions** to upload the Compose documents and any companion files. A `.env` upload is optional: missing interpolation values can be entered in the form. Compose documents contain YAML but can have any filename, including `Compose.txt`, `compose.local.yaml`, or `compose.main.yaml(2)`. Supported bundles are ZIP, TAR, TAR.GZ/TGZ, TAR.BZ2/TBZ2, and TAR.XZ/TXZ; folders and companion files are preserved. Do not upload an entire source repository when a small bundle is sufficient.
2. Selected uploads are inspected automatically. **Detected Compose documents** lists the matching paths from all folders. Use each file's dropdown to choose **Skip** or a merge position: **1** is the base, followed by overrides. Moving a file renumbers the others, and skipped documents are not merged. A single document, or a standard base and standard override beside it, is selected automatically. Other combinations start unselected so you can choose the intended files. The dropdowns populate **Compose file order**, which also accepts paths entered directly. Inspection does not start a scan and deletes its temporary copy of the uploads afterward.
3. Enter the desired **Compose profiles**, separated by commas or newlines. Services without profiles are included by default; profiled services are included only when their profile is selected. Inactive profile services are omitted from discovery, so verify the selected profiles cover the intended application.
4. Missing interpolation variables appear below the file order with masked value fields and their source files/services. Enter the values needed to identify images, such as an image registry or tag, then start scanning directly or use **Recheck variables** to update the list. Compose defaults and supplied `.env` values are already considered; entered values take precedence. Runtime-only values can remain missing when the image references are resolved. Changing the uploads clears entered values; changing merge order or profiles refreshes the check.
5. Select **Preview Compose** to inspect services, effective images, source files, configuration, and discovery issues. Preview does not pull or scan images and cannot be ingested as a security assessment.
6. Select **Start scan** to assess the discovered images. To retain the assessment automatically, choose a service and its intended version before starting. If the scan has already finished with temporary results, select the service and version, then click **Ingest completed scan** below the scan status. This attaches the existing results without rerunning the scan and shows a link to the service on success. The existing scan permissions apply.

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

Alternatively, omit `.env` and enter `1.2.3` in the `APP_TAG` field after uploading. Set the file order to `compose.yaml`, then `compose.production.yaml`. Select `observability` to include `metrics`. The API and worker share one image scan, while the evidence retains their separate service associations.

## Interpretation and limitations

Compose ingestion uses a restricted, non-executing YAML parser. It supports YAML anchors, ordered overrides, `!reset`/`!override`, common unique-resource merges, profile selection, bundled interpolation inputs, and selected service configuration evidence; it is not a replacement for the complete Docker Compose implementation. Includes, extends, provider/model services, unresolved profiles, and explicit platform selection can prevent CATS from determining the applicable images or scanning them correctly and remain blocking. Unsupported runtime features such as develop settings, lifecycle hooks, and label files are retained as review notes. Review every issue before relying on the inventory.

Interpolation uses the uploaded bundle's `.env` data, explicit values entered in the form, and supported Compose variable/default syntax. Explicit values are literal text and override `.env`; they are also available when resolving expressions inside `.env`. It does not read the portal or worker process environment. Service `env_file` inputs supply service environment metadata; they do not implicitly become interpolation variables for image references. Relative references resolve against the directory of the first selected Compose file. Keep referenced paths inside the uploaded bundle. Missing selected Compose files, unresolved image references, and unreadable or unsafe Compose/archive inputs prevent complete image discovery. Missing runtime variables (including required passwords and tokens), service env files, and deployment configuration files are review notes when image discovery can proceed. Do not supply production secrets just to scan resolved images.

External networks/volumes, unavailable bind mounts, and external secrets/configs are listed as review notes about unverifiable deployment prerequisites. CATS never inspects host paths to resolve them. Supplied sensitive values used in structural fields are withheld and reported as unresolved; an affected image reference still blocks scanning that image. Uploads are limited to 500 files, 4 MiB per extracted file, and 32 MiB total; the existing `CATS_PUBLIC_MAX_IMAGES` limit still applies.

Empty named-resource declarations such as `volumes: {data: null}` or `networks: {egress: {}}` are valid and do not count as missing inputs. Unresolved-variable messages identify the variable name without displaying its value or custom error text. Review notes remain visible in inventory, review, and exported Compose evidence; they do not populate blocking missing evidence or make a successful image scan incomplete. A complete image assessment does not establish that all deployment configuration was supplied or that the deployment is ready to run.

A service with both `image` and `build` scans the declared image; missing build inputs are review notes. This does not establish that the image matches its build context. A build-only service has no image to assess and remains missing evidence; build and publish the intended image separately, then declare that reference and rescan. Inactive profile services are outside the assessment inventory. An unreachable image or unavailable scanner evidence also prevents an otherwise clean result from proving coverage.

Published ports, selected security settings, image associations, and discovery issues appear in the Compose evidence and service overview. Configuration findings describe declared settings, not observed runtime behavior. Existing image scanning and image configuration checks still run; there is no Docker Compose deployment or runtime-validation stage.

## Private registries and sensitive inputs

For private Harbor images, use fully qualified image references such as `harbor.example.org/team/api:1.2.3` or a digest. Configure registry credentials and trusted CAs through the existing CATS administration and worker setup. A service-scoped scan passes only credentials for registries referenced by the discovered images. Preview cannot validate pull authorization or image availability.

CATS treats Compose files as untrusted input. Uploaded archives are bounded and checked; references cannot escape the bundle. Discovery never invokes Docker Compose, shell expansion, builds, application commands, or remote includes. Only sanitized image references and discovery metadata reach the scanner. Entered values travel with the private scan inputs, are excluded from public job metadata, and are removed with the raw Compose files before the scanner runs. Runtime environment values, commands, and registry credentials are not included in returned Compose evidence. Resolved non-sensitive fields, such as image tags, remain visible as evidence. Upload only the companions needed for discovery and avoid embedding credentials in image references.

## Architecture from retained Compose evidence

The service Architecture tab uses the retained Compose inventory automatically, including scans ingested before this feature was deployed. It shows services, shared images, startup dependencies, networks, published host ports, internal ports, volumes/bind mounts, and config/secret references. Select a node or connection for its source and supporting details; use the existing graph layers to focus on workloads, networking, configuration, or storage.

Compose architecture is labeled **Declared**. Startup dependencies and shared networks do not prove observed traffic, and Compose evidence does not claim Kubernetes deployment validation. Secret contents and environment values are excluded. Partial discovery still displays the known topology with its issues; unresolved images are not invented. Only services retained from the selected profiles appear. Mixed Helm/Compose evidence keeps both sources in the same graph. No rescan, database migration, or additional environment setting is required when the saved scan already contains Compose inventory.

## Deploy the feature

This feature uses the existing **portal**, **portal-control**, and **scan-worker** services and the shared CATS image. No new environment variables, service containers, or external Compose parser are required. Rebuild the image from this checkout and deploy the same version across portal, portal-control, and all existing workers using the [normal upgrade instructions](../README.md#3-start-and-verify). Existing scanner databases, registry access, trust configuration, and disconnected-operation prerequisites still apply.

The automated flow tests exercise actual bundle discovery, durable worker transfer, image deduplication, service ingestion, scoped registry authentication, sanitized result artifacts, and preview without scanner execution. Scanner binaries are simulated; these tests do not prove live Harbor connectivity or vulnerability-database availability.
