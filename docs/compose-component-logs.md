# Compose component logs

The main, local, and replica templates send container stdout and stderr into the local CATS operational database. The same release image runs the component log collector. Administrators can review recorded events by component and choose which HQ destinations receive operational logs.

| Source | Collection |
| --- | --- |
| Portal, portal control, OCI proxy, discovery, polling, settings, scanning, patching, remediation, provisioning, risk, security data and export workers | Compose captures both process streams. The event identifies the project, service, container ID, stream and original timestamp. |
| PostgreSQL, intelligence database, backups, intelligence initializer/importer and optional local Nginx | The same Compose driver captures the output these processes emit. Nginx TLS passthrough records its configured stream errors. |
| Audit forwarder and replica reporter | Process output enters local collection. Successful telemetry uploads and the collection pipeline’s own database statements are filtered to prevent repeated events. |
| Component log collector | The collector records its startup and database outage/recovery events directly in its spool. Its local Docker log remains available for receiver troubleshooting. |
| Dedicated validator VM, runtime agents, and standalone scanners | These run outside the portal Compose project. They use the CATS validator, runtime reporting and enrolled CLI paths respectively. |

## Deployment

Recreate the services with the updated Compose template and release image. Docker applies a container’s logging driver at creation. The Linux Docker daemon delivers records to a Unix socket on the Docker **host**. Each Compose project needs its own socket directory. The default is under `/run/cats-logs-<project>`. Set `CATS_COMPONENT_LOG_SOCKET_DIR` to an absolute path on the daemon host to override it. Use a directory owned by the collector UID, with group and other write access disabled. The socket accepts only its owner and the Docker daemon. The collector requires no host journal, Docker API socket, privileged container, or published network port.

The collector acknowledges a Docker message after writing it to its SQLite spool. It then commits a local CATS event and removes the spooled copy. A retry keeps the event ID, including after process or database restarts. The named `component_log_spool` volume holds the queue and the key used to protect incomplete Docker fragments. Preserve the volume when recreating the stack. PostgreSQL stores committed operational logs independently of SIEM availability.

| Setting | Default | Effect |
| --- | --- | --- |
| `CATS_COMPONENT_LOG_SOCKET_DIR` | `/run/cats-logs-<project>` | Private driver input on the Linux Docker host |
| `CATS_COMPONENT_LOG_SPOOL_MIB` | 512 | Approximate SQLite queue capacity while the local CATS database is unavailable |
| Docker pre-connection buffer | 8,192 events per container | Allows services to start before the collector. Exhausting this buffer, removing the container, or stopping the Docker daemon can lose events still in memory. |

If records stop arriving, inspect `docker compose logs component-log-collector` and check the socket directory, available volume space, and local database readiness. A full spool withholds acknowledgments until the collector can drain it. Increasing the database outage budget requires increasing spool capacity and provisioning matching disk space.

Before storage, the collector redacts known credential formats, URL queries, and private keys, and omits PostgreSQL statement and bind text. It reassembles Docker-split lines before redaction. Lines exceeding the 8 MiB assembly limit produce a marker. An event larger than 32,000 characters is delivered in numbered parts. Applications should keep secrets out of free-form messages. Managed Compose logging covers container output. Host OS logs, application-private files, and arbitrary workloads in monitored clusters have their own collection policies.
