# Portal and intelligence database backups

For an existing combined database, follow the [intelligence migration guide](../deploy/intelligence/README.md)
before starting the new stack. The updated CATS image, Compose file, and deployment
scripts must be deployed together. The migration retains the original tables until
you explicitly retire them after verification.

The `intelligence-db` service owns feed data; `intelligence-importer` installs the
image's signed package independently. The portal waits for the short schema-only
`intelligence-init` job, never for the importer. It sees the previous committed
package while an upgrade runs (or no package on the first import). Check progress
with `docker compose logs -f intelligence-importer`. A successful importer exits 0;
a failed import exits 1 and retries up to three times. Retry manually with
`docker compose run --rm intelligence-importer`. Imports stay atomic.

These containers still share the VM's CPU and disk. Separate database volumes and
processes isolate storage and transactions, but do not provide separate hardware.

The `intelligence-db-backup` service backs up the separate intelligence database on startup and daily at **03:30 UTC** (override `INTELLIGENCE_BACKUP_UTC_TIME`). It waits for schema initialization, verifies all five intelligence tables, and uses its own host directory (`CATS_INTELLIGENCE_DB_BACKUP_DIR`, default `./backups/intelligence-postgres`). Keep this directory distinct from `CATS_DB_BACKUP_DIR` so status, locks, and retention remain independent. Both services use `BACKUP_RETENTION_COUNT`.

The `db-backup` service creates a backup on startup, then daily at **03:00 UTC**.
Set `BACKUP_UTC_TIME` (`HH:MM`) to change the UTC schedule and
`BACKUP_RETENTION_COUNT` (default 7, minimum 1) to set the number retained.
Set `CATS_DB_BACKUP_DIR` to an absolute host directory on a separate disk or
mounted backup filesystem. The default `./backups/postgres` is separate from
the database volume, but does not protect against host or disk loss. Arrange
encrypted off-host replication and alerting independently; neither is included.

Every archive contains **the entire portal database, all schemas**, including
legacy intelligence tables that remain in a combined database. No table filters
are used. Migrating intelligence to a separate database does not back up that
new database: provision a separate backup policy before relying on it for
non-rebuildable data. Existing historical intelligence must be migrated or kept
in the source database; backups are not a substitute for that migration.

`pg_dump` uses a consistent PostgreSQL snapshot in custom format. Publication
requires restoring into a new temporary PostgreSQL 16 cluster with TCP disabled,
reading every user table, confirming the configured required tables, and checking index
validity. The scratch server never connects to the portal database. Restore
also validates constraints represented by the dump. This is a restore health
check, not a proof of application-level semantic correctness. Roles, global
objects, configuration secrets, and uploaded files are not included. Each archive
contains one database; retain both services' archives for complete recovery. Allow space for the dump plus a complete temporary
restored database in the backup container's writable layer.

Files are private by default. Credentials are passed through PostgreSQL's
environment; command output and connection strings are never printed. The
backup service needs database read permission and filesystem write permission.
It runs as root to initialize its isolated PostgreSQL cluster as the image's
postgres user. Do not mount the production database volume into this service.

Each published `backup-*` directory contains `database.dump`, `SHA256SUMS`, and
`manifest.json`. Files are flushed and the directory is atomically renamed on
the backup filesystem after verification. Only successfully published archives
participate in count-based retention, and retention runs only after success.
Failures leave prior archives intact, emit an error, and set `status.json` to
failed. Container health becomes unhealthy on a failed attempt or after 27
hours without success. Monitor Docker health and copy status into your alerting
system. A daemon failure is retried at the next scheduled time or on restart.
Interrupted `.pending-*` directories can be removed when no backup is running.

## Operations

The backup script, PostgreSQL 16 client/server tools, and restore runtime are
bundled in the same CATS image as the portal. No separate backup image, host-side
source directory, package download, or build is needed at deployment time.
Transfer the updated CATS image through your normal offline registry workflow and
copy the matching Compose file. Existing PostgreSQL service images must also be
available locally, as for the rest of the stack. Keep your existing `.env` and
set `CATS_IMAGE` to the updated image tag. `CATS_BACKUP_IMAGE` is no longer used.

Start offline: `docker compose up -d --no-build --pull never db-backup intelligence-db-backup`.
Run an immediate backup without starting the portal:
`docker compose run --rm --no-deps --pull never db-backup once`.
For intelligence, run `docker compose run --rm --no-deps --pull never intelligence-db-backup once`.
The corresponding database service must already be running and initialized.
It exits nonzero on failure. A lock prevents concurrent jobs using the same
backup directory. View health with `docker compose ps db-backup`, and inspect
the mounted `status.json` for the last successful archive. Required table names
can be set through `BACKUP_REQUIRED_TABLES` as comma-separated schema.table
identifiers; the default is `public.services,public.users,public.executions`.

## Recovery drill

1. Choose a published archive and verify it with `sha256sum -c SHA256SUMS`
   from that directory. Copy it to a safe recovery workspace first.
2. Start an isolated PostgreSQL 16 recovery server with fresh storage. Create
   an empty database owned by the intended application role.
3. Run `pg_restore --exit-on-error --no-owner --no-acl -h RECOVERY_HOST
   -U RECOVERY_ROLE -d RECOVERY_DATABASE database.dump` using secure credential
   handling. These options assign restored objects to the connecting role;
   recreate any custom grants separately.
4. Repeat for the other database using its own archive and an empty recovery database.
   Configure both `DATABASE_URL` and `INTELLIGENCE_DATABASE_URL` for the recovery drill.
   The two backups are independent snapshots; confirm application/feed compatibility.
5. Test the portal against that recovery database, check recent executions,
   users, findings, and historical intelligence. Keep the original database
   untouched until the recovery is accepted. Stop application writes before
   a deliberate cutover and document the selected archive's time/data loss.

Daily backups have up to one day of data loss, potentially longer after failures.
There is no point-in-time recovery or WAL archive. Regularly test recovery from
the off-host copy, including configuration keys and uploaded artifacts stored
separately.
