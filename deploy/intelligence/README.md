# Existing installation: separate intelligence storage

Run from the repository root with Python 3 and Docker Compose. The utility uses
PostgreSQL clients inside the database containers and their configured credentials;
passwords are never command arguments. Keep the same Compose project name, env file,
and volume configuration as the existing installation. Source is `db` (`cats` user
and database); destination is `intelligence-db` (`cats_intelligence` user/database).
Set `INTELLIGENCE_POSTGRES_PASSWORD` before creating its volume. Changing this setting
later does not change an already initialized PostgreSQL user's password.

1. With the existing database still running, build the small backup companion and
   take a restore-verified full backup without starting the updated application:

   ```sh
   docker compose build db-backup
   docker compose run --rm --no-deps db-backup once
   ```

   Proceed only if it exits successfully. Schedule a maintenance window and stop **all**
   portal, control, importer and external intelligence writers, including other
   replicas, scheduled import jobs, and direct database clients. Keep them stopped
   through copy, verification and optional source retirement. Stop existing services
   before updating/recreating the stack; do not start the importer on an empty
   destination. Counts alone cannot detect updates that preserve row counts: the
   maintenance window is a required consistency guarantee.
   For the checked-in Compose stack, run:

   ```sh
   docker compose stop portal portal-control intelligence-importer discovery-worker remediation-worker risk-worker export-worker provisioning-worker patch-worker scan-worker db-backup
   ```

   Also stop any additional replicas or jobs outside this Compose project. Stop the
   backup job to prevent overlapping snapshots during schema retirement.
2. Start only the databases: `docker compose up -d db intelligence-db`.
   Initialize the destination's schema without ingesting any data:
   `docker compose run --rm intelligence-init`. The copy refuses a destination with
   any rows in the nine intelligence tables. It also refuses foreign keys crossing
   the selected table boundary in either database. Schema/version differences can
   cause a restore error; align application schema before retrying.
3. Copy into the empty schema (choose a new private directory with enough free disk):

   ```sh
   python deploy/intelligence/migrate.py --output /secure/backups/intelligence-cutover --maintenance-confirmed
   ```

   This saves a custom-format, data-only dump, sequence values, a SHA-256 digest,
   and per-table counts. `pg_restore` runs as one transaction with constraints and
   immutability triggers enabled. IDs, trust settings, documents, installation
   history and package membership are copied unchanged. The source remains intact.
   Verification checks successful transactional restore and exact row counts, not
   independent per-row content hashes. The archive digest protects the saved dump.
   Only the nine tables explicitly listed in `migrate.py` are selected; operational
   `native_vex_*` tables remain in the portal database.
4. Check that `manifest.json` says `"verified": true`, and retain the archive in a
   protected backup location. Before starting writers, optionally retire the old
   tables so portal backups no longer include the large intelligence payload:

   ```sh
   python deploy/intelligence/migrate.py --output /secure/backups/intelligence-cutover --maintenance-confirmed --retire-source
   ```

   This is an explicit destructive step. It rechecks the dump digest and both
   databases' counts against the verified receipt, then drops only the nine source
   tables in one transaction, with `RESTRICT`, never `CASCADE`. External dependencies
   cause rollback. The dump is retained. Do this before resuming writers; if either
   side changes, retirement refuses and requires a fresh reviewed migration.
5. Start the updated stack with its separate intelligence connection. Confirm
   intelligence status/catalog counts and portal operational records in the UI;
   check the daily portal backup job and retain the intelligence archive under a
   separate backup policy (no second scheduled backup job is implied). Resume
   external jobs only after these checks.

If copy fails, leave writers stopped. A failed restore rolls back its data changes;
sequence values may have advanced, which a successful retry restores from the dump.
Use a fresh output directory for retries; archives are never overwritten. A count
mismatch after a successful restore needs investigation, not an automatic retry or
deletion. The source is untouched until the explicit retirement command. Before
retirement, rollback can use the prior application/configuration and retained source
tables while all writers remain stopped. After retirement, recover via the retained
dump into an initialized empty legacy schema (or the pre-migration portal backup)
before restarting the old application. Never run old and new writers simultaneously.

The utility intentionally does not vacuum, reset volumes, remove archives, rewrite
trust, disable constraints, or bypass database dependencies. Protect the archive
like a database backup; it contains the original data.
