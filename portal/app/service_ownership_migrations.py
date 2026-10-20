"""Preserve legacy ownership data; prohibit introducing further ambiguity."""
import logging
from sqlalchemy import text


def upgrade_connection(connection):
    conflicts = connection.execute(text("SELECT service_id FROM service_groups GROUP BY service_id HAVING COUNT(*) > 1")).scalars().all()
    if not conflicts:
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_service_owning_group_index ON service_groups(service_id)"))
    else:
        logging.getLogger(__name__).warning("Service ownership needs explicit administrator reconciliation for service IDs %s; existing memberships preserved", conflicts)
    # Triggers protect pre-migration databases containing conflicts too. Once
    # reconciled, the unique index is added on the next startup.
    if connection.dialect.name == "sqlite":
        connection.execute(text("""CREATE TRIGGER IF NOT EXISTS cats_service_owner_insert
            BEFORE INSERT ON service_groups
            WHEN EXISTS (SELECT 1 FROM service_groups WHERE service_id = NEW.service_id)
            BEGIN SELECT RAISE(ABORT, 'Service already has an owning group'); END"""))
        connection.execute(text("""CREATE TRIGGER IF NOT EXISTS cats_service_owner_update
            BEFORE UPDATE ON service_groups
            WHEN EXISTS (SELECT 1 FROM service_groups WHERE service_id = NEW.service_id
                AND NOT (service_id = OLD.service_id AND group_id = OLD.group_id))
            BEGIN SELECT RAISE(ABORT, 'Service already has an owning group'); END"""))
    elif connection.dialect.name == "postgresql":
        connection.execute(text("""CREATE OR REPLACE FUNCTION cats_check_service_owner() RETURNS trigger AS $$
            BEGIN
                PERFORM id FROM services WHERE id = NEW.service_id FOR UPDATE;
                IF TG_OP = 'INSERT' THEN
                    IF EXISTS (SELECT 1 FROM service_groups WHERE service_id = NEW.service_id) THEN
                        RAISE EXCEPTION 'Service already has an owning group';
                    END IF;
                ELSE
                    IF EXISTS (SELECT 1 FROM service_groups WHERE service_id = NEW.service_id
                        AND NOT (service_id = OLD.service_id AND group_id = OLD.group_id)) THEN
                        RAISE EXCEPTION 'Service already has an owning group';
                    END IF;
                END IF;
                RETURN NEW;
            END; $$ LANGUAGE plpgsql"""))
        connection.execute(text("DROP TRIGGER IF EXISTS cats_service_owner ON service_groups"))
        connection.execute(text("CREATE TRIGGER cats_service_owner BEFORE INSERT OR UPDATE ON service_groups FOR EACH ROW EXECUTE FUNCTION cats_check_service_owner()"))
