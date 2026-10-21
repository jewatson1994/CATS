"""Independent schema initialization and offline intelligence installation."""
import argparse
import logging

from .database import Base, IntelligenceSessionLocal, intelligence_engine, intelligence_tables
from . import vex_models, intelligence_models  # register the isolated schema
from .exchange_migrations import migration_transaction


def initialize_schema():
    with migration_transaction(intelligence_engine) as connection:
        Base.metadata.create_all(connection, tables=intelligence_tables())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-only', action='store_true')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    initialize_schema()
    if args.schema_only:
        return 0
    from .embedded_intelligence import install_package
    logging.info('Starting intelligence package installation in the intelligence database')
    result = install_package(IntelligenceSessionLocal)
    logging.info('Intelligence package installation: %s', result)
    return 1 if result == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
