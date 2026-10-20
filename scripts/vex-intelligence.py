#!/usr/bin/env python3
"""Explicit VEX operations; never loads feeds on application startup."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from app.database import SessionLocal, engine, Base
from app import vex_models
from app.vex_intelligence import configure_source, ingest_document, list_sources, sync_source_document
from app.vex_snapshot import export_snapshot, import_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    commands.add_parser('list')
    config = commands.add_parser('source')
    config.add_argument('name')
    config.add_argument('--host', action='append', default=[])
    config.add_argument('--authority-prefix', action='append', default=[])
    config.add_argument('--trusted', action='store_true')
    config.add_argument('--trust-reason')
    config.add_argument('--public-key', type=Path)
    config.add_argument('--max-age-days', type=int, default=30)
    for name in ('ingest', 'import', 'export', 'sync'):
        sub = commands.add_parser(name)
        sub.add_argument('source_id', type=int)
        sub.add_argument('target')
        if name == 'export':
            sub.add_argument('--private-key', type=Path, required=True)
    args = parser.parse_args()
    Base.metadata.create_all(engine, tables=[vex_models.VexSource.__table__, vex_models.VexDocument.__table__, vex_models.VexStatement.__table__, vex_models.VexIngestionAudit.__table__])
    with SessionLocal() as db:
        try:
            if args.operation == 'source':
                result = {'source_id': configure_source(db, args.name, args.host, args.trusted, args.max_age_days,
                     args.public_key.read_text() if args.public_key else None, args.trust_reason, args.authority_prefix).id}
            elif args.operation == 'list':
                result = list_sources(db)
            elif args.operation == 'ingest':
                result = {'document_id': ingest_document(db, args.source_id, Path(args.target).read_bytes()).id}
            elif args.operation == 'sync':
                result = sync_source_document(db, args.source_id, args.target)
            elif args.operation == 'import':
                result = import_snapshot(db, args.source_id, Path(args.target).read_bytes())
            else:
                payload = export_snapshot(db, args.source_id, args.private_key.read_bytes())
                # Exclusive creation prevents accidentally overwriting a previous release.
                with Path(args.target).open('xb') as output:
                    output.write(payload)
                result = {'snapshot': args.target}
            db.commit()
            print(json.dumps(result, default=str))
        except Exception:
            db.rollback()
            raise

if __name__ == '__main__':
    main()
