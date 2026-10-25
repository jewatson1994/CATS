#!/usr/bin/env python3
"""Explicit bounded backfill of execution-local SBOM lookup rows, offline.

Run after portal schema startup. No scanner findings or approval state changes.
Absent digests/metadata stay absent; this cannot make legacy evidence stronger.
"""
import argparse
from pathlib import Path
import sys
from pydantic import TypeAdapter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from sqlalchemy import exists, select
from app.database import SessionLocal
from app.models import Execution, SbomComponent
from app.schemas import ExecutionPayload
from app.sbom_components import retain_components


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after-id', type=int, default=0)
    parser.add_argument('--limit', type=int, default=50)
    args = parser.parse_args()
    if not 1 <= args.limit <= 500:
        parser.error('--limit must be between 1 and 500')
    indexed = components = 0
    with SessionLocal() as db:
        ids = list(db.scalars(select(Execution.id).where(Execution.id > args.after_id,
            ~exists(select(1).where(SbomComponent.execution_id == Execution.id)))
            .order_by(Execution.id).limit(args.limit)))
        for execution_id in ids:
            # Lock each source while indexing, and load only one payload at a time.
            execution = db.scalar(select(Execution).where(Execution.id == execution_id).with_for_update())
            if db.scalar(select(SbomComponent.id).where(SbomComponent.execution_id == execution_id).limit(1)):
                continue
            raw = execution.raw_payload if isinstance(execution.raw_payload, dict) else {}
            rows = raw.get('sbom_components', [])
            if not isinstance(rows, list) or len(rows) > 50000:
                raise ValueError(f'Execution {execution_id} has invalid retained component inventory')
            # Reuse ingestion's complete validation, including string field types.
            rows = TypeAdapter(list[dict[str, str]]).validate_python(rows)
            ExecutionPayload.validate_sbom_components(rows)
            retain_components(db, execution_id, rows)
            indexed += 1
            components += len(rows)
            db.commit()
    print(f'Indexed {components} component rows from {indexed} executions; '
          f'next --after-id {ids[-1] if ids else args.after_id}. No evidence was inferred.')


if __name__ == '__main__':
    main()
