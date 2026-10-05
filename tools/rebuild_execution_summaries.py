"""Rebuild derived execution summaries in bounded transactions.

Run from the repository root with DATABASE_URL configured for the target DB.
The database must already have the additive execution summary migration.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from portal.app.database import SessionLocal
from portal.app.execution_summaries import PAYLOAD_BATCH_SIZE, rebuild_execution_summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--after-id", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=PAYLOAD_BATCH_SIZE)
    parser.add_argument("--max-batches", type=int, default=1,
                        help="Maximum transactions per invocation; repeat with printed cursor")
    args = parser.parse_args()
    if args.after_id < 0 or not 1 <= args.batch_size <= PAYLOAD_BATCH_SIZE or args.max_batches < 1:
        parser.error("after-id must be >=0, batch-size 1..32, max-batches >=1")
    cursor, total = args.after_id, 0
    for _ in range(args.max_batches):
        with SessionLocal.begin() as db:
            cursor, count = rebuild_execution_summaries(db, after_id=cursor, limit=args.batch_size)
        total += count
        if count < args.batch_size:
            break
    print(f"rebuilt={total} after_id={cursor}")


if __name__ == "__main__":
    main()
