"""Disposable subprocess for the real PostgreSQL activation crash qualification.

Only the qualification parent may invoke this helper. The incoming package is
the same verified-format transaction fixture used by importer tests; signature
verification and registry replication are qualified separately.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import replica_import as importer
from app.replica_models import ReplicaSource


def main():
    package_path, marker_path, stage = sys.argv[1:]
    package = json.loads(Path(package_path).read_text(encoding='utf-8'))
    incoming = package['incoming']
    incoming['evidence'] = base64.b64decode(incoming['evidence'])
    schema = os.environ['CATS_RECOVERY_SCHEMA']
    if not schema.startswith('replica_test_') or not schema.removeprefix('replica_test_').isalnum():
        raise ValueError('Qualification requires an isolated test schema')
    engine = create_engine(os.environ['CATS_TEST_REPLICA_POSTGRES_URL'],
                           connect_args={'options': f'-csearch_path={schema}'})

    def pause():
        # fsync makes the kill boundary observable even if the worker dies at
        # the next instruction. There is deliberately no exception or cleanup.
        with Path(marker_path).open('w', encoding='utf-8') as marker:
            json.dump({'stage': stage, 'pid': os.getpid()}, marker)
            marker.flush()
            os.fsync(marker.fileno())
        while True:
            time.sleep(1)

    if stage == 'after_projection':
        original = importer.seal_record

        def stop_before_seal(release):
            # reconcile has flushed projected evidence and the new release.
            pause()
            original(release)

        importer.seal_record = stop_before_seal
    elif stage not in {'before_commit', 'recover'}:
        raise ValueError('Unknown activation boundary')

    with Session(engine) as db:
        source = db.get(ReplicaSource, package['source_id'])
        result = importer.reconcile(db, source, incoming)
        db.flush()
        if stage != 'recover':
            pause()
        db.commit()
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
