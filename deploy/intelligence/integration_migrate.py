"""Opt-in PG16 integration check: isolated disposable container, no published ports.

Run from repository root using the portal development Python environment.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'portal'))
from sqlalchemy import create_mock_engine
from app import vex_models, intelligence_models
from app.database import Base

spec = importlib.util.spec_from_file_location('migration', Path(__file__).with_name('migrate.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
name = 'cats-migration-test-' + uuid.uuid4().hex[:12]


def execute(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def command(endpoint, program, *args):
    database = 'source' if endpoint == m.SOURCE else 'destination'
    return ['docker', 'exec', '-i', name, program, '-U', 'postgres', '-d', database, *args]


def query(database, text):
    return execute('docker', 'exec', '-i', name, 'psql', '-U', 'postgres', '-d', database,
                   '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', input=text.encode()).stdout.decode().strip()


try:
    execute('docker', 'run', '-d', '--name', name, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16-alpine')
    for attempt in range(40):
        ready = subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'], capture_output=True)
        if ready.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('Test PostgreSQL did not become ready')
    query('postgres', 'CREATE DATABASE source; CREATE DATABASE destination;')
    statements = []
    engine = create_mock_engine('postgresql://', lambda statement, *args, **kwargs:
                                statements.append(str(statement.compile(dialect=engine.dialect))))
    Base.metadata.create_all(engine, tables=[Base.metadata.tables[t] for t in m.TABLES], checkfirst=False)
    schema = ';\n'.join(statements) + ';'
    query('source', schema)
    query('destination', schema)
    query('source', """
    INSERT INTO vex_sources(id,name,allowed_hosts,trusted,authoritative_prefixes,max_age_days,enabled,etags,trust_reason)
      VALUES (42,'trusted-source','[]',true,'[]',30,true,'{}','original trust');
    INSERT INTO vex_documents(id,source_id,sha256,raw_text,format,document_key,version,issued_at,retrieved_at,verification,withdrawn)
      VALUES (43,42,'abc','original payload','openvex','key','1',now(),now(),'verified',false);
    INSERT INTO vex_statements(id,document_id,cve,product_id,identity,status) VALUES (44,43,'CVE-2026-1','product','{}','affected');
    INSERT INTO vex_ingestion_audits(id,source_id,occurred_at,outcome) VALUES (45,42,now(),'ok');
    INSERT INTO intelligence_records(id,source_id,kind,record_id,cve,data,sha256,acquired_at,source_url,package_version)
      VALUES (46,42,'kev','record','CVE-2026-1','{}','def',now(),'https://example.test','1');
    INSERT INTO intelligence_package_installs(id,version,sequence,manifest,counts,installed_at) VALUES (47,'1',1,'{}','{}',now());
    INSERT INTO intelligence_package_catalogs(id,install_id,source_id,source_key,kind,metadata_json,record_count)
      VALUES (48,47,42,'source','kev','{}',1);
    INSERT INTO intelligence_package_members(catalog_id,record_id) VALUES (48,46);
    INSERT INTO intelligence_package_state(id,status,updated_at) VALUES (49,'ready',now());
    SELECT setval('vex_sources_id_seq',100);
    CREATE TABLE native_vex_probe(id int PRIMARY KEY); INSERT INTO native_vex_probe VALUES (1);
    """)
    m.command = command
    with tempfile.TemporaryDirectory() as root:
        directory = Path(root) / 'archive'
        m.migrate(directory, True)
        assert query('destination', "SELECT id||':'||trusted||':'||trust_reason FROM vex_sources") == '42:true:original trust'
        assert query('destination', "SELECT nextval('vex_sources_id_seq')") == '101'
        assert query('destination', 'SELECT raw_text FROM vex_documents') == 'original payload'
        m.retire_source(directory, True)
        assert query('source', 'SELECT count(*) FROM native_vex_probe') == '1'
        assert json.loads((directory / 'manifest.json').read_text())['source_retained'] is False
    print('PG16 migration integration passed: FK order, IDs, trust, content, sequences, scoped retirement.')
finally:
    subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True)
