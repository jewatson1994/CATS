"""Full database backups; publication requires an isolated, successful restore."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import fcntl

ROOT = Path(os.environ.get('BACKUP_DIR', '/backups'))
UTC = dt.timezone.utc


def run(args, env=None):
    # Database output may contain credentials or sensitive rows. Never log it.
    result = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {result.returncode})')
    return result.stdout.decode()


def status(**values):
    target = ROOT / 'status.json'
    previous = json.loads(target.read_text()) if target.exists() else {}
    previous.update(values)
    tmp = ROOT / '.status.tmp'
    tmp.write_text(json.dumps(previous))
    tmp.replace(target)


def next_run(now, schedule):
    if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', schedule):
        raise ValueError('BACKUP_UTC_TIME must be HH:MM in UTC')
    hour, minute = map(int, schedule.split(':'))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return candidate if candidate > now else candidate + dt.timedelta(days=1)


def checksum(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def restore_verify(dump):
    # A fresh cluster with no TCP listener cannot resolve to the production DB.
    import pwd
    account = pwd.getpwnam('postgres')
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    with tempfile.TemporaryDirectory(prefix='backup-verify-') as directory:
        scratch = Path(directory)
        os.chown(scratch, account.pw_uid, account.pw_gid)
        data = scratch / 'data'
        prefix = ['su-exec', 'postgres']
        run(prefix + ['initdb', '-D', str(data), '-A', 'trust', '--no-locale'], env)
        started = False
        try:
            run(prefix + ['pg_ctl', '-D', str(data), '-l', str(scratch / 'server.log'),
                          '-o', f"-c listen_addresses='' -k {scratch}", '-w', 'start'], env)
            started = True
            connection = ['-h', str(scratch), '-U', 'postgres', '-d', 'postgres']
            run(['pg_restore', *connection, '--exit-on-error', '--no-owner', '--no-acl', str(dump)], env)
            sql = ['psql', *connection, '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c']
            required = os.environ.get('BACKUP_REQUIRED_TABLES', 'public.services,public.users,public.executions').split(',')
            for table in required:
                if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*\.[A-Za-z_][A-Za-z_0-9]*', table):
                    raise ValueError('Invalid BACKUP_REQUIRED_TABLES identifier')
                if run(sql + [f"SELECT to_regclass('{table}') IS NOT NULL"], env).strip() != 't':
                    raise RuntimeError('Required portal table missing in restored backup')
            tables = run(sql + ["SELECT format('%I.%I', schemaname, tablename) FROM pg_tables "
                                "WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1"], env).splitlines()
            for table in tables:
                run(sql + [f'SELECT count(*) FROM {table}'], env)
            run(sql + ['SELECT 1 / CASE WHEN EXISTS (SELECT 1 FROM pg_index WHERE NOT indisvalid) THEN 0 ELSE 1 END'], env)
            return len(tables)
        finally:
            if started:
                run(prefix + ['pg_ctl', '-D', str(data), '-m', 'immediate', '-w', 'stop'], env)


def retain(count):
    # Only this program's published, verified directories are eligible.
    candidates = []
    for directory in ROOT.glob('backup-*'):
        manifest = directory / 'manifest.json'
        if directory.is_symlink() or not directory.is_dir() or not manifest.exists():
            continue
        try:
            info = json.loads(manifest.read_text())
            if info.get('verified') is True and (directory / 'database.dump').is_file():
                candidates.append(directory)
        except (ValueError, OSError):
            continue
    for directory in sorted(candidates, reverse=True)[count:]:
        shutil.rmtree(directory)


def backup():
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    with (ROOT / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        count = int(os.environ.get('BACKUP_RETENTION_COUNT', '7'))
        if count < 1:
            raise ValueError('BACKUP_RETENTION_COUNT must be at least one')
        status(state='running', attempt=time.time())
        staging = Path(tempfile.mkdtemp(prefix='.pending-', dir=ROOT))
        try:
            dump = staging / 'database.dump'
            run(['pg_dump', '--format=custom', '--file', str(dump)])
            tables = restore_verify(dump)
            digest = checksum(dump)
            stamp = dt.datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
            (staging / 'SHA256SUMS').write_text(f'{digest}  database.dump\n')
            (staging / 'manifest.json').write_text(json.dumps({
                'verified': True, 'created_utc': stamp, 'sha256': digest,
                'tables_read': tables, 'scope': 'entire database, all schemas',
                'verification': 'isolated PostgreSQL restore, required tables, all table counts, index validity'}))
            for file in staging.iterdir():
                with file.open('rb') as stream:
                    os.fsync(stream.fileno())
            destination = ROOT / f'backup-{stamp}-{uuid.uuid4().hex[:8]}'
            staging.rename(destination)
            parent = os.open(ROOT, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            status(state='ok', last_success=time.time(), backup=destination.name)
            retain(count)
            print('Backup restored, verified, and published.', flush=True)
        except Exception:
            status(state='failed', failed_at=time.time())
            raise
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def main(mode):
    if mode == 'health':
        try:
            info = json.loads((ROOT / 'status.json').read_text())
            fresh = time.time() - info.get('last_success', 0) < 27 * 3600
            return 0 if info.get('state') in ('ok', 'running') and fresh else 1
        except (ValueError, OSError):
            return 1
    if mode not in ('once', 'schedule'):
        raise ValueError('Use once, schedule, or health')
    schedule = os.environ.get('BACKUP_UTC_TIME', '03:00')
    next_run(dt.datetime.now(UTC), schedule)
    while True:
        try:
            backup()
        except Exception as exc:
            print(f'Backup FAILED ({type(exc).__name__}); last published backup preserved.', file=sys.stderr, flush=True)
            if mode == 'once':
                return 1
        if mode == 'once':
            return 0
        deadline = next_run(dt.datetime.now(UTC), schedule)
        while dt.datetime.now(UTC) < deadline:
            time.sleep(min(30, (deadline - dt.datetime.now(UTC)).total_seconds()))


if __name__ == '__main__':
    os.umask(0o077)
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'schedule'))
