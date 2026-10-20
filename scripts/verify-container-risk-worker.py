#!/usr/bin/env python3
"""Retained scanner evidence -> actual classification and risk worker, then rollback.

Run with DATABASE_URL selecting the isolated, already populated PostgreSQL DB.
No schema creation, importer, source injection or network retrieval occurs on
the populated database. Import-time application schema setup is isolated to an
in-memory SQLite database; no application lifespan runs. The CLI refuses commits and writes only temporary service
assessment tables inside one outer transaction. PostgreSQL sequences may advance.
The pytest companion alone supplies clearly identified synthetic VEX statements.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
from threading import Barrier
from time import perf_counter
import uuid

PRIMARY = ('ubuntu', 'debian-12-9', 'alpine-3-20-0', 'redhat-ubi', 'suse',
           'python', 'node-image-catalogers')
MAX_BYTES = 50 * 1024 * 1024
MAX_OBSERVATIONS = 100000


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def load_captures(directory, image_keys=PRIMARY):
    captures = []
    for key in image_keys:
        if not re.fullmatch(r'[a-z0-9-]+', key):
            raise ValueError('Invalid retained capture key')
        path = directory / (key + '.json')
        if path.stat().st_size > MAX_BYTES:
            raise ValueError('Retained capture exceeds size bound')
        raw = path.read_bytes()
        capture = json.loads(raw)
        if (capture.get('capture_kind') != 'live_scan'
                or capture.get('capture', {}).get('scanner_exit_code') != 0
                or capture.get('image_key') != key):
            raise ValueError('Expected successful retained live scanner capture')
        if capture['counts']['vulnerability_findings'] != len(capture['findings']):
            raise ValueError('Capture finding count does not match retained rows')
        captures.append((capture, hashlib.sha256(raw).hexdigest()))
    if not 0 < sum(len(c['findings']) for c, _ in captures) <= MAX_OBSERVATIONS:
        raise ValueError('Retained observation count outside worker bounds')
    return captures


def stage_service(db, captures, run_key):
    """Preserve CVE grouping used by the application's unique service/CVE key."""
    from app.models import Service, Group, ServiceGroup, Execution, Finding, FindingObservation
    from app.simplified_queries import observation_metadata
    service = Service(service_key=run_key, name='Rollback-only retained scanner audit')
    # Fixture ownership uses Core inserts so rollback-only staging does not
    # rewrite the shared authorization revision or serialize concurrent jobs.
    # Actual configuration resolution and classification still read these rows.
    from sqlalchemy import insert
    group_id = db.connection().scalar(insert(Group.__table__).values(
        name=run_key, description='Rollback-only audit owning group').returning(Group.id))
    db.add(service)
    db.flush()
    db.connection().execute(insert(ServiceGroup.__table__).values(service_id=service.id, group_id=group_id))
    scanned_at = max(datetime.fromisoformat(c['capture']['completed_at']) for c, _ in captures)
    execution = Execution(service_id=service.id, execution_key=run_key, scanned_at=scanned_at,
        complete=True, raw_payload={'audit': 'retained normalized real scans',
            'captures': [{'image_key': c['image_key'], 'sha256': sha} for c, sha in captures]})
    db.add(execution)
    db.flush()
    by_cve = {}
    ranks = ('unknown', 'negligible', 'low', 'medium', 'high', 'critical')
    for capture, _ in captures:
        for row in capture['findings']:
            severity = row['severity'].lower()
            if severity not in ranks:
                severity = 'unknown'
            old = by_cve.get(row['cve'])
            if old is None:
                by_cve[row['cve']] = Finding(service_id=service.id, cve=row['cve'],
                    cve_normalized=row['cve'].upper(), severity=severity,
                    severity_folded=severity, search_folded=row['cve'].lower(),
                    first_seen=scanned_at, episode_started=scanned_at,
                    last_seen=scanned_at, active=True)
            elif ranks.index(severity) > ranks.index(old.severity):
                old.severity = old.severity_folded = severity
    db.add_all(by_cve.values())
    db.flush()
    observed = {}
    for capture, sha in captures:
        for row in capture['findings']:
            evidence = {**deepcopy(row.get('evidence', {})), 'purl': row['purl'],
                'aliases': row.get('aliases', []), 'scanner_distro': capture['distro'],
                'scanner_source': capture['sbom_source'],
                'scanner_artifact': {'id': row['artifact_id'], 'name': row['package'],
                    'version': row['installed_version'], 'type': row['ecosystem'],
                    'purl': row['purl'], 'metadata': row.get('evidence', {}).get('artifact_metadata', {})},
                'retained_capture': {'image_key': capture['image_key'], 'sha256': sha}}
            fixes = evidence.get('fix', {}).get('versions', [])
            observation = FindingObservation(finding_id=by_cve[row['cve']].id,
                execution_id=execution.id, image=capture['image'], image_digest=capture['image_digest'],
                package=row['package'], installed_version=row['installed_version'],
                fixed_version=', '.join(fixes) if fixes else None, evidence=evidence,
                **observation_metadata({'package': row['package'],
                    'fixed_version': ', '.join(fixes) if fixes else None}))
            db.add(observation)
            observed[id(observation)] = (observation, deepcopy(row), capture['image_key'])
    db.flush()
    observed = {observation.id: {'row': row, 'image_key': key, 'evidence': deepcopy(observation.evidence),
        'image': observation.image, 'image_digest': observation.image_digest}
        for observation, row, key in observed.values()}
    return service.id, execution.id, observed


def snapshot_rows(db, service_id, execution_id):
    from sqlalchemy import select
    from app.models import (Finding, FindingObservation, FindingClassification,
                            FindingClassificationState, ExceptionRecord)
    snapshots = {}
    for model, predicate in (
        (Finding, Finding.service_id == service_id),
        (FindingObservation, FindingObservation.execution_id == execution_id),
        (FindingClassification, FindingClassification.service_id == service_id),
        (FindingClassificationState, FindingClassificationState.service_id == service_id),
        (ExceptionRecord, ExceptionRecord.finding_id.in_(select(Finding.id).where(Finding.service_id == service_id))),
    ):
        query = select(model.__table__).where(predicate).order_by(*model.__table__.primary_key.columns)
        snapshots[model.__tablename__] = [dict(row) for row in db.execute(query).mappings()]
    return snapshots


def assess_staged(db, service_id, execution_id, observed, now, barrier=None):
    from sqlalchemy import select
    from app import finding_classification as fc
    from app.risk_worker import refresh_assessment
    from app.risk_models import RiskAssessment
    from app.models import ServiceGroup
    groups = db.scalars(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service_id)).all()
    assert len(groups) == 1, 'Audit service must have exactly one owning group'
    config = fc._service_configuration(db, service_id)
    classification_started = perf_counter()
    # Real classification SQL, including exceptions and eligibility. The same
    # external connection retains its outer transaction across internal commits.
    fc.refresh(db.get_bind(), service_id, now, configuration=config, latest=execution_id)
    db.expire_all()
    db.info.pop(fc._CACHE, None)
    assert fc.status(db, service_id, config, now, execution_id)[0] == 'current'
    classification_seconds = perf_counter() - classification_started
    before = snapshot_rows(db, service_id, execution_id)
    if barrier is not None:
        barrier.wait(timeout=60)
    metrics = db.connection().info.setdefault('audit_metrics', {'sql_statements': 0, 'worker_sql_statements': 0})
    metrics['phase'] = 'worker'
    started = perf_counter()
    assessment = refresh_assessment(db, service_id, now)
    elapsed = perf_counter() - started
    metrics['phase'] = 'verification'
    assessment_id = assessment.id
    db.expire(assessment)
    assessment = db.scalars(select(RiskAssessment).where(RiskAssessment.id == assessment_id)).one()
    after = snapshot_rows(db, service_id, execution_id)
    assert before == after, 'Risk assessment changed findings, evidence, classification or exceptions'
    details = deepcopy(assessment.details)
    findings = {record['row']['cve'] for record in observed.values()}
    assert len(details) == len(findings) == assessment.summary['findings']
    assert assessment.summary['observations'] == len(observed)
    assert assessment.summary['coverage']['total_findings'] == len(findings)
    observations = {o['observation_id']: o for entry in details for o in entry['observations']}
    assert set(observations) == set(observed)
    for oid, expected in observed.items():
        result, row = observations[oid], expected['row']
        assert result['identity']['raw_purl'] == row['purl']
        assert result['identity']['raw_installed_version'] == row['installed_version']
        assert result['package'] == row['package']
        assert result['image'] == expected['image']
        assert result['image_digest'] == expected['image_digest']
        assert result['identity']['scanner_artifact']['id'] == row['artifact_id']
        assert result['identity']['aliases'] == row.get('aliases', [])[:8]
        assert result['classification'] is not None
    expected_images = {}
    for expected in observed.values():
        expected_images.setdefault((expected['image'], expected['image_digest']), set()).add(expected['row']['cve'])
    actual_images = {(image['image'], image['image_digest']): image['total_findings']
                     for image in assessment.summary['coverage']['images']}
    assert actual_images == {key: len(values) for key, values in expected_images.items()}
    report = {'assessment_id_before_rollback': assessment_id, 'service_id_before_rollback': service_id,
        'execution_id_before_rollback': execution_id, 'seconds_worker': round(elapsed, 6),
        'classification_and_scan_rows_unchanged': True, 'owning_groups': len(groups),
        'seconds_classification': round(classification_seconds, 6),
        'worker_sql_statements': metrics['worker_sql_statements'],
        'scope': 'retained normalized scanner observations -> real classification -> real saved risk assessment; HTTP ingest and durable queue scheduling are outside this check',
        'classification_snapshot_sha256': digest(before),
        'denominator': 'unique original scanner vulnerability identifiers (CVE or advisory ID) per service; database uniqueness is service_id + cve',
        'observations': len(observed), 'findings': len(findings),
        'summary': deepcopy(assessment.summary), 'provenance': deepcopy(assessment.provenance),
        'details_sha256': digest(details),
        'vex_statuses': dict(Counter(o['vex']['status'] for o in observations.values())),
        'identity_reasons': dict(Counter(reason for o in observations.values() for reason in o['identity']['reasons']))}
    return report, details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--details', type=Path, required=True)
    parser.add_argument('--app-path', type=Path, default=Path('/workspace/portal'))
    parser.add_argument('--images', nargs='+', default=list(PRIMARY))
    parser.add_argument('--as-of')
    parser.add_argument('--jobs', type=int, choices=(1, 4), default=1)
    args = parser.parse_args()
    sys.path.insert(0, str(args.app_path))
    from sqlalchemy import create_engine, event, select
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import Session
    url = make_url(os.environ['DATABASE_URL'])
    if url.get_backend_name() != 'postgresql' or url.host not in ('localhost', '127.0.0.1', '::1'):
        parser.error('DATABASE_URL must select the isolated loopback PostgreSQL database')
    original_connect = socket.socket.connect
    def guarded_connect(sock, address):
        if isinstance(address, tuple) and address[0] in ('localhost', '127.0.0.1', '::1') and address[1] == (url.port or 5432):
            return original_connect(sock, address)
        raise RuntimeError('External network access is prohibited during offline verification')
    socket.socket.connect = guarded_connect
    # main has import-time schema migration. Keep its global engines isolated:
    # all actual corpus operations below use explicitly passed PG connections.
    os.environ['DATABASE_URL'] = 'sqlite://'
    os.environ['CATS_CLASSIFICATION_BACKGROUND'] = 'false'
    from app import main as application  # noqa: F401
    from app.database import engine as application_engine
    assert application_engine.dialect.name == 'sqlite'
    from app.models import Group, ServiceGroup, Service, ServicePosture, DependencyProjection, Execution, Finding, FindingObservation, FindingClassification, FindingClassificationState, FindingClassificationChange
    from app.risk_models import RiskAssessment
    from app.vex_intelligence import intelligence_token
    from app.packaged_risk_intelligence import packaged_catalog_token
    # No app lifespan is executed; never create schema on the actual database.
    engine = create_engine(url, connect_args={'options': '-c statement_timeout=60000 -c jit=off'})
    allowed = {'services', 'executions', 'findings', 'finding_observations', 'finding_classifications',
        'finding_classification_state', 'finding_classification_changes', 'risk_assessments', 'service_posture',
        'groups', 'service_groups', 'dependency_projections'}
    @event.listens_for(engine, 'commit')
    def refuse_commit(connection):
        raise RuntimeError('This verifier must never commit')
    @event.listens_for(engine, 'before_cursor_execute')
    def guard_writes(connection, cursor, statement, parameters, context, executemany):
        metrics = connection.info.get('audit_metrics')
        if metrics is not None:
            metrics['sql_statements'] += 1
            if metrics.get('phase') == 'worker':
                metrics['worker_sql_statements'] += 1
        verb = statement.lstrip().split(None, 1)[0].upper()
        if verb in ('SELECT', 'SHOW', 'SAVEPOINT', 'RELEASE', 'ROLLBACK'):
            return
        compiled = getattr(getattr(context, 'compiled', None), 'statement', None)
        if getattr(compiled, 'is_select', False):
            return
        table = getattr(getattr(compiled, 'table', None), 'name', None)
        mutation = any(getattr(compiled, flag, False) for flag in ('is_insert', 'is_update', 'is_delete'))
        if not mutation or table not in allowed:
            raise RuntimeError(f'Unexpected SQL mutation in rollback-only worker verifier: {verb} table={table}')
        if metrics is not None:
            metrics['mutations'][table] += 1
    captures = load_captures(args.evidence, args.images)
    now = datetime.fromisoformat(args.as_of.replace('Z', '+00:00')) if args.as_of else datetime.now(timezone.utc)
    if now.tzinfo is None:
        parser.error('--as-of must include a timezone')
    barrier = Barrier(args.jobs) if args.jobs > 1 else None
    def run_job(index):
        key = 'retained-worker-audit-' + uuid.uuid4().hex
        metrics = {'sql_statements': 0, 'worker_sql_statements': 0, 'mutations': Counter(), 'phase': 'staging'}
        try:
            with engine.connect() as connection:
                connection.info['audit_metrics'] = metrics
                transaction = connection.begin()
                try:
                    with Session(bind=connection, join_transaction_mode='rollback_only') as db:
                        before_tokens = (intelligence_token(db), packaged_catalog_token(db))
                        service_id, execution_id, observed = stage_service(db, captures, key)
                        report, details = assess_staged(db, service_id, execution_id, observed, now, barrier)
                        assert before_tokens == (intelligence_token(db), packaged_catalog_token(db)), 'Intelligence changed during verification'
                        assert transaction.is_active, 'Outer transaction unexpectedly ended'
                finally:
                    if transaction.is_active:
                        transaction.rollback()
                    connection.info.pop('audit_metrics', None)
            with Session(engine) as check:
                assert check.scalar(select(Service.id).where(Service.service_key == key)) is None
                assert check.scalar(select(Group.id).where(Group.name == key)) is None
                checks = ((Execution, Execution.service_id), (Finding, Finding.service_id),
                    (ServiceGroup, ServiceGroup.service_id), (ServicePosture, ServicePosture.service_id),
                    (DependencyProjection, DependencyProjection.execution_id),
                    (FindingObservation, FindingObservation.execution_id), (FindingClassification, FindingClassification.service_id),
                    (FindingClassificationState, FindingClassificationState.service_id),
                    (FindingClassificationChange, FindingClassificationChange.service_id), (RiskAssessment, RiskAssessment.service_id))
                for model, column in checks:
                    target = execution_id if model in (FindingObservation, DependencyProjection) else service_id
                    assert check.execute(select(column).where(column == target).limit(1)).first() is None
                assert before_tokens == (intelligence_token(check), packaged_catalog_token(check))
            report.update(job=index, as_of=now.isoformat(), inputs=[{'image_key': c['image_key'], 'sha256': sha,
                'capture_kind': c['capture_kind'], 'captured_at': c['capture']['completed_at'],
                'observations': len(c['findings'])} for c, sha in captures],
                fixture_vex_injected=False, intelligence_tokens_unchanged=True, rollback_verified=True,
                commits_allowed=False, database_note='No persistent rows; PostgreSQL sequences may advance',
                global_application_engine='disposable in-memory SQLite; actual work explicitly bound to populated PostgreSQL',
                sql_statements_including_staging_and_verification=metrics['sql_statements'],
                mutations_before_rollback=dict(metrics['mutations']))
            return report, details
        except BaseException:
            if barrier is not None:
                barrier.abort()
            raise
    import resource
    started = perf_counter()
    if args.jobs == 1:
        results = [run_job(1)]
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(run_job, range(1, args.jobs + 1)))
    wall_seconds = round(perf_counter() - started, 6)
    peak_rss_mib = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 3)
    if args.jobs == 1:
        report, details = results[0]
        report.update(seconds_total=wall_seconds, process_peak_rss_mib=peak_rss_mib)
        compact = {key: report[key] for key in ('findings', 'observations', 'seconds_worker', 'worker_sql_statements',
            'classification_and_scan_rows_unchanged', 'rollback_verified', 'fixture_vex_injected', 'process_peak_rss_mib')}
    else:
        report = {'jobs': [report for report, _ in results], 'concurrent_jobs': args.jobs,
            'concurrency': 'four independent real refresh_assessment calls, synchronized after retained evidence staging and real classification; no durable queue scheduling',
            'seconds_total_including_staging_and_verification': wall_seconds,
            'worker_sql_statements': sum(report['worker_sql_statements'] for report, _ in results),
            'process_peak_rss_mib': peak_rss_mib,
            'rollback_verified': all(report['rollback_verified'] for report, _ in results),
            'fixture_vex_injected': False}
        details = [{'job': report['job'], 'details': rows} for report, rows in results]
        compact = {key: value for key, value in report.items() if key != 'jobs'}
        compact['worker_seconds_per_job'] = [report['seconds_worker'] for report, _ in results]
    args.details.write_text(json.dumps(details, indent=2, default=str) + '\n', encoding='utf-8')
    args.report.write_text(json.dumps(report, indent=2, default=str) + '\n', encoding='utf-8')
    print(json.dumps(compact, default=str))
    engine.dispose()


if __name__ == '__main__':
    main()
