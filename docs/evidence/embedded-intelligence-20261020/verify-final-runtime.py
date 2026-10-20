"""Bounded final-image smoke; no corpus aggregates or persistent fixture writes.
Run only after the signed expanded package is already installed.
"""
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from time import perf_counter
from types import SimpleNamespace


def require(value, message):
    if not value:
        raise RuntimeError(message)


def same_evaluation(left, right):
    # SQL row order is not an evaluator contract; compare retained evidence by ID.
    def ordered(value):
        return dict(value, statements=sorted(value['statements'], key=lambda row: row['id']))
    return ordered(left) == ordered(right)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifier-path', type=Path, default=Path('/tmp/verify-embedded-intelligence.py'))
    parser.add_argument('--report', type=Path, default=Path('/tmp/final-smoke.json'))
    args = parser.parse_args()
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'scope': 'Read-only real corpus smoke plus authenticated unchanged install status update. No database_coverage, statement totals, schema creation, service fixture or assessment writes.',
              'latency_scope': 'Single-process handler/function latency, including SQL; excludes HTTP transport and authentication middleware. Existing database/cache state is preserved.'}
    started = perf_counter()
    phase = ['setup']
    counts = Counter()
    traces = {}
    writes = []
    blocked = []
    engine = None
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex
    try:
        require(bool(os.environ.get('DATABASE_URL')), 'DATABASE_URL must explicitly select the already imported database')
        from sqlalchemy import event, select
        from sqlalchemy.engine import make_url
        from sqlalchemy.orm import sessionmaker
        url = make_url(os.environ['DATABASE_URL'])
        require(url.get_backend_name() == 'postgresql', 'Final image smoke requires the existing PostgreSQL database')
        try:
            loopback = ipaddress.ip_address(url.host).is_loopback
        except (ValueError, TypeError):
            loopback = url.host == 'localhost'
        require(loopback, 'Only the driver-provided loopback PostgreSQL endpoint is permitted')
        port = url.port or 5432

        def permitted(address):
            if not isinstance(address, tuple) or len(address) < 2:
                return False
            try:
                local = ipaddress.ip_address(address[0]).is_loopback
            except ValueError:
                local = address[0] == 'localhost'
            return local and address[1] == port

        def guard(original):
            def connect(sock, address):
                if not permitted(address):
                    blocked.append(repr(address))
                    raise RuntimeError('Prohibited Python socket connection')
                return original(sock, address)
            return connect
        socket.socket.connect = guard(original_connect)
        socket.socket.connect_ex = guard(original_connect_ex)
        report['network_guard'] = {'python_socket_connect': 'Only configured loopback PostgreSQL port allowed',
                                  'limitation': 'Container network isolation is provided by the driver; native DB client calls are not intercepted by the Python socket guard.'}
        spec = importlib.util.spec_from_file_location('final_image_verifier', args.verifier_path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        from app.database import engine
        from app.embedded_intelligence import PACKAGE_DIR, canonical, _decode, install_package, package_status
        from app.intelligence_models import IntelligencePackageInstall, IntelligencePackageCatalog, IntelligencePackageMember, IntelligenceRecord, IntelligencePackageState
        from app.packaged_risk_intelligence import packaged_catalog_token
        from app.auth import AuthContext
        from app import risk_routes, risk_worker, vex_intelligence as vex
        factory = sessionmaker(bind=engine)

        @event.listens_for(engine, 'connect')
        def set_timeout(connection, _):
            with connection.cursor() as cursor:
                cursor.execute("SET statement_timeout = '60s'")

        @event.listens_for(engine, 'before_cursor_execute')
        def observe(connection, cursor, statement, parameters, context, executemany):
            normalized = ' '.join(statement.split())
            upper = normalized.upper()
            counts[phase[0]] += 1
            allowed_update = (phase[0] == 'repeat_install' and upper.startswith('UPDATE INTELLIGENCE_PACKAGE_STATE SET '))
            require(upper.startswith(('SELECT ', 'SHOW ')) or allowed_update,
                    'Smoke refused unexpected SQL mutation/command: ' + normalized[:160])
            if allowed_update:
                writes.append({'phase': phase[0], 'sql': normalized})
            if upper.startswith('SELECT '):
                require('vex_documents.raw_text' not in normalized, 'Runtime lookup fetched full raw document text')
                require(not re.search(r'\bintelligence_package_installs\.manifest(?:\s+AS\s+\w+)?\s*(?:,|FROM\b)', normalized, re.I),
                        'Runtime fetched a complete stored package manifest')
                require(not ('FROM vex_statements' in normalized and 'count(' in normalized.lower() and 'bounded_statements' not in normalized),
                        'Smoke refused an unbounded VEX statement aggregate')
            signature = hashlib.sha256(normalized.encode()).hexdigest()
            key = (phase[0], signature)
            if key not in traces:
                require(len(traces) < 2000, 'Smoke query trace exceeded its own bound')
                values = parameters if isinstance(parameters, dict) else {}
                traces[key] = {'phase': phase[0], 'sql_sha256': signature, 'sql': normalized[:8000], 'count': 0,
                               'bound_parameters': {str(k): v for k, v in values.items()
                                                    if type(v) is int and ('bound' in str(k) or 'param' in str(k))}}
            traces[key]['count'] += 1

        # Read only the small shipped manifest. Authentication remains mandatory in install_package.
        path = PACKAGE_DIR / 'manifest.json'
        require(path.stat().st_size <= 2 * 1024 * 1024, 'Shipped manifest exceeds loader bound')
        manifest = _decode(path.read_bytes())
        phase[0] = 'installed_precondition'
        with factory() as db:
            current = db.execute(select(IntelligencePackageInstall.id, IntelligencePackageInstall.sequence,
                IntelligencePackageInstall.version, IntelligencePackageInstall.manifest['_signed_manifest_sha256'].as_string().label('signed_hash'))
                .order_by(IntelligencePackageInstall.sequence.desc()).limit(1)).first()
            require(current is not None, 'No existing package install; import is prohibited in this smoke')
            require((current.sequence, current.version, current.signed_hash) ==
                    (manifest['sequence'], manifest['version'], hashlib.sha256(canonical(manifest)).hexdigest()),
                    'Shipped package is not the exact existing installed package')
            catalog_keys = set(db.scalars(select(IntelligencePackageCatalog.source_key).where(IntelligencePackageCatalog.install_id == current.id)))
            expected = {m['id'] for m in manifest['sources'] if m['id'] in ('cisa-kev', 'first-epss')}
            require(expected == {'cisa-kev', 'first-epss'} and expected <= catalog_keys, 'Missing current enrichment membership; migration is prohibited')
            require(db.get(IntelligencePackageState, 1) is not None, 'Missing package status; insertion is prohibited')
            installed_id = current.id
        report['package'] = {'version': current.version, 'sequence': current.sequence, 'signed_manifest_sha256': current.signed_hash,
                             'payload_sha256': manifest['payload_sha256'], 'payload_bytes': manifest['payload_bytes']}

        phase[0] = 'repeat_install'
        tick = perf_counter()
        outcome = install_package(factory)
        report['repeat_install'] = {'outcome': outcome, 'seconds': perf_counter() - tick,
                                    'verification': 'Actual loader re-verifies Ed25519 manifest and every ordered compressed payload byte before unchanged comparison.'}
        require(outcome == 'unchanged', 'Repeat install did not return unchanged')

        phase[0] = 'package_status'
        with factory() as db:
            tick = perf_counter()
            status = package_status(db)
            elapsed = perf_counter() - tick
        require(status['sequence'] == manifest['sequence'] and status['status'] == 'installed', 'Package status differs from signed installed package')
        require(not any(k.endswith('_sha256s') for m in status['sources'] for k in m), 'Public metadata contains membership arrays')
        report['package_status'] = {'seconds': elapsed, 'result': status}

        phase[0] = 'runtime_sources_api'
        assignment = SimpleNamespace(role=SimpleNamespace(name='Administrator', permissions=['config.manage']),
                                     service_id=None, group_id=None, group=None)
        auth = AuthContext(user=SimpleNamespace(id=None, username='offline-smoke', role_assignments=[assignment]),
                           session=SimpleNamespace(csrf_token='offline-smoke'))
        with factory() as db:
            tick = perf_counter()
            api = risk_routes.sources(auth=auth, db=db)
            elapsed = perf_counter() - tick
        source_traces = [t for t in traces.values() if t['phase'] == phase[0] and 'bounded_statements' in t['sql']]
        require(source_traces and sum(t['count'] for t in source_traces) == len(api['items']), 'Sources API did not use bounded per-source probes')
        for trace in source_traces:
            require(trace['sql'].upper().count('LIMIT') >= 2 and trace['bound_parameters'].get('bound') == risk_routes.SOURCE_STATEMENT_COUNT_LIMIT + 1,
                    'Sources API probe is missing document-first/outer query bounds')
        require(all(item['statement_count_state'] in ('exact', 'lower_bound') and
                    (item['statements'] is not None if item['statement_count_state'] == 'exact' else item['statements'] is None)
                    for item in api['items']), 'API presented a bounded probe as an exact full count')
        report['runtime_sources_api'] = {'path': '/api/risk/sources', 'invocation': 'Actual route handler with in-memory authorized diagnostic AuthContext; no HTTP session created.',
                                        'seconds': elapsed, 'items': api['items'], 'embedded_version': api['embedded_package']['version'],
                                        'statement_probe_limit': risk_routes.SOURCE_STATEMENT_COUNT_LIMIT + 1,
                                        'count_scope': 'Retained history; exact up to configured bound, lower-bound indication thereafter.'}
        phase[0] = 'catalog_token'
        with factory() as db:
            tick = perf_counter()
            token = packaged_catalog_token(db)
            report['catalog_token'] = {'value': token, 'seconds': perf_counter() - tick}

        now = datetime.now(timezone.utc)
        phase[0] = 'scoped_lookup_examples'
        with factory() as db:
            report['scoped_lookup_examples'] = verifier.scoped_lookup_examples(db, manifest, now)

        phase[0] = 'bounded_enrichment_setup'
        bounded_manifest = deepcopy(manifest)
        with factory() as db:
            for key, member_field in (('cisa-kev', 'exploitation_sha256s'), ('first-epss', 'risk_enrichment_sha256s')):
                catalog = db.execute(select(IntelligencePackageCatalog.id, IntelligencePackageCatalog.metadata_json).where(
                    IntelligencePackageCatalog.install_id == installed_id, IntelligencePackageCatalog.source_key == key)).one()
                query = select(IntelligenceRecord.sha256).join(IntelligencePackageMember,
                    IntelligencePackageMember.record_id == IntelligenceRecord.id).where(IntelligencePackageMember.catalog_id == catalog.id)
                if key == 'first-epss':
                    query = query.where(IntelligenceRecord.data['epss'].as_float() > 0)
                hashes = list(db.scalars(query.limit(128)))
                require(hashes, 'No positive signed member found for ' + key)
                meta = next(m for m in bounded_manifest['sources'] if m['id'] == key)
                meta.update(catalog.metadata_json)
                meta[member_field] = hashes
            phase[0] = 'enrichment_examples'
            report.update(verifier.enrichment_examples(db, SimpleNamespace(manifest=bounded_manifest), now))
        report['enrichment_selection'] = 'At most 128 hashes per catalog projected from current signed membership; full historical DB manifest is never loaded.'

        phase[0] = 'worker_package_identity'
        worker_results = {}
        image_digest = 'sha256:' + 'a' * 64
        with factory() as db:
            for key, example in report['scoped_lookup_examples'].items():
                identity = example['identity']
                evidence = {'purl': identity['purl'], 'distro': identity.get('distro'),
                            'csaf_product_context': identity.get('csaf_product_context')}
                if identity.get('digest'):
                    evidence['package_digest'] = identity['digest']
                observation = SimpleNamespace(evidence=evidence, installed_version=identity['version'], image_digest=image_digest)
                context = risk_worker._observation_vex_context(observation)
                require(context.get('digest') == identity.get('digest'), 'Worker substituted containing-image digest for package digest')
                historical_at = verifier.aware(example['source_as_of']['as_of'])
                tick = perf_counter()
                actual_now = vex.evaluate(db, example['cve'], context, as_of=now)
                actual_then = vex.evaluate(db, example['cve'], context, as_of=historical_at)
                require(same_evaluation(actual_now, example['current']) and same_evaluation(actual_then, example['source_as_of']['result']), 'Worker identity changed exact real package applicability')
                wrong_version = SimpleNamespace(evidence=evidence, installed_version=identity['version'] + '-smoke-mismatch', image_digest=image_digest)
                wrong_context = risk_worker._observation_vex_context(wrong_version)
                version_result = vex.evaluate(db, example['cve'], wrong_context, as_of=historical_at)
                wrong_digest = dict(context, digest=image_digest)
                digest_result = vex.evaluate(db, example['cve'], wrong_digest, as_of=historical_at)
                require(version_result['status'] == 'no_vex' and digest_result['status'] == 'no_vex', 'Worker negative version/digest control acquired applicability')
                worker_results[key] = {'cve': example['cve'], 'context': context, 'current': actual_now,
                    'source_as_of': {'as_of': historical_at.isoformat(), 'result': actual_then},
                    'wrong_version': version_result, 'incorrect_image_as_package_digest': digest_result,
                    'seconds': perf_counter() - tick}
        report['worker_package_digest_separation'] = {'scope': 'Actual worker context helper followed by actual database evaluator, using the selected real vendor identity; refresh_assessment is not invoked because it would persist an assessment.',
            'containing_image_digest': image_digest, 'control_provenance': 'Synthetic containing-image digest only; CVEs, package versions, PURLs, vendor context and VEX evidence come from the installed corpus.', 'examples': worker_results}

        phase[0] = 'bounded_query_controls'
        examples = list(report['scoped_lookup_examples'].values())
        inputs = [{'cve': e['cve'], 'context': e['identity']} for e in examples]
        with factory() as db:
            tick = perf_counter()
            batched = vex.evaluate_batch(db, inputs, as_of=now)
            require(len(batched) == len(examples) and all(same_evaluation(result, e['current']) for result, e in zip(batched, examples)), 'Exact-pair batch differs from individual evaluation')
            default_limit = vex.MAX_EVALUATION_CANDIDATES
            try:
                # Process-local diagnostic only. One known retained row must overflow zero.
                vex.MAX_EVALUATION_CANDIDATES = 0
                overflow = vex.evaluate_batch(db, inputs[:1], as_of=now)[0]
            finally:
                vex.MAX_EVALUATION_CANDIDATES = default_limit
            require(overflow['status'] == 'under_investigation' and overflow['statements'] == [] and overflow['reasons'] == ['candidate_limit'],
                    'Candidate overflow did not fail conservatively')
            elapsed = perf_counter() - tick
        candidate_traces = [t for t in traces.values() if t['phase'] == phase[0] and 'vex_statements.cve, vex_statements.product_id) IN' in t['sql']]
        require(candidate_traces and all(' LIMIT ' in t['sql'] and 'vex_documents.raw_text' not in t['sql'] for t in candidate_traces),
                'Candidate reads are not bounded exact-pair metadata queries')
        limits = {v for t in candidate_traces for v in t['bound_parameters'].values()}
        require({default_limit + 1, 1} <= limits, 'Expected normal and diagnostic candidate limits were not issued')
        report['bounded_queries'] = {'production_candidate_limit': default_limit, 'normal_batch_results': batched,
            'overflow_control': {'temporary_process_local_limit': 0, 'result': overflow, 'restored_limit': vex.MAX_EVALUATION_CANDIDATES},
            'seconds': elapsed, 'exact_pairs': True, 'raw_document_text_loaded': False, 'complete_database_manifest_loaded': False,
            'no_full_statement_aggregate': True, 'candidate_query_examples': candidate_traces}
        require(not blocked, 'Prohibited outbound connection attempted')
        report['passed'] = True
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
        report['failed_phase'] = phase[0]
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        report['seconds_total'] = perf_counter() - started
        report['sql_statement_counts'] = dict(counts)
        report['sql_trace'] = list(traces.values())
        report['sql_writes'] = writes
        report['blocked_connections'] = blocked
        args.report.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.report.with_suffix(args.report.suffix + '.tmp')
        temporary.write_text(json.dumps(report, indent=2, default=str), encoding='utf-8')
        temporary.replace(args.report)
        if engine is not None:
            engine.dispose()
        socket.socket.connect, socket.socket.connect_ex = original_connect, original_connect_ex
    print(json.dumps({'passed': report['passed'], 'report': str(args.report), 'seconds': report['seconds_total'],
                      'failed_phase': report.get('failed_phase'), 'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
