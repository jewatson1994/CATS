"""Durable offline materialization. Run: python -m app.risk_worker."""
from datetime import timedelta
from sqlalchemy import select, func
from .risk_profiles import (aware, utcnow, resolve_policy, validate_policy, DEFAULT_POLICY,
                            score_observation, digest, classification_token)
from .risk_models import RiskAssessment
from .packaged_risk_intelligence import overlay_packaged_kev, overlay_packaged_epss, packaged_catalog_token
from .models import Finding, FindingObservation, FindingClassification, FindingClassificationState, Execution

BATCH_SIZE = 250
MAX_OBSERVATIONS = 100000

def _catalog_current(snapshot, now, policy):
    expiries = []
    for name, date_key in (('kev', 'date_released'), ('epss', 'score_date')):
        feed = snapshot[name]
        raw = feed.get('metadata', {}).get(date_key) or feed.get('metadata', {}).get('date')
        if feed.get('state') != 'LOADED' or not raw:
            return False, []
        try:
            date = aware(raw)
        except (ValueError, TypeError):
            return False, []
        expiry = date + timedelta(hours=policy['max_age_hours'])
        if feed.get('metadata', {}).get('expires_at'):
            expiry = min(expiry, aware(feed['metadata']['expires_at']))
        if date > now or expiry <= now:
            return False, []
        expiries.append(expiry)
    return True, expiries

def _observation_vex_context(observation):
    from .container_intelligence import observation_identity
    return observation_identity(observation)['context']


def refresh_assessment(db, service_id, now=None, configuration=None, check=None):
    from . import finding_classification as fc
    from . import policy_data
    from .vex_intelligence import intelligence_token, _item_cves
    from .container_intelligence import (observation_identities, evaluate_container_batch,
        advisory_batch, coverage_report, valid_epss, identity_source_generation)
    now = aware(now or utcnow())
    from .native_vex import observation_excluded
    from .remediation_jobs import native_vex_token
    native_token = native_vex_token(db, service_id, now)
    from .native_vex_models import VexDispositionPolicy
    native_policy = db.get(VexDispositionPolicy, 1)
    native_enabled = bool(native_policy and native_policy.enabled)
    policy_row, assignment = resolve_policy(db, service_id)
    policy = validate_policy(configuration if configuration is not None else policy_row.configuration if policy_row else DEFAULT_POLICY)
    classification_config = fc._service_configuration(db, service_id)
    latest = fc.latest_execution_id(db, service_id)
    execution = db.get(Execution, latest) if latest is not None else None
    scan_expiry = aware(execution.scanned_at) + timedelta(hours=policy['max_age_hours']) if execution else None
    scan_current = bool(execution and execution.complete and aware(execution.scanned_at) <= now and scan_expiry > now)
    if fc.status(db, service_id, classification_config, now, latest)[0] != 'current':
        fc.refresh(db.get_bind(), service_id, now, configuration=classification_config, latest=latest)
        db.expire_all()
        db.info.pop(fc._CACHE, None)
    # Always use the existing freshness API before consuming its stored exception state.
    if fc.status(db, service_id, classification_config, now, latest)[0] != 'current':
        raise ValueError('Classification is changing; retry assessment')
    state = db.get(FindingClassificationState, service_id)
    initial_classification_token = classification_token(state)
    token = policy_data.risk_catalog_token()
    package_token = packaged_catalog_token(db)
    vex_token = intelligence_token(db)
    identity_generation = identity_source_generation(db, service_id)
    finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.service_id == service_id, Finding.active.is_(True))) or 0
    if finding_count > MAX_OBSERVATIONS:
        raise ValueError('Assessment exceeds bounded finding limit; narrow the service')
    cves = list(db.scalars(select(Finding.cve).where(Finding.service_id == service_id, Finding.active.is_(True))))
    snapshot = policy_data.review_intelligence_snapshot(cves, now.isoformat())
    catalog_metadata = {k: {'state': snapshot[k].get('state'), 'metadata': snapshot[k].get('metadata', {})} for k in ('kev', 'epss')}
    snapshot = overlay_packaged_kev(db, snapshot, now)
    snapshot = overlay_packaged_epss(db, snapshot, now)
    intel_current, expiries = _catalog_current(snapshot, now, policy)
    valid_until = min([now + timedelta(hours=policy['max_age_hours']), *expiries, *([aware(state.valid_until)] if state and state.valid_until else []), *([scan_expiry] if scan_current else [])])
    result, cursor, total = {}, 0, 0
    while True:
        if check:
            check()
        rows = db.execute(select(FindingObservation, Finding, FindingClassification)
            .join(Finding, Finding.id == FindingObservation.finding_id)
            .outerjoin(FindingClassification, FindingClassification.finding_id == Finding.id)
            .where(Finding.service_id == service_id, Finding.active.is_(True), FindingObservation.execution_id == latest,
                   FindingObservation.id > cursor).order_by(FindingObservation.id).limit(BATCH_SIZE)).all()
        if not rows:
            break
        total += len(rows)
        if total > MAX_OBSERVATIONS:
            raise ValueError('Assessment exceeds bounded observation limit; narrow the service')
        items = []
        identities = observation_identities(db, [observation for observation, _, _ in rows])
        for (observation, finding, classification), identity in zip(rows, identities):
            identity['observed_at'] = aware(execution.scanned_at).isoformat() if execution else None
            identity['evidence_valid_until'] = scan_expiry.isoformat() if scan_expiry else None
            items.append({'cve': finding.cve, 'context': identity['context'], 'identity': identity,
                          'aliases': identity['aliases']})
        native_excluded = set(db.scalars(select(FindingObservation.id).where(
            FindingObservation.id.in_([row[0].id for row in rows]), observation_excluded(FindingObservation.id, now))))
        vex_results = evaluate_container_batch(db, items, now)
        advisory_results = advisory_batch(db, items, now)
        aliases = sorted({cve for item in items for cve in _item_cves(item) if cve not in snapshot['findings']})
        alias_findings = {}
        batch_intel_current = intel_current
        if aliases:
            alias_snapshot = policy_data.review_intelligence_snapshot(aliases, now.isoformat())
            alias_snapshot = overlay_packaged_kev(db, alias_snapshot, now)
            alias_snapshot = overlay_packaged_epss(db, alias_snapshot, now)
            alias_findings = alias_snapshot['findings']
            alias_current, alias_expiries = _catalog_current(alias_snapshot, now, policy)
            batch_intel_current = intel_current and alias_current
            if alias_expiries:
                valid_until = min(valid_until, *alias_expiries)
        for (observation, finding, classification), item, vex, advisory in zip(rows, items, vex_results, advisory_results):
            required_signals = [snapshot['findings'].get(cve, alias_findings.get(cve, {})) for cve in _item_cves(item)]
            aliases_complete = not item['identity'].get('alias_overflow')
            enrichment_complete = aliases_complete and all(
                valid_epss(signal.get('epss')) and isinstance(signal.get('kev'), bool)
                for signal in required_signals)
            # A mapped GHSA needs enrichment for its CVEs, not the non-CVE label.
            # Keep any additional primary-ID signal only for risk increases.
            original = snapshot['findings'].get(finding.cve.upper(), {})
            signals = [*required_signals, original]
            scores = [v['epss'] for v in signals if valid_epss(v.get('epss'))]
            intel = {'kev': True if any(v.get('kev') is True for v in signals) else
                     False if aliases_complete and all(v.get('kev') is False for v in required_signals) else None,
                     'epss': max(scores) if scores else None}
            assessed = score_observation(policy, severity=finding.severity, epss=intel.get('epss'), kev=intel.get('kev'),
                age_days=max(0, (now - aware(finding.episode_started)).total_seconds() / 86400),
                excepted=bool(classification and classification.excepted), fixable=bool(observation.fixed_version),
                native_vex_excluded=(observation.id in native_excluded) if native_enabled else None,
                vex=vex, intelligence_current=batch_intel_current and scan_current and enrichment_complete)
            assessed['vex_excluded'] = observation.id in native_excluded
            if not scan_current:
                assessed['reasons'].append('Scan evidence is missing, incomplete, future-dated or stale')
            assessed.update(observation_id=observation.id, image=observation.image, image_digest=observation.image_digest,
                            package=observation.package, installed_version=observation.installed_version,
                            fixed_version=observation.fixed_version, epss=intel.get('epss'), kev=intel.get('kev'),
                            identity=item['identity'], advisory=advisory,
                            classification={key: getattr(classification, key) for key in ('eligible', 'noncompliant_rule', 'excepted', 'group_id')} if classification else None)
            entry = result.setdefault(finding.id, {'finding_id': finding.id, 'cve': finding.cve, 'observations': []})
            entry['observations'].append(assessed)
            for evidence in (vex, advisory):
                if evidence.get('valid_until'):
                    valid_until = min(valid_until, aware(evidence['valid_until']))
        cursor = rows[-1][0].id
        # Detach observations to keep ORM identity state bounded across batches.
        for observation, finding, classification in rows:
            db.expunge(observation)
    # Active findings absent from latest scan are uncertain, never silently dropped.
    for finding in db.scalars(select(Finding).where(Finding.service_id == service_id, Finding.active.is_(True)).execution_options(yield_per=BATCH_SIZE)):
        if finding.id not in result:
            intel = snapshot['findings'].get(finding.cve.upper(), {})
            assessed = score_observation(policy, severity=finding.severity, epss=intel.get('epss'), kev=intel.get('kev'),
                age_days=max(0, (now - aware(finding.episode_started)).total_seconds() / 86400), intelligence_current=False)
            assessed['reasons'].append('No observation in latest execution')
            result[finding.id] = {'finding_id': finding.id, 'cve': finding.cve, 'observations': [assessed]}
    details = []
    counts = {key: 0 for key in policy['thresholds']}
    for key in sorted(result):
        entry = result[key]
        actionable = [x for x in entry['observations'] if not x.get('vex_excluded')]
        entry['vex_excluded'] = not actionable
        worst = max(actionable or entry['observations'], key=lambda x: x['score'])
        entry.update(score=worst['score'], band=worst['band'], uncertain=any(x['uncertain'] for x in actionable))
        if actionable:
            counts[entry['band']] += 1
        details.append(entry)
    db.info.pop(fc._CACHE, None)
    if state is not None:
        db.refresh(state)
    if classification_token(state) != initial_classification_token:
        raise ValueError('Classification rebuilt during assessment; retry')
    if native_vex_token(db, service_id, now) != native_token:
        raise ValueError('Native VEX disposition changed during assessment; retry')
    if identity_source_generation(db, service_id) != identity_generation:
        raise ValueError('Package identity evidence changed during assessment; retry')
    final_policy, final_assignment = resolve_policy(db, service_id)
    if final_assignment != assignment or (final_policy.id if final_policy else None) != (policy_row.id if policy_row else None):
        raise ValueError('Policy assignment changed during assessment; retry')
    # Refuse to label a mixed-version build as current when sources changed during the batch.
    if fc.latest_execution_id(db, service_id) != latest or policy_data.risk_catalog_token() != token or packaged_catalog_token(db) != package_token or intelligence_token(db) != vex_token or fc.status(db, service_id, fc._service_configuration(db, service_id), now, latest)[0] != 'current':
        raise ValueError('Source changed during assessment; retry')
    from .package_identity_resolution import RESOLVER_VERSION
    provenance = {'native_vex_token': native_token, 'algorithm': 3, 'identity_resolver_version': RESOLVER_VERSION,
                  'identity_source_generation': identity_generation,
                  'configuration': policy, 'policy_digest': digest(policy), 'assignment': assignment,
                  'catalog_token': token, 'intelligence': {k: v for k, v in snapshot.items() if k != 'findings'}, 'intelligence_current': intel_current,
                  'catalog_metadata': catalog_metadata, 'packaged_catalog_token': package_token,
                  'classification_token': classification_token(state),
                  'vex_token': vex_token, 'classification_digest': state.config_digest if state else None,
                  'preview': configuration is not None, 'source_execution_id': latest, 'scan_current': scan_current}
    row = RiskAssessment(service_id=service_id, policy_id=policy_row.id if policy_row else None, source_execution_id=latest,
        as_of=now, valid_until=valid_until, provenance=provenance, details=details,
        summary={'coverage': coverage_report(details, now), 'counts': counts, 'findings': sum(not x['vex_excluded'] for x in details), 'vex_excluded_findings': sum(x['vex_excluded'] for x in details), 'observations': total,
                 'max_score': max((x['score'] for x in details if not x['vex_excluded']), default=0),
                 'uncertain': sum(x['uncertain'] for x in details), 'visual_only': True, 'assessment_state': 'no_scan' if latest is None else 'assessed' if scan_current else 'stale_or_incomplete_scan'})
    db.add(row)
    db.flush()
    return row

def handler(context, payload):
    if getattr(getattr(context, 'job', None), 'kind', None) == 'native_vex':
        from .native_vex_worker import handler as native_handler
        return native_handler(context, payload)
    from .database import SessionLocal
    with SessionLocal() as db:
        row = refresh_assessment(db, int(payload['service_id']), configuration=payload.get('configuration'), check=context.check)
        context.check()
        owned_job = context._owned(db)  # Lock and validate the durable lease in the publishing transaction.
        if owned_job.cancel_requested:
            from .durable_jobs import JobCancelled
            raise JobCancelled()
        db.commit()
        return {'assessment_id': row.id, 'service_id': row.service_id, 'preview': row.provenance['preview'], 'summary': row.summary}

if __name__ == '__main__':
    from .durable_jobs import run_worker
    from .native_vex_worker import maintenance
    run_worker(('risk_assessment', 'native_vex'), handler, maintenance=maintenance)
