"""Offline KEV and EPSS overlays for informational risk only."""
from copy import deepcopy
from datetime import timedelta
from sqlalchemy import select
from .intelligence_models import IntelligencePackageInstall, IntelligenceRecord, IntelligencePackageCatalog, IntelligencePackageMember
from .vex_models import VexSource
from .risk_profiles import aware, digest


def packaged_catalog_token(db):
    # Package manifests contain large membership lists; extract only the token fields.
    install = db.execute(select(IntelligencePackageInstall.version, IntelligencePackageInstall.sequence,
        IntelligencePackageInstall.manifest['payload_sha256'].as_string().label('payload_sha256'))
        .order_by(IntelligencePackageInstall.sequence.desc()).limit(1)).first()
    if install is None:
        return None
    sources = list(db.execute(select(VexSource.name, VexSource.enabled, VexSource.trusted, VexSource.max_age_days).order_by(VexSource.id)))
    return digest({'version': install.version, 'sequence': install.sequence, 'payload': install.payload_sha256, 'sources': [list(row) for row in sources]})


def _current_catalog(db, source_key, kind):
    latest = select(IntelligencePackageInstall.id).order_by(
        IntelligencePackageInstall.sequence.desc()).limit(1).scalar_subquery()
    # Project only small catalog metadata. Neither the historical manifest nor
    # the full membership list is decoded during an assessment.
    return db.execute(select(IntelligencePackageCatalog.id, IntelligencePackageCatalog.record_count,
        IntelligencePackageCatalog.metadata_json, IntelligencePackageInstall.version,
        VexSource.enabled, VexSource.trusted, VexSource.max_age_days)
        .join(IntelligencePackageInstall, IntelligencePackageInstall.id == IntelligencePackageCatalog.install_id)
        .join(VexSource, VexSource.id == IntelligencePackageCatalog.source_id)
        .where(IntelligencePackageCatalog.install_id == latest, IntelligencePackageCatalog.record_count > 0,
               IntelligencePackageCatalog.source_key == source_key, IntelligencePackageCatalog.kind == kind)).first()


def _current_records(db, catalog_id, requested, *, scores=False):
    columns = [IntelligenceRecord.cve]
    if scores:
        columns.append(IntelligenceRecord.data)
    for start in range(0, len(requested), 400):
        yield from db.execute(select(*columns).join(IntelligencePackageMember,
            IntelligencePackageMember.record_id == IntelligenceRecord.id).where(
                IntelligencePackageMember.catalog_id == catalog_id,
                IntelligenceRecord.cve.in_(requested[start:start + 400])))


def overlay_packaged_kev(db, snapshot, now):
    """Use a newer, trusted signed catalog; preserve unknown on missing coverage."""
    catalog = _current_catalog(db, 'cisa-kev', 'exploitation')
    if catalog is None or not catalog.enabled or not catalog.trusted:
        return snapshot
    meta = catalog.metadata_json
    acquired = aware(meta['acquired_at'])
    expiry = acquired + timedelta(days=catalog.max_age_days)
    if acquired > now or expiry <= now:
        return snapshot
    existing = snapshot.get('kev', {})
    existing_date = existing.get('metadata', {}).get('date_released') or existing.get('metadata', {}).get('date')
    if existing.get('state') == 'LOADED' and existing_date:
        try:
            if aware(existing_date) >= acquired and aware(existing_date) <= now:
                return snapshot
        except (ValueError, TypeError):
            pass
    requested = sorted({cve.upper() for cve in snapshot['findings']})
    members = {cve for cve, in _current_records(db, catalog.id, requested)}
    result = deepcopy(snapshot)
    for cve, finding in result['findings'].items():
        # Absence is unknown: only an affirmative catalog match is exploitation evidence.
        finding['kev'] = True if cve.upper() in members or finding.get('kev') is True else None
    result['kev'] = {'state': 'LOADED', 'records': catalog.record_count, 'metadata': {'date_released': acquired.isoformat(),
        'expires_at': expiry.isoformat(), 'basis': 'embedded-signed-package', 'package_version': catalog.version,
        'source': meta['id'], 'source_url': meta['url'], 'prior_catalog': existing}}
    return result


def overlay_packaged_epss(db, snapshot, now):
    """Use exact signed EPSS members, dated by the model's score publication."""
    import math
    catalog = _current_catalog(db, 'first-epss', 'risk_enrichment')
    if catalog is None or not catalog.enabled or not catalog.trusted:
        return snapshot
    meta = catalog.metadata_json
    try:
        acquired, dated = aware(meta['acquired_at']), aware(meta['score_date'])
    except (KeyError, ValueError, TypeError):
        return snapshot
    expiry = dated + timedelta(days=catalog.max_age_days)
    if acquired > now or dated > acquired or expiry <= now:
        return snapshot
    existing = snapshot.get('epss', {})
    prior_date = existing.get('metadata', {}).get('score_date') or existing.get('metadata', {}).get('date')
    if existing.get('state') == 'LOADED' and prior_date:
        try:
            if dated <= aware(prior_date) <= now:
                return snapshot
        except (TypeError, ValueError):
            pass
    requested = sorted({cve.upper() for cve in snapshot['findings']})
    scores = {}
    for cve, data in _current_records(db, catalog.id, requested, scores=True):
        score, percentile = data.get('epss'), data.get('percentile')
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 <= v <= 1
               for v in (score, percentile)):
            return snapshot
        try:
            if aware(data['score_date']) != dated or data.get('model_version') != meta.get('model_version'):
                return snapshot
        except (KeyError, ValueError, TypeError):
            return snapshot
        if cve in scores and scores[cve] != (score, percentile):
            return snapshot
        scores[cve] = (score, percentile)
    result = deepcopy(snapshot)
    for cve, finding in result['findings'].items():
        value = scores.get(cve.upper())
        finding['epss'] = value[0] if value else None
        finding['epss_percentile'] = value[1] if value else None
    result['epss'] = {'state': 'LOADED', 'records': catalog.record_count, 'metadata': {
        'score_date': dated.isoformat(), 'model_version': meta.get('model_version'),
        'acquired_at': acquired.isoformat(), 'expires_at': expiry.isoformat(),
        'basis': 'embedded-signed-package', 'package_version': catalog.version,
        'source': meta['id'], 'source_url': meta['url'], 'prior_catalog': existing}}
    return result
