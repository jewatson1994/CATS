"""Provider scope, unknown preservation, and bounded offline adapters."""
import collections
import gzip
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import embedded_supplemental as supplemental


def test_epss_scores_preserve_dates_and_zero_without_inventing_exploitation(tmp_path):
    path = tmp_path / 'epss.gz'
    with gzip.open(path, 'wt', encoding='utf-8') as out:
        out.write('#model_version:vtest,score_date:2026-10-19T12:00:00Z\ncve,epss,percentile\n'
                  'CVE-2026-1234,0,0\nCVE-2026-1235,0.99,0.999\nCVE-2026-1236,nan,0.1\n')
    records, excluded = [], collections.Counter()
    supplemental.emit_epss(path, records.append, excluded, {'url': 'https://example.com/epss'})
    assert len(records) == 2
    assert records[0]['data'] == dict(cve='CVE-2026-1234', epss=0, percentile=0, model_version='vtest', score_date='2026-10-19T12:00:00Z')
    assert all(r['kind'] == 'risk_enrichment' and 'kev' not in r['data'] for r in records)
    assert excluded == {'first-epss_invalid_score': 1}


@pytest.mark.parametrize('content', [
    'cve,epss,percentile\nCVE-2026-1234,1,1\n',
    '#model_version:vtest,score_date:bad\ncve,epss,percentile\n',
    '#model_version:vtest,score_date:2026-10-19\ncve,epss,percentile\nCVE-2026-1234,1,1\nCVE-2026-1234,0,0\n',
])
def test_epss_rejects_missing_dates_and_conflicting_members(content, tmp_path):
    path = tmp_path / 'epss.gz'
    with gzip.open(path, 'wt', encoding='utf-8') as out:
        out.write(content)
    with pytest.raises(ValueError):
        supplemental.emit_epss(path, lambda _: None, collections.Counter(), {'url': 'https://example.com'})


def test_osv_only_reviewed_publisher_and_every_cve_alias(tmp_path):
    path = tmp_path / 'osv.zip'
    raw = dict(id='GO-2026-1234', aliases=['CVE-2026-1111', 'CVE-2026-2222', 'GHSA-aaaa-bbbb-cccc', 'CVE-2026-1111'],
               affected=[{'package': {'name': 'example.com/pkg', 'ecosystem': 'Go'}, 'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.2.3'}]}]}],
               withdrawn='2026-10-18T00:00:00Z')
    with zipfile.ZipFile(path, 'w') as out:
        out.writestr('GO-2026-1234.json', json.dumps(raw))
        out.writestr('GHSA-aaaa-bbbb-cccc.json', json.dumps(dict(raw, id='GHSA-aaaa-bbbb-cccc')))
        out.writestr('GO-2026-1235.json', json.dumps(dict(id='GO-2026-1235', aliases=[])))
    records, excluded = [], collections.Counter()
    supplemental.emit_osv(path, 'osv-go', 'GO-', records.append, excluded)
    assert {r['cve'] for r in records} == {'CVE-2026-1111', 'CVE-2026-2222'}
    assert all(r['data'] == raw and r['kind'] == 'advisory' and r['product'] is None for r in records)
    assert excluded == {'osv-go_other_publisher': 1, 'osv-go_without_cve_alias': 1}


def test_osv_rejects_oversized_archives_before_reading(tmp_path, monkeypatch):
    path = tmp_path / 'osv.zip'
    with zipfile.ZipFile(path, 'w') as out:
        out.writestr('GO-2026-1234.json', '{}')
    monkeypatch.setattr(supplemental, 'MAX_ARCHIVE', 1)
    with pytest.raises(ValueError, match='archive exceeds'):
        supplemental.emit_osv(path, 'osv-go', 'GO-', lambda _: None, collections.Counter())


def test_vulnrichment_preserves_only_cisa_authored_containers(tmp_path):
    path = tmp_path / 'cisa.tgz'
    cisa = {'providerMetadata': {'orgId': supplemental.CISA_ORG}, 'metrics': [{'other': {'type': 'ssvc', 'content': {'options': [{'Exploitation': 'none'}]}}}]}
    raw = dict(cveMetadata=dict(cveId='CVE-2026-1234'), containers=dict(cna={'descriptions': [{'value': 'Separate authorship'}]},
               adp=[{'providerMetadata': {'orgId': 'af854a3a-2127-422b-91ae-364da2661108'}}, cisa]))
    with tarfile.open(path, 'w:gz') as out:
        payload = json.dumps(raw).encode()
        member = tarfile.TarInfo('repo/2026/1xxx/CVE-2026-1234.json'); member.size = len(payload)
        out.addfile(member, io.BytesIO(payload))
    records = []
    supplemental.emit_vulnrichment(path, records.append, collections.Counter())
    assert records[0]['kind'] == 'risk_enrichment'
    assert records[0]['data'] == dict(cveMetadata=raw['cveMetadata'], containers={'adp': [cisa]})
    assert 'kev' not in records[0]['data']


def test_reviewed_terms_are_pinned(tmp_path):
    path = tmp_path / 'changed-terms'; path.write_text('Changed terms')
    with pytest.raises(ValueError, match='terms changed'):
        supplemental.prepare_supplemental_sources(lambda name, url: (path, {'url': url}))
