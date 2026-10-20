"""Release-time adapters for independently licensed supplemental intelligence.

The caller owns authenticated acquisition, signing and output bounds. These
adapters never perform HTTP, extract archives to disk, or manufacture VEX.
"""
import collections
import csv
import gzip
import hashlib
import json
import math
import re
import tarfile
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

CVE = re.compile(r'CVE-\d{4}-\d{4,}')
MAX_MEMBER = 8 * 1024 * 1024
MAX_JSON = 512 * 1024 * 1024
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 1000000
CISA_ORG = '134c704f-9b21-4f2e-91b3-4a467353bcc0'
INPUTS = {
    'epss.csv.gz': 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
    'nvd-modified.json.gz': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz',
    'vulnrichment.tar.gz': 'https://codeload.github.com/cisagov/vulnrichment/tar.gz/refs/heads/develop',
    'osv-go.zip': 'https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip',
    'osv-pypi.zip': 'https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip',
    'osv-rust.zip': 'https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip',
    'LICENSE-vulnrichment.txt': 'https://raw.githubusercontent.com/cisagov/vulnrichment/develop/LICENSE',
    'LICENSE-osv-go.txt': 'https://raw.githubusercontent.com/golang/vulndb/master/data/LICENSE',
    'LICENSE-osv-pypi.txt': 'https://raw.githubusercontent.com/pypa/advisory-database/main/LICENSE',
    'LICENSE-osv-rust.txt': 'https://raw.githubusercontent.com/rustsec/advisory-db/main/LICENSE.txt',
    'LICENSE-osv-rust-cc0.txt': 'https://raw.githubusercontent.com/rustsec/advisory-db/main/LICENSES/CC0-1.0.txt',
    'LICENSE-osv-rust-ccby.txt': 'https://raw.githubusercontent.com/rustsec/advisory-db/main/LICENSES/CC-BY-4.0.txt',
    'TERMS-epss.html': 'https://www.first.org/epss/faq',
    'TERMS-nvd.html': 'https://www.nist.gov/open/license',
}
# Data licenses/express data-use terms, never a convenient code-only license.
LICENSE_SHA256 = {
    'LICENSE-vulnrichment.txt': 'a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499',
    'LICENSE-osv-go.txt': '419896aea50c15d6e40c5b4baf4bd346f78223b9a354c7357ad00262afdc08ec',
    'LICENSE-osv-pypi.txt': '9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411',
    'LICENSE-osv-rust.txt': 'b342fe896e158b8c5a83e707446113f3a149fa0104d834afa78cd2a48eaf1906',
    'LICENSE-osv-rust-cc0.txt': 'a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499',
    'LICENSE-osv-rust-ccby.txt': '28a9529c7d0bb4dc51f4bf5c116a3d16ef247a052f7591466768ddf563fd1cf5',
    'TERMS-epss.html': 'ab8e4e7d7c2e4a94d72b78ee5081f636f7d195e2aa3daf0220acee6b39dc2474',
    'TERMS-nvd.html': '6f000573e348a13030a39ee074a3b7eccd3a3a248a78d66791078c860e69dfa1',
}
ATTRIBUTION = "Supplemental data: FIRST/EPSS (https://www.first.org/epss/) scores, published freely for product use with attribution requested; see TERMS-epss.html. EPSS is a probability estimate of exploitation within 30 days, not evidence of exploitation. CISA ADP Vulnrichment (https://github.com/cisagov/vulnrichment), CC0-1.0; only CISA's ADP containers are retained. Go vulnerability data and PyPA advisory data, CC-BY-4.0; RustSec advisory data CC0-1.0 except imported GitHub advisory content CC-BY-4.0. OSV.dev supplies the transport; individual publishers retain their respective terms. Full licenses and original reference links accompany the package. NVD/NIST data is provided under the terms in TERMS-nvd.html, including its public-service disclaimer and attribution conditions. Contains NVD data; not endorsed or certified by NVD or NIST. Data is reorganized as CVE-keyed supplemental records at the acquisition dates recorded in the manifest; original advisory objects and NVD CVE objects are preserved. These publishers do not endorse CATS.\n\nRustSec license-file clarification: LICENSE-osv-rust-ccby.txt preserves the upstream file named LICENSES/CC-BY-4.0.txt, whose full text is actually CC-BY-SA-4.0. RustSec LICENSE.txt and the applicable advisories explicitly declare CC-BY-4.0 for imported GitHub content; that declaration and GitHub Advisory Database terms (https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#advisory-database) are the inclusion basis. Correct CC-BY-4.0 full text is included as LICENSE-ghsa.txt. Original upstream files are retained to disclose this inconsistency. GitHub Advisory Database attribution: https://github.com/advisories.\n"


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def _json(stream, limit):
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Supplemental JSON exceeds byte bound')
    return json.loads(raw, object_pairs_hook=_strict_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def _date(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _epss_header(path):
    with gzip.open(path, 'rt', encoding='utf-8', newline='') as stream:
        line = stream.readline(4097)
        if len(line) > 4096 or not line.startswith('#'):
            raise ValueError('EPSS dated model header required')
        header = dict(part.strip().split(':', 1) for part in line.lstrip('#').strip().split(','))
        _date(header['score_date'])
        if not header.get('model_version'):
            raise ValueError('EPSS model version required')
        return header


def prepare_supplemental_sources(acquire):
    inputs = {name: acquire(name, url) for name, url in INPUTS.items()}
    for name, expected in LICENSE_SHA256.items():
        if hashlib.sha256(inputs[name][0].read_bytes()).hexdigest() != expected:
            raise ValueError('Supplemental data terms changed; review required: ' + name)
    sources = []

    def source(key, name, filename, license_name, category, coverage, hosts, licenses):
        meta = inputs[filename][1]
        entry = dict(id=key, name=name, url=meta['url'], acquired_at=meta['acquired_at'],
                     allowed_hosts=sorted(set([urlsplit(meta['url']).hostname, *hosts])), authoritative_prefixes=[],
                     trusted=True, max_age_days=7 if key == 'first-epss' else 30,
                     license=license_name, attribution=name, provenance=meta, category=category,
                     coverage=coverage, counts={}, license_evidence=[dict(filename=n, **inputs[n][1]) for n in licenses])
        sources.append(entry)
        return entry

    epss = source('first-epss', 'FIRST Exploit Prediction Scoring System', 'epss.csv.gz',
                  'LicenseRef-FIRST-EPSS', 'risk_enrichment', 'Entire daily EPSS CSV, all CVE scores',
                  ['www.first.org'], ['TERMS-epss.html'])
    epss.update(_epss_header(inputs['epss.csv.gz'][0]))
    if _date(epss['score_date']) > _date(epss['acquired_at']):
        raise ValueError('EPSS score date is in the future')
    source('nvd-modified', 'NIST NVD modified CVE feed', 'nvd-modified.json.gz',
           'LicenseRef-NIST-Public-Service', 'vulnerability', 'Current rolling modified feed only; not full NVD history',
           [], ['TERMS-nvd.html'])
    source('cisa-vulnrichment', 'CISA ADP Vulnrichment', 'vulnrichment.tar.gz', 'CC0-1.0',
           'risk_enrichment', 'CISA-authored ADP containers across the current Vulnrichment repository',
           ['github.com'], ['LICENSE-vulnrichment.txt'])
    for key, title, file, license_name, evidence in (
        ('osv-go', 'Go vulnerability database via OSV', 'osv-go.zip', 'CC-BY-4.0', ['LICENSE-osv-go.txt']),
        ('osv-pypi', 'PyPA advisory database via OSV', 'osv-pypi.zip', 'CC-BY-4.0', ['LICENSE-osv-pypi.txt']),
        ('osv-rust', 'RustSec advisory database via OSV', 'osv-rust.zip', 'CC0-1.0 AND CC-BY-4.0',
         ['LICENSE-osv-rust.txt', 'LICENSE-osv-rust-cc0.txt', 'LICENSE-osv-rust-ccby.txt']),
    ):
        source(key, title, file, license_name, 'advisory',
               'Publisher-owned records from selected ecosystem dump with every CVE alias; other publishers and records without CVE aliases excluded',
               ['osv.dev'], evidence)
    return sources, dict(inputs=inputs, sources=sources,
                         license_files={name: inputs[name][0] for name in LICENSE_SHA256}, attribution=ATTRIBUTION)


def emit_epss(path, emit, exclusions, meta):
    header = _epss_header(path)
    seen = set()
    with gzip.open(path, 'rt', encoding='utf-8', newline='') as stream:
        next(stream)
        def lines():
            for number in range(MAX_MEMBERS + 2):
                line = stream.readline(4097)
                if not line:
                    return
                if len(line) > 4096 or number > MAX_MEMBERS:
                    raise ValueError('EPSS CSV exceeds safety bound')
                yield line
        rows = csv.DictReader(lines())
        if rows.fieldnames != ['cve', 'epss', 'percentile']:
            raise ValueError('Unexpected EPSS columns')
        for row in rows:
            cve = row['cve']
            if not CVE.fullmatch(cve or ''):
                exclusions['first-epss_invalid_cve'] += 1
                continue
            try:
                score, percentile = float(row['epss']), float(row['percentile'])
                if not all(math.isfinite(v) and 0 <= v <= 1 for v in (score, percentile)):
                    raise ValueError('Invalid probability')
            except (ValueError, TypeError):
                exclusions['first-epss_invalid_score'] += 1
                continue
            if cve in seen:
                raise ValueError('Duplicate EPSS CVE')
            seen.add(cve)
            emit(dict(source='first-epss', kind='risk_enrichment', record_id=cve, cve=cve, product=None,
                      data=dict(cve=cve, epss=score, percentile=percentile, **header), url=meta['url']))


def emit_osv(path, source, prefix, emit, exclusions):
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS or sum(m.file_size for m in members) > MAX_ARCHIVE:
            raise ValueError('OSV archive exceeds safety bound')
        for member in members:
            if member.is_dir() or not member.filename.endswith('.json'):
                continue
            if member.file_size > MAX_MEMBER:
                raise ValueError('OSV member exceeds safety bound')
            with archive.open(member) as stream:
                data = _json(stream, MAX_MEMBER)
            record_id = data.get('id', '')
            if not isinstance(record_id, str) or not record_id.startswith(prefix):
                exclusions[source + '_other_publisher'] += 1
                continue
            cves = sorted({v for v in data.get('aliases', []) if isinstance(v, str) and CVE.fullmatch(v)})
            if not cves:
                exclusions[source + '_without_cve_alias'] += 1
            for cve in cves:
                emit(dict(source=source, kind='advisory', record_id=record_id, cve=cve, product=None,
                          data=data, url='https://osv.dev/vulnerability/' + record_id))


def emit_vulnrichment(path, emit, exclusions):
    from embedded_tar import bounded_tar_open
    total = count = 0
    with bounded_tar_open(path, 'r|gz') as archive:
        for member in archive:
            count += 1
            total += member.size
            if count > MAX_MEMBERS or total > MAX_ARCHIVE:
                raise ValueError('Vulnrichment archive exceeds safety bound')
            if not member.isfile() or not re.fullmatch(r'CVE-\d{4}-\d{4,}\.json', member.name.rsplit('/', 1)[-1]):
                continue
            if member.size > 32 * 1024 * 1024:
                raise ValueError('Vulnrichment source document exceeds safety bound')
            data = _json(archive.extractfile(member), 32 * 1024 * 1024)
            metadata = data.get('cveMetadata', {})
            cve = metadata.get('cveId', '')
            if not CVE.fullmatch(cve):
                exclusions['cisa-vulnrichment_non_cve_document'] += 1
                continue
            adp = [item for item in data.get('containers', {}).get('adp', [])
                   if item.get('providerMetadata', {}).get('orgId') == CISA_ORG]
            if not adp:
                exclusions['cisa-vulnrichment_without_cisa_adp'] += 1
                continue
            # The surrounding CNA and other ADP content has independent authorship.
            emit(dict(source='cisa-vulnrichment', kind='risk_enrichment', record_id=cve, cve=cve, product=None,
                      data=dict(cveMetadata=metadata, containers=dict(adp=adp)),
                      url='https://github.com/cisagov/vulnrichment/blob/develop/' + member.name.split('/', 1)[-1]))


def emit_supplemental_records(state, emit, exclusions):
    counts = collections.Counter()
    def output(record):
        emit(record)
        counts[record['source']] += 1
    inputs = state['inputs']
    epss = next(s for s in state['sources'] if s['id'] == 'first-epss')
    emit_epss(inputs['epss.csv.gz'][0], output, exclusions, epss)
    with gzip.open(inputs['nvd-modified.json.gz'][0], 'rb') as stream:
        data = _json(stream, MAX_JSON)
    if data.get('format') != 'NVD_CVE' or data.get('version') != '2.0':
        raise ValueError('Unexpected NVD feed format')
    nvd = next(s for s in state['sources'] if s['id'] == 'nvd-modified')
    nvd['feed_timestamp'] = data['timestamp']
    if _date(data['timestamp']) > _date(nvd['acquired_at']):
        raise ValueError('NVD feed timestamp is in the future')
    if len(data['vulnerabilities']) != data['totalResults'] or data['totalResults'] > MAX_MEMBERS:
        raise ValueError('Incomplete or oversized NVD feed')
    for wrapper in data['vulnerabilities']:
        item = wrapper['cve']
        cve = item.get('id', '')
        if not CVE.fullmatch(cve):
            exclusions['nvd-modified_invalid_cve'] += 1
            continue
        output(dict(source='nvd-modified', kind='vulnerability', record_id=cve, cve=cve, product=None,
                    data=item, url='https://nvd.nist.gov/vuln/detail/' + cve))
    del data
    emit_vulnrichment(inputs['vulnrichment.tar.gz'][0], output, exclusions)
    for key, prefix in [('osv-go', 'GO-'), ('osv-pypi', 'PYSEC-'), ('osv-rust', 'RUSTSEC-')]:
        emit_osv(inputs[key + '.zip'][0], key, prefix, output, exclusions)
    return dict(records=dict(counts), epss_score_date=epss['score_date'], nvd_feed_timestamp=nvd['feed_timestamp'])
