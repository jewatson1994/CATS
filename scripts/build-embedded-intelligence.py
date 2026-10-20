#!/usr/bin/env python3
"""Build a signed, offline intelligence snapshot. Network is used only with --refresh.

Requires cryptography. Keep --cache and --private-key outside the source tree.
Replay checks every cached input against acquisition-lock.json; no network occurs.
Whole Ubuntu CVE and USN documents are selected by canonical byte size, never truncated.
"""
import argparse, base64, collections, gzip, hashlib, json, os, re, shutil, ssl, tarfile, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Reviewed upstream license bytes; changed terms require review before refresh.
LICENSE_SHA256 = {
    'LICENSE-ubuntu.txt': '23ee78c8bae49cf08ea2f0c84945c66b987ebe4520881fb51b3dad4fb43d07c2',
    'LICENSE-alpine.txt': '3b2890eacd851373001c4a14623458e3adaf1b1967939aa9c38a318e28d61c00',
    'LICENSE-ghsa.txt': '9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94',
    'LICENSE-kev.txt': '8dfcf2d0cba33bede386eb470daf2ac08caf6540fc2516baab10dd546f90938a',
}

MAX_UBUNTU_MEMBERS = 200000


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=strict_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def now():return datetime.now(timezone.utc).isoformat()

def source_adapters():
    from embedded_redhat import prepare_sources, emit_records
    from embedded_vendors import prepare_vendor_sources, emit_vendor_records
    from embedded_supplemental import prepare_supplemental_sources, emit_supplemental_records
    return [(prepare_sources, emit_records, True), (prepare_vendor_sources, emit_vendor_records, True),
            (prepare_supplemental_sources, emit_supplemental_records, False)]

def split_payload(path, part_bytes=64*1024*1024):
    if path.stat().st_size <= part_bytes:
        return None
    parts = []
    with path.open('rb') as stream:
        index = 0
        while block := stream.read(part_bytes):
            name = f'intelligence.jsonl.gz.part{index:04d}'
            (path.parent/name).write_bytes(block)
            parts.append(dict(name=name, bytes=len(block), sha256=hashlib.sha256(block).hexdigest()))
            index += 1
            if index > 32:
                raise ValueError('Compressed release exceeds shard bound')
    path.unlink()
    return parts
class ScopedRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old,new=urlsplit(req.full_url),urlsplit(newurl)
        if new.scheme!='https' or new.hostname!=old.hostname or new.username or new.password or new.port not in (None,443):
            raise ValueError('Redirect leaves HTTPS publisher scope')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cache',type=Path,required=True);p.add_argument('--private-key',type=Path,required=True)
    p.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'portal/app/embedded_intelligence_data')
    p.add_argument('--refresh',action='store_true');p.add_argument('--generate-key',action='store_true')
    p.add_argument('--sequence',type=int,required=True);p.add_argument('--version',required=True)
    p.add_argument('--ubuntu-max-bytes',type=int,default=524288)
    a=p.parse_args()
    if not 1024 <= a.ubuntu_max_bytes <= 4*1024*1024:raise ValueError('Ubuntu cap must be between 1 KiB and 4 MiB')
    a.cache.mkdir(parents=True,exist_ok=True);a.output.mkdir(parents=True,exist_ok=True)
    final_output=a.output; a.output=Path(tempfile.mkdtemp(prefix='.intelligence-stage-',dir=final_output.parent))
    repo=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(repo/'portal'))
    sys.path.insert(0,str(repo/'scripts'))
    from app.vex_intelligence import _parse
    from embedded_tar import bounded_tar_open
    if a.private_key.resolve().is_relative_to(repo):raise ValueError('Private signing key must remain outside repository')
    lockpath=a.cache/'acquisition-lock.json'
    lock={'schema':'cats-acquisition-lock/v1','inputs':{}} if a.refresh else strict_json(lockpath.read_bytes())
    if lock.get('schema')!='cats-acquisition-lock/v1' or not isinstance(lock.get('inputs'),dict):raise ValueError('Invalid acquisition lock schema')
    def acquire(name,url):
        target=a.cache/name
        if a.refresh:
            if urlsplit(url).scheme!='https':raise ValueError('HTTPS required')
            opener=build_opener(HTTPSHandler(context=ssl.create_default_context()),ScopedRedirect())
            with opener.open(Request(url,headers={'User-Agent':'CATS-intelligence-release-builder/1'}),timeout=120) as response:
                if urlsplit(response.url).scheme!='https' or urlsplit(response.url).hostname!=urlsplit(url).hostname:raise ValueError('Unexpected redirect')
                with target.with_suffix(target.suffix+'.part').open('wb') as f:
                    received=0
                    while block:=response.read(1024*1024):
                        received+=len(block)
                        if received>512*1024*1024:raise ValueError('Input exceeds acquisition byte bound')
                        f.write(block)
                target.with_suffix(target.suffix+'.part').replace(target)
                lock['inputs'][name]={'url':url,'sha256':sha(target),'bytes':target.stat().st_size,'acquired_at':now(),'tls_verified':True,'last_modified':response.headers.get('Last-Modified')}
        info=lock['inputs'][name]
        if info.get('tls_verified') is not True or info['url']!=url or target.stat().st_size!=info['bytes'] or sha(target)!=info['sha256']:raise ValueError('Cached input integrity mismatch: '+name)
        return target,info
    index,indexmeta=acquire('alpine-index.html','https://secdb.alpinelinux.org/')
    releases=re.findall(r'href="(v\d+\.\d+)/"',index.read_text())
    release=max(releases,key=lambda v:tuple(map(int,v[1:].split('.'))))
    specs=[('ubuntu-vex.tar.xz','https://security-metadata.canonical.com/vex/vex-all.tar.xz'),('kev.json','https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),('alpine-main.json',f'https://secdb.alpinelinux.org/{release}/main.json'),('alpine-community.json',f'https://secdb.alpinelinux.org/{release}/community.json'),('LICENSE-ubuntu.txt','https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/LICENSE'),('LICENSE-kev.txt','https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE'),('LICENSE-alpine.txt','https://secdb.alpinelinux.org/license.txt'),('ghsa.tar.gz','https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main'),('LICENSE-ghsa.txt','https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md')]
    inputs={name:acquire(name,url) for name,url in specs}
    for name,expected in LICENSE_SHA256.items():
        if sha(inputs[name][0])!=expected:raise ValueError('Upstream license changed; review required: '+name)
        shutil.copyfile(inputs[name][0],a.output/name)
    def source(id,name,file,license,hosts,prefixes):
        meta=inputs[file][1]
        return dict(id=id,name=name,url=meta['url'],acquired_at=meta['acquired_at'],allowed_hosts=hosts,authoritative_prefixes=prefixes,trusted=True,max_age_days=30,license=license,attribution=name,provenance=meta,counts={})
    sources=[source('ubuntu-vex','Canonical Ubuntu VEX','ubuntu-vex.tar.xz','CC-BY-SA-4.0',['security-metadata.canonical.com','github.com'],['pkg:deb/ubuntu/']),source('cisa-kev','CISA Known Exploited Vulnerabilities','kev.json','CC0-1.0',['www.cisa.gov'],[]),source('alpine-secdb','Alpine SecDB '+release,'alpine-main.json','CC-BY-SA-4.0',['secdb.alpinelinux.org'],[]),source('ghsa-reviewed','GitHub Reviewed Advisory Database','ghsa.tar.gz','CC-BY-4.0',['codeload.github.com','github.com'],[])]
    sources[2]['provenance']={'main':inputs['alpine-main.json'][1],'community':inputs['alpine-community.json'][1],'release_index':indexmeta}
    sources[0].update(category='vex', coverage='Bounded whole Ubuntu CVE and USN documents with explicit CVE aliases')
    sources[1].update(category='exploitation', coverage='Entire current KEV catalog')
    sources[2].update(category='advisory', coverage='Latest stable main and community SecDB')
    sources[3].update(category='advisory', coverage='All GitHub-reviewed advisories having CVE aliases')
    adapters=[]
    for prepare, emitter, parses in source_adapters():
        extra_sources,state=prepare(acquire)
        sources.extend(extra_sources);adapters.append((emitter,state,parses))
        for name,path in state.get('license_files',{}).items():
            shutil.copyfile(path,a.output/name)
    if a.refresh:
        lock['built_at']=now();lockpath.write_bytes(canonical(lock))
    cohorts={str(cap):collections.Counter() for cap in (65536,131072,262144,524288,1048576,2097152,4194304)}
    ubuntu_statuses=collections.Counter();ubuntu_kinds=collections.Counter()
    seen=set();versioned_rows=0;versioned_documents=0
    counts=collections.defaultdict(collections.Counter);exclusions=collections.Counter();total=0;rows=0;largest=0;archive_count=0;archive_members=0;archive_bytes=0
    payload=a.output/'intelligence.jsonl.gz'
    with payload.open('wb') as f,gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0,compresslevel=9) as out:
        def emit(record):
            nonlocal total,largest
            # Preserve conflicting content even when publisher identities coincide.
            line=canonical(record)+b'\n'
            identity=hashlib.sha256(line).digest()
            if identity in seen:
                exclusions[record['source']+'_duplicate_records']+=1;return False
            seen.add(identity)
            total+=len(line);largest=max(largest,len(line))
            if len(line)>8*1024*1024 or total>8*1024*1024*1024:raise ValueError('Release exceeds agreed size bounds')
            out.write(line);counts[record['source']][record['kind']]+=1
            return True
        with bounded_tar_open(inputs['ubuntu-vex.tar.xz'][0],'r|xz') as archive:
            for member in archive:
                archive_members+=1;archive_bytes+=member.size
                if archive_members>MAX_UBUNTU_MEMBERS or archive_bytes>64*1024*1024*1024:raise ValueError('Ubuntu archive exceeds aggregate bounds')
                if not member.isfile():continue
                archive_count+=1
                if archive_count%10000==0:print(f'Ubuntu scanned {archive_count} documents; retained {counts["ubuntu-vex"]["vex"]}',flush=True)
                if member.size>32*1024*1024:raise ValueError('Upstream member exceeds safety bound')
                kind='cve' if '/cve/' in member.name else 'usn' if '/usn/' in member.name else None
                if kind is None:exclusions['ubuntu_other_documents']+=1;continue
                try:data=strict_json(archive.extractfile(member).read());raw=canonical(data)
                except (ValueError,TypeError):exclusions['ubuntu_malformed_json']+=1;continue
                from app.ubuntu_vex import statement_cves
                try:n=sum(len(statement_cves(data,st))*len(st.get('products',[])) for st in data.get('statements',[]))
                except (ValueError,KeyError,TypeError) as error:
                    exclusions['ubuntu_invalid_alias_or_identifier']+=1;continue
                for cap,cohort in cohorts.items():
                    if len(raw)<=int(cap):
                        cohort.update({kind+'_documents':1,kind+'_canonical_bytes':len(raw),kind+'_product_statements':n})
                        if n<=10000:cohort.update({kind+'_bounded_documents':1,kind+'_bounded_statements':n})
                if len(raw)>a.ubuntu_max_bytes:exclusions['ubuntu_canonical_size_above_limit']+=1;continue
                if n>10000:exclusions['ubuntu_normalized_statement_limit']+=1;continue
                try:parsed=_parse(raw)
                except (ValueError,KeyError,TypeError) as error:
                    exclusions['ubuntu_invalid_'+type(error).__name__+':'+str(error)[:100]]+=1;continue
                if not emit(dict(source='ubuntu-vex',kind='vex',url='https://github.com/canonical/ubuntu-security-notices/blob/main/'+member.name,acquired_at=inputs['ubuntu-vex.tar.xz'][1]['acquired_at'],raw=data)):
                    continue
                n=len(parsed[-1]);ubuntu_kinds[kind+'_documents']+=1;ubuntu_kinds[kind+'_statements']+=n
                ubuntu_statuses.update(row[2] for row in parsed[-1])
                rows+=n
                versioned=sum(bool(row[1].get('purl') and row[1].get('version')) for row in parsed[-1])
                versioned_rows+=versioned;versioned_documents+=bool(versioned)
        for item in strict_json(inputs['kev.json'][0].read_bytes())['vulnerabilities']:
            emit(dict(source='cisa-kev',kind='exploitation',record_id=item['cveID'],cve=item['cveID'],product=item['vendorProject']+':'+item['product'],data=item,url=inputs['kev.json'][1]['url']))
        for component in ('main','community'):
            path,meta=inputs['alpine-'+component+'.json'];db=strict_json(path.read_bytes())
            for wrapper in db['packages']:
                pkg=wrapper['pkg']
                for fixed,identifiers in pkg.get('secfixes',{}).items():
                    for identifier in identifiers:
                        cves=re.findall(r'CVE-\d{4}-\d{4,}',identifier)
                        if not cves:exclusions['alpine_non_cve_identifiers']+=1
                        for cve in cves:
                            emit(dict(source='alpine-secdb',kind='advisory',record_id=f'{release}/{component}/{pkg["name"]}/{fixed}/{cve}',cve=cve,product=f'pkg:apk/alpine/{pkg["name"]}?distro={release}',data=dict(package=pkg['name'],fixed_version=fixed,release=release,repository=component,upstream_identifier=identifier,secfixes=pkg.get('secfixes',{}).get(fixed,[])),url=meta['url']))
        ghsa_members=ghsa_bytes=0
        with bounded_tar_open(inputs['ghsa.tar.gz'][0],'r|gz') as archive:
            for member in archive:
                ghsa_members+=1;ghsa_bytes+=member.size
                if ghsa_members>500000 or ghsa_bytes>8*1024*1024*1024:raise ValueError('GHSA archive exceeds aggregate bounds')
                if not member.isfile() or '/advisories/github-reviewed/' not in member.name or not member.name.endswith('.json'):continue
                if member.size>8*1024*1024:raise ValueError('GHSA member exceeds safety bound')
                data=strict_json(archive.extractfile(member).read())
                cves=[v for v in data.get('aliases',[]) if re.fullmatch(r'CVE-\d{4}-\d{4,}',v)]
                if not cves:exclusions['ghsa_reviewed_without_cve']+=1
                for cve in cves:
                    emit(dict(source='ghsa-reviewed',kind='advisory',record_id=data['id'],cve=cve,product=None,data=data,url='https://github.com/advisories/'+data['id']))
        for emitter,state,parses in adapters:
            print('Building additional source '+str(state.get('source',{}).get('id','supplemental/vendor')),flush=True)
            if parses:emitter(state,emit,_parse,exclusions)
            else:emitter(state,emit,exclusions)
    for source_meta in sources:
        source_meta['counts']=dict(counts[source_meta['id']])
    sources[0]['selection']={'measured_size_cohorts':{k:dict(v) for k,v in cohorts.items()},'policy':'Complete CVE and verified USN documents within canonical bytes and 10,000 expanded statements; no statements truncated','max_canonical_document_bytes':a.ubuntu_max_bytes,'archive_documents':archive_count,'archive_uncompressed_bytes':archive_bytes,'normalized_statements':rows,'versioned_purl_statements':versioned_rows,'documents_with_versioned_purls':versioned_documents,'status_counts':dict(ubuntu_statuses),'document_kinds':dict(ubuntu_kinds),'excluded':{k:v for k,v in exclusions.items() if k.startswith(('ubuntu_', 'ubuntu-vex_'))}}
    payload_digest=sha(payload);payload_bytes=payload.stat().st_size
    if payload_bytes>2*1024*1024*1024:raise ValueError('Compressed release exceeds 2 GiB bound')
    manifest=dict(schema='cats-embedded-intelligence/v1',version=payload_digest,release_label=a.version,sequence=a.sequence,built_at=lock['built_at'],payload_sha256=payload_digest,payload_bytes=payload_bytes,uncompressed_bytes=total,sources=sources,exclusions=[{'source':'selection','reason':'Whole-document and scoped-feed bounds; individual reasons and counts are preserved.','counts':dict(exclusions)}],acquisition_lock_sha256=sha(lockpath),largest_line_bytes=largest)
    parts=split_payload(payload)
    if parts:manifest['payload_parts']=parts
    if a.generate_key and not a.private_key.exists():
        a.private_key.parent.mkdir(parents=True,exist_ok=True)
        a.private_key.write_bytes(Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        os.chmod(a.private_key,0o600)
    key=serialization.load_pem_private_key(a.private_key.read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):raise ValueError('Ed25519 key required')
    (a.output/'ATTRIBUTION.txt').write_text('Contains Canonical Ubuntu vulnerability data and Alpine SecDB under CC-BY-SA-4.0 (https://creativecommons.org/licenses/by-sa/4.0/), GitHub Advisory Database under CC-BY-4.0 (https://creativecommons.org/licenses/by/4.0/), and CISA KEV under CC0-1.0. Source URLs, hashes, acquisition dates, selection limits and excluded counts are in manifest.json and acquisition-lock.json. Original VEX object content is preserved; JSON serialization is canonicalized. Supplemental data is reorganized into CVE-keyed records. The included data and its adaptations remain under their respective source licenses. These publishers do not endorse CATS. Full license texts accompany this package.\n',encoding='utf-8')
    with (a.output/'ATTRIBUTION.txt').open('a',encoding='utf-8') as attribution:
        for _,state,_ in adapters:
            attribution.write(state.get('attribution','')+'\n')
        for source_meta in sources[4:]:
            attribution.write(source_meta['name']+' | '+source_meta['license']+' | '+source_meta['url']+'\n')
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    if (final_output/'release-key.pem').exists() and (final_output/'release-key.pem').read_bytes()!=public:raise ValueError('Signing key differs from existing release pin; explicit release rotation required')
    raw=canonical(manifest);(a.output/'manifest.json').write_bytes(raw);(a.output/'manifest.sig').write_bytes(base64.b64encode(key.sign(raw)))
    (a.output/'release-key.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    (a.output/'acquisition-lock.json').write_bytes(canonical(lock))
    for item in a.output.iterdir():
        if item.name!='manifest.json':os.replace(item,final_output/item.name)
    os.replace(a.output/'manifest.json',final_output/'manifest.json');a.output.rmdir()
    expected={part['name'] for part in parts} if parts else {'intelligence.jsonl.gz'}
    for old in final_output.glob('intelligence.jsonl.gz*'):
        if old.name not in expected and (old.name=='intelligence.jsonl.gz' or re.fullmatch(r'intelligence\.jsonl\.gz\.part\d{4}',old.name)):old.unlink()
    print(json.dumps(dict(bytes=manifest['payload_bytes'],uncompressed_bytes=total,counts={k:dict(v) for k,v in counts.items()},normalized_statements=rows,excluded=dict(exclusions)),indent=2),flush=True)
if __name__=='__main__':main()
