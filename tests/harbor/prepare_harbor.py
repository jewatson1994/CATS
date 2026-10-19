"""Generate isolated Harbor fixture using its pinned official prepare image."""
import argparse, datetime, hashlib, ipaddress, json, pathlib, secrets, subprocess, tarfile, urllib.request
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
VERSION = 'v2.15.4'
SHA256 = 'eeb899cf7b626c925790adba87db9008dd1d73a693a72442651b5bdece9805c6'
PREPARE = 'goharbor/prepare@sha256:79b5614d0d02b5d2c6c9b7b9755f5caaea882797353bfcb6421f77e6d69cc317'

def run(*args): subprocess.run(args, check=True)

def prepare(root, port, offline=False):
    root = pathlib.Path(root).resolve(); root.mkdir(parents=True, exist_ok=True)
    archive = root/'installer.tgz'
    if not archive.exists() and offline:
        raise ValueError('Offline installer archive missing')
    if not archive.exists():
        urllib.request.urlretrieve(f'https://github.com/goharbor/harbor/releases/download/{VERSION}/harbor-online-installer-{VERSION}.tgz', archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError('Official installer SHA-256 mismatch')
    harbor = root/'harbor'
    if not (harbor/'harbor.yml.tmpl').exists():
        with tarfile.open(archive) as bundle: bundle.extractall(root, filter='data')
    credentials = root/'credentials.json'
    if credentials.exists():
        passwords = json.loads(credentials.read_text())
    else:
        passwords = {'admin': secrets.token_urlsafe(24), 'database': secrets.token_urlsafe(24)}
        credentials.write_text(json.dumps(passwords)); credentials.chmod(0o600)
    tls = harbor/'tls'; tls.mkdir(exist_ok=True)
    if not (tls/'server.crt').exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CATS isolated Harbor test')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5))
                .not_valid_after(now+datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.DNSName('host.docker.internal'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
                .sign(key,hashes.SHA256()))
        (tls/'server.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (tls/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        (tls/'server.key').chmod(0o600)
    config = yaml.safe_load((harbor/'harbor.yml.tmpl').read_text())
    config.update(hostname='localhost', external_url=f'https://localhost:{port}', data_volume='/fixture/data', harbor_admin_password=passwords['admin'])
    config.pop('http',None)
    config['https']={'port':port,'certificate':'/fixture/tls/server.crt','private_key':'/fixture/tls/server.key'}
    config['database']['password']=passwords['database']
    config['log']['local']['location']='/fixture/log'
    config['jobservice']['max_job_workers']=2
    (harbor/'harbor.yml').write_text(yaml.safe_dump(config))
    for directory in ('data','common/config','log'):
        (harbor/directory).mkdir(parents=True,exist_ok=True)
    prepare_image=PREPARE
    if offline:
        metadata=json.loads((root/'offline-images.json').read_text())
        prepare_image='cats-harbor-prepare:v2.15.4'
        actual=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',prepare_image],text=True).strip()
        if actual != metadata['prepare_image_id']:
            raise ValueError('Offline prepare image identity mismatch')
    run('docker','run','--pull=never' if offline else '--pull=missing','--rm','--name','cats-harbor-prepare',
        '-v',f'{harbor}:/input','-v',f'{harbor}/data:/data',
        '-v',f'{harbor}:/compose_location','-v',f'{harbor}/common/config:/config',
        '-v',f'{harbor}:/hostfs/fixture',prepare_image,'prepare')
    compose=yaml.safe_load((harbor/'docker-compose.yml').read_text())
    compose['name']='cats-harbor-test'
    image_lock=json.loads((pathlib.Path(__file__).parent/'images.lock.json').read_text())
    # Scope names, ports, log routing and mounts to this fixture only.
    for name,service in compose['services'].items():
        if offline:
            locked=image_lock[service['image']]['id']
            actual=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',locked],text=True).strip()
            if actual != locked:
                raise ValueError('Offline Harbor image identity mismatch')
            service['image']=locked
        else:
            service['image']=image_lock[service['image']]['repo_digests'][0]
        service.pop('container_name',None)
        if 'env_file' in service:
            service['env_file']=[str(harbor/entry.removeprefix('./')) for entry in service['env_file']]
        service['restart']='unless-stopped'
        service['logging']={'driver':'json-file','options':{'max-size':'10m','max-file':'2'}}
        service.pop('ports',None)
        if name=='proxy': service['ports']=[f'127.0.0.1:{port}:8443']
        replaced=[]
        for mount in service.get('volumes',[]):
            if isinstance(mount,str):
                source,target,*mode=mount.split(':')
                if source.startswith('/fixture/'):
                    source=str(harbor/source[len('/fixture/'):])
                elif source.startswith('./'):
                    source=str(harbor/source[2:])
                mount={'type':'bind','source':source,'target':target,'read_only':bool(mode and mode[0]=='ro')}
            source=mount['source']
            if source.startswith('/fixture/'):
                mount['source']=str(harbor/source[len('/fixture/'):])
            elif source.startswith('./'):
                mount['source']=str(harbor/source[2:])
            replaced.append(mount)
        service['volumes']=replaced
    output=root/'compose.harbor.yml'; output.write_text(yaml.safe_dump(compose,sort_keys=False))
    print(f'Prepared {output}; secrets remain in {credentials}')
    return output

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--root',default='.test-temp/harbor-local'); parser.add_argument('--port',type=int,default=18443)
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args(); prepare(args.root,args.port,args.offline)
