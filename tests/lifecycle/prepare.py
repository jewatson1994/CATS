"""Create a fresh, isolated local fixture. Refuses to overwrite an existing run."""
import json,shutil,os,hashlib
from pathlib import Path
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
source=Path(__file__).resolve().parents[2]
root=source/'.test-temp'/os.getenv('CATS_LIFECYCLE_RUN','lifecycle-repro')
root.mkdir(parents=True,exist_ok=False)
for name in ['run.py','gateway.py','active.py','clients.py','concurrency.py']:shutil.copyfile(Path(__file__).parent/name,root/name)
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'registry')]);now=datetime.now(timezone.utc)
cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('registry')]),False).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256())
(root/'server.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(root/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
project='cats-lifecycle-'+hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:12]
compose={'name':project,'services':{
 'registry':{'image':'registry:2.8.3','volumes':[str(root)+':/tls:ro'],'environment':{'REGISTRY_HTTP_TLS_CERTIFICATE':'/tls/server.crt','REGISTRY_HTTP_TLS_KEY':'/tls/server.key'}},
 'db':{'image':'postgres:16-alpine','environment':{'POSTGRES_PASSWORD':'lifecycle-disposable-only','POSTGRES_DB':'lifecycle'},'healthcheck':{'test':['CMD-SHELL','pg_isready -U postgres'],'interval':'2s','timeout':'2s','retries':30}},
 'runner':{'image':'cats:1.2','entrypoint':['python','/test/run.py'],'volumes':[str(source)+':/source:ro',str(root)+':/test'],'environment':{'DATABASE_URL':'postgresql+psycopg://postgres:lifecycle-disposable-only@db/lifecycle','PYTHONPATH':'/source/portal','CATS_APPROVED_RELEASE_ROOT':'/test/approved'},'depends_on':{'db':{'condition':'service_healthy'},'registry':{'condition':'service_started'}}}}}
if os.getenv('CATS_CLIENT_PROBE'):
 compose['services']['runner']['ports']=['127.0.0.1:18083:18083']
 compose['services']['runner']['environment']['CATS_CLIENT_PROBE']='1'
(root/'compose.json').write_text(json.dumps(compose,indent=2))
print(root/'compose.json')
