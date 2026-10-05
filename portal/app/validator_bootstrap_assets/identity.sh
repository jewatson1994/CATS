set -eu
umask 077
python3 - "$1" <<'PY'
import ipaddress,json,pathlib,subprocess,sys
value=json.loads((pathlib.Path(sys.argv[1])/'input.json').read_text())
identity=value['validator_id']; host=value['host']
try: ipaddress.ip_address(host); san='IP:'+host
except ValueError: san='DNS:'+host
san += ',URI:urn:cats:validator:' + identity
key='/etc/cats-validator/server.key'
if not pathlib.Path(key).exists(): subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',key],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['chown','cats-validator:cats-validator',key],check=True)
subprocess.run(['chmod','600',key],check=True)
result=subprocess.run(['openssl','req','-new','-key',key,'-subj','/CN='+identity,'-addext','subjectAltName='+san],check=True,capture_output=True,text=True)
print(result.stdout)
PY
