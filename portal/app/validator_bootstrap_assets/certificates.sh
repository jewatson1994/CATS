set -eu
umask 077
python3 - "$1" <<'PY'
import json,os,pathlib,re,subprocess,sys,stat
v=json.loads((pathlib.Path(sys.argv[1])/'input.json').read_text()); config=v['configuration']
root=pathlib.Path('/etc/cats-validator')
for name,value in [('server.crt',v['cert']),('ca.crt',v['ca'])]:
    (root/name).write_text(value); os.chmod(root/name,0o600)
subprocess.run(['openssl','verify','-CAfile',str(root/'ca.crt'),str(root/'server.crt')],check=True,stdout=subprocess.DEVNULL)
cert=subprocess.check_output(['openssl','x509','-in',str(root/'server.crt'),'-pubkey','-noout'])
key=subprocess.check_output(['openssl','pkey','-in',str(root/'server.key'),'-pubout'])
if cert != key: raise RuntimeError('Certificate does not match private key')
def invalidate_rotation_state(state_root):
    # Walk from / using directory descriptors; never follow managed-state symlinks.
    path = pathlib.Path(state_root) / 'identity'
    if not path.is_absolute(): raise RuntimeError('Identity state must be absolute')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                return
            os.close(descriptor)
            descriptor = child
        for name in ('current.json', 'pending.json'):
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode): raise RuntimeError('Unsafe persisted rotation pointer')
            os.unlink(name, dir_fd=descriptor)
    finally:
        os.close(descriptor)

# Enrollment certificates supersede any previously rotated operational identity.
# Only invalidate pointers after trust and private-key matching have succeeded.
invalidate_rotation_state('/var/lib/cats-validator')
port=int(config.get('api_port',8443))
if port < 1 or port > 65535: raise RuntimeError('Invalid port')
node=config.get('node_image','')
if not re.fullmatch(r'[A-Za-z0-9_./:@-]+',node): raise RuntimeError('Explicit node image required')
env={'CATS_VALIDATOR_SERVER_CERT':str(root/'server.crt'),'CATS_VALIDATOR_SERVER_KEY':str(root/'server.key'),'CATS_VALIDATOR_CLIENT_CA':str(root/'ca.crt'),'CATS_VALIDATOR_CLIENT_FINGERPRINTS':v['client_fingerprint'],'CATS_VALIDATOR_STATE_DIR':'/var/lib/cats-validator','CATS_VALIDATOR_SELF_TEST_DIR':'/opt/cats-validator/self-test','CATS_VALIDATOR_ID':config['validator_id'],'CATS_VALIDATOR_HOST':config['host'],'CATS_VALIDATOR_PORT':str(port),'CATS_VALIDATOR_EXECUTION_MODE':'strict','CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS':'false','CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES':'true','CATS_DEPLOYMENT_KIND_NODE_IMAGE':node,'CATS_KIND_NODE_IMAGE':node}
(root/'runtime.env').write_text(''.join(k+'='+value+'\n' for k,value in env.items()))
os.chmod(root/'runtime.env',0o600)
subprocess.run(['chown','-R','cats-validator:cats-validator',str(root)],check=True)
PY
