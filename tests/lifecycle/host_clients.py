"""Run on the host after prepare.py and compose up -d runner with CATS_CLIENT_PROBE=1."""
import argparse,base64,json,subprocess,time,os
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);args=parser.parse_args();root=args.root.resolve()
def wait(name):
 for _ in range(600):
  if (root/name).exists():return
  time.sleep(.5)
 raise RuntimeError('Timed out waiting for '+name)
wait('clients-ready.json')
config=root/'docker-config';config.mkdir(exist_ok=True)
(config/'config.json').write_text(json.dumps({'auths':{'127.0.0.1:18083':{'auth':base64.b64encode(b'client-robot:fixture-token').decode()}}}))
env=dict(os.environ,DOCKER_CONFIG=str(config));results={}
def run(name,command,success):
 start=time.perf_counter();completed=subprocess.run(command,env=env,capture_output=True,text=True,timeout=120)
 results[name]={'exit_code':completed.returncode,'elapsed_ms':round((time.perf_counter()-start)*1000,2),'output':(completed.stdout+completed.stderr)[-3000:]}
 (root/'client-results.json').write_text(json.dumps(results,indent=2))
 if (completed.returncode==0)!=success:raise RuntimeError(name+': '+results[name]['output'])
image='127.0.0.1:18083/clients/image:stable'
run('docker_pull',['docker','pull',image],True)
registry_config=str(root/'helm-registry.json')
Path(registry_config).write_text((config/'config.json').read_text())
helm=['helm','pull','oci://127.0.0.1:18083/clients/fixture','--version','0.1.0','--plain-http','--registry-config',registry_config,'--destination',str(root)]
run('helm_pull',helm,True)
(root/'clients-pulled').touch();wait('clients-revoked')
run('docker_revoked',['docker','pull',image],False)
run('helm_revoked',helm,False)
(root/'clients-finished').touch()
print(json.dumps(results,indent=2))
