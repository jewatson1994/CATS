set -eu
python3 - "$2" <<'PY'
import json, os, shutil, subprocess, socket, sys, time
from pathlib import Path
values = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
arch = subprocess.check_output(['dpkg','--print-architecture'],text=True).strip() if shutil.which('dpkg') else os.uname().machine
sudo = os.geteuid() == 0
port = int(sys.argv[1])
probe = socket.socket()
try:
    probe.bind(('0.0.0.0', port)); available = True
except OSError:
    available = False
finally:
    probe.close()
existing = subprocess.run(['systemctl','is-active','--quiet','cats-validator.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0 if shutil.which('systemctl') else False
docker_version = subprocess.run(['docker','version','--format','{{.Server.Version}}'],capture_output=True,text=True,timeout=15).stdout.strip() if shutil.which('docker') else None
print(json.dumps({'os':values.get('ID','').strip('"'),'os_version':values.get('VERSION_ID','').strip('"'),'architecture':arch,'cpus':os.cpu_count(),'memory_bytes':int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))*1024,'disk_bytes':shutil.disk_usage('/var').free,'sudo':sudo,'root':os.geteuid() == 0,'systemd':Path('/run/systemd/system').is_dir(),'api_port_available':available,'existing_service':existing,'cgroup_v2':Path('/sys/fs/cgroup/cgroup.controllers').is_file(),'epoch':int(time.time()),'docker_version':docker_version,'docker_present':shutil.which('docker') is not None}))
PY
