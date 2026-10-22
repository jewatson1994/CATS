"""Export cached official Harbor images for offline reuse; contains no fixture secrets."""
import argparse, hashlib, json, pathlib, subprocess
import yaml
from prepare_harbor import PREPARE
parser=argparse.ArgumentParser();parser.add_argument('--root',default='.test-temp/harbor-local');args=parser.parse_args()
root=pathlib.Path(args.root).resolve()
compose=yaml.safe_load((root/'compose.harbor.yml').read_text())
image_pins=json.loads((pathlib.Path(__file__).parent/'images.lock.json').read_text())
images=sorted(name for name in image_pins if name.startswith('goharbor/'))
for name in images:
 subprocess.run(['docker','tag',image_pins[name]['id'],name],check=True)
# Save a tag for prepare too: Docker archives do not preserve repository digests.
subprocess.run(['docker','tag',PREPARE,'cats-harbor-prepare:v2.15.4'],check=True)
images.append('cats-harbor-prepare:v2.15.4')
archive=root/'harbor-images.tar'
subprocess.run(['docker','image','save','-o',str(archive),*images],check=True)
with archive.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
prepare_id=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',PREPARE],text=True).strip()
image_lock={name:json.loads(subprocess.check_output(['docker','image','inspect',name],text=True))[0] for name in images}
image_lock={name:{'id':value['Id'],'repo_digests':value.get('RepoDigests',[])} for name,value in image_lock.items()}
metadata={'image_lock':image_lock,'prepare_image_id':prepare_id,'archive':archive.name,'sha256':digest,'images':images}
(root/'offline-images.json').write_text(json.dumps(metadata,indent=2))
print(json.dumps(metadata,indent=2))
