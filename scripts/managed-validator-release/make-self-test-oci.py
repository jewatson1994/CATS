"""Build a deterministic OCI scratch image using only a locally compiled static binary."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

binary, layout = map(Path, sys.argv[1:])
blobs = layout / 'blobs/sha256'; blobs.mkdir(parents=True)
def serialize(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def blob(data, media):
    digest = hashlib.sha256(data).hexdigest()
    (blobs / digest).write_bytes(data)
    return {'mediaType':media, 'digest':'sha256:' + digest, 'size':len(data)}
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
    info = tarfile.TarInfo('server'); info.size=binary.stat().st_size; info.mode=0o555
    info.mtime=0; info.uid=info.gid=0
    with binary.open('rb') as stream: archive.addfile(info,stream)
layer = blob(buffer.getvalue(), 'application/vnd.oci.image.layer.v1.tar')
config = blob(serialize({'architecture':'amd64', 'os':'linux',
    'created':'1970-01-01T00:00:00Z', 'config':{'User':'65532:65532', 'Entrypoint':['/server'],
    'ExposedPorts':{'8080/tcp':{}}, 'WorkingDir':'/'},
    'rootfs':{'type':'layers', 'diff_ids':[layer['digest']]},
    'history':[{'created':'1970-01-01T00:00:00Z', 'created_by':'CATS deterministic scratch self-test 1.0.0'}]}),
    'application/vnd.oci.image.config.v1+json')
manifest = blob(serialize({'schemaVersion':2, 'mediaType':'application/vnd.oci.image.manifest.v1+json',
    'config':config, 'layers':[layer]}), 'application/vnd.oci.image.manifest.v1+json')
manifest['annotations']={'org.opencontainers.image.ref.name':'1.0.0'}
(layout / 'index.json').write_bytes(serialize({'schemaVersion':2, 'manifests':[manifest]}))
(layout / 'oci-layout').write_bytes(serialize({'imageLayoutVersion':'1.0.0'}))
(layout / 'reference.txt').write_text('cats.local/validator-self-test@' + manifest['digest'] + '\n')
