"""Real Cosign attestation smoke test against a disposable localhost OCI registry.
Run in an isolated container sharing the test registry network namespace.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urljoin

import requests
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from app import signing, oci_attestations

endpoint = 'http://localhost:5000'
api = endpoint + '/v2/attestation-smoke'
session = requests.Session()
session.trust_env = False

def blob(data, media):
    response = session.post(api + '/blobs/uploads/', timeout=10)
    response.raise_for_status()
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    location = urljoin(endpoint, response.headers['Location'])
    response = session.put(location, params={'digest': digest}, data=data,
                           headers={'Content-Type': 'application/octet-stream'}, timeout=10)
    response.raise_for_status()
    return {'digest': digest, 'size': len(data), 'mediaType': media}

config = blob(b'{}', 'application/vnd.oci.image.config.v1+json')
layer = blob(b'retained test evidence', 'application/vnd.oci.image.layer.v1.tar')
manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                       'config': config, 'layers': [layer]}).encode()
digest = 'sha256:' + hashlib.sha256(manifest).hexdigest()
response = session.put(api + '/manifests/' + digest, data=manifest,
                       headers={'Content-Type': 'application/vnd.oci.image.manifest.v1+json'}, timeout=10)
response.raise_for_status()
reference = 'localhost:5000/attestation-smoke@' + digest
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    env = dict(os.environ, COSIGN_PASSWORD='temporary-attestation-smoke-password')
    subprocess.run(['cosign', 'generate-key-pair', '--output-key-prefix', str(root / 'key')],
                   env=env, check=True, capture_output=True)
    import base64
    pem, fingerprint = signing.public_key((root / 'key.pub').read_bytes())
    material = ({'signing_enabled': True, 'signing_public_key': pem, 'signing_fingerprint': fingerprint},
                {signing.SECRET_ENV[0]: base64.b64encode((root / 'key.key').read_bytes()).decode(),
                 signing.SECRET_ENV[1]: env['COSIGN_PASSWORD']})
    evidence = {'report.json': 'sha256:' + hashlib.sha256(b'report').hexdigest()}
    receipt = oci_attestations.attest_and_verify(reference, 'scan', evidence, material)
    assert receipt['status'] == 'verified'
    for purpose, claims, trust in [('patch', evidence, fingerprint),
                                   ('scan', {'report.json': 'sha256:' + '0' * 64}, fingerprint),
                                   ('scan', evidence, 'sha256:' + '0' * 64)]:
        try:
            oci_attestations.verify_attestation(reference, purpose, claims, pem.encode(), trust)
        except oci_attestations.AttestationError:
            pass
        else:
            raise AssertionError('Mismatched attestation accepted')
print('PASS real Cosign OCI attestation; pinned offline verification; wrong purpose/evidence/trust rejected')
