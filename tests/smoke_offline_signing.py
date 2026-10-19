"""Run inside the CATS image with --network none; uses the existing signer."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from cryptography.fernet import Fernet
from app import signing, release_signing


def main():
    os.environ['CATS_CONFIG_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
    cosign = shutil.which('cosign')
    assert cosign, 'Cosign must be installed in the CATS image'
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        env = signing.clean_environment(dict(os.environ))
        env['COSIGN_PASSWORD'] = 'disposable-test-password'
        prefix = root / 'key'
        subprocess.run([cosign, 'generate-key-pair', '--output-key-prefix', str(prefix)],
            env=env, check=True, capture_output=True, timeout=60)
        saved = signing.store_keys(prefix.with_suffix('.key').read_bytes(),
            prefix.with_suffix('.pub').read_bytes(), env['COSIGN_PASSWORD'], True)
        material = signing.job_material({signing.SETTING: json.dumps(saved)}, 'push')
        manifest = root / 'release-manifest.json'
        manifest.write_text(json.dumps({'format': 'disposable-verification-fixture'}))
        result = release_signing.sign_release_manifest(manifest, root / 'signed', material)
        assert result['status'] == 'signed', result
        signature = root / 'signed' / result['signature_file']
        public = root / 'signed' / result['public_key_file']
        assert release_signing.verify_release_manifest(manifest, signature, public,
            saved['fingerprint'])['status'] == 'verified'
        manifest.write_bytes(manifest.read_bytes() + b' ')
        assert release_signing.verify_release_manifest(manifest, signature, public,
            saved['fingerprint'])['status'] == 'verification_failed'
        print('PASS: encrypted Cosign key, existing CATS signer, offline verification, tamper denial')


if __name__ == '__main__':
    main()
