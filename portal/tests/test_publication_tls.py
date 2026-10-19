"""Real TLS regression for destination publication and its subprocess environment."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import subprocess
import sys
import threading
from urllib.error import URLError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from app.release_documentation import registry_environment
from app.release_oci import _Client
from app import cyber_release_publication as publication


def test_managed_ca_verifies_registry_token_service_and_subprocess(tmp_path, monkeypatch):
    for name in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('NO_PROXY', 'localhost,127.0.0.1')
    now = datetime.now(timezone.utc)

    def certificate(name, issuer=None, ca=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(issuer[0].subject if issuer else subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if not ca:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
        return builder.sign(issuer[1] if issuer else key, hashes.SHA256()), key

    root = certificate('managed root', ca=True)
    intermediate = certificate('managed intermediate', root, ca=True)
    leaf, key = certificate('localhost', intermediate)
    pem = lambda cert: cert.public_bytes(serialization.Encoding.PEM).decode()
    certfile, keyfile = tmp_path / 'server.pem', tmp_path / 'server.key'
    certfile.write_text(pem(leaf))  # Deliberately omit the intermediate at the server.
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            calls.append(self.path)
            if self.path.startswith('/token'):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"token":"test-token"}')
            elif self.headers.get('Authorization') != 'Bearer test-token':
                self.send_response(401)
                self.send_header('WWW-Authenticate', f'Bearer realm="https://localhost:{self.server.server_port}/token",service="harbor"')
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    destination = {'name': 'Harbor', 'endpoint': f'https://localhost:{server.server_port}'}
    certificates = [{'pem': pem(root[0])}, {'pem': pem(intermediate[0])}]
    try:
        # Reproduce the old destination-only environment: managed trust was omitted.
        with registry_environment(destination) as env:
            client = _Client(f'localhost:{server.server_port}', 'cyber-approved/test', env)
            with pytest.raises(URLError) as error:
                client.request('GET', client.api + '/manifests/test')
            assert isinstance(error.value.reason, ssl.SSLCertVerificationError)
        with registry_environment(destination, certificates) as env:
            bundle = Path(env['SSL_CERT_FILE'])
            assert all(pem(cert[0]) in bundle.read_text() for cert in (root, intermediate))
            client = _Client(f'localhost:{server.server_port}', 'cyber-approved/test', env)
            assert client.request('GET', client.api + '/manifests/test')[0] == 200
            assert any(path.startswith('/token?') for path in calls)
            # A real child process uses exactly the environment supplied to publication tools.
            subprocess.run([sys.executable, '-c',
                'import ssl,urllib.request,sys; c=ssl.create_default_context(); '
                'assert c.check_hostname and c.verify_mode == ssl.CERT_REQUIRED; '
                'assert urllib.request.urlopen(sys.argv[1],context=c).status == 200',
                destination['endpoint'] + '/token'], env=env, check=True, capture_output=True)
            archive = tmp_path / 'image.tar'
            archive.write_bytes(b'retained archive')
            digest = 'sha256:' + 'a' * 64
            def skopeo(args, **kwargs):
                assert '--dest-tls-verify=true' in args
                certdir = Path(args[args.index('--dest-cert-dir') + 1])
                assert (certdir / 'ca.crt').read_bytes() == bundle.read_bytes()
                assert kwargs['env']['SSL_CERT_FILE'] == str(bundle)
                Path(args[args.index('--digestfile') + 1]).write_text(digest)
            with monkeypatch.context() as scoped:
                scoped.setattr(publication.shutil, 'which', lambda name: name)
                scoped.setattr(publication.subprocess, 'run', skopeo)
                assert publication._publish_image_archive(client, {
                    'path': str(archive), 'digest': publication.file_digest(archive)
                }, env, tmp_path, 0) == digest
            wrong_host = _Client(f'127.0.0.1:{server.server_port}', 'test', env)
            with pytest.raises(URLError) as error:
                wrong_host.request('GET', wrong_host.api + '/manifests/test')
            assert isinstance(error.value.reason, ssl.SSLCertVerificationError)
        assert not bundle.exists()
        with registry_environment({**destination, 'ca_pem': pem(intermediate[0])},
                                  [{'pem': pem(root[0])}]) as env:
            client = _Client(f'localhost:{server.server_port}', 'test', env)
            assert client.request('GET', client.api + '/manifests/test')[0] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
