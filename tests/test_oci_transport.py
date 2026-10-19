import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from app.oci_transport import ContentCache, RegistryClient, RegistryError

def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()
def response(raw, **headers):
    r = io.BytesIO(raw); r.headers = Message()
    for k,v in headers.items(): r.headers[k] = v
    return r
class TransportTests(unittest.TestCase):
    def client(self, **kw):
        return RegistryClient(dict(endpoint='https://registry.example', username='user', password='secret', **kw))
    def test_raw_manifest(self):
        raw = b'{ "schemaVersion": 2 }\n'; c = self.client()
        c.opener.open = Mock(return_value=response(raw, **{'Content-Type':'application/json'}))
        self.assertEqual(c.fetch_manifest('a/b', digest(raw)), (raw,'application/json',digest(raw)))
    def test_mismatch(self):
        c = self.client(); c.opener.open = Mock(return_value=response(b'wrong'))
        with self.assertRaises(RegistryError): c.fetch_manifest('a', digest(b'right'))
    def test_scope(self):
        c = self.client(token_realms=['https://auth.example']); h = Message()
        h['WWW-Authenticate'] = 'Bearer realm="https://auth.example/token?scope=evil",scope="repository:other:push"'
        c.opener.open = Mock(side_effect=[urllib.error.HTTPError(c.base,401,'auth',h,None),response(b'{"token":"abc"}'),response(b'{}')])
        c.fetch_manifest('a/b','latest')
        req = c.opener.open.call_args_list[1].args[0]
        self.assertIn('scope=repository%3Aa%2Fb%3Apull',req.full_url)
        self.assertNotIn('evil',req.full_url)
        self.assertEqual(c.opener.open.call_args_list[2].args[0].get_header('Authorization'),'Bearer abc')
    def test_realm_denied(self):
        with self.assertRaises(RegistryError): self.client()._token('a','Bearer realm="https://evil.example/token"')
    def test_redirect(self):
        c = self.client(redirect_origins=['https://cdn.example']); h = Message(); h['Location']='https://cdn.example/blob'
        c.opener.open = Mock(side_effect=[urllib.error.HTTPError(c.base,307,'redirect',h,None),response(b'{}')])
        c.fetch_manifest('a','tag')
        self.assertIsNone(c.opener.open.call_args_list[1].args[0].get_header('Authorization'))
    def test_redirect_denied(self):
        c = self.client(); h = Message(); h['Location']='http://registry.example/blob'
        c.opener.open = Mock(side_effect=urllib.error.HTTPError(c.base,307,'redirect',h,None))
        with self.assertRaises(RegistryError): c.fetch_manifest('a','tag')
        self.assertEqual(c.opener.open.call_count,1)
    def test_cache(self):
        with tempfile.TemporaryDirectory() as root:
            cache=ContentCache(root,8,8); p=cache.store(digest(b'12345'),io.BytesIO(b'12345'))
            p.write_bytes(b'bad'); self.assertIsNone(cache.get(digest(b'12345')))
            cache.store(digest(b'12345'),io.BytesIO(b'12345'))
            (Path(root)/'.download-stale').write_bytes(b'junk')
            p2=cache.store(digest(b'abcde'),io.BytesIO(b'abcde'))
            self.assertFalse(p.exists()); self.assertEqual(p2.read_bytes(),b'abcde')
            self.assertFalse((Path(root)/'.download-stale').exists())
            self.assertIsNotNone(ContentCache(root,8,8).get(digest(b'abcde')))
    def test_referrers_pagination(self):
        c = self.client(); d = digest(b'a')
        c.opener.open = Mock(side_effect=[response(b'{"manifests":[{"digest":"one"}]}', Link='</v2/a/referrers/' + d + '?n=1&last=one>; rel="next"'), response(b'{"manifests":[{"digest":"two"}]}')])
        self.assertEqual(len(c.referrers('a', d)['manifests']), 2)
    def test_referrers_pagination_origin(self):
        c = self.client(); d = digest(b'a')
        c.opener.open = Mock(return_value=response(b'{"manifests":[]}', Link='<https://evil.example/steal>; rel="next"'))
        with self.assertRaises(RegistryError): c.referrers('a', d)
        self.assertEqual(c.opener.open.call_count, 1)
    def test_failed_cache(self):
        with tempfile.TemporaryDirectory() as root:
            cache=ContentCache(root,8,8)
            for data in (b'wrong',b'0123456789'):
                with self.assertRaises(RegistryError): cache.store(digest(b'right'),io.BytesIO(data))
            self.assertEqual([p.name for p in Path(root).iterdir()],['.lock'])


class LocalHTTPSTests(unittest.TestCase):
    def test_custom_ca_manifest_blob_and_untrusted_rejection(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            self.skipTest('cryptography required for local HTTPS fixture')
        import datetime
        import ssl
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        raw = b'{ "schemaVersion": 2 }\n'
        blob = b'x' * (2 * 1024 * 1024 + 7)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                if self.headers.get('Authorization') != 'Basic dXNlcjpzZWNyZXQ=':
                    self.send_response(401); self.end_headers(); return
                data = blob if '/blobs/' in self.path else raw
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Content-Type', 'application/vnd.oci.image.manifest.v1+json')
                self.send_header('Docker-Content-Digest', digest(data))
                self.end_headers(); self.wfile.write(data)
        with tempfile.TemporaryDirectory() as root:
            cert_file, key_file = Path(root)/'cert.pem', Path(root)/'key.pem'
            cert_file.write_bytes(pem)
            key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_file, key_file)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            try:
                config = dict(endpoint='https://localhost:' + str(server.server_port), username='user', password='secret')
                client = RegistryClient(dict(config, ca_pem=pem.decode()))
                self.assertEqual(client.fetch_manifest('a', 'tag')[0], raw)
                cache = ContentCache(Path(root)/'cache')
                path = client.fetch_blob('a', digest(blob), cache)
                self.assertEqual(path.stat().st_size, len(blob))
                self.assertEqual(digest(path.read_bytes()), digest(blob))
                with self.assertRaises(RegistryError):
                    RegistryClient(config).fetch_manifest('a', 'tag')
            finally:
                server.shutdown(); server.server_close(); worker.join()

if __name__ == '__main__': unittest.main()
