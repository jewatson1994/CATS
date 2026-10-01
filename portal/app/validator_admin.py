"""Minimal standalone validator administration, without CATS database dependencies."""
import hashlib
import hmac
import html
import json
import re
import secrets
import threading
import time
from collections import OrderedDict

from cryptography import x509
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import os

from .validator_settings import state_dir, read_settings, write_settings, fingerprints, execution_settings

app = FastAPI(title="CATSchrödinger Administration", docs_url=None, redoc_url=None, openapi_url=None)
SESSIONS = OrderedDict()
ATTEMPTS = OrderedDict()
LOCK = threading.Lock()
COOKIE = "cats_validator_admin"


def password_hash(password):
    if len(password) < 14 or len(password) > 1024:
        raise ValueError("Use a password of 14–1024 characters")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()
    return salt + ":" + digest


def password_matches(password, stored):
    try:
        salt, digest = stored.split(":")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()
        return hmac.compare_digest(actual, digest)
    except (ValueError, AttributeError):
        return False


@app.on_event("startup")
def bootstrap():
    settings = read_settings()
    if "admin_password_hash" not in settings:
        username = os.getenv("CATS_VALIDATOR_ADMIN_USERNAME", "admin")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
            raise RuntimeError("Invalid local administrator username")
        settings.update(admin_username=username,
                        admin_password_hash=password_hash(os.getenv("CATS_VALIDATOR_ADMIN_PASSWORD", "")))
        write_settings(settings)


@app.middleware("http")
async def secure(request, call_next):
    if request.url.scheme != "https":
        return HTMLResponse("HTTPS required", status_code=403)
    response = await call_next(request)
    response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000", "Referrer-Policy": "no-referrer"})
    return response


def session(request):
    token = request.cookies.get(COOKIE, "")
    with LOCK:
        item = SESSIONS.get(token)
        if not item or item["expires"] < time.monotonic():
            SESSIONS.pop(token, None)
            raise HTTPException(401, "Sign in required")
        return item


async def form(request, authenticated=True):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 100000:
            raise HTTPException(413, "Form too large")
    from urllib.parse import parse_qs
    if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
        raise HTTPException(415, "Expected form")
    try:
        parsed = parse_qs(data.decode("utf-8"), keep_blank_values=True, max_num_fields=20)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Invalid form")
    if any(len(values) != 1 for values in parsed.values()):
        raise HTTPException(400, "Duplicate field")
    value = {key: values[0] for key, values in parsed.items()}
    if authenticated and not hmac.compare_digest(value.get("csrf", "").encode(), session(request)["csrf"].encode()):
        raise HTTPException(403, "Invalid form token")
    return value


def page(content):
    return HTMLResponse('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>CATSchrödinger</title><style>body{background:#091310;color:#e7f4ef;font:16px system-ui;margin:0}main{max-width:1000px;margin:48px auto;padding:24px}section{background:#10211b;border:1px solid #294239;border-radius:14px;padding:24px;margin:20px 0}h1{font-size:32px}p,small{color:#aac5ba}label{display:block;margin:16px 0 8px}input,select,textarea{box-sizing:border-box;width:100%;background:#08130f;color:#e7f4ef;border:1px solid #39584b;border-radius:6px;padding:12px}button{background:#76dfb4;border:0;border-radius:6px;padding:12px 20px;margin-top:18px;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #294239}code{overflow-wrap:anywhere}a{color:#76dfb4}</style><main><small>VALIDATOR APPLIANCE</small><h1>CATSchrödinger</h1>''' + content + '</main></html>')


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    try:
        current = session(request)
    except HTTPException:
        return page('<section><h2>Local administrator sign-in</h2><form method="post" action="/login"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><button>Sign in</button></form></section>')
    escape = html.escape
    config = execution_settings()
    csrf = '<input type="hidden" name="csrf" value="' + current["csrf"] + '">'
    mode = config["execution_mode"]
    rows = []
    paths = sorted(state_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in paths:
        if len(rows) >= 50:
            break
        if not re.fullmatch(r"[0-9a-f]{32}\.json", path.name) or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            continue
        try:
            record = json.loads(path.read_text())
            result = record.get("result") or {}
            rows.append('<tr>' + ''.join('<td>' + escape(str(value)) + '</td>' for value in
                (path.stem[:12], record.get("status", ""), record.get("phase", ""), result.get("cleanup_status", "—"))) + '</tr>')
        except (ValueError, OSError, AttributeError):
            continue
    content = '<p>Production CATS initiates requests. This appliance never calls back into production.</p>'
    content += '<section><h2>Connection readiness</h2><p>Check local tools, Docker and disk space here. Use Test connection in main CATS for the end-to-end mTLS test. Jobs below confirm requests arrived without a reverse connection.</p><form method="post" action="/readiness">' + csrf + '<button>Test appliance readiness</button></form></section>'
    content += '<section><h2>Execution &amp; trust</h2><p>Permissive mode can compromise this entire VM and falsify results. Your external network boundary must protect production.</p><form method="post" action="/settings">' + csrf
    content += '<label>Execution mode</label><select name="execution_mode">' + ''.join('<option ' + ('selected ' if item == mode else '') + 'value="' + item + '">' + item.title() + '</option>' for item in ('strict', 'permissive')) + '</select>'
    content += '<label>Authorized CATS client leaf SHA256 fingerprints (comma-separated)</label><textarea name="client_fingerprints" rows="3" required>' + escape(fingerprints()) + '</textarea>'
    content += '<label>Approved Kind node image (digest-pinned)</label><input name="node_image" value="' + escape(config['node_image'], quote=True) + '">'
    for key, label in [('allow_network_egress', 'Allow project network egress'), ('require_local_images', 'Require preloaded images')]:
        content += '<label>' + label + '</label><select name="' + key + '">' + ''.join('<option ' + ('selected ' if config[key] == value else '') + 'value="' + str(value).lower() + '">' + text + '</option>' for value, text in [(False, 'No'), (True, 'Yes')]) + '</select>'
    content += '<label>Shared CA bundle PEM (leave blank to retain existing)</label><textarea name="ca_bundle" rows="5" placeholder="-----BEGIN CERTIFICATE-----"></textarea><small>Used by orchestration tools. Docker daemon and workload trust require separate provisioning. API client CA and server certificate remain mounted operator-managed files.</small><button>Save settings</button></form></section>'
    content += '<section><h2>Recent jobs</h2><table><tr><th>Job</th><th>Status</th><th>Phase</th><th>Cleanup</th></tr>' + ''.join(rows) + '</table><p>Refresh this page for current status. Main CATS provides the authenticated API connection test.</p></section>'
    content += '<section><h2>Local credentials</h2><form method="post" action="/password">' + csrf + '<label>Current password</label><input type="password" name="current_password" required><label>New password (minimum 14 characters)</label><input type="password" name="new_password" minlength="14" required><button>Change password</button></form><form method="post" action="/logout">' + csrf + '<button>Sign out</button></form></section>'
    return page(content)


@app.post("/login")
async def login(request: Request):
    values = await form(request, authenticated=False)
    origin = request.headers.get("origin")
    if origin and origin != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Invalid origin")
    address = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with LOCK:
        timestamps = [value for value in ATTEMPTS.get(address, []) if value > now - 300]
        if len(timestamps) >= 5:
            raise HTTPException(429, "Try again in five minutes")
        ATTEMPTS[address] = timestamps + [now]
        if len(ATTEMPTS) > 1024:
            ATTEMPTS.popitem(last=False)
    settings = read_settings()
    if len(values.get('password', '')) > 1024 or not password_matches(values.get('password', ''), settings.get('admin_password_hash')) or not hmac.compare_digest(values.get('username', '').encode(), settings.get('admin_username', '').encode()):
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(32)
    with LOCK:
        SESSIONS[token] = {"expires": now + 3600, "csrf": secrets.token_urlsafe(32)}
        if len(SESSIONS) > 128:
            SESSIONS.popitem(last=False)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(COOKIE, token, secure=True, httponly=True, samesite="strict", max_age=3600)
    return response


@app.post('/readiness')
async def readiness(request: Request):
    await form(request)
    from .validator_api import health
    import asyncio
    result = await asyncio.to_thread(health)
    return page('<section><h2>Appliance readiness</h2><pre>' + html.escape(json.dumps(result, indent=2)) + '</pre><a href="/">Back to administration</a></section>')


@app.post("/settings")
async def save(request: Request):
    value = await form(request)
    if value.get('execution_mode') not in ('strict', 'permissive') or any(value.get(key) not in ('true', 'false') for key in ('allow_network_egress', 'require_local_images')):
        raise HTTPException(422, "Invalid execution settings")
    authorized = value.get('client_fingerprints', '').lower().replace(' ', '').replace('\n', '')
    if not re.fullmatch(r'[0-9a-f]{64}(,[0-9a-f]{64}){0,31}', authorized):
        raise HTTPException(422, "Provide SHA256 leaf fingerprints")
    image = value.get('node_image', '')
    if image and not re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}', image):
        raise HTTPException(422, "Node image must be digest-pinned")
    if value['execution_mode'] == 'strict' and (value['allow_network_egress'] == 'true' or value['require_local_images'] == 'false'):
        raise HTTPException(422, "Strict mode requires offline, preloaded images")
    bundle = value.get('ca_bundle', '').strip()
    if bundle:
        try:
            certificates = x509.load_pem_x509_certificates(bundle.encode())
            if not certificates or 'PRIVATE KEY' in bundle:
                raise ValueError()
        except ValueError:
            raise HTTPException(422, "Invalid CA certificate bundle")
    with LOCK:
        settings = read_settings()
        settings.update(execution_mode=value['execution_mode'], client_fingerprints=authorized, node_image=image,
                        allow_network_egress=value['allow_network_egress'] == 'true', require_local_images=value['require_local_images'] == 'true')
        if bundle:
            from cryptography.hazmat.primitives.serialization import Encoding
            bundle_path = state_dir() / 'ca-bundle.pem'
            # Replace atomically: existing jobs retain valid readers during edits.
            import tempfile
            with tempfile.NamedTemporaryFile(dir=state_dir(), delete=False) as stream:
                os.chmod(stream.name, 0o600)
                stream.write(b''.join(cert.public_bytes(Encoding.PEM) for cert in certificates))
                staged = stream.name
            os.replace(staged, bundle_path)
        write_settings(settings)
    return RedirectResponse('/', status_code=303)


@app.post('/password')
async def change_password(request: Request):
    value = await form(request)
    with LOCK:
        settings = read_settings()
        if not password_matches(value.get('current_password', ''), settings['admin_password_hash']):
            raise HTTPException(403, 'Current password is incorrect')
        try:
            settings['admin_password_hash'] = password_hash(value.get('new_password', ''))
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        write_settings(settings)
        SESSIONS.clear()
    return RedirectResponse('/', status_code=303)


@app.post('/logout')
async def logout(request: Request):
    await form(request)
    with LOCK:
        SESSIONS.pop(request.cookies.get(COOKIE, ''), None)
    response = RedirectResponse('/', status_code=303)
    response.delete_cookie(COOKIE)
    return response
