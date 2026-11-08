"""Interactive, authenticated post-install configuration; Python standard library only.

This client uses the same session, CSRF and authorization boundary as the portal UI.
It never prints request bodies, server error bodies, passwords or signing material.
"""
from __future__ import annotations

import getpass
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
import urllib.error
import urllib.parse
import urllib.request


PAGE_TYPE = "application/vnd.cats.page+json"
REPOSITORY = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*\Z")
PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")


class SetupError(RuntimeError):
    """A deliberately credential-free setup failure suitable for terminal output."""


class PortalError(SetupError):
    def __init__(self, method, path, status):
        self.status = status
        super().__init__(f"Portal rejected {method} {path} (HTTP {status}). Review access and configuration in the portal.")


def https_url(value: str, *, allow_path: bool = False) -> str:
    value = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    try:
        parsed.port
    except ValueError:
        raise SetupError("Use a valid HTTPS port.") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or (parsed.path and not allow_path) or len(value) > 500
            or any(char.isspace() or ord(char) < 32 for char in value)
            or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", parsed.hostname)):
        raise SetupError("Use a credential-free HTTPS origin, such as https://registry.example.org.")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PortalClient:
    def __init__(self, portal_url: str, ca_file: str | None = None):
        self.base = https_url(portal_url)
        context = ssl.create_default_context()
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect())
        self.csrf = ""

    def request(self, method, path, body=None, content_type=None, *, accept="application/json", redirect=False):
        if not path.startswith("/") or path.startswith("//"):
            raise SetupError("Invalid portal request path.")
        headers = {"Accept": accept, "User-Agent": "CATS-guided-setup/1"}
        if content_type:
            headers["Content-Type"] = content_type
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            try:
                response = self.opener.open(request, timeout=240 if "signing" in path else 60)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                status = response.code
                location = response.headers.get("Location", "")
                if 300 <= status < 400:
                    target = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + path, location))
                    base = urllib.parse.urlsplit(self.base)
                    if not redirect or status != 303 or not location or (target.scheme, target.netloc) != (base.scheme, base.netloc):
                        raise SetupError("Portal returned an unexpected redirect; no credentials were forwarded.")
                    return target.path
                if not 200 <= status < 300:
                    raise PortalError(method, path, status)
                if redirect:
                    raise SetupError("Portal did not confirm the form submission. Review it in the portal.")
                payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise SetupError("Portal response exceeded the setup size limit.")
                try:
                    return json.loads(payload)
                except (ValueError, UnicodeError):
                    raise SetupError("Portal returned an unexpected response; check the public URL and sign-in.") from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError):
            raise SetupError("Unable to reach the portal with verified HTTPS. Check DNS, reachability and the CA bundle.") from None

    def page(self, path):
        response = self.request("GET", path, accept=PAGE_TYPE)
        if not isinstance(response, dict) or not isinstance(response.get("data"), dict):
            raise SetupError("Portal page data was not recognized.")
        data = response["data"]
        if not isinstance(data.get("csrf_token"), str) or not data["csrf_token"]:
            raise SetupError("An authenticated portal session is required.")
        self.csrf = data["csrf_token"]
        return data

    def form(self, path, values, *, login=False):
        fields = dict(values)
        if not login:
            fields["csrf_token"] = self.csrf
        return self.request("POST", path, urllib.parse.urlencode(fields).encode(),
                            "application/x-www-form-urlencoded", redirect=True)

    def json(self, path, values=None):
        return self.request("GET" if values is None else "POST", path,
                            None if values is None else json.dumps(values).encode(),
                            None if values is None else "application/json")

    def upload(self, path, values, files):
        boundary = "cats-setup-" + secrets.token_hex(24)
        parts = []
        for key, value in {**values, "csrf_token": self.csrf}.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'.encode() + str(value).encode() + b"\r\n")
        for key, filename, content in files:
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + content + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return self.request("POST", path, b"".join(parts), f"multipart/form-data; boundary={boundary}", redirect=True)

    def login(self, username, password):
        current = getpass.getpass("Current administrator password [Enter uses the installation password]: ") or password
        destination = self.form("/login", {"username": username, "password": current, "next": "/"}, login=True)
        if destination == "/account/access":
            raise SetupError("This account needs an authorized administrator role before registry setup.")
        data = self.page("/account/password")
        if destination == "/account/password":
            print("Set a new administrator password (at least 14 characters). Save it in your password manager.")
            while True:
                replacement = getpass.getpass("New administrator password: ")
                confirmation = getpass.getpass("Confirm new administrator password: ")
                if len(replacement) >= 14 and replacement == confirmation and replacement != current:
                    break
                print("Use matching passwords of at least 14 characters, different from the current password.")
            self.form("/account/password", {"current_password": current, "new_password": replacement, "confirmation": confirmation})
            print("Administrator password changed. The installation password no longer signs in.")
        return data


def ask(prompt, default="", *, optional=False, validate=None):
    while True:
        answer = input(prompt + (f" [{default}]" if default else "") + ": ").strip() or default
        if not answer and optional:
            return ""
        if not answer:
            print("Enter a value, or cancel setup with Ctrl+C.")
            continue
        try:
            return validate(answer) if validate else answer
        except (SetupError, ValueError):
            print("That value is not valid for this setting. Please try again.")


def yes(prompt, default=False):
    return ask(prompt, "yes" if default else "no", validate=lambda value: _choice(value.lower(), {"yes", "no", "y", "n"})) in {"yes", "y"}


def _choice(value, choices):
    if value not in choices:
        raise ValueError()
    return value


def bounded_int(value, low, high):
    number = int(value)
    if not low <= number <= high:
        raise ValueError()
    return number


def repo(value, *, pattern=False):
    name = value[:-2] if pattern and value.endswith("/*") else value
    if (len(value) > 255 or not REPOSITORY.fullmatch(name)
            or (pattern and value.endswith("/*") and value.count("/") != 1)):
        raise ValueError()
    return value


def read_file(filename, maximum):
    try:
        with Path(filename).expanduser().open("rb") as stream:
            content = stream.read(maximum + 1)
        if not content or len(content) > maximum:
            raise SetupError("The selected file is empty or exceeds the allowed size.")
        return content
    except OSError:
        raise SetupError("The selected file cannot be read.") from None


def ca_bundle():
    filename = ask("Registry CA bundle path (PEM; Enter uses system trust)", optional=True)
    if not filename:
        return ""
    content = read_file(filename, 262144).decode("ascii")
    try:
        ssl.create_default_context().load_verify_locations(cadata=content)
    except (ssl.SSLError, ValueError):
        raise SetupError("The registry CA bundle is not a valid PEM certificate bundle.") from None
    return content


def select_existing(rows, label):
    enabled = [row for row in rows if row.get("enabled", True)]
    if not enabled:
        return None
    for row in enabled:
        print(f"  {row['id']}: {row.get('name') or row.get('public_repository') or row.get('display_name')}")
    selection = ask(f"Existing {label} ID, or new", "new",
                    validate=lambda value: _choice(value, {"new", *(str(row["id"]) for row in enabled)}))
    return next((row for row in enabled if str(row["id"]) == selection), None)


def upstream(client, mode):
    if not yes("Configure the local replicated registry connection" if mode == "replica" else "Configure the OCI distribution upstream", True):
        return None
    selected = select_existing(client.json("/api/oci/upstreams"), "registry connection")
    if selected:
        return selected
    name = ask("Registry connection name", "Local registry" if mode == "replica" else "Distribution registry")
    endpoint = ask("Registry HTTPS origin", validate=https_url)
    username = ask("Registry read-only username (Enter for anonymous)", optional=True)
    password = getpass.getpass("Registry read-only password/token: ") if username else ""
    ca = ca_bundle()
    print("Allow only registry authentication realms and blob redirect origins you independently trust.")
    realms = ask("Additional token realm URLs, comma-separated (Enter for none)", optional=True,
                 validate=lambda value: [https_url(item, allow_path=True) for item in value.split(",")])
    redirects = ask("Additional blob redirect HTTPS origins, comma-separated (Enter for none)", optional=True,
                    validate=lambda value: [https_url(item) for item in value.split(",")])
    return client.json("/api/oci/upstreams", {"name": name, "endpoint": endpoint, "username": username,
                       "password": password, "ca_pem": ca, "token_realms": realms or [], "redirect_origins": redirects or [], "enabled": True})


def destination(client, completed, pending):
    if not yes("Configure the main registry destination for release publication", True):
        pending.append("Main: configure a release destination under Configuration > OCI registries.")
        return
    data = client.page("/admin/configuration")
    existing = [row for row in data.get("registries", []) if row.get("use_for_remediation")]
    if existing and yes("Keep the current default publication/staging registry", True):
        completed.append("Existing default publication registry retained")
        return
    endpoint = ask("Publication registry HTTPS origin", validate=https_url)
    namespace = ask("Publication project/namespace", validate=repo)
    name = ask("Publication registry name", "CATS publication")
    username = ask("Publication registry username with push permission (Enter for anonymous)", optional=True)
    password = getpass.getpass("Publication registry password/token: ") if username else ""
    ca = ca_bundle()
    if ca:
        print("This CA bundle will be added to the portal's shared outbound trust store.")
        try:
            client.upload("/admin/configuration/trusted-certificates", {}, [("certificate", "registry-ca.pem", ca.encode())])
        except PortalError as exc:
            # This endpoint uses 409 only when every uploaded certificate is
            # already configured. Retain the existing trust without replacing it.
            if exc.status != 409:
                raise
    client.form("/admin/configuration/registries", {"registry_id": "setup-" + secrets.token_hex(6), "display_name": name,
                "endpoint": endpoint, "namespace": namespace, "auth_mode": "credentials" if username else "none",
                "username": username, "password": password, "use_for_remediation": "true", "action": "save"})
    completed.append("Default publication/staging registry saved")
    pending.append("Main: verify registry push access with a service release; saving a destination does not test publication.")


def generate_signing_key(image, state_dir, docker_endpoint=None):
    if not docker_endpoint or not docker_endpoint.startswith("unix:///"):
        raise SetupError("Signing-key generation requires the installer's verified local Docker endpoint.")
    folder = Path(state_dir).expanduser().resolve() / "signing"
    if "," in str(folder):
        raise SetupError("Choose a signing backup directory without commas for the Docker bind mount.")
    # Never reuse a directory: interrupted attempts remain available for recovery.
    try:
        folder.mkdir(mode=0o700)
        folder.chmod(0o700)
    except FileExistsError:
        raise SetupError("Signing backup directory already exists. Import its existing key; generation never overwrites it.") from None
    password = getpass.getpass("Signing key passphrase [Enter generates a strong random passphrase]: ") or secrets.token_urlsafe(48)
    password_file = folder / "passphrase.txt"
    descriptor = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(password)
    docker_variables = {"DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("COSIGN_") and key not in docker_variables}
    environment["COSIGN_PASSWORD"] = password
    try:
        result = subprocess.run(["docker", "--host", docker_endpoint, "run", "--rm", "--pull", "never", "--network", "none",
                                 "--user", f"{os.getuid()}:{os.getgid()}",
                                 "--entrypoint", "/usr/local/bin/cosign", "-e", "COSIGN_PASSWORD",
                                 "--mount", f"type=bind,source={folder},target=/keys", image,
                                 "generate-key-pair", "--output-key-prefix", "/keys/cats-signing"],
                                env=environment, capture_output=True, timeout=180, check=False, stdin=subprocess.DEVNULL)
        if result.returncode:
            raise SetupError("Signing-key generation failed. Retained backup files can be inspected locally; command output was suppressed.")
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError("Signing-key generation could not finish. Existing backup files were retained.") from None
    finally:
        environment.pop("COSIGN_PASSWORD", None)
    private = folder / "cats-signing.key"
    public = folder / "cats-signing.pub"
    private.chmod(0o600)
    public.chmod(0o600)
    print(f"Signing key and passphrase saved privately in {folder}. Back up this directory securely.")
    return read_file(str(private), 32768), read_file(str(public), 32768), password


def signing(client, completed, pending, image, state_dir, docker_endpoint=None):
    if not yes("Configure and enable release signing", True):
        pending.append("Main: configure and enable signing under Configuration > Signing.")
        return
    metadata = client.page("/admin/configuration").get("signing", {})
    if metadata.get("configured") and yes("Keep the configured signing key", True):
        if not metadata.get("enabled"):
            if yes("Enable the existing signing key", True):
                client.form("/admin/configuration/signing", {"enabled": "true", "action": "save"})
                metadata = client.page("/admin/configuration").get("signing", {})
                if not metadata.get("configured") or not metadata.get("enabled"):
                    raise SetupError("The portal did not confirm enabled signing; review Configuration > Signing.")
                completed.append("Existing signing key enabled")
            else:
                pending.append("Main: enable the retained signing key under Configuration > Signing.")
        print("Publisher root fingerprint: " + str(metadata.get("publisher_root") or metadata.get("fingerprint")))
        completed.append("Existing signing key retained")
        return
    if image and state_dir and yes("Generate a new signing key using the installed image", True):
        private, public, password = generate_signing_key(image, state_dir, docker_endpoint)
    else:
        filename = ask("Cosign private key path (Enter to finish signing later in the portal)", optional=True)
        if not filename:
            pending.append("Main: import a Cosign signing key and enable signing under Configuration > Signing.")
            return
        private = read_file(filename, 32768)
        public_filename = ask("Matching public key path (Enter lets CATS derive it)", optional=True)
        public = read_file(public_filename, 32768) if public_filename else b""
        password = getpass.getpass("Signing private-key passphrase: ")
    files = [("private_key", "cosign.key", private)]
    if public:
        files.append(("public_key", "cosign.pub", public))
    client.upload("/admin/configuration/signing", {"enabled": "true", "action": "save", "key_password": password}, files)
    metadata = client.page("/admin/configuration").get("signing", {})
    if not metadata.get("configured") or not metadata.get("enabled"):
        raise SetupError("The portal did not confirm enabled signing; review Configuration > Signing.")
    print("Publisher root fingerprint: " + str(metadata.get("publisher_root") or metadata.get("fingerprint")))
    print("Share this public fingerprint with replica administrators over an independently trusted channel.")
    completed.append("Signing key installed and enabled")


def replica_source(client, registry, completed, pending):
    if not registry or not yes("Configure the trusted replica release source", True):
        pending.append("Replica: configure a local registry and trusted release source in Replica administration.")
        return None
    rows = client.json("/api/replica/sources")["sources"]
    source = select_existing([row for row in rows if row["upstream_id"] == registry["id"]], "replica source")
    if source is None:
        name = ask("Replica source name", "Approved releases")
        repository = ask("Release discovery scope (project/* or exact project/service/releases)",
                         validate=lambda value: repo(value, pattern=True) if value.endswith(("/*", "/releases")) else _choice(value, set()))
        print("Obtain the ORIGINAL publisher root fingerprint independently from the main administrator; do not copy it from an untrusted registry.")
        fingerprint = ask("Trusted publisher root fingerprint (sha256: followed by 64 lowercase hex digits)",
                          validate=lambda value: value if PIN.fullmatch(value) else _choice(value, set()))
        poll = ask("Automatic sync interval in seconds (10–86400)", "300", validate=lambda value: bounded_int(value, 10, 86400))
        source = client.json("/api/replica/sources", {"name": name, "upstream_id": registry["id"], "repository": repository,
                            "trusted_publishers": [fingerprint], "poll_seconds": poll, "enabled": True})
    completed.append("Trusted replica source configured")
    if yes("Queue an initial sync now", True):
        client.json("/api/replica/sync", {"source_id": source["id"]})
        completed.append("Initial replica sync queued")
        pending.append("Replica: confirm the sync succeeded and approved releases are visible in Replica administration.")
    else:
        pending.append("Replica: confirm a scheduled or manual sync succeeds before using this replica.")
    return source


def distribution(client, registry, completed, pending):
    if not registry or not yes("Configure a project-scoped OCI distribution mapping", True):
        pending.append("Configure OCI distribution repository mappings before allowing consumer pulls.")
        return
    rows = [row for row in client.json("/api/oci/repositories") if row["upstream_id"] == registry["id"] and not row.get("suspended")]
    mapping = select_existing(rows, "distribution mapping")
    if mapping is None:
        def project(value):
            if not value.endswith("/*"):
                raise ValueError()
            return repo(value, pattern=True)
        upstream_name = ask("Upstream project scope (project/*)", validate=project)
        public_name = ask("Public project scope (project/*)", upstream_name, validate=project)
        mapping = client.json("/api/oci/repositories", {"upstream_id": registry["id"], "public_repository": public_name,
                              "upstream_repository": upstream_name, "service_id": None, "policy": {}, "enabled": True, "suspended": False})
    completed.append("OCI distribution repository mapping configured")
    if not yes("Create an optional consumer credential scoped only to this mapping"):
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        pending.append("Create consumer credentials in OCI distribution administration; terminal-only secret display was unavailable.")
        return
    print(f"The consumer credential will allow pulls only through mapping {mapping['public_repository']} while current approval permits them.")
    name = ask("Consumer machine name", validate=lambda value: value if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) else _choice(value, set()))
    days = ask("Credential lifetime in days (1–365)", "90", validate=lambda value: bounded_int(value, 1, 365))
    principal = client.json("/api/oci/principals", {"name": name, "repository_ids": [mapping["id"]], "enabled": True,
                            "expires_at": (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()})
    # This is the only secret output, created explicitly and only on a terminal.
    print("ONE-TIME CONSUMER CREDENTIAL — save in your password manager now:")
    print("Username: " + name)
    print("Password: " + principal.pop("secret"))
    completed.append("Consumer credential created for one repository mapping")


def configure_registry(mode: str, portal_url: str, username: str, password: str,
                       ca_file: str | None = None, *, image: str | None = None,
                       state_dir: str | Path | None = None, docker_endpoint: str | None = None) -> dict:
    """Prompt for post-start configuration and return completed/pending action lists.

    The caller must provide a verified HTTPS portal hostname. No connection occurs
    when the operator declines this stage. Existing settings are retained unless
    the operator explicitly chooses to create or replace the relevant setting.
    """
    if mode not in {"main", "replica"}:
        raise SetupError("Expected main or replica setup mode.")
    completed, pending = [], []
    if not yes("Configure registries, trust and signing through the running portal now", True):
        pending.append(f"Finish {mode} registry, trust and signing/distribution setup in the portal.")
    else:
        client = PortalClient(portal_url, ca_file)
        try:
            data = client.login(username, password)
            expected = "full" if mode == "main" else "replica"
            if data.get("cats_mode") != expected:
                raise SetupError("The portal operating mode does not match this installer.")
            registry = upstream(client, mode)
            if registry:
                completed.append("OCI registry connection configured")
            if mode == "main":
                destination(client, completed, pending)
                signing(client, completed, pending, image, state_dir, docker_endpoint)
            else:
                replica_source(client, registry, completed, pending)
            distribution(client, registry, completed, pending)
        finally:
            if client.csrf:
                try:
                    client.form("/logout", {})
                except SetupError:
                    pass
    for item in completed:
        print("Configured: " + item)
    for item in pending:
        print("Remaining: " + item)
    return {"completed": completed, "pending": pending}
