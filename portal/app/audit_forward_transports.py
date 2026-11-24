"""Outbound protocols for a single committed CATS event. Queueing and retry belong to the worker."""
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


TIMEOUT = 8
CLOUDS = {
    "public": ("login.microsoftonline.com", "monitor.azure.com"),
    "government": ("login.microsoftonline.us", "monitor.azure.us"),
    "china": ("login.partner.microsoftonline.cn", "monitor.azure.cn"),
}
CONFIG_KEYS = {
    "syslog": {"host", "port", "transport", "ca_pem"},
    "splunk": {"url", "index", "sourcetype", "ca_pem"},
    "azure": {"endpoint", "rule_id", "stream", "tenant_id", "client_id", "cloud", "ca_pem"},
}
PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")


class DeliveryError(RuntimeError):
    """A transport failure safe to display in the delivery status."""


def _text(value, name, limit=255):
    if not isinstance(value, str):
        raise ValueError(f"Invalid {name}")
    value = value.strip()
    if not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"Invalid {name}")
    return value


def _host(value):
    host = _text(value, "host")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.removesuffix(".").split(".")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                   for part in labels):
            raise ValueError("Enter an IP address or DNS hostname") from None
        return host.lower()


def _https(value):
    message = "Enter an HTTPS endpoint without credentials, a query, or a fragment"
    url = _text(value, "HTTPS endpoint", 2048)
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError(message) from None
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or "?" in url or "#" in url or "\\" in url or not url.isascii() or any(c.isspace() for c in url)
            or port == 0 or parts.netloc.endswith(":")):
        raise ValueError(message)
    _host(parts.hostname)
    return parts


@lru_cache(maxsize=8)
def _tls_context(ca_pem):
    context = ssl.create_default_context()
    if ca_pem:
        context.load_verify_locations(cadata=ca_pem)
    return context


def validate_config(kind: str, config: dict) -> dict:
    """Return only public settings suitable for storage and display."""
    if not isinstance(kind, str) or kind not in CONFIG_KEYS or not isinstance(config, dict) or set(config) - CONFIG_KEYS[kind]:
        raise ValueError("Unsupported destination type or configuration field")
    clean = {}
    ca = config.get("ca_pem")
    if ca:
        # OpenSSL skips extraneous PEM objects. Public configuration must never store a private key.
        if (not isinstance(ca, str) or len(ca) > 65536 or not PEM_CERTIFICATE.search(ca)
                or PEM_CERTIFICATE.sub("", ca).strip()):
            raise ValueError("Enter PEM-encoded public CA certificates")
        try:
            _tls_context(ca)
        except (ValueError, ssl.SSLError):
            raise ValueError("Invalid CA certificate bundle") from None
        clean["ca_pem"] = ca

    if kind == "syslog":
        transport = config.get("transport", "tls")
        if transport not in ("tls", "tcp", "udp"):
            raise ValueError("Select TLS, TCP or UDP")
        if ca and transport != "tls":
            raise ValueError("Select TLS to use a CA certificate")
        port = config.get("port", 6514 if transport == "tls" else 514)
        if not re.fullmatch(r"[0-9]{1,5}", str(port)) or not 1 <= int(port) <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        clean.update(host=_host(config.get("host")), port=int(port), transport=transport)
    elif kind == "splunk":
        url = _https(config.get("url"))
        path = url.path.rstrip("/")
        if path in ("", "/services/collector"):
            path = "/services/collector/event"
        if not path.endswith("/services/collector/event"):
            raise ValueError("Enter a Splunk HEC base URL or event endpoint")
        clean["url"] = url._replace(path=path).geturl()
        clean["sourcetype"] = _text(config.get("sourcetype") or "cats:audit", "source type")
        if config.get("index"):
            clean["index"] = _text(config["index"], "index")
    else:
        cloud = config.get("cloud", "public")
        if not isinstance(cloud, str) or cloud not in CLOUDS:
            raise ValueError("Select a supported Azure cloud")
        endpoint = _https(config.get("endpoint"))
        suffix = ".ingest." + CLOUDS[cloud][1]
        if (not endpoint.hostname.endswith(suffix) or endpoint.path not in ("", "/")
                or endpoint.port not in (None, 443)):
            raise ValueError("Enter the Logs Ingestion endpoint for the selected Azure cloud")
        clean.update(endpoint=endpoint._replace(path="").geturl(), cloud=cloud)
        for name in ("tenant_id", "client_id"):
            try:
                clean[name] = str(uuid.UUID(_text(config.get(name), name)))
            except ValueError:
                raise ValueError(f"Enter a valid Azure {name} GUID") from None
        clean["rule_id"] = _text(config.get("rule_id"), "data collection rule ID")
        clean["stream"] = _text(config.get("stream"), "stream name")
        if not re.fullmatch(r"dcr-[a-fA-F0-9]{32}", clean["rule_id"]):
            raise ValueError("Enter the immutable data collection rule ID (dcr-...)")
        if not re.fullmatch(r"(?:Custom|Microsoft)-[A-Za-z0-9_-]+", clean["stream"]):
            raise ValueError("Enter the data collection rule stream name")
    return clean


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _timestamp(event):
    timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Missing event time zone")
    return timestamp.astimezone(timezone.utc)


def _syslog(config, event):
    timestamp = _timestamp(event).isoformat(timespec="microseconds").replace("+00:00", "Z")
    hostname = socket.gethostname()
    if not re.fullmatch(r"[!-~]{1,255}", hostname):
        hostname = "-"
    # local0 facility, with info for audit/test events and the recorded severity for diagnostics.
    details = event["data"]
    for _ in range(3):
        if "severity" in details or not isinstance(details.get("reported"), dict):
            break
        details = details["reported"]
    severity = str(details.get("severity", "info")).lower()
    priority = 128 + {"critical": 2, "error": 3, "warning": 4, "notice": 5, "debug": 7}.get(severity, 6)
    message = f"<{priority}>1 {timestamp} {hostname} CATS - cats-event - ".encode("ascii") + _json(event)
    address = (config["host"], config["port"])
    transport = config["transport"]
    if transport == "udp":
        if len(message) > 65507:
            raise DeliveryError("Event exceeds a UDP datagram. Use syslog TCP or TLS")
        addresses = socket.getaddrinfo(*address, type=socket.SOCK_DGRAM)
        for family, socktype, proto, _, target in addresses:
            try:
                with socket.socket(family, socktype, proto) as sock:
                    sock.settimeout(TIMEOUT)
                    if sock.sendto(message, target) == len(message):
                        return
            except OSError:
                continue
        raise DeliveryError("Could not send syslog datagram")
    frame = str(len(message)).encode("ascii") + b" " + message
    with socket.create_connection(address, timeout=TIMEOUT) as sock:
        if transport == "tls":
            with _tls_context(config.get("ca_pem")).wrap_socket(sock, server_hostname=config["host"]) as secure:
                secure.sendall(frame)
        else:
            sock.sendall(frame)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HTTPFailure(DeliveryError):
    def __init__(self, operation, status):
        self.status = status
        super().__init__(f"{operation} returned HTTP {status}")


def _post(operation, url, body, headers, ca=None, expected=200):
    request = Request(url, data=body, headers=headers, method="POST")
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=_tls_context(ca)))
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            if response.status != expected:
                raise _HTTPFailure(operation, response.status)
            if expected == 204:
                return {}
            raw = response.read(65537)
    except HTTPError as error:
        error.close()
        raise _HTTPFailure(operation, error.code) from None
    try:
        if len(raw) > 65536:
            raise ValueError
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, RecursionError):
        raise DeliveryError(f"{operation} returned an invalid response") from None


def _splunk(config, secret, event):
    if not re.fullmatch(r"[!-~]+", secret):
        raise ValueError("Invalid Splunk HEC token")
    payload = {"time": _timestamp(event).timestamp(), "event": event, "source": "CATS",
               "sourcetype": config["sourcetype"]}
    if config.get("index"):
        payload["index"] = config["index"]
    result = _post("Splunk HEC", config["url"], _json(payload),
                   {"Authorization": "Splunk " + secret, "Content-Type": "application/json"}, config.get("ca_pem"))
    if type(result.get("code")) is not int or result["code"] != 0:
        raise DeliveryError("Splunk HEC did not accept the event")


# Workers reuse short-lived tokens. Rotating a credential produces a different cache entry.
_token_lock = threading.Lock()
_tokens = {}


def _azure_token(config, secret, key):
    with _token_lock:
        cached = _tokens.get(key)
        if cached and time.monotonic() < cached[0]:
            return cached[1]
    authority, audience = CLOUDS[config["cloud"]]
    url = f"https://{authority}/{config['tenant_id']}/oauth2/v2.0/token"
    form = urlencode({"grant_type": "client_credentials", "client_id": config["client_id"],
                      "client_secret": secret, "scope": f"https://{audience}/.default"})
    result = _post("Azure authentication", url, form.encode("ascii"),
                   {"Content-Type": "application/x-www-form-urlencoded"})
    token = result.get("access_token")
    if not isinstance(token, str) or not re.fullmatch(r"[!-~]+", token):
        raise DeliveryError("Azure authentication returned an invalid token")
    try:
        lifetime = max(0, min(86400, int(result["expires_in"])) - 60)
    except (KeyError, ValueError, TypeError, OverflowError):
        lifetime = 0
    with _token_lock:
        if len(_tokens) >= 32 and key not in _tokens:
            _tokens.pop(min(_tokens, key=lambda item: _tokens[item][0]))
        _tokens[key] = (time.monotonic() + lifetime, token)
    return token


def _azure(config, secret, event):
    key = (config["cloud"], config["tenant_id"], config["client_id"], hashlib.sha256(secret.encode()).digest())
    token = _azure_token(config, secret, key)
    url = (f"{config['endpoint']}/dataCollectionRules/{config['rule_id']}/streams/{config['stream']}"
           "?api-version=2023-01-01")
    try:
        _post("Azure Logs Ingestion", url, _json([event]),
              {"Authorization": "Bearer " + token, "Content-Type": "application/json"}, config.get("ca_pem"), expected=204)
    except _HTTPFailure as error:
        if error.status == 401:
            with _token_lock:
                _tokens.pop(key, None)
        raise


def send_event(kind: str, config: dict, secret: str, event: dict) -> None:
    config = validate_config(kind, config)
    if kind != "syslog" and (not isinstance(secret, str) or not secret):
        raise ValueError("Missing destination credential")
    try:
        if kind == "syslog":
            _syslog(config, event)
        elif kind == "splunk":
            _splunk(config, secret, event)
        else:
            _azure(config, secret, event)
    except (URLError, OSError, http.client.HTTPException) as error:
        cause = error.reason if isinstance(error, URLError) else error
        if isinstance(cause, ssl.SSLCertVerificationError):
            raise DeliveryError("Collector TLS certificate verification failed") from None
        if isinstance(cause, TimeoutError):
            raise DeliveryError("Collector connection timed out") from None
        raise DeliveryError("Collector connection failed") from None
