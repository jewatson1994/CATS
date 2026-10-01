"""HTTPS local-administrator listener; deliberately separate from the mTLS API."""
import os
import ssl
from pathlib import Path
import stat
import uvicorn


def tls_configuration():
    cert = os.environ.get("CATS_VALIDATOR_SERVER_CERT", "")
    key = os.environ.get("CATS_VALIDATOR_SERVER_KEY", "")
    if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
        raise RuntimeError("Admin HTTPS requires a server certificate and key")
    if os.name == "posix" and stat.S_IMODE(Path(key).stat().st_mode) & 0o077:
        raise RuntimeError("Private key permissions must be 0600")
    return {"ssl_certfile": cert, "ssl_keyfile": key, "ssl_version": ssl.PROTOCOL_TLS_SERVER}


if __name__ == "__main__":
    configuration = uvicorn.Config("app.validator_admin:app", host=os.getenv("CATS_VALIDATOR_ADMIN_LISTEN", "0.0.0.0"),
        port=int(os.getenv("CATS_VALIDATOR_ADMIN_PORT", "8444")), proxy_headers=False, **tls_configuration())
    configuration.load()
    configuration.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    uvicorn.Server(configuration).run()
