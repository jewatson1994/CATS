"""Launch CATSchrödinger with mandatory mutual TLS."""

import os
from pathlib import Path
import ssl
import hashlib
import stat
import re
from app.validator_settings import fingerprints as trusted_fingerprints

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol


class MutualTLSH11Protocol(H11Protocol):
    """Attach identity exclusively from the authenticated TLS transport."""

    def connection_made(self, transport):
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        fingerprint = hashlib.sha256(certificate).hexdigest() if certificate else None
        application = self.app

        async def authenticated_application(scope, receive, send):
            scope["validator_peer_sha256"] = fingerprint
            await application(scope, receive, send)

        self.app = authenticated_application


def tls_configuration() -> dict:
    fingerprints = trusted_fingerprints().split(",")
    if not fingerprints or any(not re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()) for value in fingerprints):
        raise RuntimeError("Explicit trusted client SHA256 certificate fingerprints are required")
    names = {"ssl_certfile": "CATS_VALIDATOR_SERVER_CERT",
             "ssl_keyfile": "CATS_VALIDATOR_SERVER_KEY",
             "ssl_ca_certs": "CATS_VALIDATOR_CLIENT_CA"}
    values = {key: os.getenv(variable, "") for key, variable in names.items()}
    if any(not value or not Path(value).is_file() for value in values.values()):
        raise RuntimeError("Validator server certificate, key, and trusted client CA are required")
    if os.name == "posix" and stat.S_IMODE(Path(values["ssl_keyfile"]).stat().st_mode) & 0o077:
        raise RuntimeError("Validator private key must not be accessible to group or others")
    return {**values, "ssl_cert_reqs": ssl.CERT_REQUIRED, "ssl_version": ssl.PROTOCOL_TLS_SERVER}


if __name__ == "__main__":
    configuration = uvicorn.Config("app.validator_api:app", host=os.getenv("CATS_VALIDATOR_LISTEN", "0.0.0.0"),
                port=int(os.getenv("CATS_VALIDATOR_PORT", "8443")), proxy_headers=False,
                http=MutualTLSH11Protocol,
                **tls_configuration())
    configuration.load()
    configuration.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    uvicorn.Server(configuration).run()
