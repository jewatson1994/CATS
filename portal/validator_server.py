"""Launch CATSchrödinger with mandatory mutual TLS."""

import os
from pathlib import Path
import ssl

import uvicorn


def tls_configuration() -> dict:
    names = {"ssl_certfile": "CATS_VALIDATOR_SERVER_CERT",
             "ssl_keyfile": "CATS_VALIDATOR_SERVER_KEY",
             "ssl_ca_certs": "CATS_VALIDATOR_CLIENT_CA"}
    values = {key: os.getenv(variable, "") for key, variable in names.items()}
    if any(not value or not Path(value).is_file() for value in values.values()):
        raise RuntimeError("Validator server certificate, key, and trusted client CA are required")
    return {**values, "ssl_cert_reqs": ssl.CERT_REQUIRED}


if __name__ == "__main__":
    uvicorn.run("app.validator_api:app", host=os.getenv("CATS_VALIDATOR_LISTEN", "0.0.0.0"),
                port=int(os.getenv("CATS_VALIDATOR_PORT", "8443")), proxy_headers=False,
                **tls_configuration())
