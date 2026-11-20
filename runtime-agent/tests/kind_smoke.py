"""Live smoke for a dedicated kind-cats-runtime-smoke cluster on a Linux Docker host.

Build cats-runtime:check and create the cluster first. The workflow provisions
and removes it; this script deliberately refuses a different Kubernetes context.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import httpx
import uvicorn
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "runtime-agent/helm/cats-runtime"
CLUSTER = "cats-runtime-smoke"
CONTEXT = "kind-" + CLUSTER
NAMESPACE = "cats-runtime"
WITNESS_NS = "runtime-observed"


def command(*args, capture=False, **kwargs):
    result = subprocess.run(list(map(str, args)), check=True, text=True, stdout=subprocess.PIPE if capture else None, **kwargs)
    return result.stdout


def kube(*args, **kwargs):
    return command("kubectl", "--context", CONTEXT, *args, **kwargs)


def certificates(work, address):
    # The throwaway CA private key stays in memory. Pods receive its public certificate.
    now = datetime.now(timezone.utc)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CATS kind smoke CA")])
    ca_key = ec.generate_private_key(ec.SECP256R1())
    tls_key = ec.generate_private_key(ec.SECP256R1())
    def builder(subject, key, is_ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(minutes=2)).not_valid_after(now+timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=not is_ca, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=is_ca,
                    crl_sign=is_ca, encipher_only=False, decipher_only=False), critical=True))
    ca = builder(issuer, ca_key, True).sign(ca_key, hashes.SHA256())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CATS kind smoke server")])
    leaf = (builder(subject, tls_key, False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert, key, trust = work / "server.crt", work / "server.key", work / "ca.crt"
    trust.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return trust, cert, key


def isolated_portal(work):
    # Configure the databases before importing any portal models.
    database = "sqlite:///" + (work / "runtime.db").as_posix()
    os.environ.update(DATABASE_URL=database, INTELLIGENCE_DATABASE_URL=database, CATS_MODE="full",
                      CATS_ENV="production", CATS_DEV_AUTH_BYPASS="false", SESSION_COOKIE_SECURE="true",
                      CATS_BOOTSTRAP_USERNAME="kind-operator", CATS_BOOTSTRAP_PASSWORD=secrets.token_urlsafe(48))
    sys.path.insert(0, str(ROOT / "portal"))
    from app.main import app
    from app.auth import SESSION_COOKIE, token_hash
    from app.database import SessionLocal
    from app.models import User, UserSession, utcnow
    from sqlalchemy import select

    cookie, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
    with SessionLocal() as db:
        operator = db.execute(select(User).where(User.username == "kind-operator")).scalar_one()
        db.add(UserSession(user_id=operator.id, token_hash=token_hash(cookie), csrf_token=csrf,
                           expires_at=utcnow()+timedelta(minutes=20)))
        db.commit()
    return app, {SESSION_COOKIE:cookie}, {"X-CSRF-Token":csrf}


@contextmanager
def portal_https(work, address, ca, cert, key):
    app, cookies, headers = isolated_portal(work)
    # Serve the production app on the private kind bridge; background workers
    # and scheduled external refreshes are unrelated to the runtime router.
    config = uvicorn.Config(app, lifespan="off", ssl_certfile=str(cert), ssl_keyfile=str(key),
                            access_log=False, log_level="warning")
    server = uvicorn.Server(config)
    with socket.socket() as listener:
        listener.bind((address, 0))
        listener.listen(64)
        url = f"https://{address}:{listener.getsockname()[1]}"
        thread = threading.Thread(target=server.run, kwargs={"sockets":[listener]}, daemon=True)
        thread.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                if not thread.is_alive():
                    raise RuntimeError("Portal HTTPS server exited during startup")
                time.sleep(0.1)
            if not server.started:
                raise RuntimeError("Timed out waiting for the CATS HTTPS listener")
            with httpx.Client(base_url=url, cookies=cookies, headers=headers, trust_env=False,
                              verify=ssl.create_default_context(cafile=str(ca)), timeout=10) as client:
                yield url, client
        finally:
            server.should_exit = True
            thread.join(timeout=10)


def create_key(client, work):
    response = client.post("/api/runtime/environments", json={"name":"kind smoke", "kind":"kubernetes",
                                                              "service_scope":"all", "service_ids":[]})
    response.raise_for_status()
    env_id = response.json()["id"]
    response = client.post(f"/api/runtime/environments/{env_id}/link-tokens", json={})
    response.raise_for_status()
    keyfile = work / "linking-key"
    keyfile.write_text(response.json()["linking_key"], encoding="ascii")
    return env_id, keyfile


def db_identity():
    from app.database import SessionLocal
    from app.runtime_models import RuntimeAgent
    from sqlalchemy import select
    with SessionLocal() as db:
        row = db.scalars(select(RuntimeAgent)).one()
        return (row.id, row.source_id, row.token_hash), row.last_sequence


def wait_report(client, env_id, witness, collector_uid):
    witness_uid = witness["metadata"]["uid"]
    witness_image = witness["spec"]["containers"][0]["image"]
    observed_image = witness["status"]["containerStatuses"][0]["image"]
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        response = client.get("/api/runtime", params={"environment_id":env_id})
        response.raise_for_status()
        report = response.json()
        rows = report["workloads"]
        if (len(report["agents"]) == 1 and report["agents"][0]["coverage"] == "fresh"
                and any(r["namespace"] == WITNESS_NS and r["pod"] == "witness" and r["state"] == "running"
                        and r["uid"] == f"{witness_uid}:regular:witness" and r["image_ref"] in {witness_image, observed_image}
                        for r in rows)
                and any(r["namespace"] == NAMESPACE and r["state"] == "running"
                        and r["uid"] == f"{collector_uid}:regular:collector" for r in rows)):
            return db_identity()
        time.sleep(2)
    raise RuntimeError("CATS did not report a fresh inventory containing the running witness and current collector Pod")


def collector_uid():
    pods = json.loads(kube("-n", NAMESPACE, "get", "pods", "-l", "app.kubernetes.io/instance=cats-runtime",
                           "-o", "json", capture=True))
    live = [p for p in pods["items"] if not p["metadata"].get("deletionTimestamp")]
    if len(live) != 1:
        raise RuntimeError("Expected one live collector Pod")
    return live[0]["metadata"]["uid"]


def main():
    if command("kubectl", "config", "current-context", capture=True).strip() != CONTEXT:
        raise RuntimeError(f"Run in the disposable {CONTEXT} context")
    os.umask(0o077)
    version = yaml.safe_load((CHART / "Chart.yaml").read_text())["appVersion"]
    repository = yaml.safe_load((CHART / "values.yaml").read_text())["image"]["repository"]
    image = f"{repository}:{version}"
    command("docker", "tag", "cats-runtime:check", image)
    command("kind", "load", "docker-image", "--name", CLUSTER, image)
    networks = json.loads(command("docker", "network", "inspect", "kind", capture=True))
    address = next(item["Gateway"] for item in networks[0]["IPAM"]["Config"]
                   if item.get("Gateway") and ipaddress.ip_address(item["Gateway"]).version == 4)
    kube("create", "namespace", NAMESPACE)
    kube("create", "namespace", WITNESS_NS)
    kube("-n", WITNESS_NS, "run", "witness", "--image="+image, "--image-pull-policy=Never",
         "--restart=Never", "--command", "--", "python", "-c", "import time; time.sleep(1800)")
    kube("-n", WITNESS_NS, "wait", "--for=condition=Ready", "pod/witness", "--timeout=180s")
    witness = json.loads(kube("-n", WITNESS_NS, "get", "pod", "witness", "-o", "json", capture=True))

    with tempfile.TemporaryDirectory(prefix="cats-kind-") as directory:
        work = Path(directory)
        ca, cert, key = certificates(work, address)
        kube("-n", NAMESPACE, "create", "secret", "generic", "portal-ca", f"--from-file=ca.crt={ca}")
        with portal_https(work, address, ca, cert, key) as (url, client):
            env_id, keyfile = create_key(client, work)
            command("helm", "install", "cats-runtime", CHART, "--kube-context", CONTEXT, "-n", NAMESPACE,
                    "--set-string", f"catsUrl={url.removeprefix('https://')}", "--set-file", f"linkingKey={keyfile}",
                    "--set-string", "caSecret=portal-ca", "--wait", "--timeout", "4m")
            original_uid = collector_uid()
            original, sequence = wait_report(client, env_id, witness, original_uid)
            # A replacement Pod must report from its retained PVC, even after
            # the setup key is gone. A new Pod UID proves the second report is fresh.
            kube("-n", NAMESPACE, "delete", "secret", "cats-runtime-link")
            kube("-n", NAMESPACE, "rollout", "restart", "deployment/cats-runtime")
            kube("-n", NAMESPACE, "rollout", "status", "deployment/cats-runtime", "--timeout=4m")
            restarted_uid = collector_uid()
            if restarted_uid == original_uid:
                raise RuntimeError("Collector Pod was not replaced")
            current, next_sequence = wait_report(client, env_id, witness, restarted_uid)
            if current != original or next_sequence <= sequence:
                raise RuntimeError("Collector identity or report sequence changed unexpectedly across rollout")
            print("Helm enrollment, live namespace/image reporting, and persisted agent identity passed.")


if __name__ == "__main__":
    main()
