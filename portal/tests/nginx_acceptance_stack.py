"""Opt-in provisioning for the real nginx workflow/replica acceptance drivers.

The default invocation prints a plan without invoking Docker or writing files.
Use --provision to start services, adding --build to build the full runtime image
once for both operating modes. Supply an existing image otherwise. For example::

    python portal/tests/nginx_acceptance_stack.py --repo . --workspace /tmp/nginx-check \
        --project cats-nginx-check --provision --build --scanner-base catscan-base:local \
        --trivy-source-volume existing_fresh_trivy_cache

Scanner source volumes are copied read-only into this project's own volumes.
Without an explicit source volume, the runtime image must contain that scanner's
real database. Existing workspace credentials and signing keys are preserved.
Cleanup requires the ownership record written by this script and runs Compose
down for that exact project only; --remove-volumes additionally removes its data.
No registry, scanner, signature, evidence, or application response is mocked.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import uuid


OWNER = "cats-real-nginx-acceptance-v1"
SELECTED_SERVICES = (
    "db", "intelligence-db", "intelligence-init", "patch-worker", "portal",
    "portal-control", "scan-worker", "discovery-worker", "remediation-worker",
    "export-worker",
)
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,62}$")
VOLUME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
ENGINE_ENV = {
    "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "COMSPEC", "PATHEXT",
    "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH", "SSH_AUTH_SOCK",
}


def private_write(path: Path, content: str) -> None:
    """Do not print generated credentials; use private file modes where supported."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    if os.name != "nt":
        path.chmod(0o600)


def write_json(path: Path, value: object) -> None:
    private_write(path, json.dumps(value, indent=2) + "\n")


class Docker:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.sequence = 0
        # A user's unrelated CATS_* variables must not override this stack's .env.
        self.env = {k: v for k, v in os.environ.items() if k.upper() in ENGINE_ENV}

    def run(self, label: str, arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
        self.sequence += 1
        log = self.workspace / f"provision-{self.sequence:02d}-{label}.log"
        result = subprocess.run(["docker", *arguments], env=self.env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        private_write(log, result.stdout + result.stderr)
        if check and result.returncode:
            raise RuntimeError(f"{label} failed; private diagnostic log: {log}")
        return result


def mount(source: Path, target: str, *, readonly: bool = True) -> dict:
    return {"type": "bind", "source": str(source), "target": target, "read_only": readonly}


def public_trust_mounts(workspace: Path) -> list[dict]:
    # Client processes must never receive the registry's TLS private key.
    return [mount(workspace / "tls" / name, "/run/acceptance-tls/" + name)
            for name in ("registry.crt", "ca-bundle.crt")]


def helper_user_arguments() -> list[str]:
    # Keep mode-0600 output readable by the invoking host user on Linux/macOS.
    return ["--user", f"{os.getuid()}:{os.getgid()}"] if os.name == "posix" else []


def credentials(workspace: Path, args) -> dict:
    path = workspace / "credentials.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8-sig"))
    token = lambda: secrets.token_urlsafe(32)
    key = lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    full = {
        "CATS_IMAGE": args.full_image, "POSTGRES_PASSWORD": token(),
        "INTELLIGENCE_POSTGRES_PASSWORD": token(),
        "CATS_BOOTSTRAP_USERNAME": "acceptance-admin", "CATS_BOOTSTRAP_PASSWORD": token(),
        "CATS_CONFIG_ENCRYPTION_KEY": key(), "CATS_PATCH_WORKER_TOKEN": token(),
        "CATS_SCAN_WORKER_TOKEN": token(), "PIPELINE_API_TOKEN": token(),
        "CATS_SCAN_REGISTRY_AUTH_SOURCE": (workspace / "registry-auth").as_posix(),
        "CATS_PORT": str(args.full_port), "SESSION_COOKIE_SECURE": "false",
        "CATS_DEPLOYMENT_VALIDATION_ENABLED": "false", "CATS_SCAN_CONCURRENCY": "1",
        "CATS_REMEDIATION_WORKERS": "1",
    }
    value = {"full": full, "replica": {"username": "replica-admin", "password": token(),
             "db_password": token(), "encryption_key": key()},
             "admin_new_password": token(), "replica_admin_new_password": token()}
    write_json(path, value)
    return value


# Run in the actual full image: no host Python crypto or Cosign installation needed.
TLS_AND_SIGNER = r'''
import json,os,secrets,subprocess
from pathlib import Path
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
def private_bytes(path, content):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(descriptor,'wb') as output:
        os.fchmod(output.fileno(),0o600)
        output.write(content)
root=Path('/runtime'); folder=root/'tls'; folder.mkdir(exist_ok=True)
cert_path=folder/'registry.crt'
if not cert_path.exists():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'CATS isolated nginx acceptance')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
        .not_valid_after(now+timedelta(days=7)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('publisher.test'),x509.DNSName('replica.test')]),False)
        .sign(key,hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path=folder/'registry.key'
    private_bytes(key_path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
cert=x509.load_pem_x509_certificate(cert_path.read_bytes())
if cert.not_valid_after_utc <= datetime.now(timezone.utc):
    raise RuntimeError('Acceptance TLS certificate expired; use a fresh workspace.')
(folder/'ca-bundle.crt').write_bytes(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()+b'\n'+cert_path.read_bytes())
if not (root/'signer.json').exists():
    password=secrets.token_urlsafe(32)
    subprocess.run(['cosign','generate-key-pair','--output-key-prefix',str(root/'signer')],
        env=dict(os.environ,COSIGN_PASSWORD=password),check=True,capture_output=True)
    private_bytes(root/'signer.json',json.dumps({'private_key':'signer.key','public_key':'signer.pub','password':password}).encode())
    (root/'signer.key').chmod(0o600)
'''


def composition(canonical: dict, args, values: dict) -> dict:
    workspace, project = args.workspace, args.project
    result = {"name": project, "services": {}, "volumes": {},
              "networks": copy.deepcopy(canonical["networks"])}
    for name, network in result["networks"].items():
        network["name"] = f"{project}_{name}"
    trust = {"SSL_CERT_FILE": "/run/acceptance-tls/ca-bundle.crt",
             "REQUESTS_CA_BUNDLE": "/run/acceptance-tls/ca-bundle.crt",
             "CURL_CA_BUNDLE": "/run/acceptance-tls/ca-bundle.crt"}
    for name in SELECTED_SERVICES:
        service = copy.deepcopy(canonical["services"][name])
        service.pop("build", None)
        service.pop("x-shared-environment", None)
        service["restart"] = "no"
        if "security_opt" in service:
            service["security_opt"] = [
                "seccomp=" + str(args.repo / "deploy/discovery-seccomp.json")
                if option.startswith("seccomp=") else option for option in service["security_opt"]]
        service.setdefault("environment", {}).update(trust)
        service.setdefault("volumes", []).extend(public_trust_mounts(workspace))
        for volume in service["volumes"]:
            if volume.get("type") == "volume":
                source = volume["source"]
                result["volumes"][source] = {"name": f"{project}_{source}"}
        for dependency in service.get("depends_on", {}):
            if dependency not in SELECTED_SERVICES:
                raise ValueError(f"Selected service {name} requires omitted service {dependency}")
        if name == "portal":
            service["ports"] = [f"127.0.0.1:{args.full_port}:8000"]
        if name == "scan-worker":
            service["environment"]["TRIVY_SKIP_DB_UPDATE"] = "true"
        result["services"][name] = service

    registry_environment = {
        "REGISTRY_HTTP_ADDR": "0.0.0.0:5000",
        "REGISTRY_HTTP_TLS_CERTIFICATE": "/tls/registry.crt",
        "REGISTRY_HTTP_TLS_KEY": "/tls/registry.key",
        "REGISTRY_STORAGE_DELETE_ENABLED": "true",
    }
    for name, alias in (("publisher-registry", "publisher.test"), ("replica-registry", "replica.test")):
        result["services"][name] = {
            "image": "registry:2.8.3", "environment": registry_environment,
            "volumes": [mount(workspace / "tls/registry.crt", "/tls/registry.crt"),
                        mount(workspace / "tls/registry.key", "/tls/registry.key"),
                        f"{name}-data:/var/lib/registry"],
            "networks": {"default": {"aliases": [alias]}, "scan_egress": {"aliases": [alias]}},
            "restart": "no",
        }
        result["volumes"][name + "-data"] = {"name": project + "_" + name + "-data"}

    # Only this dedicated daemon has privileges. Its socket is never mounted in
    # the portal or scan/discovery workers, and no host daemon configuration changes.
    # Copa needs the Docker BuildKit MergeOp/DiffOp capabilities supplied by the
    # containerd image store; the classic overlay2 image store disables them.
    result["services"]["patch-daemon"] = {
        "image": args.dind_image, "privileged": True, "entrypoint": ["/bin/sh", "-c"],
        "command": ["mkdir -p /etc/docker/certs.d/publisher.test:5000 /etc/docker/certs.d/replica.test:5000"
                    " && cp /run/acceptance-tls/registry.crt /etc/docker/certs.d/publisher.test:5000/ca.crt"
                    " && cp /run/acceptance-tls/registry.crt /etc/docker/certs.d/replica.test:5000/ca.crt"
                    " && exec dockerd --host=unix:///run/patch-docker/docker.sock --feature containerd-snapshotter=true"],
        "environment": {"DOCKER_TLS_CERTDIR": ""},
        "volumes": ["patch_docker_data:/var/lib/docker", "patch_docker_socket:/run/patch-docker",
                    *public_trust_mounts(workspace)],
        "healthcheck": {"test": ["CMD-SHELL", "docker --host unix:///run/patch-docker/docker.sock info "
                                 "--format '{{json .DriverStatus}}' | grep -q 'io.containerd.snapshotter.v1'"],
                        "interval": "5s", "timeout": "5s", "retries": 20}, "restart": "no",
    }
    patch = result["services"]["patch-worker"]
    patch["volumes"] = [v for v in patch["volumes"] if v.get("target") != "/var/run/docker.sock"]
    patch["volumes"].append("patch_docker_socket:/run/patch-docker")
    patch["environment"]["DOCKER_HOST"] = "unix:///run/patch-docker/docker.sock"
    patch["depends_on"] = {"patch-daemon": {"condition": "service_healthy"}}

    replica = values["replica"]
    replica_env = {
        **trust, "CATS_MODE": "replica", "CATS_ENV": "production", "CATS_DEV_AUTH_BYPASS": "false",
        "DATABASE_URL": "postgresql+psycopg://cats@replica-db:5432/cats", "PGPASSWORD": replica["db_password"],
        "CATS_BOOTSTRAP_USERNAME": replica["username"], "CATS_BOOTSTRAP_PASSWORD": replica["password"],
        "CATS_CONFIG_ENCRYPTION_KEY": replica["encryption_key"], "SESSION_COOKIE_SECURE": "false",
        "CATS_APPROVED_RELEASE_ROOT": "/var/lib/cats/releases", "CATS_REPLICA_STORAGE": "/var/lib/cats/replica",
        "CATS_OCI_CACHE_DIR": "/var/cache/cats-oci", "CATS_DEPLOYMENT_VALIDATION_ENABLED": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result["services"]["replica-db"] = {
        "image": "postgres:16-alpine", "environment": {"POSTGRES_DB": "cats", "POSTGRES_USER": "cats",
                                                       "POSTGRES_PASSWORD": replica["db_password"]},
        "volumes": ["replica_db:/var/lib/postgresql/data"],
        "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U cats -d cats"], "interval": "5s",
                        "timeout": "5s", "retries": 20}, "restart": "no",
    }
    for name, host_port, port, application, endpoint in (
        ("replica-portal", args.replica_port, 8000, "app.main:app", "/readyz"),
        ("replica-proxy", args.proxy_port, 5000, "app.oci_proxy:app", "/healthz"),
    ):
        result["services"][name] = {
            "image": args.replica_image,
            "entrypoint": [],
            "command": ["uvicorn", application, "--host", "0.0.0.0", "--port", str(port), "--no-proxy-headers"],
            "environment": replica_env, "ports": [f"127.0.0.1:{host_port}:{port}"],
            "volumes": ["replica_evidence:/var/lib/cats" + (":ro" if name == "replica-proxy" else ""),
                        "replica_cache:/var/cache/cats-oci", *public_trust_mounts(workspace)],
            "depends_on": {"replica-db": {"condition": "service_healthy"}},
            "healthcheck": {"test": ["CMD", "python", "-c",
                f"import urllib.request; urllib.request.urlopen('http://127.0.0.1:{port}{endpoint}', timeout=3)"],
                "interval": "10s", "timeout": "5s", "retries": 12, "start_period": "30s"},
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "restart": "no",
        }
    result["services"]["replica-proxy"]["depends_on"]["replica-portal"] = {"condition": "service_healthy"}
    for name in ("replica_db", "replica_evidence", "replica_cache", "patch_docker_data", "patch_docker_socket"):
        result["volumes"][name] = {"name": f"{project}_{name}"}
    return result


def seed_cache(docker: Docker, args, logical: str, source: str | None) -> None:
    if not source:
        return  # Docker initializes a new named volume from the real image data.
    docker.run("inspect-source-" + logical, ["volume", "inspect", source])
    destination = f"{args.project}_{logical}"
    exists = docker.run("inspect-target-" + logical, ["volume", "inspect", destination], check=False)
    if exists.returncode == 0:
        return  # Never recopy into an active or previously seeded scanner database.
    docker.run("create-" + logical, ["volume", "create", "--label", f"com.docker.compose.project={args.project}",
               "--label", f"com.docker.compose.volume={logical}", destination])
    docker.run("copy-" + logical, ["run", "--rm", "--network", "none", "--entrypoint", "python",
               "--mount", f"type=volume,src={source},dst=/source,readonly",
               "--mount", f"type=volume,src={destination},dst=/target", args.full_image,
               "-c", "import shutil; shutil.copytree('/source','/target',dirs_exist_ok=True,symlinks=True)"])


def prepare_images(docker: Docker, args) -> None:
    if args.build:
        docker.run("build-full", ["build", "-f", str(args.repo / "cats-image/Dockerfile.all-in-one"),
                   "--build-arg", "CATSCAN_BASE_IMAGE=" + args.scanner_base,
                   "--tag", args.full_image, str(args.repo)])
    docker.run("inspect-full", ["image", "inspect", args.full_image])
    if args.replica_image != args.full_image:
        # Compatibility override: callers provide this image; never build a
        # separate lightweight replica as part of single-image qualification.
        docker.run("inspect-replica", ["image", "inspect", args.replica_image])


def provision(args, owned: dict | None) -> None:
    workspace = args.workspace
    workspace.mkdir(parents=True, exist_ok=True)
    owner_file = workspace / "stack-owner.json"
    docker = Docker(workspace)
    if not owned:
        for filename in ("compose.json", "credentials.json", "stack.json", "signer.json"):
            if (workspace / filename).exists():
                raise ValueError("Workspace contains an unmanaged stack; use a fresh workspace.")
        for kind, command in (
            ("containers", ["ps", "-aq", "--filter", f"label=com.docker.compose.project={args.project}"]),
            ("volumes", ["volume", "ls", "-q", "--filter", f"name={args.project}_"]),
            ("networks", ["network", "ls", "-q", "--filter", f"name={args.project}_"]),
        ):
            if docker.run("check-project-" + kind, command).stdout.strip():
                raise ValueError("Project name already has Docker resources; choose a fresh project name.")
        write_json(owner_file, {"owner": OWNER, "project": args.project, "repo": str(args.repo),
                               "compose_file": str(workspace / "compose.json")})
    prepare_images(docker, args)
    values = credentials(workspace, args)
    values["full"]["CATS_IMAGE"] = args.full_image
    values["full"]["CATS_PORT"] = str(args.full_port)
    write_json(workspace / "credentials.json", values)
    private_write(workspace / ".env", "\n".join(k + "=" + v for k, v in values["full"].items()) + "\n")
    (workspace / "registry-auth").mkdir(exist_ok=True)
    if not (workspace / "registry-auth/config.json").exists():
        write_json(workspace / "registry-auth/config.json", {"auths": {}})
    docker.run("tls-signer", ["run", "--rm", "--network", "none", *helper_user_arguments(), "--entrypoint", "python",
               "--mount", f"type=bind,src={workspace},dst=/runtime", args.full_image, "-c", TLS_AND_SIGNER])
    resolved = docker.run("resolve-compose", ["compose", "--project-directory", str(args.repo), "--env-file", str(workspace / ".env"),
                          "-f", str(args.repo / "templates/compose.local.yaml"), "config", "--format", "json"])
    config = composition(json.loads(resolved.stdout), args, values)
    compose_file = workspace / "compose.json"
    write_json(compose_file, config)
    seed_cache(docker, args, "security_grype_db", args.grype_source_volume)
    seed_cache(docker, args, "security_trivy_db", args.trivy_source_volume)
    full, replica = values["full"], values["replica"]
    stack = {
        "full_url": f"http://127.0.0.1:{args.full_port}", "replica_url": f"http://127.0.0.1:{args.replica_port}",
        "proxy_url": f"http://127.0.0.1:{args.proxy_port}", "admin_username": full["CATS_BOOTSTRAP_USERNAME"],
        "admin_password": full["CATS_BOOTSTRAP_PASSWORD"], "admin_new_password": values["admin_new_password"],
        "replica_admin_username": replica["username"], "replica_admin_password": replica["password"],
        "replica_admin_new_password": values["replica_admin_new_password"], "compose_file": str(compose_file),
        "project": args.project, "full_service": "portal", "replica_service": "replica-portal",
        "ca_file": str(workspace / "tls/registry.crt"),
    }
    write_json(workspace / "stack.json", stack)
    compose = ["compose", "-p", args.project, "-f", str(compose_file)]
    docker.run("start", [*compose, "up", "-d", "--wait", "--wait-timeout", "240"])
    docker.run("scanner-databases", [*compose, "exec", "-T", "patch-worker", "python", "-c",
        "from pathlib import Path; import json; "
        "assert Path('/opt/catscan/grype-db/6/vulnerability.db').stat().st_size > 1000000; "
        "assert Path('/opt/catscan/trivy-cache/db/trivy.db').stat().st_size > 1000000; "
        "json.loads(Path('/opt/catscan/trivy-cache/db/metadata.json').read_text())"])
    print(json.dumps({"status": "ready", "project": args.project, "stack_file": str(workspace / "stack.json"),
                      "services": list(config["services"]), "configure_trusted_ca": str(workspace / "tls/registry.crt")}))


def cleanup(args, owned: dict | None) -> None:
    if not owned:
        raise ValueError("Cleanup requires this script's existing stack-owner.json.")
    compose_file = args.workspace / "compose.json"
    if Path(owned["compose_file"]).resolve() != compose_file:
        raise ValueError("Ownership record points outside the selected workspace.")
    config = json.loads(compose_file.read_text(encoding="utf-8-sig"))
    if config.get("name") != args.project:
        raise ValueError("Compose project does not match the ownership record.")
    for collection in ("volumes", "networks"):
        for resource in config.get(collection, {}).values():
            if resource.get("external") or not resource.get("name", "").startswith(args.project + "_"):
                raise ValueError("Cleanup configuration references resources outside the owned project.")
    command = ["compose", "-p", args.project, "-f", str(compose_file), "down"]
    if args.remove_volumes:
        command.append("--volumes")
    Docker(args.workspace).run("cleanup", command)
    print(json.dumps({"status": "stopped", "project": args.project, "removed_volumes": args.remove_volumes}))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--project", help="Unique Compose project; generated once when omitted")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--provision", action="store_true")
    action.add_argument("--cleanup", action="store_true")
    parser.add_argument("--build", action="store_true", help="Build the full image once for both modes; requires --provision")
    parser.add_argument("--remove-volumes", action="store_true", help="With --cleanup, also remove this project's data volumes")
    parser.add_argument("--full-image", default="cats:nginx-acceptance")
    parser.add_argument("--replica-image", help="Optional existing image override; defaults to --full-image")
    parser.add_argument("--scanner-base", default="catscan-base:local")
    parser.add_argument("--dind-image", default="docker:28.5.2-dind")
    parser.add_argument("--grype-source-volume")
    parser.add_argument("--trivy-source-volume")
    parser.add_argument("--full-port", type=int, default=18886)
    parser.add_argument("--replica-port", type=int, default=18887)
    parser.add_argument("--proxy-port", type=int, default=15887)
    args = parser.parse_args(argv)
    args.replica_image = args.replica_image or args.full_image
    if args.build and not args.provision:
        parser.error("--build requires --provision")
    if args.remove_volumes and not args.cleanup:
        parser.error("--remove-volumes requires --cleanup")
    args.repo, args.workspace = args.repo.resolve(), args.workspace.resolve()
    for path in (args.repo, args.workspace):
        if any(character in str(path) for character in (",", "\n", "\r", "$", "#", "'", '"')):
            parser.error("Repository/workspace paths contain characters unsafe for Docker mount or .env syntax")
    for relative in ("templates/compose.local.yaml", "cats-image/Dockerfile.all-in-one"):
        if not (args.repo / relative).is_file():
            parser.error(f"Required repository file missing: {relative}")
    ports = (args.full_port, args.replica_port, args.proxy_port)
    if len(set(ports)) != 3 or any(not 1024 <= port <= 65535 for port in ports):
        parser.error("Use three distinct unprivileged ports between 1024 and 65535")
    for volume in (args.grype_source_volume, args.trivy_source_volume):
        if volume and not VOLUME_RE.fullmatch(volume):
            parser.error("Invalid scanner source volume name")
    return parser, args


def main(argv=None) -> int:
    parser, args = parse_args(argv)
    owned = None
    owner_file = args.workspace / "stack-owner.json"
    if owner_file.exists():
        owned = json.loads(owner_file.read_text(encoding="utf-8-sig"))
        if owned.get("owner") != OWNER:
            parser.error("Workspace ownership marker is not recognized")
        if args.project and args.project != owned["project"]:
            parser.error("Requested project differs from the workspace's recorded project")
        args.project = owned["project"]
    args.project = args.project or "cats-nginx-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:8]
    if not PROJECT_RE.fullmatch(args.project):
        parser.error("Project must be a lowercase Compose name of 3 to 63 characters")
    if args.cleanup:
        cleanup(args, owned)
    elif args.provision:
        provision(args, owned)
    else:
        print(json.dumps({"action": "plan-only", "project": args.project, "workspace": str(args.workspace),
            "repo": str(args.repo), "full_image": args.full_image, "replica_image": args.replica_image,
            "services": [*SELECTED_SERVICES, "patch-daemon", "publisher-registry", "replica-registry",
                         "replica-db", "replica-portal", "replica-proxy"],
            "ports": {"full": args.full_port, "replica": args.replica_port, "proxy": args.proxy_port},
            "next": "Add --provision; add --build only when the full runtime image must be built."}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Acceptance provisioning failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
