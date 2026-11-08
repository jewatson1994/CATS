"""Smoke-test a built full CATS image using the real replica Compose commands.

Requires Docker Compose and an existing local image. Creates a unique temporary
project with PostgreSQL and no published ports or external network access, then
removes its containers, network and volumes even when a check fails. Run with::

    python scripts/verify-replica-image.py --image cats:local
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import uuid


ENGINE_ENV = {
    "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "COMSPEC", "PATHEXT",
    "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH", "SSH_AUTH_SOCK",
}
APPLICATIONS = {"portal": ("app.main:app", 8000), "oci-proxy": ("app.oci_proxy:app", 5000)}


def isolated_config(config: dict, *, image: str, project: str) -> dict:
    """Retain production startup commands and storage, isolate host resources."""
    result = copy.deepcopy(config)
    services = result["services"]
    if set(services) != {"db", *APPLICATIONS}:
        raise ValueError("Replica Compose must contain only db, portal and oci-proxy")
    for name, (application, port) in APPLICATIONS.items():
        service = services[name]
        expected = ["uvicorn", application, "--host", "0.0.0.0", "--port", str(port), "--no-proxy-headers"]
        if service.get("image") != image:
            raise ValueError(f"{name} does not use the supplied full CATS image")
        if service.get("command") != expected or service.get("entrypoint") != []:
            raise ValueError(f"{name} must explicitly run the replica uvicorn command")
        env = service.get("environment", {})
        if env.get("CATS_MODE") != "replica" or str(env.get("CATS_DEPLOYMENT_VALIDATION_ENABLED")).lower() != "false":
            raise ValueError(f"{name} must disable assessment in replica mode")
        if "INTELLIGENCE_DATABASE_URL" in env:
            raise ValueError(f"{name} must not connect to an intelligence database")
    for name, service in services.items():
        if service.get("privileged"):
            raise ValueError(f"{name} must not be privileged")
        for volume in service.get("volumes", []):
            if volume.get("type") != "volume":
                raise ValueError(f"{name} must not mount host files or sockets")
        service.pop("build", None)
        service.pop("ports", None)
        service["restart"] = "no"
        service["networks"] = {"default": None}
    result["name"] = project
    result["networks"] = {"default": {"name": project + "_default", "internal": True}}
    result["volumes"] = {name: {"name": project + "_" + name} for name in result.get("volumes", {})}
    return result


# Runs in each live container. HTTP checks exercise real startup, schema creation,
# database access and the replica middleware; the process check catches accidental
# worker/scanner launch while retaining the tools bundled in the full image.
CONTAINER_CHECK = r'''
import json, os, sys, urllib.error, urllib.request
from pathlib import Path
from app.operating_mode import is_replica
assert is_replica(), 'Container is not operating in replica mode'
service = sys.argv[1]
application, port, endpoint = (('app.main:app', 8000, '/readyz') if service == 'portal'
                              else ('app.oci_proxy:app', 5000, '/healthz'))
base = 'http://127.0.0.1:' + str(port)
with urllib.request.urlopen(base + endpoint, timeout=10) as response:
    assert response.status == 200
    assert json.load(response)['status'] == 'ready'
if service == 'portal':
    for method in ('GET', 'POST'):
        try:
            urllib.request.urlopen(urllib.request.Request(base + '/scan', method=method), timeout=10)
        except urllib.error.HTTPError as response:
            assert response.code == 403, response.code
            assert json.load(response)['code'] == 'replica_read_only'
        else:
            raise AssertionError('Replica permitted assessment request: ' + method)
assert not Path('/var/run/docker.sock').exists(), 'Replica has a Docker socket'
argv = Path('/proc/1/cmdline').read_bytes().split(b'\0')
assert application.encode() in argv, 'PID 1 is not the expected replica application'
for process in Path('/proc').iterdir():
    if not process.name.isdigit() or int(process.name) == os.getpid():
        continue
    try:
        argv = process.joinpath('cmdline').read_bytes().decode(errors='replace').split('\0')
    except (FileNotFoundError, PermissionError):
        continue
    forbidden = {'grype', 'trivy', 'syft', 'copa', 'cats-scan', 'cats-patch',
                 'cats-scan-worker', 'cats-discovery-worker', 'cats-remediation-worker',
                 'cats-export-worker', 'validator_server.py', 'run-scan.sh'}
    assert not any(Path(arg).name in forbidden or arg.startswith((
        'app.scan_worker', 'app.patch_worker', 'app.discovery_worker',
        'app.remediation_worker', 'app.export_worker', 'app.scan_control',
        'app.intelligence_importer', 'app.daily_security_data', 'app.risk_worker',
        'app.provisioning_worker'))
        for arg in argv), 'Assessment process running: ' + str(argv)
print(service + ': database ready, replica guard active, no assessment processes')
'''


def run_smoke(image: str, repo: Path, timeout: int) -> None:
    env = {key: value for key, value in os.environ.items() if key.upper() in ENGINE_ENV}
    env.update({
        "CATS_IMAGE": image,
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "CATS_BOOTSTRAP_USERNAME": "replica-smoke-admin",
        "CATS_BOOTSTRAP_PASSWORD": secrets.token_urlsafe(32),
        "CATS_CONFIG_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    })

    def docker(*args: str, check: bool = True, seconds: int = 300) -> subprocess.CompletedProcess:
        result = subprocess.run(["docker", *args], env=env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=seconds)
        if check and result.returncode:
            # Compose configuration contains credentials; never print its output.
            diagnostics = result.stderr if "config" in args else result.stdout + result.stderr
            raise RuntimeError("Docker operation failed: " + args[0] + "\n" + diagnostics.strip())
        return result

    docker("image", "inspect", image)
    project = "cats-replica-smoke-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix=project + "-") as directory:
        folder = Path(directory)
        env_file = folder / ".env"
        env_file.write_text("", encoding="utf-8")
        # An explicit empty env file prevents this checkout's .env from changing
        # the generated smoke deployment or importing real site credentials.
        resolved = docker("compose", "--project-name", project, "--env-file", str(env_file),
                          "--file", str(repo / "compose.replica.yaml"), "config", "--format", "json")
        config = isolated_config(json.loads(resolved.stdout), image=image, project=project)
        config_file = folder / "compose.json"
        descriptor = os.open(config_file, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(config, output)
        command = ("compose", "--project-name", project, "--env-file", str(env_file), "--file", str(config_file))
        active_error = False
        try:
            docker(*command, "up", "--detach", "--wait", "--wait-timeout", str(timeout),
                   "--no-build", "--pull", "missing", seconds=timeout + 300)
            for service in APPLICATIONS:
                result = docker(*command, "exec", "-T", service, "python", "-c", CONTAINER_CHECK, service)
                print(result.stdout.strip())
        except BaseException:
            active_error = True
            logs = docker(*command, "logs", "--no-color", "--tail", "80", check=False)
            print(logs.stdout + logs.stderr, file=sys.stderr)
            raise
        finally:
            cleanup = docker(*command, "down", "--volumes", "--remove-orphans", check=False)
            if cleanup.returncode:
                print(f"Cleanup failed for temporary project {project}:\n{cleanup.stderr}", file=sys.stderr)
                if not active_error:
                    raise RuntimeError("Replica smoke passed but temporary project cleanup failed")
    print("Full CATS image passed replica-mode smoke verification.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Existing local full CATS image tag or digest")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=int, default=180, help="Service startup timeout in seconds")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    run_smoke(args.image, args.repo.resolve(), args.timeout)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Replica image verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
