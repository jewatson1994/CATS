"""Launch exactly one CATS role; a Docker socket is forbidden in HQ."""
import os
from pathlib import Path
import shutil
import sys


def selected_role(environment):
    return environment.get("CATS_ROLE", "hq").strip().lower()


def command(environment=None, *, socket_present=None, arguments=()):
    env = os.environ if environment is None else environment
    role = selected_role(env)
    if role == "runtime-agent":
        return [sys.executable, "-B", "-u", "-m", "cats_runtime", *(arguments or ("run", "--source", "kubernetes"))]
    if env.get("CATS_IMAGE_VARIANT") == "runtime-arm64":
        raise RuntimeError("The linux/arm64 CATS image supports only CATS_ROLE=runtime-agent")
    socket_present = Path("/var/run/docker.sock").exists() if socket_present is None else socket_present
    if role == "hq":
        if socket_present:
            raise RuntimeError("HQ must not mount a Docker socket; use a dedicated validator host")
        return ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    if role not in ("validator", "validator-appliance"):
        raise RuntimeError("CATS_ROLE must be hq, validator, validator-appliance, or runtime-agent")
    if not socket_present:
        raise RuntimeError("Validator requires the dedicated host Docker socket")
    missing = [tool for tool in ("docker", "kind", "kubectl", "helm", "bash", "tar") if not shutil.which(tool)]
    if missing:
        raise RuntimeError("Validator runtime tools missing: " + ", ".join(missing))
    if role == "validator-appliance":
        return [sys.executable, "-u", "/app/validator_appliance.py"]
    return [sys.executable, "/app/validator_server.py"]


if __name__ == "__main__":
    argv = command(arguments=sys.argv[1:])
    # Helm sets the pod identity. Direct runs with the unified image default
    # to root for other roles, so also drop privileges for this collector.
    if selected_role(os.environ) == "runtime-agent" and os.geteuid() == 0:
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    os.execvp(argv[0], argv)
