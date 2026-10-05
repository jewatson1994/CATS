"""Launch exactly one CATS role; a Docker socket is forbidden in HQ."""
import os
from pathlib import Path
import shutil
import sys


def command(environment=None, *, socket_present=None):
    env = os.environ if environment is None else environment
    role = env.get("CATS_ROLE", "hq").strip().lower()
    socket_present = Path("/var/run/docker.sock").exists() if socket_present is None else socket_present
    if role == "hq":
        if socket_present:
            raise RuntimeError("HQ must not mount a Docker socket; use a dedicated validator host")
        return ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    if role != "validator":
        raise RuntimeError("CATS_ROLE must be hq or validator")
    if not socket_present:
        raise RuntimeError("Validator requires the dedicated host Docker socket")
    missing = [tool for tool in ("docker", "kind", "kubectl", "helm", "bash", "tar") if not shutil.which(tool)]
    if missing:
        raise RuntimeError("Validator runtime tools missing: " + ", ".join(missing))
    return [sys.executable, "/app/validator_server.py"]


if __name__ == "__main__":
    argv = command()
    os.execvp(argv[0], argv)
