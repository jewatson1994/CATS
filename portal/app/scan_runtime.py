"""Per-attempt untrusted-tool identity and environment; no control secrets."""
import contextvars
import os
from pathlib import Path

_identity = contextvars.ContextVar("scan_identity", default=None)

def privileges():
    identity = _identity.get()
    return {"user": identity[0], "group": identity[0], "extra_groups": []} if identity and identity[0] is not None else {}

def sanitized_environment(source=None):
    source = os.environ if source is None else source
    return {key: value for key, value in source.items()
            if not key.startswith(("CATS_SCAN_", "CATS_PORTAL_"))
            and key not in {"DATABASE_URL", "CATS_CONFIG_ENCRYPTION_KEY"}
            and "SECRET" not in key.upper()
            and not key.upper().endswith(("TOKEN", "PASSWORD", "PRIVATE_KEY"))}


def environment():
    identity = _identity.get()
    return identity[1] if identity else sanitized_environment()

def readable(path):
    identity = _identity.get()
    if identity and identity[0] is not None:
        path = Path(path)
        os.chown(path, 0, 0)
        path.chmod(0o770 if path.is_dir() else 0o660)
        os.chown(path, identity[0], 0)


def reclaim(directory):
    """Reclaim scanner-owned output using CHOWN, without DAC/FOWNER caps."""
    directory = Path(directory)
    if os.name == "nt" or os.geteuid() != 0 or not directory.exists():
        return
    def normalize(path):
        if path.is_symlink(): return
        os.chown(path, 0, 0)
        path.chmod(0o700 if path.is_dir() else 0o600)
    normalize(directory)
    for parent, folders, files in os.walk(directory, topdown=True, followlinks=False):
        for name in folders + files:
            normalize(Path(parent) / name)

class identity:
    def __init__(self, uid, env): self.uid, self.env = uid, env
    def __enter__(self):
        self.token = _identity.set((self.uid, self.env))
        return self
    def __exit__(self, *_): _identity.reset(self.token)
