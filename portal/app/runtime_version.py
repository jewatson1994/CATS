"""Version embedded in the running CATS image."""
import os


def normalize_version(value: str | None) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None
    return "v" + value.lstrip("vV")


def deployed_version() -> str | None:
    return normalize_version(os.getenv("CATS_VERSION"))
