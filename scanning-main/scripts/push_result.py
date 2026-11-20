"""Send CATS scanner output with the caller's delivery credentials."""
import argparse
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit


def project_endpoint(base, path, parser):
    try:
        url = urlsplit(base)
        valid = (url.scheme == "https" and url.hostname and url.username is None and url.password is None
                 and not any(char in base for char in ("?", "#", "\\")) and base.isascii() and base.isprintable())
        if url.port is not None and url.port < 1:
            valid = False
    except ValueError:
        valid = False
    if not valid:
        parser.error("Set CATS_PORTAL_URL to the HTTPS portal address")
    return base.rstrip("/") + path


def post(endpoint, token, data_args, *, project, idempotency_key=None, push_timeout=False):
    # Feed curl its credential through stdin, retaining the file for streaming.
    headers = f"Authorization: Bearer {token}\n"
    if idempotency_key is not None:
        headers += f"Idempotency-Key: {idempotency_key}\n"
    command = ["curl", "--disable", "--silent", "--show-error", "--fail-with-body", "--globoff"]
    if project:
        command.extend(["--proto", "=https", "--location", "--max-redirs", "0"])
    if push_timeout:
        command.extend(["--connect-timeout", "5", "--max-time", "30"])
    else:
        command.extend(["--connect-timeout", "15"])
    command.extend(["--header", "@-", "--header", "Accept: application/json"])
    ca_file = os.environ.get("CATS_PORTAL_CA_FILE") or os.environ.get("CATS_PORTAL_CA_CERT")
    if ca_file:
        command.extend(["--cacert", ca_file])
    command.extend([*data_args, "--url", endpoint])
    env = os.environ.copy()
    env.pop("CATS_PROJECT_TOKEN", None)
    env.pop("CATS_PORTAL_TOKEN", None)
    return subprocess.run(command, input=headers.encode(), env=env, check=False).returncode


def project_token(token, parser):
    if not re.fullmatch(r"cats_project_[A-Za-z0-9_-]+", token):
        parser.error("Set CATS_PROJECT_TOKEN to the service's project credential")
    return token


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cats push")
    parser.add_argument("kind", choices=("assessment", "patch"))
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    if not args.input.is_file():
        parser.error("Input must be a result file")
    override = os.environ.get(f"CATS_{args.kind.upper()}_PUSH_URL", "")
    if args.kind == "patch" and not override:
        print("Patch result push skipped: set CATS_PATCH_PUSH_URL to enable delivery.")
        return 0

    base = os.environ.get("CATS_PORTAL_URL", "")
    if not base:
        parser.error("CATS_PORTAL_URL is required")
    legacy = os.environ.get("CATS_PORTAL_TOKEN", "")
    scoped = os.environ.get("CATS_PROJECT_TOKEN", "") if args.kind == "assessment" else ""
    if legacy.startswith("cats_project_"):
        if args.kind == "patch":
            parser.error("Patch delivery requires its configured CATS_PORTAL_TOKEN")
        scoped = scoped or legacy
    if scoped:
        token = project_token(scoped, parser)
        endpoint = project_endpoint(base, "/api/v1/pipeline-results", parser)
        if override and override != endpoint:
            parser.error("Project assessment delivery requires the configured portal pipeline-results endpoint")
    else:
        if not legacy or not legacy.isprintable():
            parser.error("Set CATS_PORTAL_TOKEN or use CATS_PROJECT_TOKEN for assessments")
        token = legacy
        endpoint = override or base.rstrip("/") + "/api/v1/pipeline-results"
    return post(endpoint, token, ["--header", "Content-Type: application/json", "--data-binary", "@" + str(args.input)],
                project=bool(scoped), push_timeout=True)


if __name__ == "__main__":
    raise SystemExit(main())
