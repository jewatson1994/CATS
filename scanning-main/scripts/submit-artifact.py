"""Submit an artifact to the CATS service bound to a project credential."""
import argparse
import json
import os
from pathlib import Path
import re
from push_result import post, project_endpoint, project_token


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cats submit")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--reference", help="Container image or OCI Helm chart reference")
    source.add_argument("--file", type=Path, help="Local artifact to upload")
    parser.add_argument("--key", required=True, help="Stable identifier for this submission and its retries")
    parser.add_argument("--version", help="Target service version")
    parser.add_argument("--kind", choices=("auto", "image", "docker-archive", "helm-chart", "compose"),
                        help="Artifact kind when the input is ambiguous")
    args = parser.parse_args(argv)

    endpoint = project_endpoint(os.environ.get("CATS_PORTAL_URL", ""), "/api/v1/artifact-submissions", parser)
    token = project_token(os.environ.get("CATS_PROJECT_TOKEN", ""), parser)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.key):
        parser.error("--key must be 1–128 characters, start with a letter or number, and use only letters, numbers, . _ : -")

    data_args = []
    options = {key: value for key, value in (("version", args.version), ("kind", args.kind)) if value is not None}
    if args.file:
        if not args.file.is_file():
            parser.error("--file must identify a regular file")
        path = str(args.file.resolve()).replace("\\", "\\\\").replace('"', '\\"')
        data_args.extend(["--form", f'file=@"{path}"'])
        for key, value in options.items():
            data_args.extend(["--form-string", f"{key}={value}"])
    else:
        body = {"reference": args.reference, **options}
        data_args.extend(["--header", "Content-Type: application/json", "--data-binary", json.dumps(body)])
    return post(endpoint, token, data_args, project=True, idempotency_key=args.key)


if __name__ == "__main__":
    raise SystemExit(main())
