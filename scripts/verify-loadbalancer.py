"""Run a read-only-source helm-test acceptance without changing stored runs.

Run inside the existing portal container. Supply --module-dir for an isolated
copy of deployment_validation.py/load_balancer.py and --bundle-dir for a staged
distribution bundle. Only the disposable validation cluster is mutated.
"""
import argparse
import importlib
import json
import logging
from pathlib import Path
import sys

from app.database import SessionLocal
from app.models import Execution

parser = argparse.ArgumentParser()
parser.add_argument("--execution", type=int, required=True)
parser.add_argument("--module-dir")
parser.add_argument("--bundle-dir")
parser.add_argument("--output", required=True)
parser.add_argument("--job-id", required=True)
parser.add_argument("--offline", action="store_true", help="Also require a Docker internal network; otherwise preserve deployment settings")
args = parser.parse_args()
logging.basicConfig(level=logging.INFO)
if args.module_dir:
    import types
    package = types.ModuleType("cats_lb_acceptance")
    package.__path__ = [args.module_dir]
    sys.modules[package.__name__] = package
    validation = importlib.import_module("cats_lb_acceptance.deployment_validation")
else:
    validation = importlib.import_module("app.deployment_validation")
with SessionLocal() as db:
    execution = db.get(Execution, args.execution)
    if execution is None:
        raise SystemExit("Execution not found")
    payload = execution.raw_payload
    artifact = validation.ValidationArtifact(
        source_files=dict(payload["helm_source_files"]),
        values_files=list(payload.get("helm_values_files") or []),
        # Use actual rendered chart for baseline comparison, not unrelated scans.
        job_id=args.job_id, reference=execution.execution_key,
    )
config = validation.ValidationConfig.from_env()
if args.offline:
    config.allow_network_egress = False
if args.bundle_dir:
    config.load_balancer_bundle_dir = args.bundle_dir
    config.load_balancer_provider_enabled = True
def acceptance_runner(command, *, timeout, env=None):
    if command[:3] == ["kind", "create", "cluster"]:
        command = [*command, "--retain"]
    result = validation._default_runner(command, timeout=timeout, env=env)
    if result.returncode:
        print("COMMAND_FAILURE", command[:3], validation._bounded(result.stderr or result.stdout, 3000), flush=True)
        if command[:3] == ["kind", "create", "cluster"]:
            logs = validation._default_runner(["docker", "logs", "--tail", "60", env["KIND_CLUSTER_NAME"] + "-control-plane"], timeout=15, env=env)
            print("KIND_NODE_LOG", validation._bounded(logs.stdout + logs.stderr, 6000), flush=True)
    return result

result = validation.validate_artifact(artifact, config=config, runner=acceptance_runner,
    progress_callback=lambda phase: print(phase, flush=True))
Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
summary = {key: result.get(key) for key in ("status", "reason", "cleanup_status", "duration_seconds", "helm_result")}
summary["capabilities"] = [{key: row.get(key) for key in ("capability", "status", "source_resource")} for row in result["capability_preflight"]]
summary["bootstrap_ms"] = result["capability_bootstrap"].get("duration_ms")
print(json.dumps(summary, indent=2))
