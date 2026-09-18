"""Export a persisted Deployment Validation run without changing database state."""
import argparse
import json
from pathlib import Path

from sqlalchemy import select

from app.database import SessionLocal
from app.models import DeploymentValidationRun


parser = argparse.ArgumentParser()
parser.add_argument("--execution", type=int, required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

with SessionLocal() as database:
    run = database.scalar(
        select(DeploymentValidationRun)
        .where(DeploymentValidationRun.execution_id == args.execution)
        .order_by(DeploymentValidationRun.created_at.desc())
        .limit(1)
    )
    if run is None:
        raise SystemExit("No persisted validation run was found for that execution")
    evidence = {
        "source": "persisted-deployment-validation-run",
        "run_id": run.id,
        "run_key": run.run_key,
        "execution_id": run.execution_id,
        "status": run.status,
        "reason_category": run.reason_category,
        "reason": run.reason,
        "helm_result": run.helm_result,
        "resource_summary": run.resource_summary,
        "conditions": run.conditions,
        "capability_preflight": run.capability_preflight,
        "capability_bootstrap": run.capability_bootstrap,
        "cleanup_status": run.cleanup_status,
        "duration_seconds": run.duration_seconds,
        "created_at": run.created_at,
        "completed_at": run.completed_at,
    }

Path(args.output).write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")
