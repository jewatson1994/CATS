"""Conservative recipe identity and durable single-publication claims.

Identity must come from the trusted worker's immutable-input manifest. Merely
naming a repository or tool version is insufficient to enable reuse.

Production identity is issued only by the authenticated worker prepare protocol.
That protocol binds retained scanner/repository bytes and isolated execution,
then consumes the opaque handle once and returns a consumed-input receipt.
Workers without an isolated input specification return no identity and never
claim reuse from mirror URLs or operator-provided digest assertions.
Interrupted publication claims never
expire automatically because registry side effects may already have happened.
"""
from __future__ import annotations
import hashlib
import json
import time
from sqlalchemy import ForeignKey, String, select
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import PatchExecution
from .artifact_catalog import (GlobalArtifact, ArtifactPatchLineage, _get_or_add,
                               _verified_receipt, validate_digest)


class PatchRecipeClaim(Base):
    __tablename__ = "patch_recipe_claims"
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_job_id: Mapped[str] = mapped_column(ForeignKey("durable_jobs.id"))
    patch_execution_id: Mapped[int | None] = mapped_column(ForeignKey("patch_executions.id"))


def recipe_fingerprint(*, source, config, identity, destination_scope):
    """Return None unless every mutable engine input has an immutable identity.

    The caller must obtain identity from its engine, never from request JSON.
    All policy/signing configuration participates, except per-attempt output
    names. No credentials are stored by this function or the claim table.
    """
    if not isinstance(config, dict):
        return None
    if not isinstance(identity, dict) or identity.get("schema") != "cats-patch-inputs-v1":
        return None
    # Unknown manifest fields may describe additional material inputs. Never
    # silently discard them and collapse distinct recipes into one claim.
    if set(identity) != {"schema", "engine_digest", "repository_snapshot_digest",
                         "scanner_database_digest"}:
        return None
    try:
        immutable = {key: validate_digest(identity.get(key)) for key in (
            "engine_digest", "repository_snapshot_digest", "scanner_database_digest")}
        digest = validate_digest(source.digest)
    except (ValueError, AttributeError):
        return None
    source_reference = config.get("source_image")
    if not isinstance(source_reference, str) or not source_reference.endswith("@" + digest):
        return None
    if not isinstance(config.get("signing_fingerprint"), str) or not config["signing_fingerprint"].strip():
        return None
    if not source.media_type or source.platform in (None, "", "unknown") or not destination_scope:
        return None
    policy = {key: value for key, value in config.items()
              if key not in {"job_id", "source_image", "destination_image", "execution_binding"}}
    value = {"schema": 1, "source": [digest, source.media_type, source.platform],
             "inputs": immutable, "policy": policy, "destination": destination_scope}
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded.encode()).hexdigest()


def claim_recipe(db, fingerprint, job_id):
    """Unique-key winner owns publication; no takeover after uncertain effects."""
    return _get_or_add(db, PatchRecipeClaim, fingerprint=fingerprint,
                       defaults={"owner_job_id": job_id})


def _consumed_inputs_match(patch, claim, source, receipt):
    """Validate retained trusted-worker evidence, never a request assertion.

    This gate does not authenticate a worker or establish hermetic execution.
    A production provider must do both before retaining this receipt. Legacy
    artifact receipts and scanner-only evidence deliberately cannot pass.
    """
    consumed = receipt.get("consumed_inputs")
    if not isinstance(consumed, dict) or set(consumed) != {
        "schema", "job_id", "source_image", "immutable_destination",
        "identity", "config", "destination_scope",
    }:
        return False
    if (consumed.get("schema") != "cats-patch-consumed-inputs-v1" or
            consumed.get("job_id") != patch.job_key or
            consumed.get("source_image") != patch.source_image or
            consumed.get("source_image") != receipt.get("source_image") or
            consumed.get("immutable_destination") != receipt.get("immutable_destination")):
        return False
    config = consumed.get("config")
    if (not isinstance(config, dict) or config.get("job_id") != patch.job_key or
            config.get("source_image") != consumed["source_image"] or
            config.get("signing_fingerprint") != receipt["signature"].get("key_fingerprint")):
        return False
    fingerprint = recipe_fingerprint(source=source, config=config,
        identity=consumed.get("identity"), destination_scope=consumed.get("destination_scope"))
    return fingerprint is not None and fingerprint == claim.fingerprint


def reusable_patch(db, claim, source, *, signing_fingerprint=None, destination_scope=None):
    """Only retained signed, scanned, immutable outputs qualify for reuse.

    Deployment eligibility remains a separate service-specific decision.
    """
    patch = db.get(PatchExecution, claim.patch_execution_id) if claim.patch_execution_id else None
    if patch is None:
        return None
    lineage = db.scalar(select(ArtifactPatchLineage).where(
        ArtifactPatchLineage.patch_execution_id == patch.id,
        ArtifactPatchLineage.source_artifact_id == source.id))
    output = db.get(GlobalArtifact, lineage.output_artifact_id) if lineage else None
    if output is None or output.platform != source.platform or not _verified_receipt(patch, output):
        return None
    receipt = patch.summary["artifact_receipt"]
    if not _consumed_inputs_match(patch, claim, source, receipt):
        return None
    if signing_fingerprint is not None and receipt["signature"].get("key_fingerprint") != signing_fingerprint:
        return None
    if destination_scope is not None:
        # A valid signature for another registry/namespace is not a delivery
        # into this campaign destination, even when its digest is identical.
        prefix = "/".join(str(destination_scope.get(key) or "").strip("/")
                          for key in ("host", "namespace", "prefix")
                          if destination_scope.get(key))
        reference = receipt.get("immutable_destination")
        if not prefix or not isinstance(reference, str) or not reference.startswith(prefix + "/"):
            return None
    if not isinstance(receipt.get("source_image"), str) or not receipt["source_image"].endswith("@" + source.digest):
        return None
    return patch


def wait_for_recipe(session_factory, fingerprint, ctx, *, timeout=300, interval=1):
    """Wait for the original publisher without holding campaign/database locks.

    Cancellation affects only this waiter. A missing, terminal, or expired owner
    never grants permission to repeat possibly completed registry side effects.
    """
    from . import durable_jobs
    deadline = time.monotonic() + timeout
    ctx.stage("Waiting for equivalent patch", 5)
    while True:
        ctx.check()
        with session_factory() as db:
            claim = db.get(PatchRecipeClaim, fingerprint)
            owner = db.get(durable_jobs.DurableJob, claim.owner_job_id) if claim else None
            patch = db.get(PatchExecution, claim.patch_execution_id) if claim and claim.patch_execution_id else None
            if patch is not None and patch.status == "complete":
                return
            if (owner is None or owner.status != "running" or owner.cancel_requested or
                    not owner.lease_until or durable_jobs.aware(owner.lease_until) <= durable_jobs.now()):
                raise durable_jobs.JobError("Equivalent patch has no active publisher or verified retained output; inspect its original campaign")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise durable_jobs.JobError("Equivalent patch is still running; inspect its original campaign before retrying")
        time.sleep(min(interval, remaining))
