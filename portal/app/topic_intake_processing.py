"""Durable handoff from GitLab's immutable project/commit identity to CATS evidence."""
from contextlib import closing, contextmanager
from hashlib import sha256
import logging
import os
from pathlib import Path
import re
import shutil
import tempfile
import errno
import time
from uuid import NAMESPACE_URL, uuid4, uuid5

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from . import discovery_gitlab, durable_jobs
from .auth import AuthContext
from .database import SessionLocal
from .discovery_limits import limit
from .discovery_models import DiscoveryConfirmation, DiscoveryInventory, DiscoveryScan
from .discovery_sources import encrypted_writer
from .discovery_worker import upload_root
from .models import Execution, Service, ServiceGroup, ServiceVersion, User
from .scan_coordination import ScanJob, TERMINAL, enqueue_job
from .replica_models import reserve_sqlite_writer
from .topic_intake_models import GitLabTopicSource, TopicProject, TopicRevision
from .topic_scope_rules import effective_project_claim_group, scope_sources

KIND = "topic_intake_process"
_FAILURE = ("failed", "cancelled")
_PAGE = 16
_OPTED_OUT = "The GitLab project is no longer opted in to this source."
_ROUTE_CHANGED = "The GitLab project's claim routing changed. Review the namespace rules and poll again."
_PROJECT_MOVED = "The GitLab project moved. Poll its new path before retrieving the archive."
_SUPERSEDED = "A newer revision superseded this intake."
logger = logging.getLogger(__name__)


class IntakeError(ValueError):
    """A safe, actionable reason a revision cannot advance."""


def _queue(db, source, revision):
    job = durable_jobs.submit(db, kind=KIND, payload={"revision_id": revision.id},
                              requested_by_id=source.authorized_by_id, commit=False)
    revision.status, revision.error, revision.processing_job_id = "pending", None, job.id
    db.flush()
    return job


def queue_observed(db, source, revision):
    """Admit an observed revision while its project is locked, or leave it in the outbox."""
    if revision.status != "pending" or revision.processing_job_id is not None:
        return True
    try:
        _queue(db, source, revision)
    except HTTPException as exc:
        if exc.status_code != 429:
            raise
        # A committed pending revision survives queue saturation and worker restarts.
        return False
    return True


def observe_project(db, source, *, gitlab_project_id, project_path, web_url, default_branch, commit_sha,
                    claim_group_id=None, observed_topics=None, defer_queue=False):
    if not source.enabled:
        return None
    if claim_group_id is None and not source.namespace:
        raise IntakeError("The project has no resolved claim group in this GitLab source.")
    reserve_sqlite_writer(db)
    query = select(TopicProject).where(TopicProject.origin == source.origin,
                                      TopicProject.gitlab_project_id == gitlab_project_id).with_for_update()
    project = db.scalar(query)
    if project is None:
        try:
            with db.begin_nested():
                project = TopicProject(source_id=source.id, origin=source.origin, gitlab_project_id=gitlab_project_id,
                                       project_path=project_path, default_branch=default_branch, web_url=web_url)
                db.add(project)
                db.flush()
        except IntegrityError:
            project = db.scalar(query)
            if project is None:
                raise
    if project.source_id != source.id:
        return None
    was_eligible = project.eligible
    claim_group_id = claim_group_id if claim_group_id is not None else source.claim_group_id
    observed_topics = observed_topics if observed_topics is not None else [source.topic]
    routing_changed = (project.claim_group_id != claim_group_id or project.project_path != project_path
                       or set(project.observed_topics or [source.topic]) != set(observed_topics))
    project.eligible = True
    project.claim_group_id = claim_group_id
    project.observed_topics = observed_topics
    project.project_path, project.web_url, project.default_branch = project_path, web_url, default_branch
    revision = db.scalar(select(TopicRevision).where(TopicRevision.project_id == project.id,
                                                     TopicRevision.commit_sha == commit_sha))
    if revision is not None:
        advanced = project.latest_revision_id != revision.id
        project.latest_revision_id = revision.id
        error = revision.error or ""
        if revision.status == "failed" and (
            (advanced and error.startswith(_SUPERSEDED))
            or (not was_eligible and error.startswith(_OPTED_OUT))
            or ((routing_changed or not was_eligible) and error.startswith((_ROUTE_CHANGED, _PROJECT_MOVED)))
        ):
            revision.status, revision.error, revision.processing_job_id = "pending", None, None
            revision.discovery_job_id = revision.inventory_id = revision.scan_job_id = revision.execution_id = None
        return revision
    revision = TopicRevision(project_id=project.id, ref=default_branch, commit_sha=commit_sha)
    db.add(revision)
    db.flush()
    project.latest_revision_id = revision.id
    if not defer_queue:
        queue_observed(db, source, revision)
    return revision


def _binding(db, revision_id, *, read_only=False, project_metadata=None):
    if read_only:
        binding = db.execute(select(GitLabTopicSource, TopicProject, TopicRevision).select_from(TopicRevision)
            .join(TopicProject, TopicProject.id == TopicRevision.project_id)
            .join(GitLabTopicSource, GitLabTopicSource.id == TopicProject.source_id)
            .where(TopicRevision.id == revision_id)).one_or_none()
        source, project, revision = binding or (None, None, None)
    else:
        # Serialize publication against claim, source configuration and a newer commit.
        project_id = db.scalar(select(TopicRevision.project_id).where(TopicRevision.id == revision_id))
        source_id = db.scalar(select(TopicProject.source_id).where(TopicProject.id == project_id))
        source = db.scalar(select(GitLabTopicSource).where(GitLabTopicSource.id == source_id).with_for_update(read=True).execution_options(populate_existing=True))
        project = db.scalar(select(TopicProject).where(TopicProject.id == project_id).with_for_update().execution_options(populate_existing=True))
        revision = db.scalar(select(TopicRevision).where(TopicRevision.id == revision_id).with_for_update().execution_options(populate_existing=True))
    if (not source or not source.enabled or not project or project.source_id != source.id
            or project.origin != source.origin or not revision or revision.project_id != project.id):
        raise IntakeError("The GitLab source is disabled or its project binding changed.")
    if not project.eligible:
        raise IntakeError(_OPTED_OUT)
    if project.latest_revision_id != revision.id:
        raise IntakeError(_SUPERSEDED)
    if effective_project_claim_group(source, project, project_metadata, scope_sources(db, source)) is None:
        raise IntakeError(_ROUTE_CHANGED)
    user = db.get(User, source.authorized_by_id)
    if not user or not user.enabled or not AuthContext(user, None).can_manage_group(None):
        raise IntakeError("The source administrator no longer has global configuration access.")
    from .service_ownership import active_service_predicate
    from .imported_services import is_imported_service
    from .topic_intake_models import TopicIntakeGroup
    if project.claimed_at is not None:
        if (not project.service_id or not db.scalar(select(Service.id).where(
                Service.id == project.service_id, active_service_predicate()))
                or is_imported_service(db, project.service_id)):
            raise IntakeError("The claimed service is missing, archived or managed by an upstream publisher.")
    elif project.service_id:
        held = db.scalar(select(Service.id).join(ServiceGroup).join(TopicIntakeGroup,
            TopicIntakeGroup.group_id == ServiceGroup.group_id).where(Service.id == project.service_id,
            Service.lifecycle_status == "unclaimed").execution_options(include_topic_intake=True))
        if not held:
            raise IntakeError("The unclaimed service is no longer bound to its intake group.")
    return source, project, revision


def retry_revision(db, rev):
    try:
        source, _, revision = _binding(db, rev.id)
    except IntakeError as exc:
        raise HTTPException(409, str(exc)) from exc
    if revision.status != "failed":
        raise HTTPException(409, "Only a failed revision can be retried")
    # Old Discovery, scan and execution history remain immutable and retain the revision association.
    revision.discovery_job_id = revision.inventory_id = revision.scan_job_id = revision.execution_id = None
    return _queue(db, source, revision)


def fetch_project_archive(source, project_id, sha, output, *, check, check_project):
    """Download only the opted-in numeric project and exact commit, never a project-supplied URL."""
    if type(project_id) is not int or not 0 < project_id <= 2**63 - 1 or not re.fullmatch(
            r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha or ""):
        raise IntakeError("The GitLab project ID or immutable revision is invalid.")
    from .secrets import decrypt_secret
    token = decrypt_secret(source["token"]) if source["token"] else None
    origin, namespace, topic = source["origin"], source["namespace"], source["topic"]
    namespaces = [route["namespace"] for route in source["namespace_routes"] or []]
    opener, api = discovery_gitlab.gitlab_api_client(origin, namespace, topic, token=token,
                                trusted_ca_certificates=source["ca"], namespaces=namespaces)
    endpoint = f"{api}/projects/{project_id}"
    deadline = time.monotonic() + 300
    metadata = discovery_gitlab._metadata(opener, endpoint, token, deadline, check)
    current = discovery_gitlab.topic_project(metadata, origin, namespace, topic, namespaces=namespaces)
    if not current or current["project_id"] != project_id:
        raise IntakeError("GitLab no longer reports the selected project with this namespace and topic.")
    check_project(current)
    identity = discovery_gitlab._metadata(opener, f"{endpoint}/repository/commits/{sha}", token, deadline, check)
    if not isinstance(identity, dict) or identity.get("id") != sha:
        raise IntakeError("GitLab did not confirm the requested immutable commit.")
    digest, prefix = sha256(), bytearray()
    with closing(discovery_gitlab._chunks(opener, f"{endpoint}/repository/archive.zip?sha={sha}", token,
                 limit("UPLOAD_BYTES"), metadata=False, check=check, deadline=deadline)) as chunks:
        for chunk in chunks:
            prefix.extend(chunk[:max(0, 4 - len(prefix))])
            if len(prefix) == 4 and prefix not in (b"PK\x03\x04", b"PK\x05\x06"):
                raise IntakeError("GitLab did not return a ZIP archive for the selected commit.")
            output.write(chunk)
            digest.update(chunk)
    if len(prefix) != 4:
        raise IntakeError("GitLab returned an incomplete commit archive.")
    return digest.hexdigest()


@contextmanager
def _archive_part(identity, lease):
    # Both identifiers are generated by the durable queue. Retrying owns the same
    # final archive; distinct leases can never write the same partial file.
    if not all(re.fullmatch("[a-f0-9]{32}", str(key)) for key in (identity, lease)):
        raise IntakeError("The archive staging identity is invalid.")
    root = upload_root()
    root.mkdir(parents=True, exist_ok=True)
    folder = root / identity
    folder.mkdir(mode=0o750, exist_ok=True)
    if folder.is_symlink() or folder.resolve().parent != root.resolve():
        raise IntakeError("The archive staging workspace is invalid.")
    if os.name == "posix":
        os.chown(folder, -1, int(os.getenv("CATS_DISCOVERY_GID", "10003")))
        folder.chmod(0o750)
    for old in folder.glob("*.part"):
        # Other leases have expired before this attempt was claimed. Their own
        # publication is fenced; on Windows a still-open file is cleaned next time.
        if re.fullmatch(r"[a-f0-9]{32}\.part", old.name) and old.name != lease + ".part":
            try:
                old.unlink(missing_ok=True)
            except PermissionError:
                pass
    part = folder / (lease + ".part")
    try:
        yield part
    finally:
        part.unlink(missing_ok=True)
        try:
            folder.rmdir()
        except OSError:
            pass


def _submit_discovery(db, source, project, revision, processing):
    from .topic_intake_claims import ensure_intake_service
    archive = (processing.result or {}).get("topic_archive") or {}
    identity = processing.id
    if (not archive or archive.get("config_revision") != source.config_revision
            or archive.get("commit_sha") != revision.commit_sha
            or not (upload_root() / identity / "repository.zip").is_file()):
        raise IntakeError("The staged commit archive or its source settings changed. Retry this revision.")
    service = ensure_intake_service(db, project)
    group_id = db.scalar(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service.id))
    job = durable_jobs.submit(db, kind="discovery", requested_by_id=source.authorized_by_id, commit=False,
        payload={"source_id": identity, "source_hash": archive["source_hash"], "filename": "repository.zip",
                 "group_id": group_id, "options": {}, "topic_revision_id": revision.id,
                 "gitlab_source": {"repository_url": project.web_url, "requested_ref": revision.ref,
                                   "commit_sha": revision.commit_sha, "project_id": project.gitlab_project_id}})
    revision.discovery_job_id, revision.status = job.id, "discovering"
    processing.result = {**processing.result, "discovery_job_id": job.id}
    return job


def handler(ctx, payload):
    from .trusted_ca import configured_certificates
    revision_id = payload["revision_id"]
    try:
        with ctx.session_factory() as db:
            source, project, revision = _binding(db, revision_id, read_only=True)
            if revision.processing_job_id != ctx.job.id or revision.status != "pending":
                return {"revision_id": revision_id}
            if (ctx.job.result or {}).get("topic_archive"):
                # A previous lease committed this archive. Reconciliation admits it.
                return {"revision_id": revision_id}
            settings = {key: getattr(source, key) for key in (
                "origin", "namespace", "namespace_routes", "topic", "token", "config_revision")}
            settings["ca"] = configured_certificates(db)
            git_id, sha = project.gitlab_project_id, revision.commit_sha

        fresh_project = None

        def current_binding(db, *, read_only):
            source, project, revision = _binding(db, revision_id, read_only=read_only, project_metadata=fresh_project)
            owner = ctx._owned(db)
            if owner.cancel_requested:
                raise durable_jobs.JobCancelled()
            if revision.processing_job_id != owner.id or revision.status != "pending":
                raise IntakeError("The intake job was replaced.")
            if (source.config_revision != settings["config_revision"]
                    or project.gitlab_project_id != git_id or revision.commit_sha != sha):
                raise RuntimeError("Source configuration or commit binding changed during retrieval")
            if fresh_project is not None and fresh_project["path_with_namespace"] != project.project_path:
                raise IntakeError(_PROJECT_MOVED)
            return source, project, revision, owner

        def check_fetch():
            with ctx.session_factory() as db:
                current_binding(db, read_only=True)

        def check_project(metadata):
            nonlocal fresh_project
            fresh_project = metadata
            check_fetch()

        ctx.stage("Fetching the GitLab commit archive", 10)
        with _archive_part(ctx.job.id, ctx.job.lease_token) as part:
            with encrypted_writer(part, ctx.job.id) as stream:
                digest = fetch_project_archive(settings, git_id, sha, stream, check=check_fetch, check_project=check_project)
            if os.name == "posix":
                os.chown(part, -1, int(os.getenv("CATS_DISCOVERY_GID", "10003")))
                part.chmod(0o640)
            with ctx.session_factory.begin() as db:
                reserve_sqlite_writer(db)
                source, project, revision, owner = current_binding(db, read_only=False)
                if fresh_project is not None:
                    project.observed_topics = fresh_project["topics"]
                os.replace(part, part.parent / "repository.zip")
                owner.result = {**(owner.result or {}), "topic_archive": {"source_hash": digest,
                    "commit_sha": sha, "config_revision": source.config_revision}}
                try:
                    job = _submit_discovery(db, source, project, revision, owner)
                except HTTPException as exc:
                    if exc.status_code != 429:
                        raise
                    # Complete this slot. The next tick can admit Discovery without
                    # another archive download even with a one-slot durable queue.
                    return {"revision_id": revision_id}
                return {"revision_id": revision_id, "discovery_job_id": job.id}
    except IntakeError as exc:
        raise durable_jobs.JobError(str(exc)) from exc
    except discovery_gitlab.GitLabSourceError as exc:
        if exc.status_code in (403, 404, 422):
            raise durable_jobs.JobError(str(exc)) from exc
        raise


def _scan_selection(inventory):
    from .pipeline_scan_dispatch import _image
    data = inventory.inventory
    roots, occurrences = data.get("roots") or [], data.get("images") or []
    if (data.get("completeness") != "complete" or not isinstance(roots, list) or not roots
            or any(not isinstance(r, dict) or not isinstance(r.get("id"), str) or not r["id"]
                   or r.get("completeness") != "complete" for r in roots)):
        raise IntakeError("Discovery was incomplete. Review unresolved charts, sources and deployment roots.")
    ids = {r["id"] for r in roots}
    if (not isinstance(occurrences, list) or not occurrences
            or any(not isinstance(i, dict) or i.get("root_id") not in ids or i.get("completeness") != "complete"
                   for i in occurrences)):
        raise IntakeError("Discovery did not produce a complete inventory of resolved images.")
    try:
        refs = sorted({_image(i.get("reference")) for i in occurrences})
    except HTTPException as exc:
        raise IntakeError("Discovery included an unresolved or invalid image reference.") from exc
    return sorted(ids), refs


def _scan_binding(source, project, revision, inventory, confirmation, group_id):
    return {"source_id": source.id, "project_id": project.id, "revision_id": revision.id,
            "commit_sha": revision.commit_sha, "group_id": group_id, "inventory_id": inventory.id,
            "content_hash": inventory.content_hash, "source_hash": inventory.source_hash,
            "confirmation_id": confirmation.id, "oci_charts": _chart_provenance(inventory)}


def _admit_scan(db, source, project, revision, discovery):
    from . import main
    from .trusted_ca import configured_certificates
    inventory = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id == discovery.id))
    service = db.get(Service, project.service_id)
    group_id = db.scalar(select(ServiceGroup.group_id).where(ServiceGroup.service_id == project.service_id))
    if (not inventory or not service or inventory.group_id != group_id
            or discovery.payload.get("topic_revision_id") != revision.id
            or inventory.source_hash != discovery.payload.get("source_hash")
            or (inventory.inventory.get("gitlab_source") or {}).get("commit_sha") != revision.commit_sha
            or (inventory.inventory.get("gitlab_source") or {}).get("project_id") != project.gitlab_project_id):
        raise IntakeError("Discovery evidence did not match the project, commit and service owner.")
    revision.inventory_id = inventory.id
    root_ids, images = _scan_selection(inventory)
    image_limit = int(os.getenv("CATS_PUBLIC_MAX_IMAGES", "50"))
    if len(images) > image_limit:
        raise IntakeError(f"Discovery found {len(images)} images, above CATS_PUBLIC_MAX_IMAGES={image_limit}. "
                          "Raise the polling-worker limit and retry this revision.")
    confirm = DiscoveryConfirmation(id=uuid4().hex, inventory_id=inventory.id, service_id=service.id,
                                   confirmed_by=source.authorized_by_id, root_ids=root_ids, acknowledge_partial=False)
    key = uuid5(NAMESPACE_URL, "cats:topic-scan:" + revision.processing_job_id).hex
    root = Path(main.PUBLIC_JOB_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root, prefix=".topic-scan-") as temporary:
        directory = Path(temporary) / key
        directory.mkdir()
        skipped, checksum = main._stage_scan_inputs(directory, key, images, [], None, [], {},
                                                    configured_certificates(db), [])
        binding = _scan_binding(source, project, revision, inventory, confirm, group_id)
        enqueue_job(db, key, {"job_id": key, "job_kind": "scan", "phase": "queued", "status": "queued",
            "topic_intake": binding, "ingest_service_db_id": service.id, "ingest_service_id": service.service_key,
            "ingest_service_version": _version(inventory, revision.commit_sha), "ingest_scope": "service", "credential_policy": "topic",
            "owner_user_id": None, "sbom_formats": ["syft-json"], "input_digest": checksum,
            "chart_url": "", "chart_names": [], "archive_names": [], "image_list": "\n".join(images),
            "skipped_charts": skipped, "summary": {}, "created_at": main.utcnow().isoformat()})
        db.add(confirm)
        db.flush()
        db.add(DiscoveryScan(confirmation_id=confirm.id, scan_job_id=key))
        revision.scan_job_id, revision.status = key, "scanning"
        db.flush()
        # All queue records are still uncommitted; workers can only see a complete input envelope.
        target = root / key
        if target.exists():
            # Reclaim an unpublished input from a crash between rename and DB commit.
            # A persisted job or a worker output directory must never be replaced.
            if (target.is_symlink() or target.resolve().parent != root.resolve() or
                    (target / "output").exists() or (target / "attempts").exists()):
                raise IntakeError("The topic scan input workspace conflicts with retained evidence.")
            shutil.rmtree(target)
        os.rename(directory, target)

def _chart_provenance(inventory):
    """Only retain the exact OCI references, versions and digests verified by Discovery."""
    charts = []
    seen = set()
    for node in inventory.inventory.get("nodes") or ():
        if node.get("kind") not in ("HelmDependency", "HelmRelease"):
            continue
        for evidence in node.get("provenance") or ():
            ref, version, digest = (evidence.get(key) for key in ("reference", "version", "chart_sha256"))
            if (isinstance(ref, str) and ref.startswith("oci://") and isinstance(version, str)
                    and version and isinstance(digest, str) and re.fullmatch("[a-f0-9]{64}", digest)
                    and (ref, version, digest) not in seen):
                seen.add((ref, version, digest))
                charts.append({"reference": ref, "version": version, "sha256": digest,
                               "digest_kind": evidence.get("chart_digest_kind") or "tree"})
    return charts


def _version(inventory, fallback):
    roots = inventory.inventory.get("roots") or []
    if len(roots) == 1 and roots[0].get("technology") == "helm":
        version = roots[0].get("chart_version")
        if isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,119}", version):
            return version
    return fallback


def verify_scan(db, job_id, payload, service):
    """Only the automatic scanner can ingest this exact inventory into its bound service."""
    reserve_sqlite_writer(db)
    binding = payload.get("topic_intake") or {}
    try:
        source, project, revision = _binding(db, binding.get("revision_id"))
        inventory = db.get(DiscoveryInventory, revision.inventory_id)
        confirmation = db.get(DiscoveryConfirmation, binding.get("confirmation_id"))
        link = db.get(DiscoveryScan, binding.get("confirmation_id"))
        owner = db.scalar(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service.id))
        if (payload.get("job_kind") != "scan" or payload.get("ingest_scope") != "service" or
                payload.get("credential_policy") != "topic" or payload.get("owner_user_id") is not None
                or any(payload.get(key) for key in ("chart_url", "chart_names", "archive_names", "compose_enabled",
                    "compose_uploads", "definition_context", "definition_component", "definition_components",
                    "proposal_context", "schedule_context", "pipeline_input_kind"))
                or revision.status != "scanning" or revision.scan_job_id != job_id or not inventory or not confirmation
                or project.service_id != service.id or owner != inventory.group_id
                or payload.get("ingest_service_db_id") != service.id or payload.get("ingest_service_id") != service.service_key
                or inventory.job_id != revision.discovery_job_id or not link or link.scan_job_id != job_id
                or confirmation.service_id != service.id or confirmation.inventory_id != inventory.id
                or binding != _scan_binding(source, project, revision, inventory, confirmation, owner)
                or payload.get("ingest_service_version") != _version(inventory, revision.commit_sha)):
            raise IntakeError("The scan no longer matches its GitLab revision, inventory or owning service.")
        roots, refs = _scan_selection(inventory)
        if roots != confirmation.root_ids or refs != payload.get("image_list", "").splitlines():
            raise IntakeError("The scan inputs differ from the complete Discovery selection.")
        return revision
    except IntakeError as exc:
        raise HTTPException(409, str(exc)) from exc


def bind_result(data, payload, summary):
    """A revision becomes claimable only with a complete SBOM for each selected image."""
    expected = set(payload["image_list"].splitlines())
    seen = set(data.get("sbom_images") or ())
    data["complete"] = bool(expected and expected == seen and data.get("complete") is True
                            and payload.get("returncode") == 0 and summary.get("status") == "complete"
                            and not any(obj.get(key) for obj in (data, summary) for key in ("skipped_images", "skipped_charts")))
    data["scan_scope"] = "service" if data["complete"] else "evidence"
    data.pop("scope_image", None)
    data["commit_sha"] = payload["topic_intake"]["commit_sha"]
    from .main import _overview_image_references
    overview = {**(data.get("service_overview") or {}), "topic_intake": payload["topic_intake"]}
    documented = {ref for ref, _ in _overview_image_references(overview)}
    # Images with no findings or packages still belong in service inventory when
    # the scanner actually produced their SBOM. Preserve any observed digests.
    overview["container_images"] = [*(overview.get("container_images") or []), *sorted((expected & seen) - documented)]
    data["service_overview"] = overview


def _finish_scan(db, project, revision, job):
    if job.status != "complete" or job.payload.get("ingested") is not True:
        raise IntakeError("Scan or automatic ingestion was incomplete. Review the scan job and retry this revision.")
    service = db.get(Service, project.service_id)
    if not service:
        raise IntakeError("The target service is unavailable.")
    verify_scan(db, job.id, job.payload, service)
    # Select only provenance: completed executions can retain large SBOM and finding payloads.
    execution = db.execute(select(Execution.id, Execution.raw_payload["service_overview"]["topic_intake"])
        .join(ServiceVersion, ServiceVersion.id == Execution.service_version_id)
        .where(Execution.execution_key == "public:" + job.id, Execution.complete.is_(True),
               Execution.scan_scope == "service", Execution.service_id == service.id,
               Execution.commit_sha == revision.commit_sha, ServiceVersion.service_id == service.id,
               ServiceVersion.version == job.service_version)).first()
    if not execution or execution[1] != job.payload["topic_intake"]:
        raise IntakeError("No complete ingested execution matches the exact scan, commit and service.")
    revision.execution_id, revision.status, revision.error = execution.id, "ready", None


def _actionable_ids(db):
    # Running jobs never occupy a reconciliation slot. Pending failures, Discovery and
    # completed scans each get a bounded page even if another stage is backlogged.
    yield from db.scalars(select(TopicRevision.id).where(TopicRevision.status == "pending",
        TopicRevision.processing_job_id.is_(None)).order_by(TopicRevision.updated_at, TopicRevision.id).limit(_PAGE))
    for state, model, join_column, statuses in (
        ("pending", durable_jobs.DurableJob, TopicRevision.processing_job_id, (*_FAILURE, "completed")),
        ("discovering", durable_jobs.DurableJob, TopicRevision.discovery_job_id, (*_FAILURE, "completed")),
        ("scanning", ScanJob, TopicRevision.scan_job_id, TERMINAL),
    ):
        yield from db.scalars(select(TopicRevision.id).join(model, model.id == join_column)
            .where(TopicRevision.status == state, model.status.in_(statuses))
            .order_by(TopicRevision.updated_at, TopicRevision.id).limit(_PAGE))


def advance_ready(session_factory=SessionLocal):
    from .operating_mode import is_replica
    if is_replica():
        return
    with session_factory() as db:
        candidates = list(_actionable_ids(db))
    for revision_id in candidates:
        attempt = None
        try:
            with session_factory.begin() as db:
                if db.get_bind().dialect.name == "sqlite":
                    db.execute(update(TopicRevision).where(TopicRevision.id == revision_id)
                               .values(updated_at=TopicRevision.updated_at))
                revision = db.get(TopicRevision, revision_id)
                if not revision or revision.status not in ("pending", "discovering", "scanning"):
                    continue
                attempt = revision.processing_job_id
                try:
                    source, project, revision = _binding(db, revision_id)
                    if revision.status == "pending" and not revision.processing_job_id:
                        _queue(db, source, revision)
                    elif revision.status == "scanning":
                        scan = db.get(ScanJob, revision.scan_job_id)
                        if scan and scan.status in TERMINAL:
                            _finish_scan(db, project, revision, scan)
                    elif revision.status in ("pending", "discovering"):
                        job = db.get(durable_jobs.DurableJob, revision.processing_job_id
                                     if revision.status == "pending" else revision.discovery_job_id)
                        if job and job.status in _FAILURE:
                            if (revision.status == "pending" and
                                    (job.error or "").startswith((_SUPERSEDED, _OPTED_OUT))):
                                # The head or opt-in returned between the old attempt
                                # failing and reconciliation. The current binding is valid.
                                revision.processing_job_id = None
                                continue
                            raise IntakeError(job.error or f"{job.kind} {job.status}.")
                        if job and job.status == "completed":
                            if revision.status == "pending":
                                _submit_discovery(db, source, project, revision, job)
                            else:
                                with db.begin_nested():
                                    _admit_scan(db, source, project, revision, job)
                except IntakeError as exc:
                    revision.status, revision.error = "failed", str(exc)[:512]
        except (HTTPException, OSError, ValueError, IntegrityError) as exc:
            if isinstance(exc, HTTPException) and exc.status_code == 429:
                continue
            message = ("Storage is full while preparing the scan inputs." if isinstance(exc, OSError)
                       and exc.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)) else
                       "Could not prepare or validate the immutable scan inputs. Check polling-worker diagnostics.")
            logger.exception("Could not advance topic revision %s", revision_id)
            with session_factory.begin() as db:
                failed = db.get(TopicRevision, revision_id, with_for_update=True)
                if failed and failed.status in ("discovering", "scanning") and failed.processing_job_id == attempt:
                    failed.status, failed.error = "failed", message
        except Exception:
            logger.exception("Could not advance topic revision %s", revision_id)
