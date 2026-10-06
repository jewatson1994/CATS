"""Small remediation history projections; report evidence stays on its own route."""
from types import SimpleNamespace

from sqlalchemy import select

from .models import RemediationExecution, ServiceImage


def remediation_history(db, service_id, limit=100):
    names = (
        "id", "job_key", "finding_type", "original_revision", "resulting_revision",
        "retry_of_id", "status", "output_mode", "failure_reason", "rollback_reference",
        "source_execution_id", "source_version_id", "revision_number", "remediation_status",
        "delivery_status", "verification_status", "signing_status", "artifact_digest",
        "started_at", "completed_at", "artifact_path", "created_at",
    )
    statement = select(*(getattr(RemediationExecution, name) for name in names)).where(
        RemediationExecution.service_id == service_id).order_by(
        RemediationExecution.created_at.desc(), RemediationExecution.id.desc()).limit(limit)
    return [SimpleNamespace(**dict(row)) for row in db.execute(statement).mappings()]


def active_image_references(db, service_id):
    return set(db.scalars(select(ServiceImage.image_reference).where(
        ServiceImage.service_id == service_id, ServiceImage.lifecycle_status == "active")))


# ---------------------------------------------------------------------------
# Paged Service Remediations collections.
#
# The Service Remediations workspace renders one collection at a time.  Each
# collection is counted and paged in the database; only the requested page is
# hydrated.  Ordering matches the previous unpaged lists (newest first, with a
# deterministic id tiebreak), and every record stays reachable by page.
# ---------------------------------------------------------------------------
REMEDIATION_PAGE_SIZES = (25, 50, 100, 250)


def page_window(total, page, page_size):
    pages = max(1, (int(total) + page_size - 1) // page_size)
    page = max(1, min(int(page or 1), pages))
    return page, pages, (page - 1) * page_size


def remediation_jobs_page(db, service_id, page=1, page_size=50):
    from sqlalchemy import func
    total = db.scalar(select(func.count(RemediationExecution.id)).where(RemediationExecution.service_id == service_id)) or 0
    page, pages, offset = page_window(total, page, page_size)
    names = (
        "id", "job_key", "finding_type", "original_revision", "resulting_revision",
        "retry_of_id", "status", "output_mode", "failure_reason", "rollback_reference",
        "source_execution_id", "source_version_id", "revision_number", "remediation_status",
        "delivery_status", "verification_status", "signing_status", "artifact_digest",
        "started_at", "completed_at", "artifact_path", "created_at",
    )
    rows = db.execute(select(*(getattr(RemediationExecution, name) for name in names)).where(
        RemediationExecution.service_id == service_id).order_by(
        RemediationExecution.created_at.desc(), RemediationExecution.id.desc()).offset(offset).limit(page_size)).mappings()
    return [SimpleNamespace(**dict(row)) for row in rows], {"page": page, "page_count": pages, "total_items": total}


def poam_entries_page(db, service_id, *, mitigations, page=1, page_size=50):
    """POA&M (non-mitigation, including untyped legacy rows) or mitigation entries."""
    from sqlalchemy import func, or_
    from sqlalchemy.orm import selectinload
    from .models import PoamEntry
    kind = (PoamEntry.item_type == "mitigation") if mitigations else or_(
        PoamEntry.item_type.is_(None), PoamEntry.item_type != "mitigation")
    scope = (PoamEntry.service_id == service_id, kind)
    total = db.scalar(select(func.count(PoamEntry.id)).where(*scope)) or 0
    page, pages, offset = page_window(total, page, page_size)
    entries = db.scalars(select(PoamEntry).where(*scope).options(
        selectinload(PoamEntry.finding), selectinload(PoamEntry.policy_finding),
        selectinload(PoamEntry.created_by), selectinload(PoamEntry.approved_by),
    ).order_by(PoamEntry.created_at.desc(), PoamEntry.id.desc()).offset(offset).limit(page_size)).all()
    return entries, {"page": page, "page_count": pages, "total_items": total}


def exceptions_page(db, service, now, aware, page=1, page_size=50):
    """Vulnerability exceptions, then configuration exceptions, then pending requests.

    The three segments keep the previous concatenated order (each newest first);
    the page window is applied across segment boundaries with database
    offsets, so only displayed rows are loaded.
    """
    from sqlalchemy import func, or_
    from sqlalchemy.orm import selectinload
    from .models import ExceptionRecord, Finding, PolicyExceptionRecord, PolicyFinding, WorkflowRequest
    vulnerability = (ExceptionRecord.finding_id == Finding.id, Finding.service_id == service.id)
    configuration = (PolicyExceptionRecord.policy_finding_id == PolicyFinding.id, PolicyFinding.service_id == service.id)
    # Requests whose target finding no longer exists were never listed.
    pending = (WorkflowRequest.service_id == service.id, WorkflowRequest.request_type == "exception",
               WorkflowRequest.status == "pending",
               or_(select(Finding.id).where(Finding.id == WorkflowRequest.finding_id).exists(),
                   select(PolicyFinding.id).where(PolicyFinding.id == WorkflowRequest.policy_finding_id).exists()))
    counts = [
        db.scalar(select(func.count(ExceptionRecord.id)).where(*vulnerability)) or 0,
        db.scalar(select(func.count(PolicyExceptionRecord.id)).where(*configuration)) or 0,
        db.scalar(select(func.count(WorkflowRequest.id)).where(*pending)) or 0,
    ]
    total = sum(counts)
    page, pages, offset = page_window(total, page, page_size)
    windows, skip, remaining = [], offset, page_size
    for count in counts:
        segment_offset = min(skip, count)
        skip -= segment_offset
        take = min(remaining, count - segment_offset)
        remaining -= take
        windows.append((segment_offset, take))
    rows = []
    (vuln_offset, vuln_limit), (policy_offset, policy_limit), (request_offset, request_limit) = windows
    if vuln_limit:
        for record in db.scalars(select(ExceptionRecord).where(*vulnerability).options(
                selectinload(ExceptionRecord.finding)).order_by(ExceptionRecord.created_at.desc(), ExceptionRecord.id.desc())
                .offset(vuln_offset).limit(vuln_limit)):
            finding = record.finding
            state = "Revoked" if record.revoked_at else ("Expired" if aware(record.expires_at) < now else "Active")
            rows.append({"kind": "Vulnerability", "item": finding.cve, "severity": finding.severity,
                         "status": state, "expires_at": record.expires_at, "approved_by": record.approved_by,
                         "created_at": record.created_at, "justification": record.justification,
                         "record_id": record.id, "href": f"/services/{service.service_key}/findings/{finding.id}",
                         "revoke_href": f"/exceptions/{record.id}/revoke"})
    if policy_limit:
        for record in db.scalars(select(PolicyExceptionRecord).where(*configuration).options(
                selectinload(PolicyExceptionRecord.policy_finding)).order_by(
                PolicyExceptionRecord.created_at.desc(), PolicyExceptionRecord.id.desc())
                .offset(policy_offset).limit(policy_limit)):
            finding = record.policy_finding
            state = "Revoked" if record.revoked_at else ("Expired" if aware(record.expires_at) < now else "Active")
            rows.append({"kind": "Configuration", "item": finding.finding, "severity": finding.severity,
                         "status": state, "expires_at": record.expires_at, "approved_by": record.approved_by,
                         "created_at": record.created_at, "justification": record.justification,
                         "record_id": record.id, "href": f"/services/{service.service_key}?finding_state=exceptions&finding_type=configuration",
                         "revoke_href": f"/policy-exceptions/{record.id}/revoke"})
    if request_limit:
        for workflow in db.scalars(select(WorkflowRequest).where(*pending).options(
                selectinload(WorkflowRequest.finding), selectinload(WorkflowRequest.policy_finding)).order_by(
                WorkflowRequest.created_at.desc(), WorkflowRequest.id.desc()).offset(request_offset).limit(request_limit)):
            target = workflow.finding or workflow.policy_finding
            is_vulnerability = bool(workflow.finding)
            rows.append({"kind": "Vulnerability" if is_vulnerability else "Configuration",
                         "item": target.cve if is_vulnerability else target.finding,
                         "severity": target.severity, "status": "Pending", "expires_at": workflow.requested_expires_at,
                         "approved_by": "Pending review", "created_at": workflow.created_at,
                         "justification": workflow.justification, "record_id": workflow.id,
                         "href": f"/services/{service.service_key}/findings/{target.id}" if is_vulnerability else f"/services/{service.service_key}?finding_state=exceptions&finding_type=configuration"})
    return rows, {"page": page, "page_count": pages, "total_items": total}
