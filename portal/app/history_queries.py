"""Paginate retained history before hydrating native or imported scan evidence."""
from sqlalchemy import Integer, JSON, case, cast, func, select, true, tuple_, type_coerce
from .models import Execution, ServiceTransferProvenance


def historical_approval_posture(db, execution, version):
    """Read the capture-time assessment verified when Cyber approved this exact scan."""
    from .cyber_approvals import CyberApproval
    from .execution_summaries import payload_digest

    snapshot = CyberApproval.snapshot
    capture = snapshot['history_posture']
    recorded = db.scalar(select(capture).where(
        CyberApproval.service_id == execution.service_id,
        CyberApproval.source_execution_id == execution.id, CyberApproval.status == 'approved',
        CyberApproval.variant == 'current_service', snapshot['evidence_scope'].as_string() == 'current-service-scan',
        snapshot['version'].as_string() == version,
        snapshot['source_payload_digest'].as_string() == (execution.payload_digest or payload_digest(execution.raw_payload)),
        capture['source_execution_id'].as_integer() == execution.id,
    ).order_by(CyberApproval.requested_at.desc(), CyberApproval.id.desc()).limit(1))
    if not isinstance(recorded, dict) or recorded.get('posture') not in ('compliant', 'warning', 'non_compliant'):
        return {}
    counts = ('watchlist', 'open_poams', 'overdue_poams')
    if not recorded.get('posture_captured_at') or any(type(recorded.get(k)) is not int or recorded[k] < 0 for k in counts):
        return {}
    return {'posture_source': 'approval_capture', **{k: recorded[k] for k in ('posture', 'posture_captured_at', *counts)}}


def historical_releases(db, service_id, version):
    """Release identities and approval dates captured for this service version."""
    from .cyber_approvals import CyberApproval
    from .replica_models import ReplicaRelease
    from .replica_integrity import digest, verify_record
    from fastapi import HTTPException

    approval = CyberApproval
    scan_version = func.coalesce(func.nullif(Execution.raw_payload["service"]["version"].as_string(), ""), "Unknown")
    approval_version = approval.snapshot["version"].as_string()
    native = db.execute(select(approval.release_key, approval.decided_at, approval.snapshot_digest,
        Execution.execution_key).join(Execution, Execution.id == approval.source_execution_id).where(
        approval.service_id == service_id, Execution.service_id == service_id, scan_version == version,
        func.coalesce(approval_version, scan_version) == version,
        approval.status == "approved").order_by(approval.decided_at.desc(), approval.id.desc()))
    result = [dict(release_key=key, approved_at=date, digest=checksum, source="Local",
                   scan=scan) for key, date, checksum, scan in native]

    captured = ReplicaRelease.evidence_state["extension"]["approval_context"]
    replicas = db.scalars(select(ReplicaRelease).where(ReplicaRelease.service_id == service_id,
        captured["version"].as_string() == version).order_by(ReplicaRelease.sequence.desc()))
    for release in replicas:
        if not verify_record(release) or digest(release.evidence_state) != release.evidence_state_digest:
            raise HTTPException(409, detail="Retained release integrity check failed")
        context = release.evidence_state["extension"]["approval_context"]
        source_id = context.get("source_execution_id")
        result.append(dict(release_key=release.source_release_id, approved_at=release.approved_at,
                           digest=release.manifest_digest, source="Publisher", scan=f"#{source_id}" if source_id else None))
    return result


def imported_source(db):
    source = ServiceTransferProvenance
    array = source.detail["historical_executions"]
    if db.get_bind().dialect.name == "sqlite":
        elements = func.json_each(array).table_valued("key", "value").alias("history_elements")
        position = cast(elements.c.key, Integer)
    else:
        elements = func.json_array_elements(array).table_valued(
            "value", with_ordinality="position").render_derived().alias("history_elements")
        position = elements.c.position - 1
    item = type_coerce(elements.c.value, JSON)
    # Transfer formats retain either a complete execution or its direct payload.
    version = case((item["raw_payload"].as_string().is_not(None), item["raw_payload"]["service"]["version"]),
                   else_=item["service"]["version"])
    return source, elements, position, item, version


def imported_metadata(db, service_id):
    source, elements, position, item, version = imported_source(db)
    return db.execute(select(source.id, position.label("position"), version.label("version"))
        .select_from(source).join(elements, true()).where(source.service_id == service_id)
        .order_by(source.id, position)).all()


def _scan_options(db, service_id, page_ids, pairs):
    """Select display metadata without reading the retained scan documents."""
    options = []
    if page_ids:
        local = db.execute(select(Execution.id, Execution.execution_key, Execution.scanned_at,
            Execution.raw_payload["service"]["name"].as_string()).where(Execution.service_id == service_id,
            Execution.id.in_(page_ids)).order_by(Execution.scanned_at.desc(), Execution.id.desc()))
        options.extend(dict(scan_id=f"scan-{identity}", key=key, at=at, name=name, source="native")
                       for identity, key, at, name in local)
    if pairs:
        source, elements, position, item, _ = imported_source(db)
        raw = item["raw_payload"]
        captures = db.execute(select(source.id, position,
            func.coalesce(item["execution_key"].as_string(), raw["execution_id"].as_string(), item["execution_id"].as_string()),
            func.coalesce(item["scanned_at"].as_string(), raw["scanned_at"].as_string()),
            func.coalesce(raw["service"]["name"].as_string(), item["service"]["name"].as_string()))
            .select_from(source).join(elements, true()).where(source.service_id == service_id,
                tuple_(source.id, position).in_(pairs)).order_by(source.id, position))
        options.extend(dict(scan_id=f"import-{identity}-{index}", key=key or f"Import {identity}/{index}",
                            at=at, name=name, source="imported") for identity, index, key, at, name in captures)
    return options


def history_page_evidence(db, service, version, *, page=1, imported_page=1, page_size=10,
                          scan="", tab=None, preferred_source="native"):
    metadata = db.execute(select(Execution.id, Execution.raw_payload["service"]["version"])
        .where(Execution.service_id == service.id).order_by(Execution.scanned_at.desc(), Execution.id.desc())).all()
    imported = imported_metadata(db, service.id)
    native_versions = list(dict.fromkeys(str(value or "Unknown") for _, value in metadata)) or [service.manual_version or "Unknown"]
    imported_versions = list(dict.fromkeys(str(row.version or "Unknown") for row in imported))
    choices = list(dict.fromkeys(native_versions + imported_versions))
    selected = version or (imported_versions[0] if not metadata and imported_versions else choices[0])
    if selected not in choices:
        raise ValueError("Service version not found")
    ids = [identifier for identifier, value in metadata if str(value or "Unknown") == selected]
    import_ids = [(row.id, row.position) for row in imported if str(row.version or "Unknown") == selected]
    if scan:
        # Resolve a bookmarked scan inside the selected version before paging.
        native_position = next((i for i, row_id in enumerate(ids) if scan == f"scan-{row_id}"), None)
        imported_position = next((i for i, (row_id, position) in enumerate(import_ids)
                                  if scan == f"import-{row_id}-{position}"), None)
        if native_position is not None:
            page = native_position // page_size + 1
        elif imported_position is not None:
            imported_page = imported_position // page_size + 1
        else:
            raise ValueError("Scan not found for this service version")
    pages, import_pages = max(1, (len(ids) + page_size - 1) // page_size), max(1, (len(import_ids) + page_size - 1) // page_size)
    page, imported_page = max(1, min(page, pages)), max(1, min(imported_page, import_pages))
    page_ids = ids[(page - 1) * page_size:page * page_size]
    pairs = import_ids[(imported_page - 1) * page_size:imported_page * page_size]
    source, elements, position, item, _ = imported_source(db)
    options = []
    if tab:
        options = _scan_options(db, service.id, page_ids, pairs)
        if options and not scan:
            scan = next((row for row in options if row["source"] == preferred_source), options[0])["scan_id"]
        # Other scans contribute only selector metadata. The Releases view uses
        # version-bound approval records, so it needs no execution payload.
        page_ids = [identity for identity in page_ids if tab != "releases" and f"scan-{identity}" == scan]
        pairs = [(identity, index) for identity, index in pairs if tab != "releases" and f"import-{identity}-{index}" == scan]
    executions = list(db.scalars(select(Execution).where(Execution.service_id == service.id,
        Execution.id.in_(page_ids)).order_by(Execution.scanned_at.desc(), Execution.id.desc()))) if page_ids else []
    imported_items = list(db.scalars(select(item).select_from(source).join(elements, true())
        .where(source.service_id == service.id, tuple_(source.id, position).in_(pairs))
        .order_by(source.id, position))) if pairs else []
    original_positions = {(row.id, row.position): index for index, row in enumerate(imported)}
    return dict(version=selected, versions=choices, executions=executions, imported=imported_items,
        scan_options=options, selected_scan=scan,
        imported_indices=[original_positions[pair] for pair in pairs],
        imported_scan_ids=[f"import-{row_id}-{position}" for row_id, position in pairs],
        page=page, total_pages=pages, total_items=len(ids), imported_page=imported_page,
        imported_total_pages=import_pages, imported_total_items=len(import_ids), page_size=page_size)
