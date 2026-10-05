"""Paginate retained history before hydrating native or imported scan evidence."""
import json
from sqlalchemy import Integer, JSON, case, cast, func, select, true, tuple_, type_coerce
from .models import Execution, ServiceTransferProvenance


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


def history_page_evidence(db, service, version, *, page=1, imported_page=1, page_size=10):
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
    pages, import_pages = max(1, (len(ids) + page_size - 1) // page_size), max(1, (len(import_ids) + page_size - 1) // page_size)
    page, imported_page = max(1, min(page, pages)), max(1, min(imported_page, import_pages))
    sqlite = db.get_bind().dialect.name == "sqlite"
    if sqlite:
        allowed = func.json_each(json.dumps(ids)).table_valued("value").alias("history_ids")
    else:
        allowed = func.json_array_elements_text(cast(ids, JSON)).table_valued("value").render_derived().alias("history_ids")
    executions = list(db.scalars(select(Execution).join(allowed, Execution.id == cast(allowed.c.value, Integer))
        .where(Execution.service_id == service.id).order_by(Execution.scanned_at.desc(), Execution.id.desc())
        .offset((page - 1) * page_size).limit(page_size)))
    source, elements, position, item, _ = imported_source(db)
    # The selected positions are bounded to one page, including under SQLite's
    # historical variable limit. Only these elements cross the JSON boundary.
    pairs = import_ids[(imported_page - 1) * page_size:imported_page * page_size]
    imported_items = list(db.scalars(select(item).select_from(source).join(elements, true())
        .where(source.service_id == service.id, tuple_(source.id, position).in_(pairs))
        .order_by(source.id, position))) if pairs else []
    original_positions = {(row.id, row.position): index for index, row in enumerate(imported)}
    return dict(version=selected, versions=choices, executions=executions, imported=imported_items,
        imported_indices=[original_positions[pair] for pair in pairs],
        page=page, total_pages=pages, total_items=len(ids), imported_page=imported_page,
        imported_total_pages=import_pages, imported_total_items=len(import_ids), page_size=page_size)
