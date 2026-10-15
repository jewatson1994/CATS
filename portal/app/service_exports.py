"""Shared builders for individual downloads, Export All and release delivery."""
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED

from fastapi import HTTPException
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Service, Execution, PoamEntry, Finding, FindingObservation, PolicyFinding
from .architecture import build_architecture_graph
from .architecture_export import build_architecture_svg
from .helm_diagram import build_helm_diagram
from .purpose_exports import template_for_service, workbook_for

def format_sheet(sheet):
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    sheet.sheet_view.showGridLines = False
    header_fill = PatternFill("solid", fgColor="17312B")
    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(vertical="center")
    for column in sheet.columns:
        width = min(max(len(str(cell.value or "")) for cell in column) + 2, 55)
        sheet.column_dimensions[get_column_letter(column[0].column)].width = max(width, 12)
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)


def _focused_export_book(headers: list[str], rows: list[list]) -> Workbook:
    from .exchange import literal
    book = Workbook()
    sheet = book.active
    sheet.title = "CATS Export"
    sheet.append(headers)
    for row_number, row in enumerate(rows, 2):
        sheet.append([None] * len(headers))
        for index, value in enumerate(row, 1):
            literal(sheet.cell(row_number, index), value)
    format_sheet(sheet)
    return book


def _service_mitigations_book(service_key: str, db: Session):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    entries = db.execute(select(PoamEntry.id, PoamEntry.service_version, PoamEntry.item_type,
        PoamEntry.title, PoamEntry.remediation, PoamEntry.status, PoamEntry.due_date, PoamEntry.ticket)
        .where(PoamEntry.service_id == service.id, PoamEntry.remediation.is_not(None), PoamEntry.remediation != "")
        .order_by(PoamEntry.id).execution_options(yield_per=500))
    rows = ([item.id, item.service_version, item.item_type, item.title, item.remediation,
             item.status, item.due_date.isoformat() if item.due_date else "", item.ticket or ""] for item in entries)
    return _focused_export_book(
        ["Entry ID", "Service Version", "Type", "Title", "Mitigation", "Status", "Due Date", "Ticket"], rows)


def _service_findings_book(service_key: str, db: Session):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    latest_id = db.scalar(select(Execution.id).where(Execution.service_id == service.id,
        Execution.service_version_id == service.current_version_id, Execution.scan_scope == "service")
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    def export_rows():
        observations = db.execute(select(Finding.cve, Finding.severity, Finding.active,
            FindingObservation.image, FindingObservation.package, FindingObservation.installed_version,
            FindingObservation.fixed_version, Finding.first_seen, Finding.last_seen)
            .join(FindingObservation, FindingObservation.finding_id == Finding.id)
            .where(Finding.service_id == service.id, FindingObservation.execution_id == latest_id)
            .order_by(Finding.id, FindingObservation.id).execution_options(yield_per=500))
        for item in observations:
            yield ["Vulnerability", *item[:7], item.first_seen.isoformat(), item.last_seen.isoformat()]
        policies = db.execute(select(PolicyFinding.finding, PolicyFinding.severity, PolicyFinding.active,
            PolicyFinding.target, PolicyFinding.first_seen, PolicyFinding.last_seen)
            .where(PolicyFinding.service_id == service.id).order_by(PolicyFinding.id)
            .execution_options(yield_per=500))
        for item in policies:
            yield ["Configuration", item.finding, item.severity, item.active, item.target or "",
                   "", "", "", item.first_seen.isoformat(), item.last_seen.isoformat()]
    rows = export_rows()
    return _focused_export_book(
        ["Type", "Finding", "Severity", "Active", "Image or Target", "Package", "Installed Version",
         "Fixed Version", "First Seen", "Last Seen"], rows)


def _service_diagrams_bytes(service_key: str, db: Session):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    latest = db.scalar(select(Execution).where(Execution.service_id == service.id,
        Execution.service_version_id == service.current_version_id, Execution.scan_scope == "service")
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    if latest is None or not latest.raw_payload:
        raise HTTPException(422, detail="No architecture evidence is available to diagram")
    graph = build_architecture_graph(latest.raw_payload or {})
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for view_name in ("all", "configuration", "containers", "flow", "network", "storage"):
            archive.writestr(f"architecture-{view_name}.svg", build_architecture_svg(graph, view_name))
        archive.writestr("helm-diagram.svg", build_helm_diagram(service, latest))
    return output.getvalue()


def _service_sbom_components(service_key: str, db: Session):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    latest = db.scalar(select(Execution).where(Execution.service_id == service.id,
        Execution.service_version_id == service.current_version_id, Execution.scan_scope == "service")
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    if latest is None or not (latest.raw_payload or {}).get("sbom_components"):
        raise HTTPException(422, detail="No retained SBOM component evidence is available")
    return {"format": "cats-retained-sbom-components-v1", "service": service_key,
        "execution_id": latest.execution_key, "components": latest.raw_payload["sbom_components"]}



def write_all(output, service, db, auth, *, bundle_builder=None, max_bytes=None):
    """Write the same permission-scoped ZIP for downloads and retained releases."""
    from .release_exports import write_export_archive
    from .service_transfer import export_service

    if not auth.has("service.export", service.id):
        raise PermissionError("Service export permission required")
    workbooks = {}
    for kind in ("ppsm", "poam", "asset_list"):
        columns, _, _ = template_for_service(db, kind, service)
        workbooks[f"{kind}.xlsx"] = lambda kind=kind, columns=columns: workbook_for(db, service, kind, columns)
    workbooks.update({f"{name}.xlsx": lambda build=build: build(service.service_key, db)
        for name, build in (("mitigations", _service_mitigations_book), ("findings", _service_findings_book))})
    # Generate the exchange bundle outside the missing-evidence handlers: export
    # errors must not silently turn a requested bundle into an unavailable note.
    supplemental = {}
    if auth.has("bundle.export", service.id):
        supplemental["cats-service.zip"] = (bundle_builder() if bundle_builder else
            export_service(db, service, auth.user.username))
    return write_export_archive(output, workbook_builders=workbooks,
        evidence_builders={"diagrams.zip": lambda: _service_diagrams_bytes(service.service_key, db),
                           "sbom-components.json": lambda: _service_sbom_components(service.service_key, db)},
        supplemental_entries=supplemental, max_bytes=max_bytes)
