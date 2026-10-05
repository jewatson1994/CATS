"""Snapshot export keeps authorization/order while bounding evidence batches."""
import ast
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from openpyxl import Workbook
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, selectinload

from app.database import Base
from app.models import Service, Finding, PolicyFinding, PortalSetting, Group, Execution


def export_functions(namespace):
    tree = ast.parse((Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8-sig"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in {"export_services", "configurations_for_services"}]
    for function in functions:
        function.decorator_list = []
        for argument in function.args.defaults:
            if isinstance(argument, ast.Call) and getattr(argument.func, "id", None) == "Depends":
                argument.func = ast.Name(id="unused_default", ctx=ast.Load())
                argument.args = []
    exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])), "export", "exec"), namespace)
    return namespace["export_services"]


def test_export_authorization_order_configuration_and_batch_residency():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        group = Group(name="policy")
        db.add(group)
        db.flush()
        db.add(PortalSetting(key="group:policy:overdue_days", value="7", group_id=group.id))
        db.add_all(Service(service_key=str(index), name=f"Name {120-index:03}", owner="owner", poc="contact", groups=[group])
                   for index in range(121))
        db.commit()
        ids = list(db.scalars(select(Service.id)))
        seen = []
        peaks = []
        statements = []
        class ExportSession(Session):
            def close(self):
                peaks.append(len(self.identity_map))
                super().close()
        def view(service, now, configuration):
            assert configuration["overdue_days"] == "7"
            # Accesses must be eagerly loaded, including historically lazy fields.
            for relation in ("findings", "policy_findings", "executions", "archive_events", "groups", "poam_entries", "current_version"):
                assert relation in service.__dict__
            seen.append(service.id)
            return dict(service=service, version="1", archive=False, compliant=True, evidence_state="No evidence",
                        active=[], policy_findings=[], noncompliant=[], policy_noncompliant=[], excepted=[],
                        policy_excepted=[], resolved=[], policy_resolved=[], oldest_age=0, last_execution=None)
        namespace = dict(Session=ExportSession, select=select, selectinload=selectinload, Service=Service,
                         Finding=Finding, PolicyFinding=PolicyFinding, PortalSetting=PortalSetting, Execution=Execution,
                         AuthContext=object, Depends=None, unused_default=lambda: None, Workbook=Workbook,
                         utcnow=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc), get_configuration=lambda db: {"overdue_days": "90"},
                         GLOBAL_CONFIGURATION_KEYS=set(), service_view=view, excel_datetime=lambda value: value,
                         format_sheet=lambda sheet: None, workbook_response=lambda workbook, name: workbook,
                         HTTPException=HTTPException)
        export = export_functions(namespace)
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, params, context, many: statements.append(sql))
        workbook = export(db, SimpleNamespace(accessible_service_ids=lambda permission: set(ids[:-1])))
        assert seen == list(reversed(ids[:-1]))
        assert workbook.active.max_row == 121
        assert list(workbook.active.values)[1][:6] == ("119", "Name 001", "1", "owner", "contact", "policy")
        assert len(peaks) == 3 and max(peaks) <= 51
        assert sum("FROM portal_settings" in sql for sql in statements) == 3
        assert len(db.identity_map) <= 1
        with pytest.raises(HTTPException) as denied:
            export(db, SimpleNamespace(accessible_service_ids=lambda permission: set()))
        assert denied.value.status_code == 403
    engine.dispose()
