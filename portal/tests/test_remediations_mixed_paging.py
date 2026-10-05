import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import urllib.parse

from fastapi import HTTPException
from sqlalchemy import and_, create_engine, false, func, or_, select, true
from sqlalchemy.orm import Session, selectinload
from app.database import Base
from app.models import Service, Finding, PolicyFinding, ExceptionRecord, PolicyExceptionRecord, WorkflowRequest, PoamEntry, User


def test_mixed_exception_pages_are_globally_ordered_scoped_and_bounded():
    tree = ast.parse((Path(__file__).parents[1] / "app/main.py").read_text(encoding="utf-8-sig"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "remediations_page")
    function.decorator_list = []
    function.args.defaults[-2:] = [ast.Constant(None), ast.Constant(None)]
    for argument in function.args.args:
        argument.annotation = None
    namespace = dict(globals(), utcnow=lambda: now,
        aware=lambda value: value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value,
        page_context=lambda auth, **values: values,
        templates=SimpleNamespace(TemplateResponse=lambda request, name, context: context))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), "remediations", "exec"), namespace)
    route = namespace["remediations_page"]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="visible", name="Visible")
        hidden = Service(service_key="hidden", name="Hidden")
        db.add_all([service, hidden]); db.flush()
        finding = Finding(service_id=service.id, cve="CVE-visible", severity="High", first_seen=now, episode_started=now, last_seen=now)
        policy = PolicyFinding(service_id=service.id, identity_key="policy", finding="POL-visible", severity="High", first_seen=now, episode_started=now, last_seen=now)
        secret = Finding(service_id=hidden.id, cve="CVE-secret", severity="High", first_seen=now, episode_started=now, last_seen=now)
        db.add_all([finding, policy, secret]); db.flush()
        expected = []
        for index in range(61):
            created = now - timedelta(minutes=index // 3)
            common = dict(justification="Reason", created_at=created)
            if index % 3 == 0:
                row = ExceptionRecord(finding_id=finding.id, approved_by="Owner", starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=10), **common)
                kind = "vulnerability"
            elif index % 3 == 1:
                row = PolicyExceptionRecord(policy_finding_id=policy.id, approved_by="Owner", starts_at=now-timedelta(days=1), expires_at=now+timedelta(days=10), **common)
                kind = "configuration"
            else:
                row = WorkflowRequest(service_id=service.id, finding_id=finding.id, request_type="exception", status="pending", requested_by_id=1, **common)
                kind = "pending"
            db.add(row); db.flush()
            expected.append((created, kind, row.id))
        db.add(ExceptionRecord(finding_id=secret.id, justification="Secret", approved_by="Owner", starts_at=now, expires_at=now+timedelta(days=1), created_at=now+timedelta(days=1)))
        db.commit()
        expected.sort(key=lambda item: (-item[0].timestamp(), item[1], item[2]))
        auth = SimpleNamespace(accessible_service_ids=lambda permission: {service.id}, has=lambda *args: False)
        all_rows = []
        for page in range(1, 4):
            result = route(None, tab="exceptions", page=page, page_size=25, db=db, auth=auth)
            assert result["total_items"] == 61 and result["page_count"] == 3
            assert len(result["exceptions"]) == (25 if page < 3 else 11)
            all_rows.extend(("pending" if row["status"] == "Pending" else "vulnerability" if row["kind"] == "Vulnerability" else "configuration", row["record_id"]) for row in result["exceptions"])
            assert all(row["service"].id == service.id for row in result["exceptions"])
        assert all_rows == [(kind, row_id) for created, kind, row_id in expected]
        last = route(None, tab="exceptions", page=99, page_size=25, db=db, auth=auth)
        assert last["page"] == 3 and len(last["exceptions"]) == 11
        pending = route(None, tab="exceptions", status_filter="pending_approval", identifier="CVE-visible", page_size=25, db=db, auth=auth)
        assert pending["total_items"] == 20 and all(row["status"] == "Pending" for row in pending["exceptions"])
        none = route(None, tab="exceptions", identifier="CVE-secret", page_size=25, db=db, auth=auth)
        assert none["total_items"] == 0 and none["exceptions"] == []
    engine.dispose()
