import asyncio
import json
import pytest
from starlette.requests import Request
from fastapi import HTTPException
from test_artifact_catalog import db, setup_lineage, ScopedAuth
from app.artifact_catalog import assign_artifact, recommend_artifact
from app import artifact_catalog_routes as routes


def test_recommendation_decisions_are_scoped_audited_and_do_not_activate(db, monkeypatch):
    service, source, target, patch, line = setup_lineage(db)
    assign_artifact(db, service_id=service.id, artifact_id=source.id)
    rec = recommend_artifact(db, service_id=service.id, source_artifact_id=source.id, target_artifact_id=target.id)
    audit = []
    monkeypatch.setattr(routes, "record_audit", lambda *a, **kw: audit.append(kw))
    def call(action, reason="", auth=None):
        async def receive():
            return {"type": "http.request", "body": json.dumps({"action": action, "reason": reason}).encode()}
        request = Request({"type": "http", "headers": [(b"x-csrf-token", b"token")]}, receive)
        return asyncio.run(routes.recommendation_decision(service.service_key, rec.id, request, db=db, auth=auth or ScopedAuth([service.id], True)))
    with pytest.raises(HTTPException) as exc:
        call("dismiss")
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc:
        call("defer", auth=ScopedAuth([]))
    assert exc.value.status_code == 404
    assert call("defer")["status"] == "deferred"
    assert call("dismiss", "Compatibility review required")["active_release_changed"] is False
    assert audit[-1]["reason"] == "Compatibility review required"
    assert call("reopen")["status"] == "pending_verification"
    rec.status = "proposed"; db.flush()
    with pytest.raises(HTTPException) as exc:
        call("dismiss", "No longer wanted")
    assert exc.value.status_code == 409
