import asyncio
from types import SimpleNamespace

from fastapi import HTTPException


def test_scan_submission_failure_preserves_scoped_targets(monkeypatch):
    from app import main

    permitted = SimpleNamespace(id=1, service_key="allowed", current_version_id=None, manual_version="1")
    other = SimpleNamespace(id=2, service_key="other")
    db = SimpleNamespace(scalar=lambda query: permitted, scalars=lambda query: [permitted, other])
    auth = SimpleNamespace(accessible_service_ids=lambda permission: {1}, has=lambda *args: True)

    async def form():
        return SimpleNamespace(getlist=lambda key: [], get=lambda key: None)

    def fail(*args, **kwargs):
        raise HTTPException(422, "Acquisition failed")

    monkeypatch.setattr(main, "get_global_configuration", lambda db: {})
    monkeypatch.setattr(main, "_start_public_scan", fail)
    monkeypatch.setattr(main, "self_service_context", lambda *args, **kwargs: (args, kwargs))
    args, context = asyncio.run(main.public_scan_submit(
        SimpleNamespace(form=form), image_list="image:1", chart_url="", chart_archive=None,
        ingest_service_id="allowed", ingest_service_version="1", db=db, auth=auth,
    ))
    assert args[4] == "Acquisition failed"
    assert context["services"] == [permitted]
    assert context["ingest_service_id"] == "allowed"
    assert context["ingest_service_version"] == "1"
