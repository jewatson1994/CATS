"""Compose evidence survives public, refresh and persisted page boundaries."""
import json

import pytest
from starlette.requests import Request

from app.frontend import page_data


@pytest.mark.parametrize("page", ["self_service.html", "public_results.html", "service_overview.html"])
def test_compose_model_survives_page_projection_without_worker_metadata(page):
    model = {
        "complete": False, "images": ["nginx:stable"], "private_token": "worker-secret",
        "services": [{"name": "web", "image": "nginx:stable", "status": "image_declared", "image_scan": "incomplete",
                      "source_files": ["compose.yaml"], "configuration": {"environment": {"TOKEN": "[REDACTED]"}, "depends_on": ["db"]},
                      "worker_path": "worker-secret"}],
        "issues": [{"code": "image_scan_incomplete", "message": "Image was not scanned", "service": "web", "source": "compose.yaml", "blocking": True,
                    "exception": "worker-secret"}],
        "coverage": {"services": 1, "unique_images": 1, "scanned_images": 0, "preview": True, "worker_token": "worker-secret"},
    }
    context = {"job": {"compose_preview": True, "summary": {"compose": model}, "credential": "worker-secret"},
               "overview_data": {"compose": model}}
    request = Request({"type": "http", "method": "GET", "scheme": "https", "path": "/scan", "query_string": b"", "headers": [], "server": ("cats.test", 443)})
    result = page_data(request, page, context, formatters={})["data"]
    projected = result["job"]["summary"]["compose"] if page == "self_service.html" else result["overview_data"]["compose"]
    assert projected["services"][0]["configuration"] == model["services"][0]["configuration"]
    assert projected["services"][0]["source_files"] == ["compose.yaml"]
    assert projected["services"][0]["image_scan"] == "incomplete"
    assert projected["coverage"]["scanned_images"] == 0
    assert projected["issues"][0]["blocking"] is True
    assert "worker-secret" not in json.dumps(result)
    if page == "self_service.html":
        assert result["job"]["compose_preview"] is True
