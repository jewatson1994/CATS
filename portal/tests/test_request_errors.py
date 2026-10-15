"""Browser errors expose user-facing messages without dumping diagnostics."""
import asyncio
import json

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import main


def request(accept="text/html"):
    return Request({"type": "http", "method": "POST", "path": "/services/demo/remediations/start",
                    "root_path": "", "scheme": "http", "server": ("testserver", 80),
                    "headers": [(b"accept", accept.encode())], "router": main.app.router})


@pytest.mark.parametrize("status,detail,expected", [
    (422, {"code": "source_review_required", "message": "Confirm the listed chart exclusions.",
           "source_safety": {"internal": "not for display"}}, "Confirm the listed chart exclusions."),
    (409, "Rebuild the remediation plan", "Rebuild the remediation plan"),
    (422, {"code": "unknown"}, "The request could not be completed."),
    (422, {"message": {"internal": "not for display"}}, "The request could not be completed."),
    (422, ["not for display"], "The request could not be completed."),
    (403, {"message": "not for display"}, "You do not have permission to access this page or perform this action."),
    (404, {"message": "not for display"}, "The requested page or item was not found."),
])
def test_browser_error_message(monkeypatch, status, detail, expected):
    captured = {}
    def render(request, name, context, **kwargs):
        captured.update(template=name, context=context, **kwargs)
        return captured
    monkeypatch.setattr(main.templates, "TemplateResponse", render)
    response = asyncio.run(main.expected_http_error(request(), HTTPException(status, detail)))
    assert response["template"] == "request_error.html"
    assert response["status_code"] == status
    assert response["context"]["detail"] == expected
    assert "not for display" not in str(response)


def test_api_preserves_structured_error_contract():
    detail = {"code": "source_review_required", "message": "Confirm the listed chart exclusions.",
              "source_safety": {"blocked_charts": ["auth"]}}
    response = asyncio.run(main.expected_http_error(request("application/json"), HTTPException(422, detail)))
    assert response.status_code == 422
    assert json.loads(response.body) == {"detail": detail}
