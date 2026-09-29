"""Request-body ceilings before/during multipart parsing, without buffering."""
import os
from .exchange_limits import bundle_bytes, workbook_bytes

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse


class UploadLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        chart_upload = path == "/scan" or path.endswith("/artifacts/acquire") or path.endswith("/artifacts/upload")
        exchange_upload = "/exchange/" in path and path.endswith("/preview")
        if scope["type"] != "http" or scope.get("method") != "POST" or not (chart_upload or exchange_upload):
            return await self.app(scope, receive, send)
        limit = int(os.getenv("CATS_UPLOAD_REQUEST_MAX_BYTES", str(1024 * 1024 * 1024)))
        if exchange_upload:
            limit = min(limit, (bundle_bytes() if path == "/exchange/bundles/preview" else workbook_bytes()) + 1024 * 1024)
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
            if length < 0:
                raise ValueError()
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"detail": "Upload request exceeds configured byte limit"}, status_code=413)(scope, receive, send)
        consumed = 0
        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > limit:
                raise HTTPException(413, detail="Upload request exceeds configured byte limit")
            return message
        return await self.app(scope, bounded_receive, send)
