"""HTTP correlation and error envelopes, including early middleware failures."""
import json
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse

from .diagnostics import build_diagnostic, correlation, enqueue_diagnostic, public_diagnostic, request_correlation, sanitize


def request_diagnostic(request, error, *, status, summary=None, context=None):
    existing = getattr(request.state, "diagnostic", None)
    if existing:
        return existing
    params = request.path_params
    resource = {key: value for key, value in params.items() if key in {"service_id", "service_key", "job_id", "execution_id", "artifact_id", "source_id"}}
    authored_resource = getattr(error, "diagnostic_resource", None)
    if isinstance(authored_resource, dict):
        resource.update(authored_resource)
    context = {**(getattr(error, "diagnostic_context", None) or {}), **(context or {})}
    # Forbidden/missing requests must not confirm resource existence or metadata.
    if status in (401, 403, 404):
        resource = {}
    route = request.scope.get("route")
    operation = f"{request.method} {getattr(route, 'path', request.url.path)}"
    component = "Portal API / Ingestion" if any(part in operation for part in ("/ingest", "pipeline-results")) else "Portal API"
    item = build_diagnostic(error, component=component, operation=operation, status=status,
        correlation_id=request_correlation(request), resource=resource, context=context, summary=summary)
    extra = getattr(error, "diagnostic", None)
    if isinstance(extra, dict):
        item["technical"]["component_diagnostic"] = sanitize(extra)
    request.state.diagnostic = item
    enqueue_diagnostic(item)
    logging.getLogger("cats.portal").warning("request_failure error_id=%s correlation_id=%s code=%s status=%s",
        item["error_id"], item["correlation_id"], item["code"], status)
    return item


def error_response(request, error, *, status, detail, context=None, headers=None):
    # Existing authored HTTP messages remain compatible, including dict details.
    safe = sanitize(detail)
    summary = safe if isinstance(safe, str) else safe.get("message") if isinstance(safe, dict) else None
    if not isinstance(summary, str):
        summary = None
    item = request_diagnostic(request, error, status=status, summary=summary, context=context)
    return JSONResponse({"detail": safe, "diagnostic": public_diagnostic(item)}, status_code=status,
        headers={**(headers or {}), "X-Correlation-ID": item["correlation_id"], "Cache-Control": "private, no-store"})


class DiagnosticMiddleware:
    """Bound error buffering only; successful streams are passed through untouched."""
    def __init__(self, app, error_handler=None):
        self.app = app
        self.error_handler = error_handler

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope)
        identity = request_correlation(request)
        token = correlation.set(identity)
        start, chunks, size, sent = None, [], 0, False

        async def forward(message):
            nonlocal start, chunks, size, sent
            if message["type"] == "http.response.start":
                headers = [(key, value) for key, value in message.get("headers", []) if key.lower() != b"x-correlation-id"]
                headers.append((b"x-correlation-id", identity.encode("ascii")))
                if scope.get("path", "").startswith(("/api/diagnostics", "/admin/diagnostics")) or message["status"] >= 400:
                    headers = [(key, value) for key, value in headers if key.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"private, no-store"))
                message = {**message, "headers": headers}
                content_type = next((value for key, value in headers if key.lower() == b"content-type"), b"")
                compressed = any(key.lower() == b"content-encoding" for key, _ in headers)
                if message["status"] >= 400 and (compressed or b"json" not in content_type) and not getattr(request.state, "diagnostic", None):
                    # Do not decode/compress arbitrary bodies or buffer streaming responses.
                    request_diagnostic(request, "HTTP operation failed", status=message["status"],
                        context={"response_status": message["status"]})
                if message["status"] >= 400 and b"json" in content_type and not compressed:
                    start = message
                    return
                sent = True
            elif message["type"] == "http.response.body" and start is not None:
                chunks.append(message.get("body", b""))
                size += len(chunks[-1])
                if size > 65536:
                    if not getattr(request.state, "diagnostic", None):
                        request_diagnostic(request, "HTTP operation failed", status=start["status"],
                            context={"response_body": "omitted: diagnostic buffer limit exceeded"})
                    await send(start)
                    sent = True
                    await send({**message, "body": b"".join(chunks)})
                    start, chunks = None, []
                    return
                if message.get("more_body"):
                    return
                body = b"".join(chunks)
                try:
                    payload = json.loads(body)
                    if isinstance(payload, dict) and "diagnostic" not in payload:
                        detail = payload.get("detail", "The request could not be completed")
                        item = request_diagnostic(request, str(detail), status=start["status"],
                            summary=detail if isinstance(detail, str) else None)
                        payload["diagnostic"] = public_diagnostic(item)
                        body = json.dumps(sanitize(payload)).encode("utf-8")
                except (ValueError, TypeError):
                    pass
                headers = [(key, value) for key, value in start["headers"] if key.lower() not in (b"content-length", b"cache-control")]
                headers.extend([(b"content-length", str(len(body)).encode()), (b"cache-control", b"private, no-store")])
                await send({**start, "headers": headers})
                sent = True
                start, chunks = None, []
                await send({**message, "body": body})
                return
            await send(message)

        try:
            await self.app(scope, receive, forward)
        except Exception as exc:
            # Includes auth/database failures in middleware outside FastAPI's router.
            item = request_diagnostic(request, exc, status=500, summary="The operation failed while processing your request")
            if sent:
                raise
            response = JSONResponse({"detail": item["summary"], "diagnostic": public_diagnostic(item)}, status_code=500,
                headers={"X-Correlation-ID": identity, "Cache-Control": "private, no-store"})
            if self.error_handler is not None:
                try:
                    response = await self.error_handler(request, exc)
                    response.headers["X-Correlation-ID"] = identity
                    response.headers["Cache-Control"] = "private, no-store"
                except Exception:
                    # A template/database failure must not prevent the safe fallback.
                    pass
            await response(scope, receive, send)
        finally:
            correlation.reset(token)
