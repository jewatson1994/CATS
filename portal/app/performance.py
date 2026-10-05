"""Opt-in request diagnostics. Never records SQL, parameters, URLs, or identities."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import json
import logging
import os
from threading import Lock
from time import perf_counter
from weakref import WeakSet

from sqlalchemy import event

logger = logging.getLogger("cats.performance")
_current = ContextVar("cats_performance", default=None)
_installed = WeakSet()
_install_lock = Lock()
_STAGES = frozenset({"transformation", "policy", "serialization"})


def diagnostics_enabled():
    return os.getenv("CATS_PERFORMANCE_DIAGNOSTICS", "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Measurement:
    query_count: int = 0
    query_seconds: float = 0.0
    cursor_reported_rows: int = 0
    cursor_unknown_rowcount_queries: int = 0
    orm_instances_loaded: int = 0
    stages: dict = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def snapshot(self):
        with self._lock:
            return {
                "query_count": self.query_count,
                "query_ms": round(self.query_seconds * 1000, 3),
                # DBAPI rowcount is NOT the number of fetched SELECT rows.
                "cursor_reported_rows": self.cursor_reported_rows,
                "cursor_unknown_rowcount_queries": self.cursor_unknown_rowcount_queries,
                "orm_instances_loaded": self.orm_instances_loaded,
                "stage_ms": {key: round(value * 1000, 3) for key, value in self.stages.items()},
            }


@contextmanager
def capture_performance():
    """Explicit opt-in capture for benchmarks; context propagates via AnyIO threadpool."""
    measurement = Measurement()
    token = _current.set(measurement)
    try:
        yield measurement
    finally:
        _current.reset(token)


@contextmanager
def performance_scope(stage):
    """Named stages only: callers cannot accidentally log user-controlled labels."""
    if stage not in _STAGES:
        raise ValueError("Unsupported performance stage")
    measurement = _current.get()
    if measurement is None:
        yield
        return
    started = perf_counter()
    try:
        yield
    finally:
        with measurement._lock:
            measurement.stages[stage] = measurement.stages.get(stage, 0.0) + perf_counter() - started


def install_sqlalchemy_diagnostics(engine, session_class):
    """Install once per engine. Dormant listeners do not allocate measurements."""
    with _install_lock:
        if engine in _installed:
            return
        _installed.add(engine)

        def before_cursor(conn, cursor, statement, parameters, context, executemany):
            measurement = _current.get()
            if measurement is not None:
                context._cats_performance = (measurement, perf_counter())
                with measurement._lock:
                    measurement.query_count += 1

        def finish(context, cursor=None):
            tracking = getattr(context, "_cats_performance", None)
            if tracking is None:
                return
            del context._cats_performance
            measurement, started = tracking
            rows = getattr(cursor, "rowcount", -1)
            with measurement._lock:
                measurement.query_seconds += perf_counter() - started
                if isinstance(rows, int) and rows >= 0:
                    measurement.cursor_reported_rows += rows
                else:
                    measurement.cursor_unknown_rowcount_queries += 1

        def after_cursor(conn, cursor, statement, parameters, context, executemany):
            finish(context, cursor)

        def error(exception_context):
            finish(exception_context.execution_context)

        def loaded(session, instance):
            measurement = _current.get()
            if measurement is not None and session.get_bind(mapper=type(instance)) is engine:
                with measurement._lock:
                    measurement.orm_instances_loaded += 1

        event.listen(engine, "before_cursor_execute", before_cursor)
        event.listen(engine, "after_cursor_execute", after_cursor)
        event.listen(engine, "handle_error", error)
        event.listen(session_class, "loaded_as_persistent", loaded)


class PerformanceMiddleware:
    """Pure ASGI measurement includes response iteration and restores context on errors.

    Response bytes measure ASGI body bytes at this middleware's position. Put it
    outside GZipMiddleware to measure compressed bytes. Raw executor threads need
    copy_context().run; AnyIO/Starlette worker threads propagate context already.
    """
    def __init__(self, app, enabled=None, sink=None):
        self.app = app
        self.enabled = diagnostics_enabled() if enabled is None else enabled
        self.sink = sink or self._log

    @staticmethod
    def _log(record):
        logger.info("request_performance %s", json.dumps(record, sort_keys=True))

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = perf_counter()
        response_bytes = 0
        status = None
        completed = False

        async def measured_send(message):
            nonlocal response_bytes, status, completed
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                response_bytes += len(message.get("body", b""))
                completed = not message.get("more_body", False)
            await send(message)

        with capture_performance() as measurement:
            try:
                await self.app(scope, receive, measured_send)
            finally:
                record = measurement.snapshot()
                route = scope.get("route")
                record.update(route=getattr(route, "path", "<unmatched>"),
                              status=status, response_bytes=response_bytes,
                              response_completed=completed,
                              duration_ms=round((perf_counter() - started) * 1000, 3))
                try:
                    self.sink(record)
                except Exception:
                    # Diagnostics must never fail a request or disclose exception text.
                    logger.warning("Performance diagnostics sink failed")
