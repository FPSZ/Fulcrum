"""HTTP 请求关联中间件:关联 ID、完成日志和安全字段边界。"""

from __future__ import annotations

import re
import secrets
import time
from typing import TYPE_CHECKING

from .logging import bind_log_context, get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI, Request

_CORRELATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LOG = get_logger("fulcrum.http")


def _safe_id(value: str | None) -> str:
    if value and _CORRELATION_ID.fullmatch(value):
        return value
    return secrets.token_hex(16)


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else "<unmatched>"


def install_request_observability(app: FastAPI) -> None:
    """安装最外层 HTTP 观测中间件,不读取 body/query/header 凭据。"""

    @app.middleware("http")
    async def _observe(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = _safe_id(request.headers.get("x-request-id"))
        trace_id = _safe_id(request.headers.get("x-trace-id"))
        started = time.perf_counter()
        with bind_log_context(request_id=request_id, trace_id=trace_id):
            try:
                response = await call_next(request)
            except Exception as exc:
                _LOG.error(
                    "http.request.failed",
                    extra={
                        "http_method": request.method,
                        "http_path": _route_template(request),
                        "status_code": 500,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                        "exception_type": type(exc).__name__,
                    },
                )
                raise
            _LOG.info(
                "http.request.completed",
                extra={
                    "http_method": request.method,
                    "http_path": _route_template(request),
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                },
            )
            response.headers["x-request-id"] = request_id
            response.headers["x-trace-id"] = trace_id
            return response
