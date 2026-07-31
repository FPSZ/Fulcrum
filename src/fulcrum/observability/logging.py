"""零额外依赖的结构化日志与请求上下文绑定。"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from ..core.redaction import redact

_CONFIGURED = False
_LOG_CONTEXT: ContextVar[dict[str, str] | None] = ContextVar("fulcrum_log_context", default=None)
_CONTEXT_FIELDS = frozenset({"request_id", "trace_id", "session_id"})
_RECORD_FIELDS = (
    "http_method",
    "http_path",
    "status_code",
    "duration_ms",
    "exception_type",
)


@contextmanager
def bind_log_context(**fields: str | None) -> Iterator[None]:
    """在当前异步上下文绑定安全关联字段,退出时恢复原值。"""
    current = _LOG_CONTEXT.get() or {}
    bound = {key: value for key, value in fields.items() if key in _CONTEXT_FIELDS and value}
    token = _LOG_CONTEXT.set({**current, **bound})
    try:
        yield
    finally:
        _LOG_CONTEXT.reset(token)


class _JsonFormatter(logging.Formatter):
    """只输出固定白名单字段,避免 `extra` 把凭据或请求原文带入日志。"""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "event": redact(record.getMessage()),
        }
        payload.update(_LOG_CONTEXT.get() or {})
        for field in _RECORD_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        exc_type = record.exc_info[0] if record.exc_info else None
        if exc_type is not None and "exception_type" not in payload:
            payload["exception_type"] = exc_type.__name__
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), handlers=[handler])
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
