"""日志配置。

M0 用标准库 logging 保持零额外依赖;M1+ 可平滑切换 structlog/OTEL。
规范:结构化字段含 session_id/request_id/trace_id;禁止打印敏感原文(存哈希/摘要)。
"""

from __future__ import annotations

import logging

_CONFIGURED = False
_FORMAT = "%(asctime)s %(levelname)s %(name)s :: %(message)s"


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format=_FORMAT)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
