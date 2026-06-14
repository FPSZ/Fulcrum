"""请求级安全上下文 —— 在管线各阶段之间传递的状态载体。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .enums import RiskLevel
from .models import Finding, SourceSpan, ToolIntent


class Context(BaseModel):
    """一次会话/请求处理过程中的累积上下文。

    管线把它在 labeler -> detector -> attributor -> policy -> executor 之间传递,
    各能力只读取/追加,不持有跨请求状态。
    """

    session_id: str
    request_id: str | None = None
    trace_id: str | None = None
    spans: list[SourceSpan] = Field(default_factory=list)
    session_trace: list[ToolIntent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
