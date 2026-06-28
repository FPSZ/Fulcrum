"""请求路径 DTO —— /v1/chat/completions、/tools/call、/healthz。"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field, field_validator

from ....core.domain import Disposition

# 未鉴权端点(/v1/chat/completions、/tools/call)的输入上限:挡住"超大体喂同步检测链"的
# CPU/事件循环 DoS。content 对齐网关的 8000;参数 dict 以序列化长度封顶。
_MAX_CONTENT = 8000
_MAX_MESSAGES = 64
_MAX_ARGS_CHARS = 16384

__all__ = [
    "ChatMessage",
    "ChatRequest",
    "OutcomeDTO",
    "ChatResponse",
    "ToolCallRequest",
    "ToolCallResponse",
    "HealthResponse",
]


# ---- /v1/chat/completions ----
class ChatMessage(BaseModel):
    role: str = Field(max_length=32)
    content: str = Field(max_length=_MAX_CONTENT)


class ChatRequest(BaseModel):
    model: str = Field(default="fulcrum-demo", max_length=128)
    session_id: str | None = Field(default=None, max_length=256)
    messages: list[ChatMessage] = Field(max_length=_MAX_MESSAGES)


class OutcomeDTO(BaseModel):
    tool_name: str
    decision: Disposition
    executed: bool
    reason: str = ""
    output: str | None = None
    error: str | None = None


class ChatResponse(BaseModel):
    session_id: str
    content: str
    tool_calls: list[str] = Field(default_factory=list)
    outcomes: list[OutcomeDTO] = Field(default_factory=list)


# ---- /tools/call ----
class ToolCallRequest(BaseModel):
    session_id: str = Field(max_length=256)
    tool_name: str = Field(max_length=128)
    arguments: dict = Field(default_factory=dict)
    source_ids: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("arguments")
    @classmethod
    def _cap_arguments(cls, v: dict) -> dict:
        if len(json.dumps(v, ensure_ascii=False, default=str)) > _MAX_ARGS_CHARS:
            raise ValueError(f"arguments 过大(序列化上限 {_MAX_ARGS_CHARS} 字符)")
        return v


class ToolCallResponse(BaseModel):
    decision: Disposition
    executed: bool
    reason: str = ""
    output: str | None = None
    error: str | None = None


# ---- /healthz ----
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
