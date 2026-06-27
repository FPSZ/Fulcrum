"""请求路径 DTO —— /v1/chat/completions、/tools/call、/healthz。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ....core.domain import Disposition

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
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "fulcrum-demo"
    session_id: str | None = None
    messages: list[ChatMessage]


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
    session_id: str
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    source_ids: list[str] = Field(default_factory=list)


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
