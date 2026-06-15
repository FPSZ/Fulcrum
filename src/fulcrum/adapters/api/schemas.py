"""API 层 DTO(请求/响应 schema)。FastAPI 据此自动产出 OpenAPI。"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ...core.domain import Disposition


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


# ---- /audit/{session_id} ----
class AuditResponse(BaseModel):
    session_id: str
    verified: bool
    events: list[dict] = Field(default_factory=list)


# ---- /healthz ----
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str


# ---- /auth ----
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class PrincipalResponse(BaseModel):
    """当前登录主体(绝不含口令哈希或会话令牌)。"""

    username: str
    display_name: str
