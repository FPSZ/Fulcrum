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


class RegisterRequest(BaseModel):
    """申请账号:申请人自填账号口令与姓名,落为待审批。"""

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)
    display_name: str = Field(min_length=1, max_length=128)


class PrincipalResponse(BaseModel):
    """当前登录主体(绝不含口令哈希或会话令牌)。"""

    username: str
    display_name: str
    role_key: str | None = None
    role_name: str | None = None
    permissions: list[str] = Field(default_factory=list)


# ---- 权限 / 角色 / 组织 / 成员(管理后台)----
class PermissionDTO(BaseModel):
    key: str
    label: str
    group: str


class DepartmentDTO(BaseModel):
    id: int
    name: str
    parent_id: int | None = None
    sort_order: int = 100
    member_count: int = 0


class DepartmentWrite(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    parent_id: int | None = None
    sort_order: int | None = None


class RoleDTO(BaseModel):
    id: int
    key: str
    name: str
    description: str = ""
    is_system: bool = False
    permissions: list[str] = Field(default_factory=list)
    member_count: int = 0


class RoleWrite(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    permissions: list[str] = Field(default_factory=list)


class UserDTO(BaseModel):
    """成员详情(管理后台用)。绝不含口令哈希。"""

    id: int
    username: str
    display_name: str
    status: str
    employee_no: str = ""
    email: str = ""
    phone: str = ""
    title: str = ""
    department_id: int | None = None
    role_id: int | None = None
    created_at: int = 0
    last_login_at: int | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=128)
    password: str | None = Field(default=None, max_length=256)
    role_id: int | None = None
    department_id: int | None = None
    employee_no: str = ""
    email: str = ""
    phone: str = ""
    title: str = ""


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    role_id: int | None = None
    department_id: int | None = None
    employee_no: str | None = None
    email: str | None = None
    phone: str | None = None
    title: str | None = None


class StatusUpdate(BaseModel):
    status: str = Field(pattern="^(active|disabled|left)$")


class PasswordReset(BaseModel):
    password: str | None = Field(default=None, max_length=256)


class ApproveRequest(BaseModel):
    role_id: int | None = None
    department_id: int | None = None


class TempPasswordResponse(BaseModel):
    """新建成员 / 重置口令:仅这一次返回临时口令(若由系统生成)。"""

    user: UserDTO
    temp_password: str | None = None
