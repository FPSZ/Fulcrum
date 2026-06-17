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


# ---- /gateway/chat(前置网关:判恶意 → 拦截/审核/放行 → 转发企业智能体)----
class GatewayChatRequest(BaseModel):
    session_id: str = "anon"
    message: str = Field(min_length=1, max_length=8000)


class GatewayFindingDTO(BaseModel):
    kind: str
    score: float
    severity: str | None = None
    source_type: str | None = None
    matched: list[str] = Field(default_factory=list)


class GatewayChatResponse(BaseModel):
    session_id: str
    decision: Disposition  # allow=放行 / approve=审核挂起 / block=拦截
    risk_level: str
    forwarded: bool  # 是否真正转发给了企业智能体
    reason: str
    max_score: float
    findings: list[GatewayFindingDTO] = Field(default_factory=list)
    reply: str = ""  # 仅放行时为企业智能体的真实回复
    tools: list[dict] = Field(default_factory=list)  # 企业智能体本轮执行的工具轨迹
    upstream_error: str | None = None


# ---- /admin/gateway-config(网关上游接入,设置页可配)----
class GatewayConfigWrite(BaseModel):
    """更新上游接入配置。auth_value 为 None=保持不变、""=清空、其它=替换。"""

    enabled: bool = True
    name: str = Field(default="默认上游", max_length=64)
    protocol: str = Field(pattern="^(openai|rest|native)$")
    endpoint: str = Field(min_length=1, max_length=512)
    path: str = Field(default="", max_length=256)
    model: str = Field(default="", max_length=128)
    auth_type: str = Field(default="none", pattern="^(none|bearer|header)$")
    auth_header: str = Field(default="Authorization", max_length=64)
    auth_value: str | None = Field(default=None, max_length=2048)
    timeout_seconds: float = Field(default=60.0, ge=1, le=600)
    verify_tls: bool = True
    rest_message_field: str = Field(default="message", max_length=64)
    rest_response_path: str = Field(default="reply", max_length=128)


class GatewayProbeResponse(BaseModel):
    ok: bool
    latency_ms: int
    detail: str
    status_code: int | None = None


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


# ---- /overview/stats(安全总览:跨会话审计聚合,实时计数)----
class OverviewStatsResponse(BaseModel):
    """从审计链实时聚合的总览指标(无流量时各计数为 0,即诚实反映空闲网关)。

    时序/历史趋势不在此端点:审计事件不带时间戳,逐事件时间线归会话事件页。
    """

    sessions: int = 0  # 有审计链的会话数
    events: int = 0  # 审计事件总数
    verified_sessions: int = 0  # hash-chain 校验通过的会话数
    requests: int = 0  # 受控请求数(request_received)
    blocked: int = 0  # 拦截数(tool_blocked)
    pending: int = 0  # 待审批数(tool_pending_approval)
    decisions: dict[str, int] = Field(default_factory=dict)  # 按处置计数(policy_decided)
    by_type: dict[str, int] = Field(default_factory=dict)  # 按审计事件类型计数


# ---- /events(会话事件流:审计判定点投影成可溯源事件行)----
class SecurityEventDTO(BaseModel):
    """一条安全事件 = 一个判定点(policy_decided 审计事件)+ 其可展示判定依据。

    输入筛查(前置网关)路径无工具调用,故 tool/intent/args 诚实留空;
    字段刻意对齐前端 SecurityEvent,前端做一层薄映射(枚举值 → 中文/图标)即可。
    """

    id: str  # event_id
    time: float  # created_at(epoch 秒),前端格式化为时分秒
    sess: str  # session_id
    src_type: str  # SourceType 值(user/document/...)
    trust: str  # TrustLevel 值(untrusted/semi_trusted/trusted)
    risk: str  # 事件标题(按处置归纳的中文短语)
    tool: str = ""  # 工具/动作(筛查路径为空)
    policy: str = ""  # 命中策略 / 判定阶段
    level: str  # RiskLevel 值
    disp: str  # Disposition 值
    verified: bool  # 所属会话 hash-chain 校验是否通过
    excerpt: str = ""  # 来源片段摘要
    intent: str = ""  # 模型意图(筛查路径为空)
    args: str = ""  # 工具参数(筛查路径为空)
    conf: float = 0.0  # 置信度(max_score)
    derived: str = ""  # 归因依据
    reason: str = ""  # 处置理由


# ---- /audit(会话审计链列表:append-only + hash-chain 的可视化溯源)----
class AuditChainEventDTO(BaseModel):
    """链上一个审计事件(对齐审计页时间轴展示;不回大段 evidence,只取理由)。"""

    index: int
    event_type: str
    subject_id: str | None = None
    decision: str | None = None
    reason: str = ""
    prev_hash: str
    event_hash: str


class AuditSessionDTO(BaseModel):
    """一条会话审计链 + 其 hash-chain 校验结论 + 从链派生的一句话情景。"""

    session_id: str
    verified: bool
    summary: str = ""
    events: list[AuditChainEventDTO] = Field(default_factory=list)


# ---- /policies(策略中心:当前装配的声明式 YAML 策略,只读)----
class PolicyConditionDTO(BaseModel):
    key: str
    value: str  # when 值归一为展示串(list→"a, b"、bool→"true"/"false")


class PolicyRuleDTO(BaseModel):
    id: str
    when: list[PolicyConditionDTO] = Field(default_factory=list)
    decision: str
    risk_level: str = ""
    reason: str = ""


class PolicySetDTO(BaseModel):
    name: str = ""
    version: int = 1
    default: str = "allow"
    workspace: str = ""
    allow_domains: list[str] = Field(default_factory=list)
    rules: list[PolicyRuleDTO] = Field(default_factory=list)


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
