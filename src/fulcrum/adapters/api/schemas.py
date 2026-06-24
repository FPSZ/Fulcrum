"""API 层 DTO(请求/响应 schema)。FastAPI 据此自动产出 OpenAPI。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

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
    reply: str = ""  # 仅放行时为企业智能体的真实回复(出口拦截时为打码占位)
    tools: list[dict] = Field(default_factory=list)  # 企业智能体本轮执行的工具轨迹
    upstream_error: str | None = None
    # 出口闸门:对回复做敏感/危险内容检测后的结论(无回复时为 None)
    output_decision: Disposition | None = None
    output_risk_level: str = ""
    output_reason: str = ""
    output_blocked: bool = False  # 回复是否因出口检测被拦截打码
    output_sanitized: bool = False  # 回复是否经出口脱敏后回传(复核档,仅打码救得了的敏感量)


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


# ---- /admin/settings(控制台实例设置:真实可写项 + 运行态只读信息)----
class BackendModelInfo(BaseModel):
    """只读:后端模型出站配置(经 .env 注入,不在控制台改;此处仅如实回显)。"""

    endpoint: str
    model_name: str
    key_set: bool


class ConsoleSettingsWrite(BaseModel):
    """更新控制台实例元信息(真实落盘字段)。"""

    model_config = ConfigDict(extra="forbid")

    instance_name: str = Field(default="枢衡安全控制台", max_length=64)
    environment: str = Field(default="demo", pattern="^(prod|staging|demo)$")


class ConsoleSettingsPublic(ConsoleSettingsWrite):
    """回前端:真实可写项 + 只读后端模型信息。"""

    backend_model: BackendModelInfo


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
    # 按三类闸门(input/output/tool)再按处置细分:{"output":{"block":3,...},...},供总览分维度展示
    gates: dict[str, dict[str, int]] = Field(default_factory=dict)
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


class EventResolveRequest(BaseModel):
    """处置一条待审批事件:批准放行(allow)或维持阻断(block)。需 events.handle。"""

    decision: Literal["allow", "block"]
    note: str = Field(default="", max_length=400)


class EventResolveResponse(BaseModel):
    ok: bool = True


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


# ---- /eval/report(评测验证:`python -m fulcrum.eval` 的最近报告,只读)----
class EvalTotalsDTO(BaseModel):
    samples: int = 0
    malicious: int = 0
    benign: int = 0
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0


class EvalMetricsDTO(BaseModel):
    asr_baseline: float = 0.0
    asr_fulcrum: float = 0.0
    asr_reduction: float = 0.0
    recall_bsr: float = 0.0
    precision: float = 0.0
    fpr: float = 0.0
    utility: float = 0.0
    decision_accuracy: float = 0.0
    audit_complete_rate: float = 0.0
    hash_chain_pass_rate: float = 0.0
    totals: EvalTotalsDTO = Field(default_factory=EvalTotalsDTO)


class EvalSampleDTO(BaseModel):
    sample_id: str
    attack_type: str
    malicious: bool
    expected: str
    predicted: str
    held: bool
    attack_succeeded: bool
    decision_correct: bool
    audit_ok: bool = True
    reason: str = ""


class EvalReportDTO(BaseModel):
    dataset: str
    metrics: EvalMetricsDTO
    samples: list[EvalSampleDTO] = Field(default_factory=list)


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


# ---- /supply/scans(供应链:组件 manifest 静态扫描评级,只读)----
class SupplyScanRiskDTO(BaseModel):
    kind: str  # 风险项类型,如 perm.command_exec / endpoint.raw_ip
    score: float
    severity: str  # low / medium / high / critical
    detail: str = ""


class SupplyScanReportDTO(BaseModel):
    component_id: str  # name@version
    kind: str = "component"  # 组件类型(plugin/skill/mcp,据 manifest 或文件名推断)
    rating: str  # 评级 = 最严重项:critical→block / high→approve / medium→sanitize / 否则 allow
    risks: list[SupplyScanRiskDTO] = Field(default_factory=list)


class SupplyScanRequest(BaseModel):
    """控制台「登记组件」提交体:一份 manifest 原文(YAML 或 JSON,后端 yaml.safe_load 解析)。"""

    manifest: str = Field(min_length=1, max_length=64_000)


# ---- /tools/calls(工具网关:工具调用治理流水)----
class ToolCallDTO(BaseModel):
    """一次过治理的工具调用(归因→评分→链→策略→处置)+ 其可展示证据。

    数据来自工具调用穿过枢衡的判定点(policy_decided,带 `tool` 证据);前置网关「只筛输入」
    的路径无工具调用,故本流水仅在模型编排 / 直接工具调用(`/v1/chat/completions`、`/tools/call`)
    有流量时非空。
    """

    id: str  # event_id
    time: float  # created_at(epoch 秒),前端格式化为时分秒
    sess: str  # session_id
    tool: str  # 工具名
    args: str = ""  # 参数摘要(截断)
    source_trust: str | None = None  # 来源最坏信任级(untrusted/semi_trusted/trusted)
    risk_score: float = 0.0  # 工具风险评分
    risk_level: str = "low"  # RiskLevel 值
    attribution_confidence: float = 0.0  # 归因置信度
    decision: str  # Disposition 值(allow/sanitize/approve/block)
    rule: str | None = None  # 命中的策略规则 id
    executed: bool = False  # 是否真正执行(有 tool_executed 关联)
    reason: str = ""  # 处置理由


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
    capability: str  # 能力域 id(成对看/改共享,前端合成只读/读写三态)
    cap_label: str  # 能力域中文名(展示一行)
    access: str  # read | write | action


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


# ---- AI 操作助手(后端大脑)----
class AssistantActionDTO(BaseModel):
    """动作目录条目(供助手面板展示「当前角色能调哪些动作」)。"""

    id: str
    label: str
    description: str
    risk: str
    requires: list[str] = Field(default_factory=list)
    args_hint: str = ""


class AssistantPlanRequest(BaseModel):
    intent: str = Field(min_length=1, max_length=2000)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantPlanResponse(BaseModel):
    """规划结果:选了哪个动作、是否准许、是否需二次确认、为什么。"""

    ok: bool
    reason: str
    action_id: str | None = None
    label: str = ""
    args: dict = Field(default_factory=dict)
    risk: str = ""
    requires_confirmation: bool = False
    denied: bool = False


# ---- AI 操作助手(真 Agent · plan/11)----
class AssistantChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantResetRequest(BaseModel):
    """清空某会话的多轮记忆(新建会话 / 显式清除上下文)。"""

    session_id: str = Field(min_length=1, max_length=128)


class AssistantResetResponse(BaseModel):
    ok: bool = True


class AssistantToolDTO(BaseModel):
    """当前角色可调的一个工具(供助手面板侧栏 + /assistant/tools 列出)。"""

    name: str
    kind: str
    label: str
    description: str
    risk: str
    requires: list[str] = Field(default_factory=list)
    reversible: bool = False


class AssistantUiDirectiveDTO(BaseModel):
    """前端待执行的 ui 指令(导航/筛选/开面板)。"""

    tool: str
    label: str
    args: dict = Field(default_factory=dict)


class AssistantProposedActionDTO(BaseModel):
    """写操作的待确认提案(可编辑卡片;确认走 /assistant/confirm,默认不执行)。"""

    tool: str
    label: str
    risk: str
    args: dict = Field(default_factory=dict)
    requires: list[str] = Field(default_factory=list)
    note: str = ""
    action_token: str = ""  # 防篡改令牌,确认时回传
    reversible: bool = False  # 执行后能否一键撤销
    before: dict = Field(default_factory=dict)  # 改动字段的当前值(before→after 差异)


class AssistantApprovalRequestDTO(BaseModel):
    """需管理员审批的「待发起申请」(闸判 APPROVE 时产出;不自动落工单)。

    助手当面提示操作员「需审批,是否发起?」,由人点「发起申请」(/assistant/request-approval)
    才真正进实时事件·待审批。stage:input=可疑输入待审 / output=回复待人工复核。
    """

    stage: str
    title: str
    reason: str
    risk_level: str
    excerpt: str = ""
    score: float = 0.0


class AssistantStepDTO(BaseModel):
    """一步执行轨迹(透明展示助手调了什么)。"""

    tool: str
    kind: str
    label: str
    ok: bool
    detail: str = ""


class AssistantChatResponse(BaseModel):
    session_id: str
    reply: str
    blocked: bool = False
    compressed: bool = False  # 本轮是否触发上下文自动压缩
    ui_directives: list[AssistantUiDirectiveDTO] = Field(default_factory=list)
    proposed_actions: list[AssistantProposedActionDTO] = Field(default_factory=list)
    approval_requests: list[AssistantApprovalRequestDTO] = Field(default_factory=list)
    steps: list[AssistantStepDTO] = Field(default_factory=list)


class AssistantRequestApprovalRequest(BaseModel):
    """操作员在对话里「发起审批申请」:把某条 APPROVE 判定落成真·待审批工单。"""

    session_id: str | None = Field(default=None, max_length=128)
    stage: str = Field(default="output", max_length=16)  # input | output
    reason: str = Field(default="", max_length=400)
    risk_level: str = Field(default="medium", max_length=16)
    excerpt: str = Field(default="", max_length=400)
    score: float = 0.0


class AssistantRequestApprovalResponse(BaseModel):
    ok: bool = True


class AssistantConfirmRequest(BaseModel):
    action_token: str = Field(min_length=1, max_length=4096)
    edited_args: dict = Field(default_factory=dict)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantConfirmResponse(BaseModel):
    ok: bool
    summary: str
    action_id: str | None = None
    reversible: bool = False
    undo_preview: str = ""
    error: str | None = None


class AssistantUndoRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)


class AssistantUndoResponse(BaseModel):
    ok: bool
    summary: str
    error: str | None = None


class AssistantModelConfigDTO(BaseModel):
    """回前端的模型接入配置(密钥掩码,只暴露是否已设置 / 是否配置完成)。"""

    protocol: str
    endpoint: str
    model: str
    api_key_masked: str
    api_key_set: bool
    timeout_seconds: float
    verify_tls: bool
    configured: bool
    ready: bool


class AssistantModelConfigUpdate(BaseModel):
    """保存模型接入配置。api_key 语义:None=保持原值;""=清空;非空=设新值(防掩码覆盖真值)。"""

    protocol: Literal["openai", "ollama", "anthropic"]
    endpoint: str = Field(max_length=512)
    model: str = Field(max_length=128)
    api_key: str | None = Field(default=None, max_length=2048)
    timeout_seconds: float = Field(default=90.0, ge=1, le=600)
    verify_tls: bool = True


class AssistantModelTestRequest(BaseModel):
    """测试连接:用「待保存的表单值」试调一次(api_key=None 时用已存密钥)。"""

    protocol: Literal["openai", "ollama", "anthropic"]
    endpoint: str = Field(max_length=512)
    model: str = Field(max_length=128)
    api_key: str | None = Field(default=None, max_length=2048)
    timeout_seconds: float = Field(default=30.0, ge=1, le=600)
    verify_tls: bool = True


class AssistantModelTestResponse(BaseModel):
    ok: bool
    detail: str
    latency_ms: int | None = None


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
