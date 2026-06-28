"""只读看板投影 DTO —— 安全总览 / 会话事件 / 审计溯源 / 工具网关 / 供应链 / 策略 / 评测。

均为审计链或扫描结果的**可展示投影**(前端做薄映射:枚举值→中文/图标),不承载业务写入。
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "OverviewStatsResponse",
    "SecurityEventDTO",
    "EventResolveRequest",
    "EventResolveResponse",
    "AuditResponse",
    "AuditChainEventDTO",
    "AuditSessionDTO",
    "ToolCallDTO",
    "SupplyScanRiskDTO",
    "SupplyScanReportDTO",
    "PolicyConditionDTO",
    "PolicyRuleDTO",
    "PolicySetDTO",
    "EvalTotalsDTO",
    "EvalMetricsDTO",
    "EvalSampleDTO",
    "EvalReportDTO",
]


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


# ---- /audit/{session_id} ----
class AuditResponse(BaseModel):
    session_id: str
    verified: bool
    events: list[dict] = Field(default_factory=list)


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
