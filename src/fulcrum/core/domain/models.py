"""领域类型(pydantic v2)—— 枢衡的"通用语言",可校验、可序列化、可直接当 API schema。"""

from __future__ import annotations

import time
import uuid

from pydantic import BaseModel, Field

from .enums import (
    AuditEventType,
    Disposition,
    RiskLevel,
    SourceType,
    TrustLevel,
)


def _uuid() -> str:
    return uuid.uuid4().hex


class Message(BaseModel):
    role: str
    content: str
    name: str | None = None


class SourceSpan(BaseModel):
    """一段输入及其来源与信任级别(来源归因总线的基本单元)。"""

    source_id: str = Field(default_factory=_uuid)
    source_type: SourceType
    trust_level: TrustLevel
    content_hash: str
    excerpt: str
    risk_tags: list[str] = Field(default_factory=list)


class ModelRequest(BaseModel):
    request_id: str = Field(default_factory=_uuid)
    session_id: str
    messages: list[Message] = Field(default_factory=list)
    sources: list[SourceSpan] = Field(default_factory=list)


class ToolCall(BaseModel):
    """模型产出的工具调用(原始)。"""

    id: str = Field(default_factory=_uuid)
    tool_name: str
    arguments: dict = Field(default_factory=dict)


class ModelResponse(BaseModel):
    response_id: str = Field(default_factory=_uuid)
    request_id: str
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


class Attribution(BaseModel):
    """证据化来源归因(带置信度,非形式化 taint)。"""

    derived_from_sources: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    rationale: str = ""


class ToolIntent(BaseModel):
    intent_id: str = Field(default_factory=_uuid)
    session_id: str
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    derived_from_sources: list[str] = Field(default_factory=list)
    attribution_confidence: float = 0.0
    attribution_rationale: str = ""  # 归因依据(可解释),由管线从 Attribution 盖戳供溯源/展示
    # 工具固有基础风险(0~1):评分前由管线从 Tool.base_risk 盖戳;None=工具未知/未声明,评分器用兜底。
    base_risk: float | None = None
    risk_score: float = 0.0


class Finding(BaseModel):
    """检测/分析结果(归一)。"""

    kind: str
    score: float = 0.0
    evidence: dict = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    decision: Disposition
    reason: str = ""
    matched_policy_id: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW


class ExecResult(BaseModel):
    ok: bool
    output: str | None = None
    side_effects: dict = Field(default_factory=dict)
    error: str | None = None


class ScanReport(BaseModel):
    component_id: str
    rating: Disposition = Disposition.ALLOW
    risks: list[Finding] = Field(default_factory=list)


class AuditEvent(BaseModel):
    """审计事件;hash-chain 字段由 AuditSink 落库时填充。

    `schema_version` 标记"受哈希保护的字段集"的版本:AuditSink 的 canonical 表示
    只覆盖一份**白名单字段**(见 adapters/audit),与本模型的后续演进解耦——日后给
    AuditEvent 加字段不会改变历史事件的哈希,因而不破坏既有链的可验证性。要把新字段
    纳入哈希保护,必须 bump 此版本号并在 sink 端分支新的字段集 + 迁移既有链。
    """

    schema_version: int = 1
    event_id: str = Field(default_factory=_uuid)
    session_id: str
    event_type: AuditEventType
    subject_id: str | None = None
    decision: Disposition | None = None
    evidence: dict = Field(default_factory=dict)
    index: int = 0
    prev_hash: str = ""
    event_hash: str = ""
    # 落库时刻(epoch 秒)。**刻意不入哈希白名单**(见 adapters/audit._HASHED_FIELDS):
    # 时间戳是观测元数据,纳入 canonical 会让"重放验证"依赖时钟而非证据本身。
    # 供查询端做时序/逐事件展示用,不影响 hash-chain 可验证性。
    created_at: float = Field(default_factory=time.time)
