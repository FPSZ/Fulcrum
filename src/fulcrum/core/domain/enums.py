"""领域枚举 —— 全项目唯一真源。任何模块不得各自定义同义枚举。"""

from __future__ import annotations

from enum import StrEnum


class SourceType(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    DOCUMENT = "document"
    WEBPAGE = "webpage"
    RETRIEVAL = "retrieval"
    MEMORY = "memory"
    TOOL_RETURN = "tool_return"
    PLUGIN_MANIFEST = "plugin_manifest"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"


class Disposition(StrEnum):
    """分级处置(也复用于供应链评级:allow/review<=sanitize/approve/block)。"""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    APPROVE = "approve"
    BLOCK = "block"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEventType(StrEnum):
    REQUEST_RECEIVED = "request_received"
    SOURCE_LABELED = "source_labeled"
    INPUT_DETECTED = "input_detected"
    MODEL_FORWARDED = "model_forwarded"
    TOOL_INTENT_DETECTED = "tool_intent_detected"
    POLICY_DECIDED = "policy_decided"
    TOOL_EXECUTED = "tool_executed"
    TOOL_BLOCKED = "tool_blocked"
    TOOL_PENDING_APPROVAL = "tool_pending_approval"
    SUPPLYCHAIN_SCANNED = "supplychain_scanned"
    AUDIT_WRITTEN = "audit_written"
    EVAL_JUDGED = "eval_judged"
    ASSISTANT_PLANNED = "assistant_planned"  # AI 操作助手:自然语言意图 → 受治理的动作规划
