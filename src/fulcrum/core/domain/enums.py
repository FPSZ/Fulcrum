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
    ASSISTANT_PLANNED = "assistant_planned"  # AI 操作助手(旧·单轮规划器):意图 → 受治理动作规划
    ASSISTANT_CHAT = "assistant_chat"  # AI 操作助手(真 Agent):一次会话(意图/入口判定/产出)
    ASSISTANT_ACTED = "assistant_acted"  # 助手写提案被确认执行(tool/参数摘要/结果/undo 句柄)
    ASSISTANT_UNDONE = "assistant_undone"  # 已执行写操作被一键撤销(tool/回滚前后)
    SECURITY_CONFIG_UPDATED = "security_config_updated"  # 分级安全配置已变更并生效
