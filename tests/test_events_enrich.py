"""会话事件流按闸门分类映射:工具治理 / 出口检测 / 输入闸门 判定点各自正确标题与字段。

修正集成后的误标:此前所有 policy_decided 一律按「输入」标题映射,工具/出口判定被错标。
"""

from __future__ import annotations

from fulcrum.adapters.api.events_routes import to_security_event
from fulcrum.core.domain import AuditEvent, AuditEventType, Disposition


def _decided(decision: Disposition, evidence: dict) -> AuditEvent:
    return AuditEvent(
        session_id="s",
        event_type=AuditEventType.POLICY_DECIDED,
        decision=decision,
        evidence=evidence,
    )


def test_tool_decision_mapped_with_tool_fields() -> None:
    e = _decided(
        Disposition.BLOCK,
        {
            "tool": "external.send",
            "args": '{"to":"x@evil.com"}',
            "risk_score": 0.85,
            "source_trust": "untrusted",
            "matched_policy": "block-external-exfil",
            "risk_level": "critical",
            "reason": "疑似外泄",
        },
    )
    row = to_security_event(e, verified=True)
    assert row.risk == "工具调用阻断"  # 不是「高危输入拦截」
    assert row.tool == "external.send"
    assert row.args == '{"to":"x@evil.com"}'
    assert row.trust == "untrusted"
    assert row.conf == 0.85  # 取 risk_score
    assert row.policy == "block-external-exfil"


def test_output_decision_mapped_with_reply_semantics() -> None:
    e = _decided(
        Disposition.BLOCK,
        {"stage": "output_gateway", "excerpt": "***", "risk_level": "high", "reason": "回复含敏感"},
    )
    row = to_security_event(e, verified=True)
    assert row.risk == "回复敏感拦截"  # 出口语义标题
    assert row.src_type == "assistant"
    assert row.policy == "出口检测"
    assert row.tool == ""


def test_input_decision_keeps_input_semantics() -> None:
    e = _decided(
        Disposition.BLOCK,
        {
            "stage": "input_gateway",
            "excerpt": "忽略指令…",
            "max_score": 0.9,
            "risk_level": "critical",
        },
    )
    row = to_security_event(e, verified=True)
    assert row.risk == "高危输入拦截"
    assert row.policy == "前置网关"
    assert row.conf == 0.9  # 取 max_score
