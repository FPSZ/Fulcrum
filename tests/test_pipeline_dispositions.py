"""管线分级处置:未知工具 fail-closed、SANITIZE 净化参数后执行。"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.core.domain import (
    AuditEventType,
    Context,
    Disposition,
    ExecResult,
    PolicyDecision,
    ToolIntent,
)
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry


class _FixedPolicy:
    """测试用策略:总是返回指定处置。"""

    def __init__(self, disposition: Disposition) -> None:
        self._d = disposition

    async def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision:
        return PolicyDecision(decision=self._d, reason="test")


class _RaisingPolicy:
    """测试用策略:判定时抛异常,用于验证编排层 fail-closed。"""

    async def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision:
        raise RuntimeError("boom")


def _pipeline(policy: _FixedPolicy, tools: dict) -> SecurityPipeline:
    load_builtin_capabilities()
    return SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[registry.create("detector", "noop")],
        attributor=registry.create("attributor", "zero"),
        risk_scorer=registry.create("risk_scorer", "zero"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=policy,
        executor=registry.create("executor", "echo"),
        tools=tools,
        audit=InMemoryAuditSink(),
        model_client=FakeModelClient(),
    )


def test_allow_unknown_tool_is_blocked_fail_closed() -> None:
    pipe = _pipeline(_FixedPolicy(Disposition.ALLOW), tools={})  # 放行但无工具
    outcome = asyncio.run(pipe.handle_tool_call(session_id="s", tool_name="ghost", arguments={}))
    assert outcome.executed is False
    assert isinstance(outcome.result, ExecResult)
    assert outcome.result.ok is False
    assert "unknown tool" in (outcome.result.error or "")
    types = [e.event_type for e in asyncio.run(pipe.audit.events("s"))]
    assert AuditEventType.TOOL_BLOCKED in types


def test_sanitize_masks_args_then_executes() -> None:
    """SANITIZE:参数里的敏感载荷打码后再执行(落实 default.yml「先净化降级」)。"""
    pipe = _pipeline(
        _FixedPolicy(Disposition.SANITIZE),
        tools={"echo": registry.create("tool", "echo")},
    )
    outcome = asyncio.run(
        pipe.handle_tool_call(
            session_id="s2",
            tool_name="echo",
            arguments={"text": "联系 13800138000"},
        )
    )
    # 已执行,但 echo 回显的是脱敏后的参数 —— 手机号已打码,明文不出工具
    assert outcome.executed is True
    assert outcome.result is not None
    assert "13800138000" not in (outcome.result.output or "")
    assert "138****8000" in (outcome.result.output or "")
    # 审计:走 TOOL_EXECUTED,且标注净化了哪些字段
    events = asyncio.run(pipe.audit.events("s2"))
    executed = [e for e in events if e.event_type == AuditEventType.TOOL_EXECUTED]
    assert executed and executed[-1].evidence.get("sanitized") is True
    assert "text" in executed[-1].evidence.get("fields", [])
    assert asyncio.run(pipe.audit.verify_chain("s2")) is True


def test_sanitize_clean_args_executes_without_change() -> None:
    """SANITIZE 但参数无敏感量:照常执行,changed 字段为空(净化是无副作用直通)。"""
    pipe = _pipeline(
        _FixedPolicy(Disposition.SANITIZE),
        tools={"echo": registry.create("tool", "echo")},
    )
    outcome = asyncio.run(
        pipe.handle_tool_call(session_id="s2b", tool_name="echo", arguments={"text": "查询进度"})
    )
    assert outcome.executed is True
    assert (outcome.result.output if outcome.result else "") == "查询进度"
    events = asyncio.run(pipe.audit.events("s2b"))
    executed = [e for e in events if e.event_type == AuditEventType.TOOL_EXECUTED]
    assert executed and executed[-1].evidence.get("fields") == []


def test_stage_exception_fails_closed_and_audited() -> None:
    """安全关键阶段抛异常 → 编排层 fail-closed:合成 BLOCK + 留痕,绝不 fail-open。"""
    pipe = _pipeline(_RaisingPolicy(), tools={"echo": registry.create("tool", "echo")})
    outcome = asyncio.run(
        pipe.handle_tool_call(session_id="s3", tool_name="echo", arguments={"text": "x"})
    )
    assert outcome.decision.decision == Disposition.BLOCK
    assert outcome.decision.matched_policy_id == "fail-closed"
    assert outcome.executed is False
    types = [e.event_type for e in asyncio.run(pipe.audit.events("s3"))]
    assert AuditEventType.TOOL_BLOCKED in types
    assert asyncio.run(pipe.audit.verify_chain("s3")) is True
