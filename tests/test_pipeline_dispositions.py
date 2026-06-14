"""管线分级处置:未知工具 fail-closed、SANITIZE 记桩不执行。"""

from __future__ import annotations

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.core.domain import AuditEventType, Context, Disposition, PolicyDecision, ToolIntent
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry


class _FixedPolicy:
    """测试用策略:总是返回指定处置。"""

    def __init__(self, disposition: Disposition) -> None:
        self._d = disposition

    def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision:
        return PolicyDecision(decision=self._d, reason="test")


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
    outcome = pipe.handle_tool_call(session_id="s", tool_name="ghost", arguments={})
    assert outcome.executed is False
    assert outcome.result is not None and outcome.result.ok is False
    assert "unknown tool" in (outcome.result.error or "")
    types = [e.event_type for e in pipe.audit.events("s")]
    assert AuditEventType.TOOL_BLOCKED in types


def test_sanitize_records_stub_and_not_executed() -> None:
    pipe = _pipeline(
        _FixedPolicy(Disposition.SANITIZE),
        tools={"echo": registry.create("tool", "echo")},
    )
    outcome = pipe.handle_tool_call(session_id="s2", tool_name="echo", arguments={"text": "x"})
    assert outcome.executed is False
    types = [e.event_type for e in pipe.audit.events("s2")]
    assert AuditEventType.TOOL_PENDING_APPROVAL in types
