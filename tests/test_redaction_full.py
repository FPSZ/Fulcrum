"""审计脱敏全覆盖:出口检测摘要 + 工具参数摘要也脱敏(补齐 §4.6,不只 screen_input)。"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.app import build_pipeline
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.policy.allow_all import AllowAllPolicy
from fulcrum.core.domain import AuditEventType
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry
from fulcrum.eval.__main__ import _EVAL_CONFIG

_ID = "110101199001011234"


def _gateway_pipeline(audit: InMemoryAuditSink) -> SecurityPipeline:
    load_builtin_capabilities()
    return SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[registry.create("detector", "keyword_rules")],
        attributor=registry.create("attributor", "evidence"),
        risk_scorer=registry.create("risk_scorer", "heuristic"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=AllowAllPolicy(),
        executor=registry.create("executor", "echo"),
        tools={},
        audit=audit,
        model_client=FakeModelClient(),
    )


def test_output_gateway_excerpt_redacted() -> None:
    """企业回复里夹带敏感量,出口审计摘要不存明文(回复正是泄露高发处)。"""
    audit = InMemoryAuditSink()
    pipe = _gateway_pipeline(audit)
    asyncio.run(pipe.screen_output("o", f"您查询的居民身份证号是 {_ID},请妥善保管"))
    decided = [
        e for e in asyncio.run(audit.events("o")) if e.event_type == AuditEventType.POLICY_DECIDED
    ]
    excerpt = decided[-1].evidence["excerpt"]
    assert _ID not in excerpt  # 审计库不存明文身份证
    assert "居民" in excerpt  # 非敏感正文保留


def test_tool_args_excerpt_redacted() -> None:
    """工具参数里夹带敏感量,审计的参数摘要打码。"""
    pipe = build_pipeline(_EVAL_CONFIG)  # 真治理管线(yaml 策略 + echo 工具)
    asyncio.run(
        pipe.handle_tool_call(
            session_id="t",
            tool_name="external.send",
            arguments={"payload": f"张三 {_ID}", "to": "x@gov.cn"},
        )
    )
    decided = [
        e
        for e in asyncio.run(pipe.audit.events("t"))
        if e.event_type == AuditEventType.POLICY_DECIDED and e.evidence.get("tool")
    ]
    args = decided[-1].evidence["args"]
    assert _ID not in args  # 参数摘要里身份证已打码
    assert "张三" in args  # 非敏感部分保留
