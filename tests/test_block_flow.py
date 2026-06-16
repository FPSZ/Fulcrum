"""集成:真实能力装配下,管线对高危调用 block 并留下可溯源审计。

验证 P0-a 验收点:不可信文档驱动的敏感文件读取 → 阻断 → 审计链可查、hash-chain 完整。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.policy.yaml_policy import YamlPolicyEngine
from fulcrum.core.domain import AuditEventType, Disposition
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry


def _real_pipeline(audit: InMemoryAuditSink) -> SecurityPipeline:
    load_builtin_capabilities()
    return SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[registry.create("detector", "keyword_rules")],
        attributor=registry.create("attributor", "evidence"),
        risk_scorer=registry.create("risk_scorer", "heuristic"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=YamlPolicyEngine(Path("data/policies/default.yml")),
        executor=registry.create("executor", "echo"),
        tools={},  # block 在执行前发生,无需真实工具
        audit=audit,
        model_client=FakeModelClient(),
    )


def test_sensitive_read_blocked_and_audited() -> None:
    audit = InMemoryAuditSink()
    pipe = _real_pipeline(audit)
    outcome = asyncio.run(
        pipe.handle_tool_call(
            session_id="s1", tool_name="file.read", arguments={"path": "/etc/passwd"}
        )
    )
    assert outcome.decision.decision == Disposition.BLOCK
    assert outcome.executed is False
    assert outcome.decision.matched_policy_id == "block-sensitive-path"

    events = audit.events("s1")
    types = [e.event_type for e in events]
    assert AuditEventType.POLICY_DECIDED in types
    assert AuditEventType.TOOL_BLOCKED in types
    assert audit.verify_chain("s1") is True


def test_benign_workspace_read_allowed() -> None:
    audit = InMemoryAuditSink()
    pipe = _real_pipeline(audit)
    outcome = asyncio.run(
        pipe.handle_tool_call(
            session_id="s2", tool_name="file.read", arguments={"path": "data/workspace/notice.txt"}
        )
    )
    # 工作区内普通读取 → 放行(但本测试未注册工具,放行后 fail-closed 记 unknown_tool)。
    assert outcome.decision.decision == Disposition.ALLOW
    assert audit.verify_chain("s2") is True
