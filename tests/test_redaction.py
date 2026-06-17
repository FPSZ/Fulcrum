"""审计脱敏:敏感信息打码,避免审计日志自身泄露(01 §4.6/§4.8)。"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.policy.allow_all import AllowAllPolicy
from fulcrum.core.domain import AuditEventType
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.redaction import redact
from fulcrum.core.registry import registry


def test_redacts_id_card() -> None:
    out = redact("身份证 110101199001011234 请核对")
    assert "199001011234" not in out  # 中间被打码
    assert "110101" in out and "1234" in out  # 保留首尾便于核对
    assert "*" in out


def test_redacts_phone_and_email() -> None:
    out = redact("联系电话 13812345678,邮箱 zhangsan@gov.cn")
    assert "1234567" not in out  # 手机中段打码
    assert "138" in out and "5678" in out
    assert "zhangsan@gov.cn" not in out and "@gov.cn" in out


def test_redacts_explicit_secret_and_long_token() -> None:
    assert "hunter2secret" not in redact("密码: hunter2secret")
    assert "AKIA1234567890ABCDEFGHIJ" not in redact("key=AKIA1234567890ABCDEFGHIJ")


def test_keeps_normal_text() -> None:
    text = "你好,请帮我查询低保办件进度,谢谢。"
    assert redact(text) == text  # 无敏感量 → 原样


def test_screen_input_audit_excerpt_is_redacted() -> None:
    load_builtin_capabilities()
    pipe = SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[registry.create("detector", "keyword_rules")],
        attributor=registry.create("attributor", "evidence"),
        risk_scorer=registry.create("risk_scorer", "heuristic"),
        chain_analyzer=registry.create("chain_analyzer", "noop"),
        policy=AllowAllPolicy(),
        executor=registry.create("executor", "echo"),
        tools={},
        audit=InMemoryAuditSink(),
        model_client=FakeModelClient(),
    )
    asyncio.run(pipe.screen_input("s", "我的身份证是 110101199001011234,帮我查低保"))
    events = asyncio.run(pipe.audit.events("s"))
    decided = [e for e in events if e.event_type == AuditEventType.POLICY_DECIDED]
    excerpt = decided[-1].evidence["excerpt"]
    assert "199001011234" not in excerpt  # 审计库里不存明文身份证
    assert "低保" in excerpt  # 非敏感正文保留
