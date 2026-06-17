"""结构化敏感量泄露检测:按命中条数升级,出口闸门借此拦"名册原样吐出"类泄露。

补 sensitive_file 的盲区——后者只识"提到了凭据"的措辞,识别不了回复里**真的夹带**了
多条身份证/手机号/邮箱的批量外泄。单条多属正常(用户报自己手机号),批量才判高危。
"""

from __future__ import annotations

import asyncio

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.detectors.keyword_rules import KeywordRuleDetector
from fulcrum.capabilities.policy.allow_all import AllowAllPolicy
from fulcrum.core.domain import (
    AuditEventType,
    Context,
    Disposition,
    SourceSpan,
    SourceType,
    TrustLevel,
)
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry

_CTX = Context(session_id="s")


def _span(text: str) -> SourceSpan:
    return SourceSpan(
        source_type=SourceType.ASSISTANT,
        trust_level=TrustLevel.UNTRUSTED,
        content_hash="x",
        excerpt=text,
    )


def _pii(spans: list[SourceSpan]) -> list:
    return [f for f in KeywordRuleDetector().detect(spans, _CTX) if f.kind == "pii_leak"]


def test_single_pii_low_not_blocking() -> None:
    """单条手机号:0.4 低分,出口不拦(用户报自己电话属正常)。"""
    f = _pii([_span("我的联系电话是 13800138000,有事请联系。")])
    assert len(f) == 1
    assert f[0].score < 0.6  # 低于复核阈,不升级
    assert f[0].evidence["pii_hits"] == 1


def test_bulk_pii_critical() -> None:
    """三条不同结构化敏感量(身份证+手机+邮箱)→ 批量名册外泄 → critical。"""
    text = "张三 110101199003078888 13900001111 zhangsan@gov.example.cn"
    f = _pii([_span(text)])
    assert len(f) == 1
    assert f[0].evidence["pii_hits"] >= 3
    assert f[0].score >= 0.8
    assert f[0].evidence["severity"] == "critical"


def test_secret_kv_counted() -> None:
    f = _pii([_span("password=Hunter2longsecret api_key=AKIA1234567890ABCD")])
    assert f and f[0].evidence["pii_hits"] >= 2


def test_clean_reply_no_pii_finding() -> None:
    assert _pii([_span("您的低保办件已受理,预计 3 个工作日内完成。")]) == []


def _pipeline(audit: InMemoryAuditSink) -> SecurityPipeline:
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


def test_output_gateway_blocks_bulk_pii_leak() -> None:
    """出口端到端:回复把市民名册(多条身份证/手机)原样吐出 → 拦截 + 落审计。"""
    audit = InMemoryAuditSink()
    pipe = _pipeline(audit)
    roster = (
        "查询结果:李四 110101198805062345 13700002222;"
        "王五 310104199201018765 13600003333;"
        "赵六 440305199511234567 13500004444"
    )
    verdict = asyncio.run(pipe.screen_output("p1", roster))
    assert verdict.decision == Disposition.BLOCK
    events = asyncio.run(audit.events("p1"))
    decided = [e for e in events if e.event_type == AuditEventType.POLICY_DECIDED]
    assert decided[-1].decision == Disposition.BLOCK
    assert decided[-1].evidence.get("stage") == "output_gateway"
