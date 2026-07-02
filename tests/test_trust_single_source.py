"""来源信任级归约单一真源(回归 M1)。

core.pipeline._intent_source_trust 与 yaml_policy._worst_trust 曾各写一份,现同源于
core.trust.intent_worst_trust。本测试锁定语义,并断言两个调用点确实指向同一实现。
"""

from __future__ import annotations

from fulcrum.capabilities.policy.yaml_policy import YamlPolicyEngine
from fulcrum.core.domain import Context, SourceSpan, SourceType, ToolIntent, TrustLevel
from fulcrum.core.pipeline import _intent_source_trust
from fulcrum.core.trust import intent_worst_trust


def _span(sid: str, trust: TrustLevel) -> SourceSpan:
    return SourceSpan(
        source_id=sid, source_type=SourceType.DOCUMENT, trust_level=trust, content_hash="x",
        excerpt="x",
    )


def _ctx(*spans: SourceSpan) -> Context:
    c = Context(session_id="t")
    c.spans = list(spans)
    return c


def _intent(*source_ids: str) -> ToolIntent:
    return ToolIntent(
        session_id="t", tool_name="x", arguments={}, derived_from_sources=list(source_ids)
    )


def test_worst_first_takes_least_trusted() -> None:
    ctx = _ctx(_span("a", TrustLevel.TRUSTED), _span("b", TrustLevel.UNTRUSTED))
    assert intent_worst_trust(_intent("a", "b"), ctx) == TrustLevel.UNTRUSTED.value


def test_semi_trusted_when_no_untrusted() -> None:
    ctx = _ctx(_span("a", TrustLevel.TRUSTED), _span("b", TrustLevel.SEMI_TRUSTED))
    assert intent_worst_trust(_intent("a", "b"), ctx) == TrustLevel.SEMI_TRUSTED.value


def test_declared_source_without_span_fails_closed_untrusted() -> None:
    # 有声明来源却无 span 可核验(工具网关路径)→ fail-closed 视为不可信。
    assert intent_worst_trust(_intent("ghost"), _ctx()) == TrustLevel.UNTRUSTED.value


def test_no_declared_source_returns_none() -> None:
    assert intent_worst_trust(_intent(), _ctx()) is None


def test_both_callsites_share_the_single_source() -> None:
    # pipeline 与 policy 两个调用点都指向 core.trust 的同一实现(消除漂移的结构性保证)。
    assert _intent_source_trust is intent_worst_trust
    assert YamlPolicyEngine._worst_trust is intent_worst_trust
