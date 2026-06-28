"""灰区级联检测器:仅"规则拿不准"的灰区 span 落 judge,快路径不调(降延迟)、judge 故障降级。

注入 fast(受控分数)与 judge(受控裁决/抛错)后端,无需真实 LLM 即可确定性验证门控与 fail-safe。
"""

from __future__ import annotations

from fulcrum.capabilities.detectors.injection_cascade import InjectionCascadeDetector
from fulcrum.capabilities.detectors.llm_judge import LlmJudgeDetector
from fulcrum.core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel

_CTX = Context(session_id="s")


def _span(text: str = "x") -> SourceSpan:
    return SourceSpan(
        source_type=SourceType.USER,
        trust_level=TrustLevel.UNTRUSTED,
        content_hash="x",
        excerpt=text,
    )


class _FakeFast:
    """桩:keyword_rules 替身,每个 span 产一条给定分数的 finding(分数为 0 则不产)。"""

    name = "fake_fast"

    def __init__(self, score: float) -> None:
        self._score = score

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        if self._score <= 0:
            return []
        return [Finding(kind="kw", score=self._score, evidence={}) for _ in spans]


def _cascade(fast_score: float, verdict: bool, **kw) -> InjectionCascadeDetector:
    judge = LlmJudgeDetector(backend=lambda _t: verdict)
    return InjectionCascadeDetector(fast=_FakeFast(fast_score), judge_detector=judge, **kw)


def test_below_gray_low_skips_judge() -> None:
    # 设了下界 gray_low=0.2 时,弱信号 0.1 < 下界 → 快路径放行,不调 judge。
    det = _cascade(0.1, verdict=True, gray_low=0.2)
    findings = det.detect([_span()], _CTX)
    assert [f.kind for f in findings] == ["kw"]  # 只有规则 finding
    assert det.judged_count == 0
    assert det.span_count == 1


def test_default_gray_low_zero_judges_unflagged() -> None:
    # 默认 gray_low=0.0:规则零信号(0)的 span 也落 judge(=判所有未被规则拦下的)。
    # 对应实测:keyword 分二极,漏网攻击全在 0 档,必须判 0 档才补得回召回。
    det = _cascade(0.0, verdict=True)  # fast 产 0 分 → 空 findings,max_kw=0
    kinds = {f.kind for f in det.detect([_span()], _CTX)}
    assert "llm_injection" in kinds
    assert det.judged_count == 1


def test_at_or_above_gray_high_skips_judge() -> None:
    # 规则已足以拦/复核(0.8 ≥ gray_high 0.6)→ 结果已定,不调 judge(无召回损失)。
    det = _cascade(0.8, verdict=True)
    findings = det.detect([_span()], _CTX)
    assert [f.kind for f in findings] == ["kw"]
    assert det.judged_count == 0


def test_gray_zone_invokes_judge_and_merges() -> None:
    # 灰区(0.4 ∈ [0.2, 0.6))→ 落 judge;judge 裁 ATTACK → 规则 + judge 两条 finding。
    det = _cascade(0.4, verdict=True)
    kinds = {f.kind for f in det.detect([_span()], _CTX)}
    assert kinds == {"kw", "llm_injection"}
    assert det.judged_count == 1


def test_gray_zone_judge_safe_keeps_only_rule() -> None:
    # 灰区但 judge 裁 SAFE → 只留规则 finding(judge 仍被调用一次)。
    det = _cascade(0.4, verdict=False)
    assert [f.kind for f in det.detect([_span()], _CTX)] == ["kw"]
    assert det.judged_count == 1


def test_judge_failure_degrades_to_rule_only() -> None:
    # 灰区落 judge 但后端抛错 → 降级:规则 finding 照常返回,不崩、不 fail-open。
    def boom(_t: str) -> bool:
        raise RuntimeError("endpoint down")

    det = InjectionCascadeDetector(
        fast=_FakeFast(0.4), judge_detector=LlmJudgeDetector(backend=boom)
    )
    assert [f.kind for f in det.detect([_span()], _CTX)] == ["kw"]


def test_custom_gray_band() -> None:
    # 阈值可调:gray_low=0.05/gray_high=0.9 时,0.1 进入灰区 → 调 judge。
    det = _cascade(0.1, verdict=True, gray_low=0.05, gray_high=0.9)
    det.detect([_span()], _CTX)
    assert det.judged_count == 1


def test_per_span_gating_counts() -> None:
    # 混合批:仅灰区 span 落 judge,span_count 计全部、judged_count 只计灰区。
    judge = LlmJudgeDetector(backend=lambda _t: True)

    class _VarFast:
        name = "var"

        def __init__(self) -> None:
            # 级联逐 span 调 fast,每次单 span;依次给 0.1(快放)/0.4(灰区)/0.8(快拦)。
            self._scores = iter([0.1, 0.4, 0.8])

        def detect(self, spans, ctx):  # noqa: ANN001
            return [Finding(kind="kw", score=next(self._scores), evidence={})]

    det = InjectionCascadeDetector(fast=_VarFast(), judge_detector=judge, gray_low=0.2)
    det.detect([_span("a"), _span("b"), _span("c")], _CTX)
    assert det.span_count == 3
    assert det.judged_count == 1  # 仅 0.4 落 judge(0.1<下界快放、0.8≥上界快拦)
