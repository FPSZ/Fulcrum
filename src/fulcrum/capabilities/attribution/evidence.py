"""EvidenceAttributor —— 证据化来源归因(枢衡脊柱),对应赛题目标①④。

不做形式化 taint,而用**可解释证据**判断"这次工具调用是被哪段输入驱动的":
若工具意图的具体参数(路径/URL/命令片段)原文出现在某条来源 SourceSpan 的内容里,
即建立归因边;置信度 = 来源信任权重 × 匹配强度。来源越不可信,归因风险越高。

这条归因边是审计可追溯("哪段输入 → 哪次调用")与策略判定(source_trust /
attribution_confidence)的共同依据。LLM-judge 在 P3 作为后置增强提升弱关联召回。
"""

from __future__ import annotations

from ...core.domain import Attribution, Context, SourceSpan, ToolIntent, TrustLevel
from ...core.registry import capability

# 来源信任级 -> 归因置信度权重(不可信来源的关联最值得警惕)。
_TRUST_WEIGHT: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.SEMI_TRUSTED: 0.6,
    TrustLevel.TRUSTED: 0.2,
}
# 参数片段需达到的最小长度,避免 "1"、"a" 之类噪声误关联。
_MIN_TOKEN = 4


@capability("attributor", "evidence")
class EvidenceAttributor:
    def attribute(self, intent: ToolIntent, spans: list[SourceSpan], ctx: Context) -> Attribution:
        arg_vals = [
            v
            for v in (str(x).lower().strip() for x in intent.arguments.values())
            if len(v) >= _MIN_TOKEN
        ]
        derived: list[str] = []
        best = 0.0
        reasons: list[str] = []
        for span in spans:
            excerpt = span.excerpt.lower()
            matched = next((v for v in arg_vals if v in excerpt), None)
            if matched is None:
                continue
            conf = _TRUST_WEIGHT.get(span.trust_level, 0.5)
            derived.append(span.source_id)
            best = max(best, conf)
            reasons.append(
                f"参数片段 {matched!r} 出现在 {span.source_type}({span.trust_level}) 来源"
            )

        if not derived and intent.derived_from_sources:
            # 调用方(工具网关)显式声明来源但无 span 可核验 → 给中等置信度,fail-closed。
            derived = list(intent.derived_from_sources)
            best = 0.5
            reasons.append("调用方显式声明来源(未提供 span 核验)")

        return Attribution(
            derived_from_sources=derived,
            confidence=round(best, 3),
            rationale="; ".join(reasons) or "未发现来源关联",
        )
