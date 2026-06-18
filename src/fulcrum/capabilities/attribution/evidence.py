"""EvidenceAttributor —— 证据化来源归因(枢衡脊柱),对应赛题目标①④。

不做形式化 taint,而用**可解释证据**判断"这次工具调用是被哪段输入驱动的":
若工具意图的具体参数(路径/URL/命令片段)原文出现在某条来源 SourceSpan 的内容里,
即建立归因边;置信度 = 来源信任权重 × 匹配强度。来源越不可信,归因风险越高。

这条归因边是审计可追溯("哪段输入 → 哪次调用")与策略判定(source_trust /
attribution_confidence)的共同依据。LLM-judge 在 P3 作为后置增强提升弱关联召回。
"""

from __future__ import annotations

import re

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
# URL scheme 前缀(用于剥离,得到来源原文里更可能出现的"主机+路径"核心)。
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://")


def _candidates(value: str) -> list[str]:
    """由一条参数值派生可匹配片段:原值,以及剥离外层引号 / URL scheme / 尾斜杠后的核心。

    间接注入主战场上,来源(文档/网页)里常只写裸的"主机+路径"(169.254.169.254/x、
    /etc/passwd"),而模型实际调用时会包装成 http://169.254.169.254/x/、给路径加引号等。
    只比整条参数值会让这类**被规范化/包装过**的调用漏掉归因边,策略随之拿不到 source_trust。
    这里额外产出去壳后的核心片段(仍 ≥ _MIN_TOKEN 才纳入,避免过度泛化误关联)。
    """
    raw = value.strip()
    out: list[str] = []
    if len(raw) >= _MIN_TOKEN:
        out.append(raw)
    core = _SCHEME.sub("", raw.strip("\"'`")).rstrip("/")
    if core != raw and len(core) >= _MIN_TOKEN and core not in out:
        out.append(core)
    return out


@capability("attributor", "evidence")
class EvidenceAttributor:
    async def attribute(
        self, intent: ToolIntent, spans: list[SourceSpan], ctx: Context
    ) -> Attribution:
        arg_vals = [frag for x in intent.arguments.values() for frag in _candidates(str(x).lower())]
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
