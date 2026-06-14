"""KeywordRuleDetector —— 示例检测器(非桩),演示"如何加一个 detector"。

仅用最朴素的关键词规则识别常见提示注入/越权诱导措辞。
注意:这是地基示例,不代表最终检测能力;真实检测在 M1+ 增强。
"""

from __future__ import annotations

from ...core.domain import Context, Finding, SourceSpan, TrustLevel
from ...core.registry import capability

# 关键词 -> 风险标签(可解释、确定性、低延迟)。
_RULES: dict[str, str] = {
    "ignore previous": "injection",
    "ignore the above": "injection",
    "忽略以上": "injection",
    "忽略之前": "injection",
    "disregard instructions": "injection",
    "you are now": "jailbreak",
    "developer mode": "jailbreak",
    "exfiltrate": "exfiltration",
    "send to": "exfiltration",
    "读取并发送": "exfiltration",
}


@capability("detector", "keyword_rules")
class KeywordRuleDetector:
    name = "keyword_rules"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            text = span.excerpt.lower()
            for keyword, kind in _RULES.items():
                if keyword in text:
                    # 不可信来源命中的风险更高。
                    score = 0.9 if span.trust_level == TrustLevel.UNTRUSTED else 0.6
                    findings.append(
                        Finding(
                            kind=kind,
                            score=score,
                            evidence={
                                "rule": keyword,
                                "source_id": span.source_id,
                                "source_type": span.source_type,
                            },
                        )
                    )
        return findings
