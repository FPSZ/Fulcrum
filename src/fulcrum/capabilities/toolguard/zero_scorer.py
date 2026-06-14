"""ZeroRiskScorer —— M0 桩:风险分恒为 0。M1+ 按工具/参数/来源加权评分。"""

from __future__ import annotations

from ...core.domain import Context, ToolIntent
from ...core.registry import capability


@capability("risk_scorer", "zero")
class ZeroRiskScorer:
    def score(self, intent: ToolIntent, ctx: Context) -> float:
        return 0.0
