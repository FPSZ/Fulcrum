"""AllowAllPolicy —— M0 桩:一律放行。

M1+ 替换为 YAML 声明式策略引擎(source_trust/tool_name/risk_level/path_matches/
domain_allowed/command_risk/attribution_confidence 等条件 -> 分级处置)。
"""

from __future__ import annotations

from ...core.domain import Context, Disposition, PolicyDecision, RiskLevel, ToolIntent
from ...core.registry import capability


@capability("policy", "allow_all")
class AllowAllPolicy:
    async def decide(self, intent: ToolIntent, ctx: Context) -> PolicyDecision:
        return PolicyDecision(
            decision=Disposition.ALLOW,
            reason="M0 stub: allow-all",
            matched_policy_id=None,
            risk_level=RiskLevel.LOW,
        )
