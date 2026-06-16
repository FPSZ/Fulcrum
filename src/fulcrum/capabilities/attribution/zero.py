"""ZeroAttributor —— M0 桩:不做归因,置信度恒为 0。

M1+ 用证据化归因(来源标签传递 + 片段匹配 + 参数相似度 + LLM-judge)替换。
"""

from __future__ import annotations

from ...core.domain import Attribution, Context, SourceSpan, ToolIntent
from ...core.registry import capability


@capability("attributor", "zero")
class ZeroAttributor:
    async def attribute(
        self, intent: ToolIntent, spans: list[SourceSpan], ctx: Context
    ) -> Attribution:
        return Attribution(derived_from_sources=[], confidence=0.0, rationale="M0 stub")
