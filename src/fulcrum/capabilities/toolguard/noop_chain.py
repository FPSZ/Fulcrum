"""NoopChainAnalyzer —— M0 桩:不做任务链分析。M1+ 检测异常动作序列。"""

from __future__ import annotations

from ...core.domain import Context, Finding, ToolIntent
from ...core.registry import capability


@capability("chain_analyzer", "noop")
class NoopChainAnalyzer:
    def analyze(self, session_trace: list[ToolIntent], ctx: Context) -> list[Finding]:
        return []
