"""NoopDetector —— M0 桩:不产生任何 finding。"""

from __future__ import annotations

from ...core.domain import Context, Finding, SourceSpan
from ...core.registry import capability


@capability("detector", "noop")
class NoopDetector:
    name = "noop"

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        return []
