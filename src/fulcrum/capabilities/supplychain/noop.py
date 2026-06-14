"""NoopScanner —— M0 桩:评级恒为 allow。

M1+ 替换为最小供应链闭环(manifest 注入 / 高危权限 / 外联依赖 -> 评级)。
"""

from __future__ import annotations

from ...core.domain import Context, Disposition, ScanReport
from ...core.registry import capability


@capability("scanner", "noop")
class NoopScanner:
    def scan(self, manifest: dict, ctx: Context) -> ScanReport:
        component_id = str(manifest.get("name", "unknown"))
        return ScanReport(component_id=component_id, rating=Disposition.ALLOW, risks=[])
