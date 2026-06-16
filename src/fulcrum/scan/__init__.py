"""供应链扫描 CLI 的可复用逻辑 —— 加载 manifest、按装配清单取扫描器、格式化报告。

入口见 `__main__`(`python -m fulcrum.scan <manifest>`)。逻辑与打印分离,便于测试。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ..capabilities import load_builtin_capabilities
from ..config import load_capability_config
from ..core.domain import Context, Disposition, ScanReport
from ..core.registry import registry

# rating → 进程退出码:便于在 CI/脚本里据评级门禁(block 非零)。
EXIT_CODE = {
    Disposition.ALLOW: 0,
    Disposition.SANITIZE: 1,
    Disposition.APPROVE: 1,
    Disposition.BLOCK: 2,
}


def load_manifest(path: str | Path) -> dict:
    """读取 YAML/JSON manifest(YAML 是 JSON 超集,统一用 yaml 解析)。"""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"manifest 不存在:{p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"manifest 顶层应为对象/映射,实际为 {type(data).__name__}")
    return data


def scan_manifest(manifest: dict, scanner_name: str | None = None) -> ScanReport:
    """按装配清单(或显式指定)取扫描器,对 manifest 评级。"""
    load_builtin_capabilities()
    name = scanner_name or load_capability_config()["scanner"]
    scanner = registry.create("scanner", name)
    return scanner.scan(manifest, Context(session_id="cli-scan"))


def format_report(report: ScanReport) -> str:
    """把 ScanReport 渲染成人类可读文本。"""
    lines = [
        f"组件:{report.component_id}",
        f"评级:{report.rating.value}",
        f"风险项:{len(report.risks)} 条",
    ]
    for f in sorted(report.risks, key=lambda r: -r.score):
        sev = f.evidence.get("severity", "?")
        detail = f.evidence.get("detail", "")
        lines.append(f"  · [{sev}] {f.kind}(score={f.score}) — {detail}")
    return "\n".join(lines)
