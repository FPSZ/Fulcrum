"""供应链扫描路由 —— 只读暴露组件 manifest 的静态扫描评级,经 supply.view 鉴权。

供应链扫描是**组件登记/上线时的离线关切**(不在每请求管线里)。本端点对配置目录下的
组件 manifest 跑静态扫描器(不执行任何组件代码),按最严重项评级,供供应链页展示。
扫描器由组装根注入(adapters 不依赖 capabilities);目录缺失/manifest 损坏则跳过该项。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from fastapi import Depends, FastAPI

from ...core.domain import Context, ScanReport
from ..auth import Principal
from .deps import AuthDeps
from .schemas import SupplyScanReportDTO, SupplyScanRiskDTO

if TYPE_CHECKING:
    from ...core.ports import SupplyChainScanner

# 评级严重度排序:阻断项排最前,放行垫底(供应链页列表按此置顶高危组件)。
_RATING_RANK = {"block": 0, "approve": 1, "sanitize": 2, "allow": 3}
_MANIFEST_SUFFIXES = (".yml", ".yaml", ".json")


def _infer_kind(stem: str, manifest: dict) -> str:
    """组件类型:优先 manifest 自声明,否则据文件名粗推(plugin/skill/mcp),兜底 component。"""
    declared = manifest.get("type") or manifest.get("kind")
    if isinstance(declared, str) and declared:
        return declared
    low = stem.lower()
    for guess in ("plugin", "skill", "mcp"):
        if guess in low:
            return guess
    return "component"


def to_scan_report_dto(report: ScanReport, kind: str, description: str = "") -> SupplyScanReportDTO:
    """ScanReport → 供应链页 DTO(风险项按分值降序,对齐 CLI 报告呈现)。"""
    risks = [
        SupplyScanRiskDTO(
            kind=f.kind,
            score=f.score,
            severity=str(f.evidence.get("severity", "")),
            detail=str(f.evidence.get("detail", "")),
        )
        for f in sorted(report.risks, key=lambda r: -r.score)
    ]
    return SupplyScanReportDTO(
        component_id=report.component_id,
        kind=kind,
        rating=report.rating.value,
        description=" ".join(description.split()),  # 折叠多行为单行,页面副标题友好
        risks=risks,
    )


def scan_directory(scanner: SupplyChainScanner, manifest_dir: str) -> list[SupplyScanReportDTO]:
    """扫描目录下所有组件 manifest,产出评级报告列表(纯函数,便于测试)。"""
    root = Path(manifest_dir)
    if not root.is_dir():
        return []
    out: list[SupplyScanReportDTO] = []
    for path in sorted(root.iterdir()):
        if path.suffix.lower() not in _MANIFEST_SUFFIXES:
            continue
        try:
            manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(manifest, dict):
            continue
        report = scanner.scan(manifest, Context(session_id="supply-scan"))
        out.append(
            to_scan_report_dto(
                report,
                _infer_kind(path.stem, manifest),
                str(manifest.get("description") or ""),
            )
        )
    out.sort(key=lambda r: (_RATING_RANK.get(r.rating, 9), r.component_id))
    return out


def register_supply_routes(
    app: FastAPI,
    scanner: SupplyChainScanner | None,
    manifest_dir: str,
    deps: AuthDeps,
) -> None:
    can_view = deps.require("supply.view")

    @app.get("/supply/scans", response_model=list[SupplyScanReportDTO])
    async def supply_scans(_: Principal = Depends(can_view)) -> list[SupplyScanReportDTO]:
        if scanner is None:
            return []
        return scan_directory(scanner, manifest_dir)
