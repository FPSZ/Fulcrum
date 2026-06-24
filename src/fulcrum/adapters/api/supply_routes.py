"""供应链扫描路由 —— 组件 manifest 的静态扫描评级:只读列表(supply.view)+ 登记扫描(supply.manage)。

供应链扫描是**组件登记/上线时的离线关切**(不在每请求管线里)。GET 对配置目录下的组件 manifest
跑静态扫描器(不执行任何组件代码),按最严重项评级,供供应链页展示;POST 让管理员从控制台直接
贴入一份 manifest,当场出评级、落盘登记,列表随之多一行(孤儿写权限 `supply.manage` 的闭环)。
扫描器由组装根注入(adapters 不依赖 capabilities);目录缺失/manifest 损坏则跳过该项。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from fastapi import Depends, FastAPI, HTTPException, status

from ...core.domain import AuditEvent, AuditEventType, Context, ScanReport
from ..auth import Principal
from ..supply_store import SupplyManifestStore
from .deps import AuthDeps
from .schemas import SupplyScanReportDTO, SupplyScanRequest, SupplyScanRiskDTO

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
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


def to_scan_report_dto(report: ScanReport, kind: str) -> SupplyScanReportDTO:
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
        out.append(to_scan_report_dto(report, _infer_kind(path.stem, manifest)))
    out.sort(key=lambda r: (_RATING_RANK.get(r.rating, 9), r.component_id))
    return out


def merge_scans(
    seed: list[SupplyScanReportDTO], uploaded: list[SupplyScanReportDTO]
) -> list[SupplyScanReportDTO]:
    """合并种子目录与登记目录的扫描结果(纯函数,便于测试)。

    同 component_id 以登记目录(uploaded,运行期录入)为准——重新登记即覆盖种子样本;
    再按评级严重度置顶(高危在前),component_id 次序稳定。
    """
    by_id = {r.component_id: r for r in seed}
    for r in uploaded:
        by_id[r.component_id] = r
    out = list(by_id.values())
    out.sort(key=lambda r: (_RATING_RANK.get(r.rating, 9), r.component_id))
    return out


def register_supply_routes(
    app: FastAPI,
    pipeline: SecurityPipeline,
    scanner: SupplyChainScanner | None,
    seed_dir: str,
    store: SupplyManifestStore,
    deps: AuthDeps,
) -> None:
    can_view = deps.require("supply.view")
    can_manage = deps.require("supply.manage")  # 登记/扫描是写操作,单独鉴权

    @app.get("/supply/scans", response_model=list[SupplyScanReportDTO])
    async def supply_scans(_: Principal = Depends(can_view)) -> list[SupplyScanReportDTO]:
        if scanner is None:
            return []
        # 列表 = 仓库种子目录 + 控制台登记目录,同组件以登记为准。
        return merge_scans(scan_directory(scanner, seed_dir), scan_directory(scanner, store.dir))

    @app.post("/supply/scan", response_model=SupplyScanReportDTO)
    async def register_scan(
        body: SupplyScanRequest,
        principal: Principal = Depends(can_manage),
    ) -> SupplyScanReportDTO:
        """登记一份组件 manifest:当场静态扫描评级 → 落盘登记 → 写 SUPPLYCHAIN_SCANNED 审计。

        不执行任何组件代码;仅对 manifest 文本做确定性静态检查。落盘后该组件即进 GET 列表
        (同 component_id 覆盖),并在审计链留痕(谁、何时、登记了什么、评了什么级)。
        """
        if scanner is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="未装配供应链扫描器"
            )
        try:
            manifest = yaml.safe_load(body.manifest)
        except yaml.YAMLError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"manifest 解析失败:{exc}"
            ) from exc
        if not isinstance(manifest, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="manifest 须为对象(键值映射)"
            )
        report = scanner.scan(manifest, Context(session_id="supply-scan"))
        kind = _infer_kind(report.component_id, manifest)
        store.save(report.component_id, body.manifest)  # 落盘登记,进 GET 列表且重启不丢
        await pipeline.audit.append(
            AuditEvent(
                session_id="config:supply",
                event_type=AuditEventType.SUPPLYCHAIN_SCANNED,
                subject_id=report.component_id,
                decision=report.rating,
                evidence={
                    "component_id": report.component_id,
                    "kind": kind,
                    "rating": report.rating.value,
                    "risk_count": len(report.risks),
                    "actor": principal.username,
                    "reason": f"登记组件 {report.component_id},静态扫描评级 {report.rating.value}",
                },
            )
        )
        return to_scan_report_dto(report, kind)
