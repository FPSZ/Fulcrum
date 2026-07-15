"""分级安全预设配置路由：RBAC、候选构建、原子持久化与运行时热替换。"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import ValidationError

from ...core.domain import AuditEventType, Context
from ...core.errors import ConfigError
from ..auth import Principal
from ..security_config import (
    SecurityConfig,
    SecurityConfigPublic,
    SecurityConfigStore,
    available_detector_names,
)
from .deps import AuthDeps
from .schemas import SecurityConfigPublicDTO, SecurityConfigWrite

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline


def register_security_config_routes(
    app: FastAPI,
    pipeline: SecurityPipeline,
    store: SecurityConfigStore,
    base_config: dict[str, Any],
    pipeline_factory: Callable[[dict[str, Any]], SecurityPipeline],
    deps: AuthDeps,
) -> None:
    can_view = deps.require("settings.view")
    can_manage = deps.require("settings.manage")

    def _public(cfg: SecurityConfig) -> SecurityConfigPublicDTO:
        return SecurityConfigPublicDTO(
            **SecurityConfigPublic.of(cfg).model_dump(),
            available_detectors=available_detector_names(base_config),
        )

    @app.get("/admin/security-config", response_model=SecurityConfigPublicDTO)
    async def get_security_config(
        _: Principal = Depends(can_view),
    ) -> SecurityConfigPublicDTO:
        return _public(store.load())

    @app.put("/admin/security-config", response_model=SecurityConfigPublicDTO)
    async def put_security_config(
        body: SecurityConfigWrite, principal: Principal = Depends(can_manage)
    ) -> SecurityConfigPublicDTO:
        current = store.load()
        # null 保留已存密钥；空串明确清空。公开响应从不回传此字段。
        api_key = current.judge.api_key if body.judge_api_key is None else body.judge_api_key
        try:
            next_config = SecurityConfig.model_validate(
                {
                    "profile": body.profile,
                    "zone_overrides": body.zone_overrides,
                    "judge": {
                        "endpoint": body.judge_endpoint,
                        "model": body.judge_model,
                        "api_key": api_key,
                        "timeout_seconds": body.judge_timeout_seconds,
                    },
                }
            )
            # 预构建是事务的第一步：未知检测器或 options 错误必须不影响当前运行态和文件。
            candidate = pipeline_factory(next_config.apply_to(base_config))
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        # save 采用临时文件 + replace；成功后才切换内存配置。candidate 已通过完整构建校验。
        previous_zones = pipeline.detector_zones
        previous_names = {
            zone: [getattr(detector, "name", detector.__class__.__name__) for detector in detectors]
            for zone, detectors in previous_zones.items()
        }
        next_names = next_config.detector_zones()
        changed_zones = [
            zone for zone, names in next_names.items() if previous_names.get(zone) != names
        ]
        store.save(next_config)
        pipeline.replace_detector_zones(candidate.detector_zones)
        try:
            await pipeline.record(
                Context(session_id=f"security-config:{principal.user_id}"),
                AuditEventType.SECURITY_CONFIG_UPDATED,
                subject_id=str(principal.user_id),
                evidence={
                    "actor": principal.username,
                    "previous_profile": current.profile,
                    "profile": next_config.profile,
                    "changed_zones": changed_zones,
                    "detector_zones": next_names,
                    "detector_revisions": {
                        zone: candidate.detector_zone_summary(zone)["revision"]
                        for zone in next_names
                    },
                    # 只记录 judge 是否配置与是否满足隔离档，不记录 endpoint 或密钥。
                    "judge_configured": bool(next_config.judge.api_key),
                    "air_gapped": next_config.profile == "air_gapped",
                },
            )
        except Exception as exc:  # noqa: BLE001 -- 配置生效必须与审计留痕同成败
            try:
                store.save(current)
                pipeline.replace_detector_zones(previous_zones)
            except Exception:  # noqa: BLE001 -- 返回通用错误，避免泄露配置内部细节
                pass
            raise HTTPException(status_code=500, detail="安全配置审计失败，变更未生效") from exc
        return _public(next_config)
