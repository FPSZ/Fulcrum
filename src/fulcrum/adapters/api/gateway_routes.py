"""网关接入配置路由 —— 设置页"配置上游 + 测试连接",经 settings.* 权限强制鉴权。

买家在设置页填上游地址/协议/认证 → PUT 保存(热加载,无需重启)→ POST test 测试连接。
密钥写库但绝不回前端(掩码)。
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from ..auth import Principal
from ..gateway import GatewayConfig, GatewayConfigPublic, GatewayConfigStore, UpstreamForwarder
from .deps import AuthDeps
from .schemas import GatewayConfigWrite, GatewayProbeResponse


def register_gateway_routes(
    app: FastAPI,
    store: GatewayConfigStore,
    forwarder: UpstreamForwarder,
    deps: AuthDeps,
) -> None:
    can_view = deps.require("settings.view")
    can_manage = deps.require("settings.manage")

    @app.get("/admin/gateway-config", response_model=GatewayConfigPublic)
    async def get_config(_: Principal = Depends(can_view)) -> GatewayConfigPublic:
        return GatewayConfigPublic.of(store.load())

    @app.put("/admin/gateway-config", response_model=GatewayConfigPublic)
    async def put_config(
        body: GatewayConfigWrite, _: Principal = Depends(can_manage)
    ) -> GatewayConfigPublic:
        current = store.load()
        # auth_value=None 表示"不改密钥",沿用现值;否则按传入替换/清空。
        auth_value = current.auth_value if body.auth_value is None else body.auth_value
        cfg = GatewayConfig(
            enabled=body.enabled,
            name=body.name,
            protocol=body.protocol,  # type: ignore[arg-type]
            endpoint=body.endpoint,
            path=body.path,
            model=body.model,
            auth_type=body.auth_type,  # type: ignore[arg-type]
            auth_header=body.auth_header,
            auth_value=auth_value,
            timeout_seconds=body.timeout_seconds,
            verify_tls=body.verify_tls,
            rest_message_field=body.rest_message_field,
            rest_response_path=body.rest_response_path,
            team_id=body.team_id,
        )
        return GatewayConfigPublic.of(store.save(cfg))

    @app.post("/admin/gateway-config/test", response_model=GatewayProbeResponse)
    async def test_config(
        body: GatewayConfigWrite, _: Principal = Depends(can_manage)
    ) -> GatewayProbeResponse:
        # 测试"表单里当前填的"配置(可能尚未保存);密钥若为 None 用已存值。
        current = store.load()
        auth_value = current.auth_value if body.auth_value is None else body.auth_value
        cfg = GatewayConfig(
            enabled=body.enabled,
            name=body.name,
            protocol=body.protocol,  # type: ignore[arg-type]
            endpoint=body.endpoint,
            path=body.path,
            model=body.model,
            auth_type=body.auth_type,  # type: ignore[arg-type]
            auth_header=body.auth_header,
            auth_value=auth_value,
            timeout_seconds=body.timeout_seconds,
            verify_tls=body.verify_tls,
            rest_message_field=body.rest_message_field,
            rest_response_path=body.rest_response_path,
        )
        r = await forwarder.probe(cfg)
        return GatewayProbeResponse(
            ok=r.ok, latency_ms=r.latency_ms, detail=r.detail, status_code=r.status_code
        )
