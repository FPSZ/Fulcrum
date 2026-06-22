"""控制台通用设置路由 —— 设置页"通用 / 审计留存 / 通知"读写,经 settings.* 权限鉴权。

实例级偏好(非安全红线)落盘持久化(``ConsoleSettingsStore``),设置页填表即存、刷新即见。
GET 同时回显**只读**的后端模型信息(经 .env 注入,控制台不改),便于模型接入页如实展示。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI

from ..auth import Principal
from ..console_settings import ConsoleSettings, ConsoleSettingsStore
from .deps import AuthDeps
from .schemas import BackendModelInfo, ConsoleSettingsPublic, ConsoleSettingsWrite

if TYPE_CHECKING:
    from ...config import Settings


def register_console_settings_routes(
    app: FastAPI,
    store: ConsoleSettingsStore,
    env_settings: Settings,
    deps: AuthDeps,
) -> None:
    can_view = deps.require("settings.view")
    can_manage = deps.require("settings.manage")

    def _public(cfg: ConsoleSettings) -> ConsoleSettingsPublic:
        return ConsoleSettingsPublic(
            **cfg.model_dump(),
            backend_model=BackendModelInfo(
                endpoint=env_settings.model_endpoint,
                model_name=env_settings.model_name,
                key_set=bool(env_settings.model_api_key),
            ),
        )

    @app.get("/admin/settings", response_model=ConsoleSettingsPublic)
    async def get_settings(_: Principal = Depends(can_view)) -> ConsoleSettingsPublic:
        return _public(store.load())

    @app.put("/admin/settings", response_model=ConsoleSettingsPublic)
    async def put_settings(
        body: ConsoleSettingsWrite, _: Principal = Depends(can_manage)
    ) -> ConsoleSettingsPublic:
        cfg = ConsoleSettings(**body.model_dump())
        return _public(store.save(cfg))
