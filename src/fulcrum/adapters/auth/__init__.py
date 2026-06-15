"""鉴权适配器 —— 账号口令登录 + 服务端会话(Argon2id + SQLite)。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import Principal
from .service import AccountLocked, AuthError, AuthService, InvalidCredentials
from .store import SQLiteAuthStore

if TYPE_CHECKING:
    from ...config import Settings

__all__ = [
    "AccountLocked",
    "AuthError",
    "AuthService",
    "InvalidCredentials",
    "Principal",
    "SQLiteAuthStore",
    "build_auth_service",
]


def build_auth_service(settings: Settings) -> AuthService:
    """按运行时设置装配 AuthService,并完成首次启动的管理员引导。"""
    store = SQLiteAuthStore(settings.auth_db_path)
    service = AuthService(
        store,
        session_ttl_hours=settings.session_ttl_hours,
        max_failures=settings.login_max_failures,
        lockout_minutes=settings.login_lockout_minutes,
    )
    service.bootstrap_admin(
        settings.bootstrap_admin_username, settings.bootstrap_admin_password
    )
    return service
