"""鉴权 + 目录适配器 —— 账号口令登录 + 服务端会话 + 组织/角色/成员管理(RBAC)。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .directory import Conflict, DirectoryError, DirectoryService, NotFound
from .models import Department, Principal, Role, User
from .permissions import PERMISSIONS, PermissionDef
from .service import (
    AccountDisabled,
    AccountLocked,
    AuthError,
    AuthService,
    InvalidCredentials,
    PendingApproval,
    UsernameTaken,
    WeakPassword,
)
from .store import SQLiteAuthStore

if TYPE_CHECKING:
    from ...config import Settings

__all__ = [
    "PERMISSIONS",
    "AccountDisabled",
    "AccountLocked",
    "AuthBundle",
    "AuthError",
    "AuthService",
    "Conflict",
    "Department",
    "DirectoryError",
    "DirectoryService",
    "InvalidCredentials",
    "NotFound",
    "PendingApproval",
    "PermissionDef",
    "Principal",
    "Role",
    "SQLiteAuthStore",
    "UsernameTaken",
    "User",
    "WeakPassword",
    "build_auth_bundle",
]


@dataclass(frozen=True, slots=True)
class AuthBundle:
    """登录与目录两个服务共享同一个 store,打包交给 API 层装配。"""

    auth: AuthService
    directory: DirectoryService


def build_auth_bundle(settings: Settings) -> AuthBundle:
    """按运行时设置装配鉴权+目录服务,补齐角色/组织种子并完成首启管理员引导。"""
    store = SQLiteAuthStore(settings.auth_db_path)
    auth = AuthService(
        store,
        session_ttl_hours=settings.session_ttl_hours,
        max_failures=settings.login_max_failures,
        lockout_minutes=settings.login_lockout_minutes,
    )
    auth.seed(settings.bootstrap_admin_username, settings.bootstrap_admin_password)
    return AuthBundle(auth=auth, directory=DirectoryService(store))
