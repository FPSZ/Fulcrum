"""API 鉴权依赖 —— 当前主体解析 + 权限点守卫(RBAC 强制点)。

前端隐藏菜单只是体验,**真正的访问控制在这里**:每个受保护路由声明所需权限点,
无会话 → 401,有会话但缺权限 → 403。所以越权请求即使绕过前端也会被后端挡下。
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Cookie, Depends, HTTPException, status

from ..auth import AuthService, Principal


class AuthDeps:
    def __init__(self, auth: AuthService, cookie_name: str) -> None:
        self._auth = auth
        self._cookie_name = cookie_name

    def current_principal(self, request_cookie: str | None) -> Principal:
        principal = self._auth.authenticate(request_cookie)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录或会话已失效"
            )
        return principal

    def principal_dependency(self) -> Callable[..., Principal]:
        """生成读取会话 Cookie 的 FastAPI 依赖(别名按配置的 Cookie 名)。"""
        cookie_name = self._cookie_name

        def _dep(session: str | None = Cookie(default=None, alias=cookie_name)) -> Principal:
            return self.current_principal(session)

        return _dep

    def require(self, permission: str) -> Callable[..., Principal]:
        """声明某路由所需权限点;缺失即 403。"""
        principal_dep = self.principal_dependency()

        def _dep(principal: Principal = Depends(principal_dep)) -> Principal:
            if not principal.has(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"无权限:需要 {permission}",
                )
            return principal

        return _dep

    def require_member_admin(self) -> Callable[..., Principal]:
        """成员管理入口(plan/13 P1b):组织级 `users.manage` 或 **任一团队负责人** 均可进。

        进得来不代表能管所有人——具体"能否管这个目标成员"由处理器按 `can_manage_team` 复校
        (团队负责人只能管本团队子树)。这是把"团队组长读写本团队"接进真实端点的闸。
        """
        principal_dep = self.principal_dependency()

        def _dep(principal: Principal = Depends(principal_dep)) -> Principal:
            if principal.has("users.manage") or principal.managed_teams:
                return principal
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权限:需要成员管理权(组织级 users.manage 或团队负责人)",
            )

        return _dep
