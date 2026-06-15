"""鉴权路由 —— /auth/login、/auth/logout、/auth/me + require_auth 依赖。

会话令牌只走 HttpOnly Cookie:
- HttpOnly  → JS 读不到,杜绝 XSS 窃取令牌;
- SameSite=strict → 跨站请求不携带,挡 CSRF;
- Secure(TLS 后置 true)→ 只在 HTTPS 下回传;
- 令牌本身不进响应体、不进前端源码 —— 前端只知道"我登没登上"。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status

from ..auth import AccountLocked, AuthService, InvalidCredentials, Principal
from .schemas import LoginRequest, PrincipalResponse

if TYPE_CHECKING:
    from ...config import Settings


def register_auth_routes(app: FastAPI, auth: AuthService, settings: Settings) -> None:
    cookie_name = settings.session_cookie_name

    def current_principal(
        session: str | None = Cookie(default=None, alias=cookie_name),
    ) -> Principal:
        """受保护路由的守卫:无有效会话直接 401。"""
        principal = auth.authenticate(session)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录或会话已失效"
            )
        return principal

    # 导出给其它受保护路由复用(M4 接 RBAC 时在此之上叠权限校验)。
    app.state.require_auth = current_principal

    @app.post("/auth/login", response_model=PrincipalResponse)
    async def login(body: LoginRequest, response: Response) -> PrincipalResponse:
        try:
            token = auth.login(body.username, body.password)
        except AccountLocked as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=str(exc),
                headers={"Retry-After": str(exc.retry_after_seconds)},
            ) from exc
        except InvalidCredentials as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
            ) from exc
        response.set_cookie(
            key=cookie_name,
            value=token,
            max_age=auth.session_ttl_seconds,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite=settings.session_cookie_samesite,  # type: ignore[arg-type]
            path="/",
        )
        principal = auth.authenticate(token)
        assert principal is not None  # 刚签发,必有效
        return PrincipalResponse(
            username=principal.username, display_name=principal.display_name
        )

    @app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        response: Response,
        session: str | None = Cookie(default=None, alias=cookie_name),
    ) -> Response:
        auth.logout(session)
        response.delete_cookie(key=cookie_name, path="/")
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @app.get("/auth/me", response_model=PrincipalResponse)
    async def me(principal: Principal = Depends(current_principal)) -> PrincipalResponse:
        return PrincipalResponse(
            username=principal.username, display_name=principal.display_name
        )
