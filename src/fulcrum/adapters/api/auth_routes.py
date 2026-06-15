"""鉴权路由 —— /auth/login、/auth/logout、/auth/me、/auth/register。

会话令牌只走 HttpOnly Cookie(HttpOnly 防 XSS 窃取、SameSite=strict 防 CSRF、
Secure 经 TLS 后置 true、Max-Age 绝对过期)。令牌不进响应体、不进前端源码。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status

from ..auth import (
    AccountDisabled,
    AccountLocked,
    AuthService,
    InvalidCredentials,
    PendingApproval,
    Principal,
    UsernameTaken,
    WeakPassword,
)
from .deps import AuthDeps
from .schemas import LoginRequest, PrincipalResponse, RegisterRequest

if TYPE_CHECKING:
    from ...config import Settings


def _principal_dto(p: Principal) -> PrincipalResponse:
    return PrincipalResponse(
        username=p.username,
        display_name=p.display_name,
        role_key=p.role_key,
        role_name=p.role_name,
        permissions=sorted(p.permissions),
    )


def register_auth_routes(
    app: FastAPI, auth: AuthService, settings: Settings, deps: AuthDeps
) -> None:
    cookie_name = settings.session_cookie_name
    principal_dep = deps.principal_dependency()

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
        except PendingApproval as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except AccountDisabled as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
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
        assert principal is not None
        return _principal_dto(principal)

    @app.post("/auth/register", status_code=status.HTTP_202_ACCEPTED)
    async def register(body: RegisterRequest) -> dict[str, str]:
        try:
            auth.register(body.username, body.password, body.display_name)
        except (UsernameTaken, WeakPassword, InvalidCredentials) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc
        return {"detail": "申请已提交,等待管理员审批"}

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
    async def me(principal: Principal = Depends(principal_dep)) -> PrincipalResponse:
        return _principal_dto(principal)
