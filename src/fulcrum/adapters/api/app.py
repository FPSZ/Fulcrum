"""FastAPI 应用工厂 —— 只做协议转换 + 调用 SecurityPipeline。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from ... import __version__
from ...core.domain import ExecResult, Message, ModelRequest
from ...core.errors import FulcrumError
from .schemas import (
    AuditResponse,
    ChatRequest,
    ChatResponse,
    HealthResponse,
    OutcomeDTO,
    ToolCallRequest,
    ToolCallResponse,
)

if TYPE_CHECKING:
    from ...config import Settings
    from ...core.pipeline import SecurityPipeline, ToolOutcome
    from ..auth import AuthBundle


def _output_of(result: object | None) -> str | None:
    return result.output if isinstance(result, ExecResult) else None


def _error_of(result: object | None) -> str | None:
    return result.error if isinstance(result, ExecResult) else None


def _to_outcome_dto(outcome: ToolOutcome) -> OutcomeDTO:
    return OutcomeDTO(
        tool_name=outcome.intent.tool_name,
        decision=outcome.decision.decision,
        executed=outcome.executed,
        reason=outcome.decision.reason,
        output=_output_of(outcome.result),
        error=_error_of(outcome.result),
    )


def build_api(
    pipeline: SecurityPipeline,
    auth: AuthBundle | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    app = FastAPI(title="枢衡 Fulcrum API", version=__version__)

    @app.exception_handler(FulcrumError)
    async def _on_fulcrum_error(_: Request, exc: FulcrumError) -> JSONResponse:
        return JSONResponse(
            status_code=400, content={"error": type(exc).__name__, "detail": str(exc)}
        )

    # 鉴权 + 管理后台路由;auth/settings 缺省时跳过,便于纯管线测试。
    if auth is not None and settings is not None:
        from .admin_routes import register_admin_routes
        from .auth_routes import register_auth_routes
        from .deps import AuthDeps

        deps = AuthDeps(auth.auth, settings.session_cookie_name)
        register_auth_routes(app, auth.auth, settings, deps)
        register_admin_routes(app, auth.directory, deps)

    @app.get("/healthz", response_model=HealthResponse)
    async def healthz() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.post("/v1/chat/completions", response_model=ChatResponse)
    async def chat_completions(body: ChatRequest) -> ChatResponse:
        req = ModelRequest(
            session_id=body.session_id or "anon",
            messages=[Message(role=m.role, content=m.content) for m in body.messages],
        )
        result = await pipeline.handle_model_request(req)
        resp = result.response
        return ChatResponse(
            session_id=req.session_id,
            content=resp.content if resp else "",
            tool_calls=[tc.tool_name for tc in (resp.tool_calls if resp else [])],
            outcomes=[_to_outcome_dto(o) for o in result.outcomes],
        )

    @app.post("/tools/call", response_model=ToolCallResponse)
    async def tools_call(body: ToolCallRequest) -> ToolCallResponse:
        outcome = pipeline.handle_tool_call(
            session_id=body.session_id,
            tool_name=body.tool_name,
            arguments=body.arguments,
            source_ids=body.source_ids,
        )
        return ToolCallResponse(
            decision=outcome.decision.decision,
            executed=outcome.executed,
            reason=outcome.decision.reason,
            output=_output_of(outcome.result),
            error=_error_of(outcome.result),
        )

    @app.get("/audit/{session_id}", response_model=AuditResponse)
    async def audit(session_id: str) -> AuditResponse:
        events = pipeline.audit.events(session_id)
        return AuditResponse(
            session_id=session_id,
            verified=pipeline.audit.verify_chain(session_id),
            events=[e.model_dump(mode="json") for e in events],
        )

    return app
