"""FastAPI 应用工厂 —— 只做协议转换 + 调用 SecurityPipeline。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from ... import __version__
from ...core.domain import Disposition, ExecResult, Message, ModelRequest
from ...core.errors import FulcrumError
from .schemas import (
    AuditResponse,
    ChatRequest,
    ChatResponse,
    GatewayChatRequest,
    GatewayChatResponse,
    GatewayFindingDTO,
    HealthResponse,
    OutcomeDTO,
    ToolCallRequest,
    ToolCallResponse,
)

if TYPE_CHECKING:
    from ...config import Settings
    from ...core.gateway import GateVerdict
    from ...core.pipeline import SecurityPipeline, ToolOutcome
    from ..auth import AuthBundle
    from ..gateway import GatewayConfigStore, UpstreamForwarder


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


def _findings_dto(verdict: GateVerdict) -> list[GatewayFindingDTO]:
    out: list[GatewayFindingDTO] = []
    for f in verdict.findings:
        ev = f.evidence
        out.append(
            GatewayFindingDTO(
                kind=f.kind,
                score=f.score,
                severity=ev.get("severity"),
                source_type=ev.get("source_type"),
                matched=(ev.get("matched_rules") or [])[:3],
            )
        )
    return out


def build_api(
    pipeline: SecurityPipeline,
    auth: AuthBundle | None = None,
    settings: Settings | None = None,
    upstream: UpstreamForwarder | None = None,
    gateway_store: GatewayConfigStore | None = None,
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
        from .events_routes import register_events_routes
        from .overview_routes import register_overview_routes

        deps = AuthDeps(auth.auth, settings.session_cookie_name)
        register_auth_routes(app, auth.auth, settings, deps)
        register_admin_routes(app, auth.directory, deps)
        register_overview_routes(app, pipeline, deps)
        register_events_routes(app, pipeline, deps)
        if upstream is not None and gateway_store is not None:
            from .gateway_routes import register_gateway_routes

            register_gateway_routes(app, gateway_store, upstream, deps)

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
        outcome = await pipeline.handle_tool_call(
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

    @app.post("/gateway/chat", response_model=GatewayChatResponse)
    async def gateway_chat(body: GatewayChatRequest) -> GatewayChatResponse:
        """前置网关:判恶意 → 拦截/审核/放行;仅放行时转发企业智能体并回传其真实回复。"""
        verdict = await pipeline.screen_input(body.session_id, body.message)
        resp = GatewayChatResponse(
            session_id=body.session_id,
            decision=verdict.decision,
            risk_level=verdict.risk_level,
            forwarded=False,
            reason=verdict.reason,
            max_score=verdict.max_score,
            findings=_findings_dto(verdict),
        )
        if verdict.decision != Disposition.ALLOW or upstream is None:
            if upstream is None and verdict.decision == Disposition.ALLOW:
                resp.upstream_error = "未配置企业智能体端点(upstream_agent_endpoint)"
            return resp

        reply = await upstream.chat(body.session_id, body.message)
        resp.forwarded = reply.ok
        resp.reply = reply.reply
        resp.tools = reply.tools
        resp.upstream_error = reply.error
        return resp

    @app.get("/audit/{session_id}", response_model=AuditResponse)
    async def audit(session_id: str) -> AuditResponse:
        events = await pipeline.audit.events(session_id)
        return AuditResponse(
            session_id=session_id,
            verified=await pipeline.audit.verify_chain(session_id),
            events=[e.model_dump(mode="json") for e in events],
        )

    # 生产托管已构建的前端(同源 → 会话 Cookie 无需 CORS);最后挂载,API 路由优先。
    if settings is not None and settings.frontend_dir:
        _mount_frontend(app, settings.frontend_dir)

    return app


def _mount_frontend(app: FastAPI, frontend_dir: str) -> None:
    """把 console/dist 挂到根:/assets 等静态资源直出,其余路径回退 index.html(SPA)。"""
    import mimetypes
    from pathlib import Path

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    # 修正 .js/.mjs 的 MIME:Windows 注册表常把 .js 映射成 text/plain,导致浏览器按
    # 严格 MIME 规则拒绝执行 ES module(前端白屏)。显式登记,跨平台一致(StaticFiles /
    # FileResponse 都走全局 mimetypes)。
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("application/javascript", ".mjs")
    mimetypes.add_type("text/css", ".css")

    root = Path(frontend_dir).resolve()
    index = root / "index.html"
    if not index.is_file():
        return

    assets = root / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/", include_in_schema=False)
    async def _index() -> FileResponse:
        return FileResponse(str(index))

    @app.get("/{path:path}", include_in_schema=False)
    async def _spa(path: str) -> FileResponse:
        # 已存在的根级静态文件(favicon、logo 等)直出,否则回退 index.html 交前端路由;
        # resolve 后必须仍在 root 内,挡掉 ../ 穿越。
        candidate = (root / path).resolve()
        if candidate.is_file() and (candidate == root or root in candidate.parents):
            return FileResponse(str(candidate))
        return FileResponse(str(index))
