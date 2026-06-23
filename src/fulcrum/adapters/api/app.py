"""FastAPI 应用工厂 —— 只做协议转换 + 调用 SecurityPipeline。"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from ... import __version__
from ...core.domain import Disposition, ExecResult, Message, ModelRequest
from ...core.errors import FulcrumError
from ...core.redaction import redact
from .schemas import (
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
    from ...core.ports import SupplyChainScanner
    from ..assistant import ModelTurn
    from ..assistant.planner import ModelComplete
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
    scanner: SupplyChainScanner | None = None,
    assistant_complete: ModelComplete | None = None,
    assistant_model_turn: ModelTurn | None = None,
) -> FastAPI:
    app = FastAPI(title="枢衡 Fulcrum API", version=__version__)

    @app.exception_handler(FulcrumError)
    async def _on_fulcrum_error(_: Request, exc: FulcrumError) -> JSONResponse:
        return JSONResponse(
            status_code=400, content={"error": type(exc).__name__, "detail": str(exc)}
        )

    # 鉴权 + 管理后台路由;auth/settings 缺省时跳过,便于纯管线测试。
    if auth is not None and settings is not None:
        from ..assistant import make_model_backend
        from .admin_routes import register_admin_routes
        from .assistant_routes import register_assistant_routes
        from .audit_routes import register_audit_routes
        from .auth_routes import register_auth_routes
        from .deps import AuthDeps
        from .eval_routes import register_eval_routes
        from .events_routes import register_events_routes
        from .overview_routes import register_overview_routes
        from .policies_routes import register_policies_routes
        from .supply_routes import register_supply_routes
        from .tools_routes import register_tools_routes

        deps = AuthDeps(auth.auth, settings.session_cookie_name)
        register_auth_routes(app, auth.auth, settings, deps)
        register_admin_routes(app, auth.directory, deps)
        register_overview_routes(app, pipeline, deps)
        register_events_routes(app, pipeline, deps)
        register_audit_routes(app, pipeline, deps)
        register_eval_routes(app, settings.eval_report_path, deps)
        register_policies_routes(app, pipeline, deps)
        register_supply_routes(app, scanner, settings.supply_manifest_dir, deps)
        register_tools_routes(app, pipeline, deps)
        # 控制台实例元信息:落盘持久化,设置页可读写。
        from ..console_settings import ConsoleSettingsStore
        from .settings_routes import register_console_settings_routes

        console_store = ConsoleSettingsStore(settings.console_settings_path)
        register_console_settings_routes(app, console_store, settings, deps)
        # AI 操作助手:模型后端默认从 .env(endpoint/key/name)装配,组装根可覆盖(测试注入假后端)。
        complete = assistant_complete or make_model_backend(
            settings.model_endpoint, settings.model_api_key, settings.model_name
        )
        # 真 Agent(plan/11):操作服务包 + 动态工具模型客户端 + Agent 循环(三道吃狗粮闸门)
        # + 写操作提案-确认-撤销执行器(令牌签发 + 撤销句柄)。
        from ...core.operations import operation_registry
        from ..assistant import (
            ActionTokenSigner,
            AssistantActuator,
            AssistantAgent,
            AssistantServices,
            ConversationStore,
            UndoStore,
            make_dynamic_model_backend,
            make_dynamic_stream_backend,
        )

        assistant_services = AssistantServices(
            pipeline=pipeline,
            eval_report_path=settings.eval_report_path,
            supply_manifest_dir=settings.supply_manifest_dir,
            directory=auth.directory,
            scanner=scanner,
            gateway_store=gateway_store,
            console_store=console_store,
            forwarder=upstream,
        )
        model_turn = assistant_model_turn or make_dynamic_model_backend(
            settings.model_endpoint, settings.model_api_key, settings.model_name
        )
        token_signer = ActionTokenSigner()
        undo_store = UndoStore()
        stream_turn = make_dynamic_stream_backend(
            settings.model_endpoint, settings.model_api_key, settings.model_name
        )
        conversation_store = ConversationStore(settings.conversation_dir)

        async def _summarize(text: str) -> str:
            """上下文压缩用的摘要器:复用动态模型后端(无工具),把旧对话压成中文要点。"""
            reply = await model_turn(
                [
                    {
                        "role": "system",
                        "content": "把以下控制台操作助手的多轮对话压成简洁中文要点,保留关键"
                        "事实/数字/结论与未完成事项,去掉寒暄与冗余,200 字内。只输出要点。",
                    },
                    {"role": "user", "content": text},
                ],
                [],
            )
            return reply.content or ""

        assistant_agent = AssistantAgent(
            pipeline,
            assistant_services,
            model_turn,
            token_signer=token_signer,
            stream_turn=stream_turn,
            conversation=conversation_store,
            summarizer=_summarize,
        )
        assistant_actuator = AssistantActuator(
            operation_registry, assistant_services, token_signer, undo_store
        )
        register_assistant_routes(
            app,
            pipeline,
            deps,
            complete,
            agent=assistant_agent,
            actuator=assistant_actuator,
            conversation=conversation_store,
        )
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

        # 出口闸门:对回复做敏感/危险内容检测;高危则拦截打码,不把疑似外泄内容回给用户。
        if reply.ok and reply.reply:
            out = await pipeline.screen_output(body.session_id, reply.reply)
            resp.output_decision = out.decision
            resp.output_risk_level = out.risk_level
            resp.output_reason = out.reason
            if out.decision == Disposition.BLOCK:
                resp.output_blocked = True
                resp.reply = "[出口安全策略:回复疑似含敏感数据,已拦截不予返回]"
            elif out.decision == Disposition.SANITIZE:
                # 复核档且只夹带可打码的结构化敏感量:脱敏后回传,用户仍拿到实质答复。
                resp.output_sanitized = True
                resp.reply = redact(reply.reply)
        return resp

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
