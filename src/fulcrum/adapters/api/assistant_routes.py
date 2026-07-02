"""AI 操作助手路由 —— 自然语言意图 → 受治理的动作规划,经 ai.operate 鉴权。

`POST /assistant/plan`:**先把操作员意图过枢衡自家输入网关**(`screen_input`:与保护企业
智能体同一套检测/策略/审计——"吃自己的狗粮",doc 05 §1.3.1),网关判恶意即拦截、**根本不
提交给模型规划**;放行后再交规划大脑(adapters/assistant),后端**强制** RBAC(只能调当前
角色有权的动作)与风险分级(高危标 requires_confirmation)。每次规划写入审计 hash-chain
(ASSISTANT_PLANNED:谁、经由助手、想做什么、判成什么 + 网关判定)。
`GET /assistant/actions`:列「当前角色能调的动作」——与前端按钮同一套权限点过滤(doc 05 §2.2)。

边界:本端点只**规划**(选哪个动作 + 是否准许),不执行 UI 操作;高危动作的真正执行仍要前端
二次确认并各自命中 RBAC 守卫端点(纵深防御,不靠助手自觉)。
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import StreamingResponse

from ...core.domain import AuditEvent, AuditEventType, Disposition
from ...core.operations import operation_registry
from ..assistant import DEFAULT_CATALOG, Action, plan
from ..auth import Principal
from .deps import AuthDeps
from .schemas import (
    AssistantActionDTO,
    AssistantApprovalRequestDTO,
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantConfirmRequest,
    AssistantConfirmResponse,
    AssistantModelConfigDTO,
    AssistantModelConfigUpdate,
    AssistantModelTestRequest,
    AssistantModelTestResponse,
    AssistantPlanRequest,
    AssistantPlanResponse,
    AssistantProposedActionDTO,
    AssistantRequestApprovalRequest,
    AssistantRequestApprovalResponse,
    AssistantResetRequest,
    AssistantResetResponse,
    AssistantStepDTO,
    AssistantToolDTO,
    AssistantUiDirectiveDTO,
    AssistantUndoRequest,
    AssistantUndoResponse,
)

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
    from ..assistant import (
        AssistantActuator,
        AssistantAgent,
        AssistantModelConfigStore,
        ConversationStore,
    )
    from ..assistant.planner import ModelComplete


# 模型未配置时给操作员的统一提示(前端有呼吸灯,这是后端纵深兜底)。
_NOT_READY_REPLY = "模型尚未配置。请点击输入框左侧的设置按钮,配置模型协议、端点与密钥后再使用。"


# 规划结果 → 审计处置:准许且需确认=待批,准许直执行=放行,越权=拦截,未对应=无判定。
def _disposition_of(result: AssistantPlanResponse) -> Disposition | None:
    if result.denied:
        return Disposition.BLOCK
    if not result.ok:
        return None
    return Disposition.APPROVE if result.requires_confirmation else Disposition.ALLOW


def _visible_actions(catalog: tuple[Action, ...], principal: Principal) -> list[AssistantActionDTO]:
    """只列当前角色权限点全覆盖的动作 —— 助手能调的动作 = 角色能点的按钮。"""
    out: list[AssistantActionDTO] = []
    for a in catalog:
        if all(principal.has(p) for p in a.requires):
            out.append(
                AssistantActionDTO(
                    id=a.id,
                    label=a.label,
                    description=a.description,
                    risk=a.risk,
                    requires=list(a.requires),
                    args_hint=a.args_hint,
                )
            )
    return out


def register_assistant_routes(
    app: FastAPI,
    pipeline: SecurityPipeline,
    deps: AuthDeps,
    complete: ModelComplete,
    catalog: tuple[Action, ...] = DEFAULT_CATALOG,
    agent: AssistantAgent | None = None,
    actuator: AssistantActuator | None = None,
    conversation: ConversationStore | None = None,
    model_store: AssistantModelConfigStore | None = None,
    model_fallback_key: str = "",
    enforce_model_ready: bool = False,
) -> None:
    can_operate = deps.require("ai.operate")
    can_configure = deps.require("ai.configure")  # 配置模型接入:高敏,默认仅超管+系统管理员

    def _scoped(principal: Principal, raw: str | None) -> str:
        """把客户端会话 id 收敛进当前登录者命名空间:存储/审计键 = 用户名 + 客户端子键。

        session_id 由客户端提供且格式可猜(默认 `assistant:<用户名>`)。若直接用它作存储键,
        任意 ai.operate 用户传 `session_id="<他人>"` 即可读到/清空他人助手记忆(横向越权)。
        服务端强制以已认证的 principal.username 作前缀:不同用户即便传同一 id 也落各自命名空间,
        结构性杜绝跨用户读/清 —— 属主绑定。"""
        sub = (raw or "").strip() or "default"
        return f"assistant:{principal.username}:{sub}"

    def _model_not_ready() -> bool:
        """是否应因「模型未配置」拦截对话:仅在真后端(非测试注入假后端)下启用。"""
        return enforce_model_ready and model_store is not None and not model_store.load().is_ready

    @app.get("/assistant/actions", response_model=list[AssistantActionDTO])
    async def assistant_actions(
        principal: Principal = Depends(can_operate),
    ) -> list[AssistantActionDTO]:
        return _visible_actions(catalog, principal)

    # ── 真 Agent(plan/11):工具目录 + 对话执行 ─────────────────────────
    @app.get("/assistant/tools", response_model=list[AssistantToolDTO])
    async def assistant_tools(
        principal: Principal = Depends(can_operate),
    ) -> list[AssistantToolDTO]:
        """当前角色可调的工具 = 助手能用的工具(从操作注册表按权限派生,单一真源)。"""
        return [
            AssistantToolDTO(
                name=t.name,
                kind=t.kind,
                label=t.label,
                description=t.description,
                risk=t.risk,
                requires=list(t.requires),
                reversible=t.reversible,
            )
            for t in operation_registry.visible_for(principal)
        ]

    @app.post("/assistant/chat", response_model=AssistantChatResponse)
    async def assistant_chat(
        body: AssistantChatRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantChatResponse:
        """真执行 Agent:意图→自动跑读类/ui、产出写类待确认提案 + 最终答复 + 执行轨迹。

        三道吃狗粮闸门(入口/工具返回/出口)由 AssistantAgent 内部强制;一次会话落一条
        ASSISTANT_CHAT 审计。agent 未装配(纯管线测试)时回 503 语义的诚实提示。
        """
        session_id = _scoped(principal, body.session_id)
        if agent is None:
            return AssistantChatResponse(
                session_id=session_id,
                reply="助手 Agent 未装配(当前实例未启用)。",
                blocked=True,
            )
        if _model_not_ready():
            return AssistantChatResponse(
                session_id=session_id, reply=_NOT_READY_REPLY, blocked=True
            )
        run = await agent.run(body.message, principal, session_id)
        return AssistantChatResponse(
            session_id=run.session_id,
            reply=run.reply,
            blocked=run.blocked,
            compressed=run.compressed,
            ui_directives=[
                AssistantUiDirectiveDTO(tool=d.tool, label=d.label, args=d.args)
                for d in run.ui_directives
            ],
            proposed_actions=[
                AssistantProposedActionDTO(
                    tool=p.tool,
                    label=p.label,
                    risk=p.risk,
                    args=p.args,
                    requires=p.requires,
                    note=p.note,
                    action_token=p.action_token,
                    reversible=p.reversible,
                    before=p.before,
                )
                for p in run.proposed_actions
            ],
            approval_requests=[
                AssistantApprovalRequestDTO(
                    stage=a.stage,
                    title=a.title,
                    reason=a.reason,
                    risk_level=a.risk_level,
                    excerpt=a.excerpt,
                    score=a.score,
                )
                for a in run.approval_requests
            ],
            steps=[
                AssistantStepDTO(tool=s.tool, kind=s.kind, label=s.label, ok=s.ok, detail=s.detail)
                for s in run.steps
            ],
        )

    @app.post("/assistant/chat/stream")
    async def assistant_chat_stream(
        body: AssistantChatRequest,
        principal: Principal = Depends(can_operate),
    ) -> StreamingResponse:
        """流式真 Agent(SSE):逐字吐最终答复 + 实时下发 step/ui/proposal 事件。

        与 /assistant/chat 同语义、同三道闸门;事件 `data: {json}\\n\\n`,类型见 agent.run_stream。
        """
        session_id = _scoped(principal, body.session_id)

        not_ready = _model_not_ready()

        async def gen() -> AsyncIterator[bytes]:
            if agent is None or not_ready:
                reply = "助手 Agent 未装配(当前实例未启用)。" if agent is None else _NOT_READY_REPLY
                payload = {
                    "type": "done",
                    "session_id": session_id,
                    "blocked": True,
                    "reply": reply,
                }
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode()
                return
            async for ev in agent.run_stream(body.message, principal, session_id):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode()

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/assistant/reset", response_model=AssistantResetResponse)
    async def assistant_reset(
        body: AssistantResetRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantResetResponse:
        """清空某会话的多轮记忆(新建会话 / 显式清除上下文)。无记忆存储时静默成功。"""
        if conversation is not None:
            conversation.reset(_scoped(principal, body.session_id))
        return AssistantResetResponse(ok=True)

    @app.post("/assistant/request-approval", response_model=AssistantRequestApprovalResponse)
    async def assistant_request_approval(
        body: AssistantRequestApprovalRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantRequestApprovalResponse:
        """操作员在对话里「发起审批申请」→ 落一条真·待审批工单(进实时事件·待审批)。

        与自动筛查的区别:闸门判 APPROVE 时**不**自动塞待审批(否则无效信息泛滥);助手当面
        提示,只有操作员**显式发起**才在此落 evidence.approval_requested=True 的判定点——
        事件墙据此放行展示(见 events_routes.is_feed_noise)。落同会话审计链,可溯源到发起人。
        """
        # 仅审计关联键(不加载会话记忆,无跨用户读风险);沿用调用方 session_id。
        session_id = body.session_id or f"assistant:{principal.username}"
        is_output = body.stage == "output"
        await pipeline.audit.append(
            AuditEvent(
                session_id=session_id,
                event_type=AuditEventType.POLICY_DECIDED,
                subject_id=principal.username,
                decision=Disposition.APPROVE,
                evidence={
                    "approval_requested": True,
                    "stage": "output_gateway" if is_output else "input_gateway",
                    "reason": body.reason,
                    "risk_level": body.risk_level,
                    "max_score": body.score,
                    "excerpt": body.excerpt,
                    "source_type": "assistant" if is_output else "user",
                    "trust_level": "untrusted",
                    "actor": principal.username,
                },
            )
        )
        return AssistantRequestApprovalResponse(ok=True)

    # ── 模型接入配置:协议/端点/密钥/模型名(本地私有化优先;密钥掩码不回显)──────
    def _config_dto() -> AssistantModelConfigDTO:
        from ..assistant import AssistantModelConfigPublic

        assert model_store is not None
        pub = AssistantModelConfigPublic.of(model_store.load())
        return AssistantModelConfigDTO(**pub.model_dump())

    @app.get("/assistant/model-config", response_model=AssistantModelConfigDTO)
    async def assistant_model_config_get(
        _principal: Principal = Depends(can_operate),
    ) -> AssistantModelConfigDTO:
        """读当前模型接入配置(密钥掩码)。未装配存储 → 返回空未配置态(前端据此亮呼吸灯)。"""
        if model_store is None:
            return AssistantModelConfigDTO(
                protocol="openai",
                endpoint="",
                model="",
                api_key_masked="",
                api_key_set=False,
                timeout_seconds=90.0,
                verify_tls=True,
                configured=False,
                ready=False,
            )
        return _config_dto()

    @app.put("/assistant/model-config", response_model=AssistantModelConfigDTO)
    async def assistant_model_config_put(
        body: AssistantModelConfigUpdate,
        _principal: Principal = Depends(can_configure),
    ) -> AssistantModelConfigDTO:
        """保存模型接入配置(需 settings.manage)。保存即标记 configured,热加载生效。

        api_key=None 保持原密钥(防前端把掩码写回覆盖真值);""=清空;非空=设新值。
        """
        from ..assistant import AssistantModelConfig

        if model_store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="模型配置存储未装配"
            )
        cur = model_store.load()
        new_key = cur.api_key if body.api_key is None else body.api_key
        saved = model_store.save(
            AssistantModelConfig(
                protocol=body.protocol,
                endpoint=body.endpoint.strip(),
                api_key=new_key,
                model=body.model.strip(),
                timeout_seconds=body.timeout_seconds,
                verify_tls=body.verify_tls,
                configured=True,
            )
        )
        from ..assistant import AssistantModelConfigPublic

        return AssistantModelConfigDTO(**AssistantModelConfigPublic.of(saved).model_dump())

    @app.post("/assistant/model-config/test", response_model=AssistantModelTestResponse)
    async def assistant_model_config_test(
        body: AssistantModelTestRequest,
        _principal: Principal = Depends(can_configure),
    ) -> AssistantModelTestResponse:
        """用「待保存的表单值」试调一次(不落盘)。api_key=None 时复用已存密钥。"""
        import time

        from ..assistant import AssistantModelConfig, make_config_model_backend

        stored_key = model_store.load().api_key if model_store is not None else ""
        probe = AssistantModelConfig(
            protocol=body.protocol,
            endpoint=body.endpoint.strip(),
            api_key=(stored_key if body.api_key is None else body.api_key),
            model=body.model.strip(),
            timeout_seconds=body.timeout_seconds,
            verify_tls=body.verify_tls,
            configured=True,
        )
        if not probe.endpoint or not probe.model:
            return AssistantModelTestResponse(ok=False, detail="端点和模型名不能为空")
        backend = make_config_model_backend(lambda: probe, model_fallback_key)
        t0 = time.monotonic()
        reply = await backend([{"role": "user", "content": "ping"}], [])
        latency = int((time.monotonic() - t0) * 1000)
        if reply.content or reply.tool_calls:
            return AssistantModelTestResponse(
                ok=True, detail="连接成功,模型已响应。", latency_ms=latency
            )
        return AssistantModelTestResponse(
            ok=False,
            detail="未收到模型回复:请检查端点/协议/密钥/模型名是否正确,以及服务是否可达。",
            latency_ms=latency,
        )

    # ── 写操作:确认执行 + 一键撤销(plan/11 §6;人闸在 chat 循环之外)──────
    @app.post("/assistant/confirm", response_model=AssistantConfirmResponse)
    async def assistant_confirm(
        body: AssistantConfirmRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantConfirmResponse:
        """确认执行某写提案(带编辑后参数)。纵深 RBAC 在 actuator 内强制;越权 → 403。"""
        if actuator is None:
            return AssistantConfirmResponse(
                ok=False, summary="助手执行器未装配。", error="no_actuator"
            )
        # 授权由 action_token + actuator 内 RBAC 强制;session_id 仅审计关联键,沿用调用方值。
        session_id = body.session_id or f"assistant:{principal.username}"
        res = await actuator.confirm(body.action_token, body.edited_args, principal, session_id)
        if res.denied:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=res.summary)
        return AssistantConfirmResponse(
            ok=res.ok,
            summary=res.summary,
            action_id=res.action_id,
            reversible=res.reversible,
            undo_preview=res.undo_preview,
            error=res.error,
        )

    @app.post("/assistant/undo", response_model=AssistantUndoResponse)
    async def assistant_undo(
        body: AssistantUndoRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantUndoResponse:
        """一键撤销某已执行写操作(逆操作回滚)。撤销与原写操作同权;越权 → 403。"""
        if actuator is None:
            return AssistantUndoResponse(
                ok=False, summary="助手执行器未装配。", error="no_actuator"
            )
        # 授权由 action_id + actuator 内 RBAC 强制;session_id 仅审计关联键,沿用调用方值。
        session_id = body.session_id or f"assistant:{principal.username}"
        res = await actuator.undo(body.action_id, principal, session_id)
        if res.denied:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=res.summary)
        return AssistantUndoResponse(ok=res.ok, summary=res.summary, error=res.error)

    async def _audit_plan(
        session_id: str,
        actor: str,
        intent: str,
        resp: AssistantPlanResponse,
        gateway_decision: str,
        gateway_score: float,
    ) -> None:
        """规划结果入审计链:谁、经由助手、意图、判成什么动作 + 网关判定(高危/越权/被拦一并留痕)。"""
        await pipeline.audit.append(
            AuditEvent(
                session_id=session_id,
                event_type=AuditEventType.ASSISTANT_PLANNED,
                subject_id=resp.action_id,
                decision=_disposition_of(resp),
                evidence={
                    "actor": actor,
                    "intent": intent,
                    "action_id": resp.action_id,
                    "risk": resp.risk,
                    "denied": resp.denied,
                    "requires_confirmation": resp.requires_confirmation,
                    "reason": resp.reason,
                    "gateway_decision": gateway_decision,
                    "gateway_score": gateway_score,
                },
            )
        )

    @app.post("/assistant/plan", response_model=AssistantPlanResponse)
    async def assistant_plan(
        body: AssistantPlanRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantPlanResponse:
        # 仅网关判定 + 审计(不加载会话记忆);session_id 沿用调用方值作审计关联键。
        session_id = body.session_id or f"assistant:{principal.username}"

        # 吃自己的狗粮:助手的请求先过枢衡输入网关(检测/策略/审计,与企业智能体同一套)。
        # 网关判恶意 → 拦截,**根本不提交给模型规划**;screen_input 已自落 input_gateway 审计链。
        gate = await pipeline.screen_input(session_id, body.intent)
        if gate.decision == Disposition.BLOCK:
            resp = AssistantPlanResponse(
                ok=False,
                denied=True,
                reason=f"你的意图被安全网关判为高危并拦截({gate.reason}),未提交模型规划。",
            )
            await _audit_plan(
                session_id,
                principal.username,
                body.intent,
                resp,
                gate.decision.value,
                gate.max_score,
            )
            return resp

        outcome = await plan(body.intent, principal.permissions, complete, catalog)
        resp = AssistantPlanResponse(
            ok=outcome.ok,
            reason=outcome.reason,
            action_id=outcome.action_id,
            label=outcome.label,
            args=outcome.args,
            risk=outcome.risk,
            requires_confirmation=outcome.requires_confirmation,
            denied=outcome.denied,
        )
        await _audit_plan(
            session_id, principal.username, body.intent, resp, gate.decision.value, gate.max_score
        )
        return resp
