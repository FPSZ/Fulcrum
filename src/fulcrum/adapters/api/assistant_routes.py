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
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantConfirmRequest,
    AssistantConfirmResponse,
    AssistantPlanRequest,
    AssistantPlanResponse,
    AssistantProposedActionDTO,
    AssistantStepDTO,
    AssistantToolDTO,
    AssistantUiDirectiveDTO,
    AssistantUndoRequest,
    AssistantUndoResponse,
)

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
    from ..assistant import AssistantActuator, AssistantAgent
    from ..assistant.planner import ModelComplete


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
) -> None:
    can_operate = deps.require("ai.operate")

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
        session_id = body.session_id or f"assistant:{principal.username}"
        if agent is None:
            return AssistantChatResponse(
                session_id=session_id,
                reply="助手 Agent 未装配(当前实例未启用)。",
                blocked=True,
            )
        run = await agent.run(body.message, principal, session_id)
        return AssistantChatResponse(
            session_id=run.session_id,
            reply=run.reply,
            blocked=run.blocked,
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
        session_id = body.session_id or f"assistant:{principal.username}"

        async def gen() -> AsyncIterator[bytes]:
            if agent is None:
                payload = {"type": "done", "session_id": session_id, "blocked": True,
                           "reply": "助手 Agent 未装配(当前实例未启用)。"}
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode()
                return
            async for ev in agent.run_stream(body.message, principal, session_id):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode()

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
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
