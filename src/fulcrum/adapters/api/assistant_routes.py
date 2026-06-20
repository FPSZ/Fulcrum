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

from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI

from ...core.domain import AuditEvent, AuditEventType, Disposition
from ..assistant import DEFAULT_CATALOG, Action, plan
from ..auth import Principal
from .deps import AuthDeps
from .schemas import AssistantActionDTO, AssistantPlanRequest, AssistantPlanResponse

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
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
) -> None:
    can_operate = deps.require("ai.operate")

    @app.get("/assistant/actions", response_model=list[AssistantActionDTO])
    async def assistant_actions(
        principal: Principal = Depends(can_operate),
    ) -> list[AssistantActionDTO]:
        return _visible_actions(catalog, principal)

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
