"""AI 操作助手路由 —— 自然语言意图 → 受治理的动作规划,经 ai.operate 鉴权。

`POST /assistant/plan`:把操作员意图交给规划大脑(adapters/assistant),后端**强制** RBAC
(只能调当前角色有权的动作)与风险分级(高危标 requires_confirmation),并把这次规划写入
审计 hash-chain(ASSISTANT_PLANNED:谁、经由助手、想做什么、判成什么)。
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

    @app.post("/assistant/plan", response_model=AssistantPlanResponse)
    async def assistant_plan(
        body: AssistantPlanRequest,
        principal: Principal = Depends(can_operate),
    ) -> AssistantPlanResponse:
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
        # 每次规划入审计链:谁、经由助手、意图、判成什么动作(高危/越权一并留痕)。
        session_id = body.session_id or f"assistant:{principal.username}"
        await pipeline.audit.append(
            AuditEvent(
                session_id=session_id,
                event_type=AuditEventType.ASSISTANT_PLANNED,
                subject_id=outcome.action_id,
                decision=_disposition_of(resp),
                evidence={
                    "actor": principal.username,
                    "intent": body.intent,
                    "action_id": outcome.action_id,
                    "risk": outcome.risk,
                    "denied": outcome.denied,
                    "requires_confirmation": outcome.requires_confirmation,
                    "reason": outcome.reason,
                },
            )
        )
        return resp
