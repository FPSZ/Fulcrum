"""工具网关路由 —— 工具调用治理流水与受控提案。

对应路线图 P1「工具网关页:工具调用流水 + 处置(allow/approve/block)」。工具调用穿过枢衡时
(模型编排 / 直接工具调用)逐次过 归因→评分→任务链→策略→处置,判定点带丰富证据落审计;
本端点把这些判定点投影成工具调用流水。前置网关「只筛输入」的路径无工具调用,故默认为空。
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, HTTPException, Query, status

from ...core.domain import AuditEvent, AuditEventType, Disposition
from ..auth import Principal
from .deps import AuthDeps
from .schemas import AssistantProposedActionDTO, ToolCallDTO, ToolCallProposalRequest

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline
    from ..assistant import AssistantActuator


def _to_tool_call(event: AuditEvent, executed: bool) -> ToolCallDTO:
    ev = event.evidence
    rule = ev.get("matched_policy")
    trust = ev.get("source_trust")
    return ToolCallDTO(
        id=event.event_id,
        time=event.created_at,
        sess=event.session_id,
        tool=str(ev.get("tool") or ""),
        args=str(ev.get("args") or ""),
        source_trust=str(trust) if trust is not None else None,
        risk_score=float(ev.get("risk_score") or 0.0),
        risk_level=str(ev.get("risk_level") or "low"),
        attribution_confidence=float(ev.get("attribution_confidence") or 0.0),
        decision=event.decision.value if event.decision else "allow",
        rule=str(rule) if rule is not None else None,
        executed=executed,
        reason=str(ev.get("reason") or ""),
    )


def build_tool_calls(events: list[AuditEvent]) -> list[ToolCallDTO]:
    """从审计事件提取工具调用治理流水(纯函数,便于测试)。

    工具判定点 = 带 `tool` 证据的 policy_decided(区别于输入闸门的判定点);执行与否由同一
    意图(subject_id)下是否落了 tool_executed 关联。按时间倒序。
    """
    executed_ids = {
        e.subject_id
        for e in events
        if e.event_type == AuditEventType.TOOL_EXECUTED and e.subject_id
    }
    rows = [
        _to_tool_call(e, e.subject_id in executed_ids)
        for e in events
        if e.event_type == AuditEventType.POLICY_DECIDED and e.evidence.get("tool")
    ]
    rows.sort(key=lambda r: r.time, reverse=True)
    return rows


def register_tools_routes(
    app: FastAPI, pipeline: SecurityPipeline, deps: AuthDeps, actuator: AssistantActuator
) -> None:
    can_view = deps.require("tools.view")
    can_execute = deps.require("tools.execute")
    can_operate = deps.require("ai.operate")

    def _scoped(principal: Principal, raw: str | None) -> str:
        """将客户端会话子键纳入当前工具操作员的服务端命名空间。"""
        sub = (raw or "").strip() or "default"
        return f"tools:{principal.username}:{sub}"

    @app.get("/tools/calls", response_model=list[ToolCallDTO])
    async def tool_calls(
        limit: int = Query(default=200, ge=1, le=1000),
        _: Principal = Depends(can_view),
    ) -> list[ToolCallDTO]:
        # 跨会话聚合走端口方法(内存遍历 / SQLite 聚合查询,口径一致)。
        return build_tool_calls(pipeline.audit.all_events())[:limit]

    @app.post("/tools/call/proposal", response_model=AssistantProposedActionDTO)
    async def propose_tool_call(
        body: ToolCallProposalRequest,
        principal: Principal = Depends(can_execute),
        _: Principal = Depends(can_operate),
    ) -> AssistantProposedActionDTO:
        """控制台入口:输入闸→RBAC 提案→既有确认端点→策略执行。"""
        session_id = _scoped(principal, body.session_id)
        # 工具和参数来自操作员，同样先经过助手入口闸；不会进入模型或直连执行器。
        intent = json.dumps(
            {
                "tool_name": body.tool_name,
                "arguments": body.arguments,
                "source_ids": body.source_ids,
            },
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        gate = await pipeline.screen_input(session_id, intent)
        if gate.decision != Disposition.ALLOW:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"工具调用提案未通过输入安全闸:{gate.reason}",
            )

        args = {
            "session_id": session_id,
            "tool_name": body.tool_name,
            "arguments": body.arguments,
            "source_ids": body.source_ids,
        }
        proposal = await actuator.propose("call_tool", args, principal, session_id)
        if proposal.denied:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=proposal.summary)
        if not proposal.ok or proposal.tool is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=proposal.summary,
            )

        await pipeline.audit.append(
            AuditEvent(
                session_id=session_id,
                event_type=AuditEventType.ASSISTANT_PLANNED,
                subject_id=proposal.tool.name,
                decision=Disposition.APPROVE,
                evidence={
                    "actor": principal.username,
                    "tool": proposal.tool.name,
                    "target_tool": body.tool_name,
                    "requires_confirmation": True,
                    "gateway_decision": gate.decision.value,
                },
            )
        )
        return AssistantProposedActionDTO(
            tool=proposal.tool.name,
            label=proposal.tool.label,
            risk=proposal.tool.risk,
            args=args,
            requires=list(proposal.tool.requires),
            note=proposal.summary,
            action_token=proposal.action_token,
            reversible=proposal.tool.reversible,
            before=proposal.before,
        )
