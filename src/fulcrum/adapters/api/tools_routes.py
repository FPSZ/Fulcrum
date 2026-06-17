"""工具网关路由 —— 工具调用治理流水(展示 + 处置),经 tools.view 鉴权。

对应路线图 P1「工具网关页:工具调用流水 + 处置(allow/approve/block)」。工具调用穿过枢衡时
(模型编排 / 直接工具调用)逐次过 归因→评分→任务链→策略→处置,判定点带丰富证据落审计;
本端点把这些判定点投影成工具调用流水。前置网关「只筛输入」的路径无工具调用,故默认为空。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Query

from ...core.domain import AuditEvent, AuditEventType
from ..audit.memory_sink import InMemoryAuditSink
from ..auth import Principal
from .deps import AuthDeps
from .schemas import ToolCallDTO

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline


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


def register_tools_routes(app: FastAPI, pipeline: SecurityPipeline, deps: AuthDeps) -> None:
    can_view = deps.require("tools.view")

    @app.get("/tools/calls", response_model=list[ToolCallDTO])
    async def tool_calls(
        limit: int = Query(default=200, ge=1, le=1000),
        _: Principal = Depends(can_view),
    ) -> list[ToolCallDTO]:
        sink = pipeline.audit
        # 跨会话聚合是内存实现的具体能力(端口只暴露 per-session 读);非内存实现暂返回空。
        if not isinstance(sink, InMemoryAuditSink):
            return []
        return build_tool_calls(sink.all_events())[:limit]
