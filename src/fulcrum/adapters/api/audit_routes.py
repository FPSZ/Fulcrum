"""审计溯源路由 —— 把 append-only hash-chain 列成可视化的会话链,经 audit.view 鉴权。

`/audit/{session_id}`(见 app.py)取单条链;本端点 `GET /audit` 列出**所有**会话链
+ 各自的 hash-chain 校验结论 + 从链派生的一句话情景,供审计页左侧会话列表直接渲染。
逐链校验诚实反映防篡改性:任一事件被篡改 → 该会话标记「已篡改」。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI

from ...core.domain import AuditEvent, AuditEventType
from ..audit.memory_sink import InMemoryAuditSink
from ..auth import Principal
from .deps import AuthDeps
from .schemas import AuditChainEventDTO, AuditResponse, AuditSessionDTO

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline


def _chain_event(event: AuditEvent) -> AuditChainEventDTO:
    return AuditChainEventDTO(
        index=event.index,
        event_type=event.event_type.value,
        subject_id=event.subject_id,
        decision=event.decision.value if event.decision else None,
        reason=str(event.evidence.get("reason") or ""),
        prev_hash=event.prev_hash,
        event_hash=event.event_hash,
    )


def _summary(events: list[AuditEvent]) -> str:
    """从链派生一句话情景:取最后一个判定点的理由;无则按事件数兜底。"""
    for event in reversed(events):
        if event.event_type == AuditEventType.POLICY_DECIDED:
            reason = str(event.evidence.get("reason") or "")
            if reason:
                return reason
    return f"审计链({len(events)} 个事件)"


def to_session_dto(session_id: str, events: list[AuditEvent], verified: bool) -> AuditSessionDTO:
    """把一条会话链映射成审计页所需的会话 DTO(纯函数,便于测试)。"""
    return AuditSessionDTO(
        session_id=session_id,
        verified=verified,
        summary=_summary(events),
        events=[_chain_event(e) for e in events],
    )


def register_audit_routes(app: FastAPI, pipeline: SecurityPipeline, deps: AuthDeps) -> None:
    can_view = deps.require("audit.view")

    @app.get("/audit", response_model=list[AuditSessionDTO])
    async def audit_sessions(_: Principal = Depends(can_view)) -> list[AuditSessionDTO]:
        sink = pipeline.audit
        # 列全部会话是内存实现的具体能力(端口只暴露 per-session 读);非内存实现暂返回空。
        if not isinstance(sink, InMemoryAuditSink):
            return []
        out: list[AuditSessionDTO] = []
        for sid in sink.session_ids():
            events = await sink.events(sid)
            verified = await sink.verify_chain(sid)
            out.append(to_session_dto(sid, events, verified))
        return out

    @app.get("/audit/{session_id}", response_model=AuditResponse)
    async def audit_detail(session_id: str, _: Principal = Depends(can_view)) -> AuditResponse:
        # 单条会话链(全事件 + 哈希校验);与 /audit 列表同口径鉴权(audit.view),
        # 不再裸奔 —— 审计链含判定证据,未授权读取等于把溯源数据泄露出去。
        events = await pipeline.audit.events(session_id)
        return AuditResponse(
            session_id=session_id,
            verified=await pipeline.audit.verify_chain(session_id),
            events=[e.model_dump(mode="json") for e in events],
        )
