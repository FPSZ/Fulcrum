"""安全总览统计路由 —— 从审计链实时聚合 KPI,经 overview.view 权限强制鉴权。

总览页四张 KPI 卡(受控请求 / 拦截 / 待审批 / 审计完整率)由本端点接真:
计数全部来自管线落下的 hash-chain 审计事件,跨会话汇总。无流量 → 各计数为 0,
诚实反映空闲网关,而非编造数字。时序趋势不在此(审计事件不带时间戳)。
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI

from ...core.domain import AuditEvent, AuditEventType
from ..audit.memory_sink import InMemoryAuditSink
from ..auth import Principal
from .deps import AuthDeps
from .schemas import OverviewStatsResponse

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline


def _gate_of(evidence: dict) -> str:
    """把一个判定点证据归到三类闸门之一(与 /events 同口径,避免两处漂移)。

    带 `tool` 证据 → 工具治理;`stage=output_gateway` → 出口检测;否则 → 输入闸门。
    """
    if evidence.get("tool"):
        return "tool"
    if evidence.get("stage") == "output_gateway":
        return "output"
    return "input"


def summarize(events: list[AuditEvent], verified_sessions: int = 0) -> OverviewStatsResponse:
    """把审计事件聚合成总览 KPI(纯函数,便于测试)。

    requests/blocked/pending 直接数对应事件类型;decisions 数 policy_decided 携带的处置;
    gates 把这些处置再按三类闸门(输入/出口/工具)拆开,让总览能分别看「出口拦了几条、
    工具拦了几条」而非只有一个总数;by_type 给全量事件类型分布。verified_sessions 由调用方传入。
    """
    by_type: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    gates: dict[str, Counter[str]] = {"input": Counter(), "output": Counter(), "tool": Counter()}
    sessions: set[str] = set()
    for e in events:
        by_type[e.event_type.value] += 1
        sessions.add(e.session_id)
        if e.event_type == AuditEventType.POLICY_DECIDED and e.decision is not None:
            decisions[e.decision.value] += 1
            gates[_gate_of(e.evidence)][e.decision.value] += 1
    return OverviewStatsResponse(
        sessions=len(sessions),
        events=len(events),
        verified_sessions=verified_sessions,
        requests=by_type.get(AuditEventType.REQUEST_RECEIVED.value, 0),
        blocked=by_type.get(AuditEventType.TOOL_BLOCKED.value, 0),
        pending=by_type.get(AuditEventType.TOOL_PENDING_APPROVAL.value, 0),
        decisions=dict(decisions),
        gates={gate: dict(counts) for gate, counts in gates.items()},
        by_type=dict(by_type),
    )


def register_overview_routes(app: FastAPI, pipeline: SecurityPipeline, deps: AuthDeps) -> None:
    can_view = deps.require("overview.view")

    @app.get("/overview/stats", response_model=OverviewStatsResponse)
    async def overview_stats(_: Principal = Depends(can_view)) -> OverviewStatsResponse:
        sink = pipeline.audit
        # 跨会话聚合是内存实现的具体能力(端口只暴露 per-session 读);非内存实现
        # 暂返回空统计(各计数 0),待 SQLite 落库时以聚合查询提供等价能力。
        if not isinstance(sink, InMemoryAuditSink):
            return OverviewStatsResponse()
        verified = 0
        for sid in sink.session_ids():
            if await sink.verify_chain(sid):
                verified += 1
        return summarize(sink.all_events(), verified_sessions=verified)
