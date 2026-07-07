"""安全总览统计路由 —— 从审计链实时聚合 KPI,经 overview.view 权限强制鉴权。

总览页四张 KPI 卡(受控请求 / 拦截 / 待审批 / 审计完整率)由本端点接真:
计数全部来自管线落下的 hash-chain 审计事件,跨会话汇总。无流量 → 各计数为 0,
诚实反映空闲网关,而非编造数字。时序趋势不在此(审计事件不带时间戳)。
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI

from ...core.domain import AuditEvent, AuditEventType
from ..audit.hashchain import locate_break
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
        # M14:此前 per-session `verify_chain`(每次全量重读该会话)+ `all_events()` = N+1 趟
        # 全量读,且同步 sqlite 直接跑在事件循环上 —— 前端轮询即认证后 DoS。现单遍取全量
        # (经 to_thread 卸载),按会话分组后就地 `locate_break` 校验:每事件仍全量重算哈希
        # (防篡改新鲜度不降级,故意不缓存校验结果),只是不再重复读库。
        sink = pipeline.audit
        events = await asyncio.to_thread(sink.all_events)
        chains: dict[str, list[AuditEvent]] = {}
        for e in events:
            chains.setdefault(e.session_id, []).append(e)
        verified = 0
        for chain in chains.values():
            chain.sort(key=lambda e: e.index)  # 与 sink 读路径 ORDER BY idx 同口径
            if locate_break(chain) is None:
                verified += 1
        return summarize(events, verified_sessions=verified)
