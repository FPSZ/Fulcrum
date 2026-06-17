"""会话事件流路由 —— 把审计判定点投影成可溯源的安全事件行,经 events.view 鉴权。

事件页要的是「一条经过安全管线的事件 + 证据归因链」,而审计是更细粒度的逐步留痕。
本端点取每个判定点(policy_decided)审计事件,连同其落下的判定依据(摘要/来源/置信度/
理由)映射成一行事件;同会话 hash-chain 校验结果作为该行的防篡改标记。

诚实边界:前置网关「输入筛查」路径无工具调用,故 tool/intent/args 留空 —— 这是路径
本身如此,不是缺数据。逐工具调用的富事件待工具网关真实流量接入后自然填充。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Query

from ...core.domain import AuditEvent, AuditEventType, Disposition
from ..audit.memory_sink import InMemoryAuditSink
from ..auth import Principal
from .deps import AuthDeps
from .schemas import SecurityEventDTO

if TYPE_CHECKING:
    from ...core.pipeline import SecurityPipeline

# 按处置归纳的事件标题(中文短语,供事件页大标题/处置阶段展示)。
_TITLE: dict[Disposition, str] = {
    Disposition.BLOCK: "高危输入拦截",
    Disposition.APPROVE: "可疑输入待审",
    Disposition.SANITIZE: "输入净化",
    Disposition.ALLOW: "正常输入放行",
}


def to_security_event(event: AuditEvent, verified: bool) -> SecurityEventDTO:
    """把一个 policy_decided 审计事件 + 其证据映射成事件行(纯函数,便于测试)。"""
    ev = event.evidence
    disp = event.decision or Disposition.ALLOW
    return SecurityEventDTO(
        id=event.event_id,
        time=event.created_at,
        sess=event.session_id,
        src_type=str(ev.get("source_type") or "user"),
        trust=str(ev.get("trust_level") or "untrusted"),
        risk=_TITLE.get(disp, "安全事件"),
        tool="",
        policy=str(ev.get("matched_policy") or "前置网关"),
        level=str(ev.get("risk_level") or "low"),
        disp=disp.value,
        verified=verified,
        excerpt=str(ev.get("excerpt") or ""),
        intent="",
        args="",
        conf=float(ev.get("max_score") or 0.0),
        derived="",
        reason=str(ev.get("reason") or ""),
    )


def register_events_routes(app: FastAPI, pipeline: SecurityPipeline, deps: AuthDeps) -> None:
    can_view = deps.require("events.view")

    @app.get("/events", response_model=list[SecurityEventDTO])
    async def events(
        limit: int = Query(default=200, ge=1, le=1000),
        _: Principal = Depends(can_view),
    ) -> list[SecurityEventDTO]:
        sink = pipeline.audit
        # 跨会话聚合是内存实现的具体能力(端口只暴露 per-session 读);非内存实现暂返回空,
        # 待 SQLite 落库时以一条带 created_at 排序的查询提供等价能力。
        if not isinstance(sink, InMemoryAuditSink):
            return []
        verified_cache: dict[str, bool] = {}
        rows: list[SecurityEventDTO] = []
        for e in sink.all_events():
            if e.event_type != AuditEventType.POLICY_DECIDED:
                continue
            if e.session_id not in verified_cache:
                verified_cache[e.session_id] = await sink.verify_chain(e.session_id)
            rows.append(to_security_event(e, verified_cache[e.session_id]))
        rows.sort(key=lambda r: r.time, reverse=True)  # 最新在前
        return rows[:limit]
