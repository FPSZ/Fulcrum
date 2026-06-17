"""会话事件流路由 —— 把审计判定点投影成可溯源的安全事件行,经 events.view 鉴权。

事件页要的是「一条经过安全管线的事件 + 证据归因链」,而审计是更细粒度的逐步留痕。
本端点取每个判定点(policy_decided)审计事件,连同其落下的判定依据映射成一行事件;
同会话 hash-chain 校验结果作为该行的防篡改标记。

判定点分三类闸门(按 evidence 区分),标题/字段各自对齐,避免一律按「输入」误标:
- **输入闸门**(`stage=input_gateway`):用户输入筛查,摘要/来源/置信度。
- **出口闸门**(`stage=output_gateway`):企业回复检测,回复摘要(脱敏)。
- **工具治理**(evidence 带 `tool`):逐工具调用,填工具名/参数/来源信任/风险评分/命中规则。
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

# 各闸门按处置归纳的事件标题(中文短语,供事件页大标题展示)。
_TITLE_INPUT: dict[Disposition, str] = {
    Disposition.BLOCK: "高危输入拦截",
    Disposition.APPROVE: "可疑输入待审",
    Disposition.SANITIZE: "输入净化",
    Disposition.ALLOW: "正常输入放行",
}
_TITLE_OUTPUT: dict[Disposition, str] = {
    Disposition.BLOCK: "回复敏感拦截",
    Disposition.APPROVE: "回复待人工复核",
    Disposition.SANITIZE: "回复净化",
    Disposition.ALLOW: "回复放行",
}
_TITLE_TOOL: dict[Disposition, str] = {
    Disposition.BLOCK: "工具调用阻断",
    Disposition.APPROVE: "工具调用待审批",
    Disposition.SANITIZE: "工具调用净化",
    Disposition.ALLOW: "工具调用放行",
}


def to_security_event(event: AuditEvent, verified: bool) -> SecurityEventDTO:
    """把一个 policy_decided 审计事件 + 其证据映射成事件行(纯函数,便于测试)。

    按闸门类型区分标题与字段:工具治理判定填工具名/参数/来源信任/风险评分;出口检测判定
    用回复语义标题、来源标 assistant;输入闸门保持原语义。绝不把工具/出口判定误标为「输入」。
    """
    ev = event.evidence
    disp = event.decision or Disposition.ALLOW

    if ev.get("tool"):  # 工具治理判定点(带 tool 证据)
        return SecurityEventDTO(
            id=event.event_id,
            time=event.created_at,
            sess=event.session_id,
            src_type=str(ev.get("source_type") or "user"),
            trust=str(ev.get("source_trust") or "untrusted"),
            risk=_TITLE_TOOL.get(disp, "工具调用"),
            tool=str(ev.get("tool") or ""),
            policy=str(ev.get("matched_policy") or "工具治理"),
            level=str(ev.get("risk_level") or "low"),
            disp=disp.value,
            verified=verified,
            excerpt="",
            intent="",
            args=str(ev.get("args") or ""),
            conf=float(ev.get("risk_score") or 0.0),
            derived="",
            reason=str(ev.get("reason") or ""),
        )

    is_output = ev.get("stage") == "output_gateway"
    title = (_TITLE_OUTPUT if is_output else _TITLE_INPUT).get(disp, "安全事件")
    return SecurityEventDTO(
        id=event.event_id,
        time=event.created_at,
        sess=event.session_id,
        src_type=str(ev.get("source_type") or ("assistant" if is_output else "user")),
        trust=str(ev.get("trust_level") or "untrusted"),
        risk=title,
        tool="",
        policy="出口检测" if is_output else "前置网关",
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
