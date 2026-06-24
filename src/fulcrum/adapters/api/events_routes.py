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

from fastapi import Depends, FastAPI, HTTPException, Query, status

from ...core.domain import AuditEvent, AuditEventType, Disposition
from ..auth import Principal
from .deps import AuthDeps
from .schemas import EventResolveRequest, EventResolveResponse, SecurityEventDTO

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


# 操作助手会话的 session_id 约定前缀(assistant:web:xxx / assistant:<user>)。
_ASSISTANT_SESSION_PREFIX = "assistant:"


def is_feed_noise(event: AuditEvent) -> bool:
    """该判定点是否为事件墙噪音,不投影成安全事件行。

    两类不上墙(审计哈希链仍保全痕,这里只过滤展示投影):
    ① 助手「吃狗粮」的工具返回闸:每读一次后端数据就筛一次(纵深防御),干净放行(ALLOW)
       没有安全价值,却会让一轮多步对话刷出十几行重复 —— 只有真抓到间接注入/敏感量
       (拦截/净化/待审)才值得展示。
    ② 助手会话里被判「待审批」(APPROVE)但操作员尚未在对话里点「发起审批申请」的:
       助手把它当面提示「需管理员审批,是否发起?」由人决定;只有显式发起(下方端点落
       evidence.approval_requested=True)才作为真工单进待审批,避免每条可疑判定都自动塞满。
    """
    ev = event.evidence
    disp = event.decision or Disposition.ALLOW
    if ev.get("stage") == "tool_return_gateway" and disp == Disposition.ALLOW:
        return True
    if (
        disp == Disposition.APPROVE
        and event.session_id.startswith(_ASSISTANT_SESSION_PREFIX)
        and not ev.get("approval_requested")
    ):
        return True
    return False


def event_team_visible(event: AuditEvent, principal: Principal) -> bool:
    """该事件是否对当事人可见(plan/13 P2 团队级数据隔离)。

    向后兼容、不破坏演示:
    - 事件**无团队归属**(evidence 无 team_id;演示流量 / 助手内部活动)→ 对任何 events.view 可见;
    - 事件**有团队归属**→ 仅本团队成员/负责人(team_ids ∪ managed_teams)及组织级管理员可见,
      跨团队看不到——政企不同处室/局的流量彼此隔离。
    组织级(users.manage)视为跨租户监管,看全部;细化到专门的"全租户事件"权限留 P3。
    """
    team = event.evidence.get("team_id")
    if team is None:
        return True
    if principal.has("users.manage"):
        return True
    return int(team) in (frozenset(principal.team_ids) | frozenset(principal.managed_teams))


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
    can_handle = deps.require("events.handle")  # 处置(批准放行/维持阻断)是写操作,单独鉴权

    @app.get("/events", response_model=list[SecurityEventDTO])
    async def events(
        limit: int = Query(default=200, ge=1, le=1000),
        principal: Principal = Depends(can_view),
    ) -> list[SecurityEventDTO]:
        sink = pipeline.audit  # 跨会话聚合走端口方法(内存遍历 / SQLite 按 created_at 查询)
        # 已被处置的待审工单(存在一条 evidence.resolves=该 id 的处置事件)→ 不再挂在待审批,
        # 由处置结果(放行/阻断)那一行取而代之。append-only:原工单仍留在审计链中可溯源。
        resolved: set[str] = {
            str(e.evidence["resolves"])
            for e in sink.all_events()
            if e.event_type == AuditEventType.POLICY_DECIDED and e.evidence.get("resolves")
        }
        verified_cache: dict[str, bool] = {}
        rows: list[SecurityEventDTO] = []
        for e in sink.all_events():
            if e.event_type != AuditEventType.POLICY_DECIDED:
                continue
            if e.event_id in resolved:  # 待审工单已处置,隐去原行
                continue
            if is_feed_noise(e):  # 助手吃狗粮的干净工具返回筛查 —— 不刷上墙(详见 is_feed_noise)
                continue
            if not event_team_visible(e, principal):  # 团队级数据隔离:跨团队看不到(P2)
                continue
            if e.session_id not in verified_cache:
                verified_cache[e.session_id] = await sink.verify_chain(e.session_id)
            rows.append(to_security_event(e, verified_cache[e.session_id]))
        rows.sort(key=lambda r: r.time, reverse=True)  # 最新在前
        return rows[:limit]

    @app.post("/events/{event_id}/resolve", response_model=EventResolveResponse)
    async def resolve_event(
        event_id: str,
        body: EventResolveRequest,
        principal: Principal = Depends(can_handle),
    ) -> EventResolveResponse:
        """处置一条待审批事件:批准放行 / 维持阻断。落一条带 resolves 的处置判定点(append-only)。

        处置后原待审工单从墙上隐去,代之以放行/阻断结果行;原工单与本处置都留在审计链可溯源,
        处置人(actor)、决定与理由一并入证据。
        """
        sink = pipeline.audit  # all_events()/append() 经端口暴露,任意 sink(内存/SQLite)同口径
        original = next((e for e in sink.all_events() if e.event_id == event_id), None)
        if original is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="事件不存在")
        if (original.decision or Disposition.ALLOW) != Disposition.APPROVE:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="该事件不是待审批项,无需处置"
            )
        decision = Disposition.ALLOW if body.decision == "allow" else Disposition.BLOCK
        ev = original.evidence
        default_note = "管理员批准放行" if decision == Disposition.ALLOW else "管理员维持阻断"
        await sink.append(
            AuditEvent(
                session_id=original.session_id,
                event_type=AuditEventType.POLICY_DECIDED,
                subject_id=original.subject_id,
                decision=decision,
                evidence={
                    "resolves": event_id,
                    "stage": ev.get("stage"),
                    "source_type": ev.get("source_type"),
                    "trust_level": ev.get("trust_level"),
                    "risk_level": ev.get("risk_level"),
                    "excerpt": ev.get("excerpt", ""),
                    "max_score": ev.get("max_score", 0.0),
                    "reason": body.note.strip() or default_note,
                    "actor": principal.username,
                },
            )
        )
        return EventResolveResponse(ok=True)
