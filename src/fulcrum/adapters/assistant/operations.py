"""首批控制台操作注册(`@operation`)—— 把现有 ui + read 能力暴露成 AI 可调工具(plan/11 §2.2)。

读类 handler **复用各路由背后的纯投影函数**(summarize/to_security_event/build_tool_calls/
to_policy_set/scan_directory/load_report),与 REST 端点同源同口径——加一处读法即两处皆得,
不另抄一套。ui 类无 handler(前端执行),直接登记描述符。写类(approve/改配置…)留待 P2。

导入本模块即完成注册(对称:import 某 capability 模块即注册其实现类)。
"""

from __future__ import annotations

from typing import Any, cast

from ...core.domain import AuditEventType
from ...core.operations import AssistantTool, OperationResult, operation, operation_registry

# 复用各路由的纯投影函数(adapters→adapters,允许;与 REST 端点同一份读法)。
from ..api.eval_routes import load_report
from ..api.events_routes import to_security_event
from ..api.overview_routes import summarize
from ..api.policies_routes import to_policy_set
from ..api.supply_routes import scan_directory
from ..api.tools_routes import build_tool_calls
from ..audit.memory_sink import InMemoryAuditSink
from ..gateway import GatewayConfigPublic

_KNOWN_PAGES = (
    "overview",
    "events",
    "policies",
    "audit",
    "supply",
    "tools",
    "settings",
    "users",
)
_DISPOSITIONS = ("allow", "sanitize", "approve", "block")
_SEVERITIES = ("low", "medium", "high", "critical")


def _int(value: Any, default: int, lo: int, hi: int) -> int:
    """把模型给的 limit 收敛进 [lo, hi];非法/缺省回 default(防越界与畸形输入)。"""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


# ──────────────────────────── ui(前端执行,read_only)────────────────────────────
# ui 操作零风险、即时反馈,是助手"好用"的关键;无 handler,前端据 name+args 执行。
operation_registry.register(
    AssistantTool(
        name="navigate",
        kind="ui",
        label="跳转页面",
        description="把控制台切换到某个功能页。用于「帮我打开/跳到 X 页」;目标页仍受其权限守卫。",
        parameters={
            "type": "object",
            "properties": {
                "page": {"type": "string", "enum": list(_KNOWN_PAGES), "description": "目标功能页"}
            },
            "required": ["page"],
        },
        risk="read_only",
    )
)
operation_registry.register(
    AssistantTool(
        name="filter_events",
        kind="ui",
        label="筛选实时事件",
        description="切到实时事件页并按处置/严重度设置筛选,用于「只看被阻断的」「筛高危事件」等。",
        parameters={
            "type": "object",
            "properties": {
                "disposition": {"type": "string", "enum": list(_DISPOSITIONS)},
                "severity": {"type": "string", "enum": list(_SEVERITIES)},
            },
        },
        requires=("events.view",),
        risk="read_only",
    )
)
operation_registry.register(
    AssistantTool(
        name="open_settings_panel",
        kind="ui",
        label="打开设置面板",
        description="打开系统设置的某个二级面板(如 上游接入 / 通用 / 通知)。",
        parameters={
            "type": "object",
            "properties": {"panel": {"type": "string", "description": "面板标识"}},
            "required": ["panel"],
        },
        requires=("settings.view",),
        risk="read_only",
    )
)


# ──────────────────────────── read(后端,read_only,自动连环)────────────────────────────
@operation(
    name="get_overview_stats",
    kind="read",
    label="查安全总览",
    description="返回安全总览 KPI:受控请求/拦截/待审批数、各闸门处置分布、审计链校验通过数。",
    requires=("overview.view",),
)
async def get_overview_stats(args: dict, principal: Any, services: Any) -> OperationResult:
    sink = services.pipeline.audit
    if not isinstance(sink, InMemoryAuditSink):
        return OperationResult(summary="总览统计当前不可用(非内存审计实现)。", data=None)
    verified = 0
    for sid in sink.session_ids():
        if await sink.verify_chain(sid):
            verified += 1
    stats = summarize(sink.all_events(), verified_sessions=verified)
    summary = (
        f"安全总览:会话 {stats.sessions} 条、事件 {stats.events} 起、受控请求 {stats.requests}、"
        f"拦截 {stats.blocked}、待审批 {stats.pending}、审计链校验通过 {verified} 条。"
    )
    return OperationResult(summary=summary, data=stats.model_dump())


@operation(
    name="list_events",
    kind="read",
    label="列实时事件",
    description="列出经安全管线判定的事件行(可按处置筛选、限条数)。用于「最近有哪些拦截」「看可疑事件」。",
    params={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "返回条数上限(1~200,默认 20)"},
            "disposition": {
                "type": "string",
                "enum": list(_DISPOSITIONS),
                "description": "按处置筛选",
            },
        },
    },
    requires=("events.view",),
)
async def list_events(args: dict, principal: Any, services: Any) -> OperationResult:
    sink = services.pipeline.audit
    if not isinstance(sink, InMemoryAuditSink):
        return OperationResult(summary="事件流当前不可用(非内存审计实现)。", data=[])
    limit = _int(args.get("limit"), 20, 1, 200)
    disp = args.get("disposition")
    verified_cache: dict[str, bool] = {}
    rows = []
    for e in sink.all_events():
        if e.event_type != AuditEventType.POLICY_DECIDED:
            continue
        if e.session_id not in verified_cache:
            verified_cache[e.session_id] = await sink.verify_chain(e.session_id)
        row = to_security_event(e, verified_cache[e.session_id])
        if disp and row.disp != disp:
            continue
        rows.append(row)
    rows.sort(key=lambda r: r.time, reverse=True)
    rows = rows[:limit]
    head = "；".join(f"{r.risk}[{r.disp}]" for r in rows[:5])
    summary = (
        f"命中 {len(rows)} 条事件"
        + (f"(处置={disp})" if disp else "")
        + "。"
        + (f"最近:{head}。" if head else "")
    )
    return OperationResult(summary=summary, data=[r.model_dump() for r in rows])


@operation(
    name="list_audit_sessions",
    kind="read",
    label="列审计会话链",
    description="列出全部审计会话链及其防篡改校验结果(通过/断裂)。",
    requires=("audit.view",),
)
async def list_audit_sessions(args: dict, principal: Any, services: Any) -> OperationResult:
    sink = services.pipeline.audit
    if not isinstance(sink, InMemoryAuditSink):
        return OperationResult(summary="审计会话列表当前不可用(非内存审计实现)。", data=[])
    data = []
    verified_n = 0
    for sid in sink.session_ids():
        ok = await sink.verify_chain(sid)
        verified_n += 1 if ok else 0
        data.append({"session_id": sid, "events": len(await sink.events(sid)), "verified": ok})
    summary = f"共 {len(data)} 条会话链,其中 {verified_n} 条 hash-chain 校验通过。"
    return OperationResult(summary=summary, data=data)


@operation(
    name="get_audit_chain",
    kind="read",
    label="查审计链",
    description="取某条会话的逐事件审计链(类型/处置/下标),用于溯源某次会话发生了什么。",
    params={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    requires=("audit.view",),
)
async def get_audit_chain(args: dict, principal: Any, services: Any) -> OperationResult:
    sink = services.pipeline.audit
    session_id = str(args.get("session_id") or "")
    if not session_id:
        return OperationResult(summary="缺少 session_id。", data=[], ok=False, error="missing")
    events = await sink.events(session_id) if hasattr(sink, "events") else []
    data = [
        {
            "index": e.index,
            "event_type": e.event_type.value,
            "decision": e.decision.value if e.decision else None,
            "subject_id": e.subject_id,
        }
        for e in events
    ]
    verified = await sink.verify_chain(session_id) if hasattr(sink, "verify_chain") else None
    chk = "通过" if verified else "未通过/未知"
    summary = f"会话「{session_id}」共 {len(data)} 个审计事件,链校验{chk}。"
    return OperationResult(summary=summary, data=data)


@operation(
    name="list_tool_calls",
    kind="read",
    label="列工具调用流水",
    description="列出穿过安全管线的工具调用治理流水(工具名/参数/风险/处置/是否执行)。",
    params={
        "type": "object",
        "properties": {"limit": {"type": "integer", "description": "条数上限(1~200,默认 20)"}},
    },
    requires=("tools.view",),
)
async def list_tool_calls(args: dict, principal: Any, services: Any) -> OperationResult:
    sink = services.pipeline.audit
    if not isinstance(sink, InMemoryAuditSink):
        return OperationResult(summary="工具流水当前不可用(非内存审计实现)。", data=[])
    limit = _int(args.get("limit"), 20, 1, 200)
    rows = build_tool_calls(sink.all_events())[:limit]
    summary = f"共 {len(rows)} 条工具调用记录。"
    return OperationResult(summary=summary, data=[r.model_dump() for r in rows])


@operation(
    name="get_eval_report",
    kind="read",
    label="读评测报告",
    description="读取最近一次离线评测(攻击样例回放)的报告:ASR/FPR 等指标。尚无报告则如实说明。",
    requires=("eval.view",),
)
async def get_eval_report(args: dict, principal: Any, services: Any) -> OperationResult:
    report = load_report(services.eval_report_path)
    if report is None:
        return OperationResult(summary="尚无评测报告(还没跑过离线评测)。", data=None)
    return OperationResult(summary="已读取最近一次评测报告。", data=report.model_dump())


@operation(
    name="list_policies",
    kind="read",
    label="列当前策略",
    description="列出管线当前装配的声明式安全策略(条件→分级处置)。策略为只读 YAML。",
    requires=("policies.view",),
)
async def list_policies(args: dict, principal: Any, services: Any) -> OperationResult:
    get_doc = getattr(services.pipeline.policy, "policy_document", None)
    if not callable(get_doc):
        return OperationResult(summary="当前策略引擎未暴露可列文档(如 allow_all)。", data=None)
    ps = to_policy_set(cast("dict[str, Any]", get_doc()))
    summary = f"当前策略集「{ps.name}」v{ps.version},共 {len(ps.rules)} 条规则,默认 {ps.default}。"
    return OperationResult(summary=summary, data=ps.model_dump())


@operation(
    name="list_supply_scans",
    kind="read",
    label="列供应链评级",
    description="对配置目录下的组件 manifest 跑静态供应链扫描,返回各组件评级(不执行组件代码)。",
    requires=("supply.view",),
)
async def list_supply_scans(args: dict, principal: Any, services: Any) -> OperationResult:
    if services.scanner is None:
        return OperationResult(summary="未装配供应链扫描器。", data=[])
    rows = scan_directory(services.scanner, services.supply_manifest_dir)
    summary = f"共扫描 {len(rows)} 个组件。" + (
        ";".join(f"{r.component_id}={r.rating}" for r in rows[:5]) if rows else "目录为空。"
    )
    return OperationResult(summary=summary, data=[r.model_dump() for r in rows])


def _user_brief(u: Any) -> dict:
    """成员摘要(给助手/审计看):不出口令哈希,联系方式由出口闸门兜底脱敏。"""
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "status": u.status,
        "role_id": u.role_id,
        "department_id": u.department_id,
    }


@operation(
    name="list_users",
    kind="read",
    label="列成员",
    description="列出成员(可按关键词搜索账号/姓名)。返回账号、姓名、状态、角色/部门。",
    params={
        "type": "object",
        "properties": {"query": {"type": "string", "description": "搜索关键词(账号或姓名)"}},
    },
    requires=("users.view",),
)
async def list_users(args: dict, principal: Any, services: Any) -> OperationResult:
    if services.directory is None:
        return OperationResult(summary="未装配目录服务。", data=[])
    query = (str(args.get("query")) if args.get("query") else None) or None
    users = services.directory.list_users(search=query)
    data = [_user_brief(u) for u in users]
    summary = f"共 {len(data)} 名成员" + (f"(关键词「{query}」)" if query else "") + "。"
    return OperationResult(summary=summary, data=data)


@operation(
    name="list_pending_accounts",
    kind="read",
    label="列待审批账号",
    description="列出处于「待审批」状态的注册申请。用于「有哪些账号在等审批」。",
    requires=("users.view",),
)
async def list_pending_accounts(args: dict, principal: Any, services: Any) -> OperationResult:
    if services.directory is None:
        return OperationResult(summary="未装配目录服务。", data=[])
    users = services.directory.list_users(status="pending")
    data = [_user_brief(u) for u in users]
    names = "、".join(u["username"] for u in data[:8])
    summary = f"共 {len(data)} 个待审批账号。" + (f"账号:{names}。" if names else "")
    return OperationResult(summary=summary, data=data)


@operation(
    name="list_roles",
    kind="read",
    label="列角色",
    description="列出全部角色及其权限点集合(内置/自定义)。",
    requires=("users.view",),
)
async def list_roles(args: dict, principal: Any, services: Any) -> OperationResult:
    if services.directory is None:
        return OperationResult(summary="未装配目录服务。", data=[])
    roles = services.directory.list_roles()
    data = [
        {
            "id": r.id,
            "key": r.key,
            "name": r.name,
            "is_system": r.is_system,
            "permissions": sorted(r.permissions),
        }
        for r in roles
    ]
    summary = f"共 {len(data)} 个角色:" + "、".join(r["name"] for r in data[:10]) + "。"
    return OperationResult(summary=summary, data=data)


@operation(
    name="get_gateway_config",
    kind="read",
    label="读上游网关配置",
    description="读取当前上游接入配置(协议/端点/模型/认证方式);密钥一律掩码,不返回明文。",
    requires=("settings.view",),
)
async def get_gateway_config(args: dict, principal: Any, services: Any) -> OperationResult:
    if services.gateway_store is None:
        return OperationResult(summary="未装配上游网关配置。", data=None)
    pub = GatewayConfigPublic.of(services.gateway_store.load())
    summary = (
        f"上游「{pub.name}」:协议 {pub.protocol}、端点 {pub.endpoint}、模型 {pub.model or '—'}、"
        f"认证 {pub.auth_type}({'已设密钥' if pub.auth_value_set else '无'})。"
    )
    return OperationResult(summary=summary, data=pub.model_dump())
