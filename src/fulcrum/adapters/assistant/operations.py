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
from ..auth.permissions import PERMISSIONS
from ..console_settings import ConsoleSettings
from ..gateway import GatewayConfig, GatewayConfigPublic

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
_CONSOLE_SETTING_KEYS = frozenset({"instance_name", "environment"})


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


# ──────────────────────────── write(后端,提案-确认-可撤销)────────────────────────────
# 写操作不进 chat 循环执行;助手只产出待确认提案,确认走 /assistant/confirm(纵深 RBAC + 前态
# 快照 + 审计),撤销走 /assistant/undo(逆操作 + 审计)。handler 执行时把**前态**塞进
# OperationResult.undo,undo_handler 吃它回滚——一份快照即可一键还原。


async def _set_user_status(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        uid = int(args["user_id"])
        status = str(args["status"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 user_id、status)。", ok=False, error="bad_args")
    user = d.get_user(uid)
    if user is None:
        return OperationResult(summary=f"成员 {uid} 不存在。", ok=False, error="not_found")
    old = user.status
    try:
        d.set_status(uid, status)
    except Exception as exc:  # noqa: BLE001 —— 护栏冲突(如停最后管理员)如实回报,不 500
        return OperationResult(summary=f"改状态失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"成员 {user.username} 状态 {old}→{status}。",
        data={"user_id": uid, "status": status},
        undo={"user_id": uid, "status": old},
    )


async def _set_user_status_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.set_status(int(args["user_id"]), str(args["status"]))
    return OperationResult(summary=f"已回滚成员 {args['user_id']} 状态为 {args['status']}。")


async def _set_user_status_before(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    user = d.get_user(int(args["user_id"])) if d and args.get("user_id") is not None else None
    return OperationResult(summary="", data={"status": user.status if user else None})


operation_registry.register(
    AssistantTool(
        name="set_user_status",
        kind="write",
        label="改成员状态",
        description="把某成员置为 active/disabled/left。高危:会影响其能否登录。",
        parameters={
            "type": "object",
            "properties": {
                "user_id": {"type": "integer"},
                "status": {"type": "string", "enum": ["active", "disabled", "left"]},
            },
            "required": ["user_id", "status"],
        },
        requires=("users.manage",),
        risk="high",
        handler=_set_user_status,
        reversible=True,
        inverse="恢复为原状态",
        undo_handler=_set_user_status_undo,
        before_handler=_set_user_status_before,
    )
)


async def _approve_account(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        uid = int(args["user_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 user_id)。", ok=False, error="bad_args")
    user = d.get_user(uid)
    if user is None:
        return OperationResult(summary=f"账号 {uid} 不存在。", ok=False, error="not_found")
    if user.status != "pending":
        return OperationResult(
            summary=f"账号 {user.username} 不在待审批状态。", ok=False, error="state"
        )
    role_id = args.get("role_id")
    dept_id = args.get("department_id")
    try:
        d.approve(
            uid,
            int(role_id) if role_id is not None else None,
            int(dept_id) if dept_id is not None else None,
        )
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"审批失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"已审批通过账号 {user.username}。",
        data={"user_id": uid},
        undo={"user_id": uid},
    )


async def _approve_account_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.set_status(int(args["user_id"]), "pending")
    return OperationResult(summary=f"已撤回审批,账号 {args['user_id']} 恢复为待审批。")


operation_registry.register(
    AssistantTool(
        name="approve_account",
        kind="write",
        label="审批账号申请",
        description="通过一个待审批的注册申请,使其可登录(可指定角色/部门)。",
        parameters={
            "type": "object",
            "properties": {
                "user_id": {"type": "integer"},
                "role_id": {"type": "integer"},
                "department_id": {"type": "integer"},
            },
            "required": ["user_id"],
        },
        requires=("account.approve",),
        risk="high",
        handler=_approve_account,
        reversible=True,
        inverse="恢复为待审批",
        undo_handler=_approve_account_undo,
    )
)


async def _update_gateway_config(args: dict, principal: Any, services: Any) -> OperationResult:
    store = services.gateway_store
    if store is None:
        return OperationResult(summary="未装配上游网关配置。", ok=False, error="no_store")
    old = store.load().model_dump()
    try:
        new = GatewayConfig.model_validate({**old, **(args or {})})
    except Exception as exc:  # noqa: BLE001 —— patch 非法 → 拒,不落坏配置
        return OperationResult(summary=f"配置非法,未保存:{exc}", ok=False, error="invalid")
    store.save(new)
    return OperationResult(
        summary="已更新上游网关配置(热加载生效)。", data={"name": new.name}, undo=old
    )


async def _update_gateway_config_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.gateway_store.save(GatewayConfig.model_validate(args))
    return OperationResult(summary="已回滚上游网关配置为原值。")


async def _update_gateway_config_before(
    args: dict, principal: Any, services: Any
) -> OperationResult:
    store = services.gateway_store
    old = store.load().model_dump() if store else {}
    return OperationResult(summary="", data={k: old.get(k) for k in (args or {})})


# 只把"操作员常改"的字段开放给模型/卡片(密钥 auth_value 不在卡片明文回显之列由前端按需)。
_GATEWAY_PARAMS = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "上游名称"},
        "enabled": {"type": "boolean", "description": "是否启用接入"},
        "protocol": {"type": "string", "enum": ["openai", "rest", "native"]},
        "endpoint": {"type": "string", "description": "上游地址,如 http://10.0.0.5:8000/v1"},
        "path": {"type": "string", "description": "请求路径,留空按协议默认"},
        "model": {"type": "string", "description": "模型名(openai 协议用)"},
        "timeout_seconds": {"type": "number", "description": "超时秒数"},
        "verify_tls": {"type": "boolean", "description": "是否校验 TLS 证书"},
    },
}

operation_registry.register(
    AssistantTool(
        name="update_gateway_config",
        kind="write",
        label="改上游网关配置",
        description=(
            "按字段补丁更新上游接入配置;**只把要改的字段放进参数**(如只改名就只传 name)。"
            "高危:影响所有转发请求。"
        ),
        parameters=_GATEWAY_PARAMS,
        requires=("settings.manage",),
        risk="high",
        handler=_update_gateway_config,
        reversible=True,
        inverse="恢复为原配置",
        undo_handler=_update_gateway_config_undo,
        before_handler=_update_gateway_config_before,
    )
)


async def _update_console_settings(args: dict, principal: Any, services: Any) -> OperationResult:
    store = services.console_store
    if store is None:
        return OperationResult(summary="未装配控制台设置。", ok=False, error="no_store")
    unknown = sorted(set(args or {}) - _CONSOLE_SETTING_KEYS)
    if unknown:
        return OperationResult(
            summary="设置未保存:这些字段当前没有运行时落点,不能作为控制台设置修改:"
            + ", ".join(unknown),
            ok=False,
            error="unknown_fields",
        )
    old = store.load().model_dump()
    try:
        new = ConsoleSettings.model_validate({**old, **(args or {})})
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"设置非法,未保存:{exc}", ok=False, error="invalid")
    store.save(new)
    return OperationResult(
        summary="已更新控制台设置。", data={"instance_name": new.instance_name}, undo=old
    )


async def _update_console_settings_undo(
    args: dict, principal: Any, services: Any
) -> OperationResult:
    services.console_store.save(ConsoleSettings.model_validate(args))
    return OperationResult(summary="已回滚控制台设置为原值。")


async def _update_console_settings_before(
    args: dict, principal: Any, services: Any
) -> OperationResult:
    store = services.console_store
    old = store.load().model_dump() if store else {}
    return OperationResult(summary="", data={k: old.get(k) for k in (args or {})})


_CONSOLE_PARAMS = {
    "type": "object",
    "properties": {
        "instance_name": {"type": "string", "description": "实例名称"},
        "environment": {"type": "string", "enum": ["prod", "staging", "demo"]},
    },
}

operation_registry.register(
    AssistantTool(
        name="update_console_settings",
        kind="write",
        label="改控制台设置",
        description=(
            "按字段补丁更新控制台真实落盘设置(实例名称/部署环境);"
            "**只把要改的字段放进参数**。通知、审计留存、语言等未接运行时的项不可通过本工具修改。"
        ),
        parameters=_CONSOLE_PARAMS,
        requires=("settings.manage",),
        risk="normal",
        handler=_update_console_settings,
        reversible=True,
        inverse="恢复为原设置",
        undo_handler=_update_console_settings_undo,
        before_handler=_update_console_settings_before,
    )
)


# ════════════════════════════════════════════════════════════════════════════
#  全量覆盖:把"人在管理后台能干的"剩余操作补齐(组织/角色/成员 CRUD + 网关测试)。
#  原则——助手可操作面 == 操作员可操作面;读类喂全量数据,写类一律提案-确认-(可)撤销。
#  与 admin_routes 同源同护栏:调同一个 DirectoryService,一致性违例如实回报不 500。
# ════════════════════════════════════════════════════════════════════════════


def _role_brief(r: Any, member_count: int | None = None) -> dict:
    d = {
        "id": r.id,
        "key": r.key,
        "name": r.name,
        "description": r.description,
        "is_system": r.is_system,
        "permissions": sorted(r.permissions),
    }
    if member_count is not None:
        d["member_count"] = member_count
    return d


def _dept_brief(d: Any, member_count: int | None = None) -> dict:
    out = {"id": d.id, "name": d.name, "parent_id": d.parent_id, "sort_order": d.sort_order}
    if member_count is not None:
        out["member_count"] = member_count
    return out


# ──────────────────────────── read:组织/权限/连通性 ────────────────────────────
@operation(
    name="list_departments",
    kind="read",
    label="列部门",
    description="列出全部部门(组织架构)及各部门成员数。建成员/改归属前用它拿 department_id。",
    requires=("users.view",),
)
async def list_departments(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", data=[])
    rows = d.list_departments()
    data = [_dept_brief(x, d.department_member_count(x.id)) for x in rows]
    summary = f"共 {len(data)} 个部门:" + "、".join(x["name"] for x in data[:10]) + "。"
    return OperationResult(summary=summary, data=data)


@operation(
    name="list_permissions",
    kind="read",
    label="列权限点",
    description="列出系统全部权限点(key/名称/分组)。新建或改角色前用它确认合法的权限 key。",
    requires=("users.view",),
)
async def list_permissions(args: dict, principal: Any, services: Any) -> OperationResult:
    data = [{"key": p.key, "label": p.label, "group": p.group} for p in PERMISSIONS]
    summary = f"共 {len(data)} 个权限点(按 key 传给角色 permissions)。"
    return OperationResult(summary=summary, data=data)


@operation(
    name="test_gateway_connection",
    kind="read",
    label="测试上游连通性",
    description="对当前已保存的上游接入配置发一次探测请求,返回是否连通/时延/状态码。用于「上游通不通」。",
    requires=("settings.view",),
)
async def test_gateway_connection(args: dict, principal: Any, services: Any) -> OperationResult:
    store = services.gateway_store
    fwd = getattr(services, "forwarder", None)
    if store is None or fwd is None:
        return OperationResult(summary="未装配上游网关或转发器,无法测试。", data=None)
    cfg = store.load()
    r = await fwd.probe(cfg)
    summary = (
        f"上游「{cfg.name}」连通性:{'通' if r.ok else '不通'}、"
        f"时延 {r.latency_ms}ms、状态 {r.status_code}。{r.detail}"
    )
    return OperationResult(
        summary=summary,
        data={
            "ok": r.ok,
            "latency_ms": r.latency_ms,
            "status_code": r.status_code,
            "detail": r.detail,
        },
    )


# ──────────────────────────── write:成员 CRUD ────────────────────────────
_USER_PROFILE_KEYS = ("display_name", "title", "email", "phone", "role_id", "department_id")


async def _create_user(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    username = str(args.get("username") or "").strip()
    display_name = str(args.get("display_name") or "").strip()
    if not username or not display_name:
        return OperationResult(
            summary="缺少 username 或 display_name。", ok=False, error="bad_args"
        )
    try:
        user, temp = d.create_user(
            username=username,
            display_name=display_name,
            role_id=args.get("role_id"),
            department_id=args.get("department_id"),
            employee_no=str(args.get("employee_no") or ""),
            email=str(args.get("email") or ""),
            phone=str(args.get("phone") or ""),
            title=str(args.get("title") or ""),
        )
    except Exception as exc:  # noqa: BLE001 —— 重名/引用不存在等护栏违例如实回报
        return OperationResult(summary=f"建成员失败:{exc}", ok=False, error="conflict")
    pw_note = f" 初始口令(仅此一次):{temp}" if temp else ""
    return OperationResult(
        summary=f"已创建成员 {user.username}({user.display_name})。{pw_note}",
        data=_user_brief(user),
        undo={"user_id": user.id},
    )


async def _create_user_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    # 无硬删 API:撤销=把新账号置为离职(停止登录),与"驳回删除"区分。
    services.directory.set_status(int(args["user_id"]), "left")
    return OperationResult(summary=f"已撤销:新账号 {args['user_id']} 置为离职(停用)。")


operation_registry.register(
    AssistantTool(
        name="create_user",
        kind="write",
        label="新建成员",
        description=(
            "创建一个成员账号(直接生效、可登录)。不传口令则系统生成一次性初始口令。"
            "建前可先 list_roles / list_departments 拿 role_id、department_id。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "登录账号(唯一)"},
                "display_name": {"type": "string", "description": "姓名"},
                "role_id": {"type": "integer", "description": "角色 id(见 list_roles)"},
                "department_id": {"type": "integer", "description": "部门 id(见 list_departments)"},
                "title": {"type": "string", "description": "职务"},
                "email": {"type": "string"},
                "phone": {"type": "string"},
                "employee_no": {"type": "string", "description": "工号"},
            },
            "required": ["username", "display_name"],
        },
        requires=("users.manage",),
        risk="high",
        handler=_create_user,
        reversible=True,
        inverse="置为离职(停用新账号)",
        undo_handler=_create_user_undo,
    )
)


async def _update_user(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        uid = int(args["user_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 user_id)。", ok=False, error="bad_args")
    user = d.get_user(uid)
    if user is None:
        return OperationResult(summary=f"成员 {uid} 不存在。", ok=False, error="not_found")
    fields = {k: args[k] for k in _USER_PROFILE_KEYS if k in args}
    if not fields:
        return OperationResult(summary="没有要改的字段。", ok=False, error="no_fields")
    old = {k: getattr(user, k) for k in fields}
    try:
        updated = d.update_user(uid, fields=fields)
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"更新成员失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"成员 {updated.username} 资料已更新(改了 {'、'.join(fields)})。",
        data=_user_brief(updated),
        undo={"user_id": uid, "fields": old},
    )


async def _update_user_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.update_user(int(args["user_id"]), fields=dict(args["fields"]))
    return OperationResult(summary=f"已回滚成员 {args['user_id']} 资料。")


async def _update_user_before(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    user = d.get_user(int(args["user_id"])) if d and args.get("user_id") is not None else None
    keys = [k for k in _USER_PROFILE_KEYS if k in (args or {})]
    return OperationResult(summary="", data={k: getattr(user, k) for k in keys} if user else {})


operation_registry.register(
    AssistantTool(
        name="update_user",
        kind="write",
        label="改成员资料",
        description=(
            "按字段补丁改成员资料(姓名/职务/邮箱/电话/角色/部门);**只把要改的字段放进参数**。"
            "改角色会使该成员重新登录。改状态请用 set_user_status。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "user_id": {"type": "integer"},
                "display_name": {"type": "string"},
                "title": {"type": "string"},
                "email": {"type": "string"},
                "phone": {"type": "string"},
                "role_id": {"type": "integer"},
                "department_id": {"type": "integer"},
            },
            "required": ["user_id"],
        },
        requires=("users.manage",),
        risk="high",
        handler=_update_user,
        reversible=True,
        inverse="恢复为原资料",
        undo_handler=_update_user_undo,
        before_handler=_update_user_before,
    )
)


async def _reset_password(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        uid = int(args["user_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 user_id)。", ok=False, error="bad_args")
    user = d.get_user(uid)
    if user is None:
        return OperationResult(summary=f"成员 {uid} 不存在。", ok=False, error="not_found")
    try:
        temp = d.reset_password(uid)  # 不传新口令 → 生成一次性临时口令
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"重置口令失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"已重置 {user.username} 的口令,临时口令(仅此一次):{temp}。该成员旧会话已失效。",
        data={"user_id": uid},
    )


operation_registry.register(
    AssistantTool(
        name="reset_user_password",
        kind="write",
        label="重置成员口令",
        description="为某成员生成一次性临时口令并使其旧会话失效。不可撤销(口令已变更)。",
        parameters={
            "type": "object",
            "properties": {"user_id": {"type": "integer"}},
            "required": ["user_id"],
        },
        requires=("users.manage",),
        risk="high",
        handler=_reset_password,
        reversible=False,
        inverse=None,
    )
)


async def _reject_account(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        uid = int(args["user_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 user_id)。", ok=False, error="bad_args")
    user = d.get_user(uid)
    if user is None:
        return OperationResult(summary=f"账号 {uid} 不存在。", ok=False, error="not_found")
    name = user.username
    try:
        d.reject(uid)  # 驳回即删除待审批记录
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"驳回失败:{exc}", ok=False, error="conflict")
    return OperationResult(summary=f"已驳回并删除待审批账号 {name}。", data={"user_id": uid})


operation_registry.register(
    AssistantTool(
        name="reject_account",
        kind="write",
        label="驳回账号申请",
        description="驳回一个待审批注册申请(记录被删除)。不可撤销。",
        parameters={
            "type": "object",
            "properties": {"user_id": {"type": "integer"}},
            "required": ["user_id"],
        },
        requires=("account.approve",),
        risk="high",
        handler=_reject_account,
        reversible=False,
        inverse=None,
    )
)


# ──────────────────────────── write:角色 CRUD ────────────────────────────
async def _create_role(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    name = str(args.get("name") or "").strip()
    if not name:
        return OperationResult(summary="缺少角色名 name。", ok=False, error="bad_args")
    perms = args.get("permissions") or []
    if not isinstance(perms, list):
        return OperationResult(summary="permissions 需为字符串数组。", ok=False, error="bad_args")
    try:
        role = d.create_role(name, str(args.get("description") or ""), [str(p) for p in perms])
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"建角色失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"已创建角色「{role.name}」(key={role.key}),含 {len(role.permissions)} 个权限。",
        data=_role_brief(role),
        undo={"role_id": role.id},
    )


async def _create_role_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.delete_role(int(args["role_id"]))
    return OperationResult(summary=f"已撤销:删除新建角色 {args['role_id']}。")


operation_registry.register(
    AssistantTool(
        name="create_role",
        kind="write",
        label="新建角色",
        description=("创建自定义角色并赋权限点(permissions 为权限 key 数组,见 list_permissions)。"),
        parameters={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "角色名"},
                "description": {"type": "string"},
                "permissions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "权限点 key 列表(见 list_permissions)",
                },
            },
            "required": ["name"],
        },
        requires=("roles.manage",),
        risk="high",
        handler=_create_role,
        reversible=True,
        inverse="删除新建角色",
        undo_handler=_create_role_undo,
    )
)


async def _update_role(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        rid = int(args["role_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 role_id)。", ok=False, error="bad_args")
    role = next((r for r in d.list_roles() if r.id == rid), None)
    if role is None:
        return OperationResult(summary=f"角色 {rid} 不存在。", ok=False, error="not_found")
    old = {
        "name": role.name,
        "description": role.description,
        "permissions": sorted(role.permissions),
    }
    perms = args.get("permissions")
    try:
        updated = d.update_role(
            rid,
            name=args.get("name"),
            description=args.get("description"),
            permissions=[str(p) for p in perms] if isinstance(perms, list) else None,
        )
    except Exception as exc:  # noqa: BLE001 —— 角色不存在/参数冲突等护栏
        return OperationResult(summary=f"改角色失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"角色「{updated.name}」已更新,现含 {len(updated.permissions)} 个权限。",
        data=_role_brief(updated),
        undo={"role_id": rid, **old},
    )


async def _update_role_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.update_role(
        int(args["role_id"]),
        name=args.get("name"),
        description=args.get("description"),
        permissions=list(args.get("permissions") or []),
    )
    return OperationResult(summary=f"已回滚角色 {args['role_id']}。")


async def _update_role_before(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    role = (
        next((r for r in d.list_roles() if r.id == int(args["role_id"])), None)
        if d and args.get("role_id") is not None
        else None
    )
    if role is None:
        return OperationResult(summary="", data={})
    full = {
        "name": role.name,
        "description": role.description,
        "permissions": sorted(role.permissions),
    }
    return OperationResult(summary="", data={k: full[k] for k in full if k in (args or {})})


operation_registry.register(
    AssistantTool(
        name="update_role",
        kind="write",
        label="改角色权限",
        description=(
            "按字段改角色的名称/描述/权限点;**只把要改的字段放进参数**(传 permissions "
            "则整体替换)。内置角色也可改。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "role_id": {"type": "integer"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "permissions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["role_id"],
        },
        requires=("roles.manage",),
        risk="high",
        handler=_update_role,
        reversible=True,
        inverse="恢复为原角色定义",
        undo_handler=_update_role_undo,
        before_handler=_update_role_before,
    )
)


async def _delete_role(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        rid = int(args["role_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 role_id)。", ok=False, error="bad_args")
    role = next((r for r in d.list_roles() if r.id == rid), None)
    if role is None:
        return OperationResult(summary=f"角色 {rid} 不存在。", ok=False, error="not_found")
    name = role.name
    try:
        d.delete_role(rid)
    except Exception as exc:  # noqa: BLE001 —— 仍有成员使用等一致性护栏 → 拒
        return OperationResult(summary=f"删角色失败:{exc}", ok=False, error="conflict")
    return OperationResult(summary=f"已删除角色「{name}」。", data={"role_id": rid})


operation_registry.register(
    AssistantTool(
        name="delete_role",
        kind="write",
        label="删除角色",
        description="删除一个角色(仍有成员使用会被拒)。内置角色也可删;不可撤销。",
        parameters={
            "type": "object",
            "properties": {"role_id": {"type": "integer"}},
            "required": ["role_id"],
        },
        requires=("roles.manage",),
        risk="high",
        handler=_delete_role,
        reversible=False,
        inverse=None,
    )
)


# ──────────────────────────── write:部门 CRUD ────────────────────────────
async def _create_department(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    name = str(args.get("name") or "").strip()
    if not name:
        return OperationResult(summary="缺少部门名 name。", ok=False, error="bad_args")
    try:
        dept = d.create_department(name, args.get("parent_id"), int(args.get("sort_order") or 100))
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"建部门失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"已创建部门「{dept.name}」(id={dept.id})。",
        data=_dept_brief(dept),
        undo={"dept_id": dept.id},
    )


async def _create_department_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.delete_department(int(args["dept_id"]))
    return OperationResult(summary=f"已撤销:删除新建部门 {args['dept_id']}。")


operation_registry.register(
    AssistantTool(
        name="create_department",
        kind="write",
        label="新建部门",
        description="在组织架构里新建部门(可挂在某上级部门下,parent_id 见 list_departments)。",
        parameters={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "部门名"},
                "parent_id": {"type": "integer", "description": "上级部门 id,留空为顶级"},
                "sort_order": {"type": "integer", "description": "同级排序,默认 100"},
            },
            "required": ["name"],
        },
        requires=("dept.manage",),
        risk="normal",
        handler=_create_department,
        reversible=True,
        inverse="删除新建部门",
        undo_handler=_create_department_undo,
    )
)


async def _update_department(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        did = int(args["dept_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 dept_id)。", ok=False, error="bad_args")
    dept = next((x for x in d.list_departments() if x.id == did), None)
    if dept is None:
        return OperationResult(summary=f"部门 {did} 不存在。", ok=False, error="not_found")
    old = {"name": dept.name, "parent_id": dept.parent_id, "sort_order": dept.sort_order}
    change_parent = "parent_id" in args
    try:
        updated = d.update_department(
            did,
            name=args.get("name"),
            parent_id=args.get("parent_id"),
            sort_order=args.get("sort_order"),
            change_parent=change_parent,
        )
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"改部门失败:{exc}", ok=False, error="conflict")
    return OperationResult(
        summary=f"部门「{updated.name}」已更新。",
        data=_dept_brief(updated),
        undo={"dept_id": did, **old},
    )


async def _update_department_undo(args: dict, principal: Any, services: Any) -> OperationResult:
    services.directory.update_department(
        int(args["dept_id"]),
        name=args.get("name"),
        parent_id=args.get("parent_id"),
        sort_order=args.get("sort_order"),
        change_parent=True,
    )
    return OperationResult(summary=f"已回滚部门 {args['dept_id']}。")


async def _update_department_before(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    dept = (
        next((x for x in d.list_departments() if x.id == int(args["dept_id"])), None)
        if d and args.get("dept_id") is not None
        else None
    )
    if dept is None:
        return OperationResult(summary="", data={})
    full = {"name": dept.name, "parent_id": dept.parent_id, "sort_order": dept.sort_order}
    return OperationResult(summary="", data={k: full[k] for k in full if k in (args or {})})


operation_registry.register(
    AssistantTool(
        name="update_department",
        kind="write",
        label="改部门",
        description=(
            "按字段改部门(改名/移动上级/排序);**只把要改的字段放进参数**。"
            "不能把部门移到自己或其子部门下。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "dept_id": {"type": "integer"},
                "name": {"type": "string"},
                "parent_id": {"type": "integer", "description": "新上级部门 id"},
                "sort_order": {"type": "integer"},
            },
            "required": ["dept_id"],
        },
        requires=("dept.manage",),
        risk="normal",
        handler=_update_department,
        reversible=True,
        inverse="恢复为原部门设置",
        undo_handler=_update_department_undo,
        before_handler=_update_department_before,
    )
)


async def _delete_department(args: dict, principal: Any, services: Any) -> OperationResult:
    d = services.directory
    if d is None:
        return OperationResult(summary="未装配目录服务。", ok=False, error="no_directory")
    try:
        did = int(args["dept_id"])
    except (KeyError, TypeError, ValueError):
        return OperationResult(summary="参数非法(需 dept_id)。", ok=False, error="bad_args")
    dept = next((x for x in d.list_departments() if x.id == did), None)
    if dept is None:
        return OperationResult(summary=f"部门 {did} 不存在。", ok=False, error="not_found")
    name = dept.name
    try:
        d.delete_department(did)  # 有子部门/成员 → 拒
    except Exception as exc:  # noqa: BLE001
        return OperationResult(summary=f"删部门失败:{exc}", ok=False, error="conflict")
    return OperationResult(summary=f"已删除部门「{name}」。", data={"dept_id": did})


operation_registry.register(
    AssistantTool(
        name="delete_department",
        kind="write",
        label="删除部门",
        description="删除一个部门(其下仍有子部门或成员会被拒)。不可撤销。",
        parameters={
            "type": "object",
            "properties": {"dept_id": {"type": "integer"}},
            "required": ["dept_id"],
        },
        requires=("dept.manage",),
        risk="normal",
        handler=_delete_department,
        reversible=False,
        inverse=None,
    )
)
