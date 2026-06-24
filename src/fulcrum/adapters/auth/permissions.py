"""权限点目录 + 内置角色/部门种子。

权限点(permission)是 RBAC 的最小粒度,**由系统代码定义**(不能由用户凭空发明,
因为每个点都对应后端某个受保护操作 / 前端某个功能模块)。管理员能做的是:
**新建角色 → 从这份目录里勾选权限点 → 分配给成员**,并实时强制生效。

命名约定:`<域>.<动作>`。`*.view` 控"能否看到该模块"(前端导航/路由按它过滤);
其余如 `*.manage`/`*.handle`/`*.run`/`*.approve` 控具体操作。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PermissionDef:
    """一个权限点。

    为让前端把「看(.view)」和「改(.manage/.handle/.run)」配成**同一能力的只读/读写
    三态控件**,每个点声明:
    - ``capability`` —— 能力域 id(成对的看/改共享同一个,如 events 的 view+handle);
    - ``cap_label``  —— 能力域中文名(同一能力域两条相同,展示用一行);
    - ``access``     —— ``read``(看)/ ``write``(改)/ ``action``(无看改之分的单点,如审批)。
    分类(group)按**影响面**归并:监测/管控/取证/成员与权限(涉隐私·影响他人)/系统配置(影响全体)。
    """

    key: str
    label: str  # 权限点本名(成对时如「查看成员」「管理成员」)
    group: str  # 影响面分类:监测/管控/取证/成员与权限/系统配置
    capability: str  # 能力域 id(成对看/改共享)
    cap_label: str  # 能力域中文名(展示一行)
    access: str  # read | write | action


# ── 权限点目录(唯一真源)──────────────────────────────────────────
# 同一 capability 的 read+write 在前端合成一行三态(无→只读→读写);access=action 为单点开关。
PERMISSIONS: tuple[PermissionDef, ...] = (
    # 监测
    PermissionDef("overview.view", "安全总览", "监测", "overview", "安全总览", "read"),
    PermissionDef("events.view", "查看会话事件", "监测", "events", "会话事件", "read"),
    PermissionDef("events.handle", "处置会话事件", "监测", "events", "会话事件", "write"),
    # 管控
    PermissionDef("policies.view", "查看策略", "管控", "policies", "策略中心", "read"),
    PermissionDef("policies.manage", "编辑策略", "管控", "policies", "策略中心", "write"),
    PermissionDef("tools.view", "查看工具网关", "管控", "tools", "工具网关", "read"),
    PermissionDef("tools.manage", "管控工具", "管控", "tools", "工具网关", "write"),
    PermissionDef("supply.view", "查看供应链", "管控", "supply", "供应链", "read"),
    PermissionDef("supply.manage", "处置供应链风险", "管控", "supply", "供应链", "write"),
    # 取证
    PermissionDef("audit.view", "审计溯源", "取证", "audit", "审计溯源", "read"),
    PermissionDef("eval.view", "查看评测", "取证", "eval", "评测验证", "read"),
    PermissionDef("eval.run", "发起评测", "取证", "eval", "评测验证", "write"),
    # 成员与权限(涉隐私 / 影响他人)
    PermissionDef("users.view", "查看成员", "成员与权限", "users", "成员", "read"),
    PermissionDef("users.manage", "管理成员", "成员与权限", "users", "成员", "write"),
    PermissionDef("dept.manage", "管理组织架构", "成员与权限", "dept", "组织架构", "write"),
    PermissionDef("roles.manage", "管理角色权限", "成员与权限", "roles", "角色权限", "write"),
    PermissionDef("account.approve", "审批账号申请", "成员与权限", "account", "账号审批", "action"),
    # 系统配置(影响全体)
    PermissionDef("settings.view", "查看系统设置", "系统配置", "settings", "系统设置", "read"),
    PermissionDef("settings.manage", "修改系统设置", "系统配置", "settings", "系统设置", "write"),
    # 能否使用 AI 副驾代操作控制台。
    PermissionDef("ai.operate", "AI 操作助手", "系统配置", "ai_operate", "AI 操作助手", "action"),
    # 能否配置 AI 助手的模型接入(协议/端点/密钥/模型名)——高敏:默认仅超管+系统管理员。
    # 其余内置角色显式列举权限、不含本点,故天然无权;新建角色需管理员显式勾选。
    PermissionDef("ai.configure", "AI 模型配置", "系统配置", "ai_config", "AI 模型配置", "action"),
)

ALL_PERMISSION_KEYS: frozenset[str] = frozenset(p.key for p in PERMISSIONS)


def valid_permissions(keys: object) -> list[str]:
    """过滤出目录内的合法权限点(挡掉前端传来的未知 key),保持原顺序去重。"""
    if not isinstance(keys, (list, tuple, set, frozenset)):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        if isinstance(k, str) and k in ALL_PERMISSION_KEYS and k not in seen:
            seen.add(k)
            out.append(k)
    return out


# ── 内置角色种子(is_system=True:不可删除;super_admin 不可改)──────
@dataclass(frozen=True, slots=True)
class RoleSeed:
    key: str
    name: str
    description: str
    permissions: frozenset[str]


# 业务看板的只读视图(不含 settings.view / users.view 等"系统管理"面 ——
# 低信任访客绝不该看到系统设置和成员目录)
_BOARD_VIEW = frozenset(
    {
        "overview.view",
        "events.view",
        "policies.view",
        "tools.view",
        "supply.view",
        "audit.view",
        "eval.view",
    }
)

BUILTIN_ROLES: tuple[RoleSeed, ...] = (
    RoleSeed(
        "super_admin",
        "超级管理员",
        "系统拥有者:全部权限,可管理成员、组织与角色",
        ALL_PERMISSION_KEYS,
    ),
    RoleSeed(
        "sys_admin",
        "系统管理员",
        "日常管理:成员/组织/设置/管控,审批账号(不含重定义角色)",
        ALL_PERMISSION_KEYS - {"roles.manage"},
    ),
    RoleSeed(
        "sec_manager",
        "安全主管",
        "统筹研判:看全局、审批高危处置与账号申请、发起评测",
        frozenset(
            {
                "overview.view",
                "events.view",
                "events.handle",
                "policies.view",
                "policies.manage",
                "tools.view",
                "supply.view",
                "supply.manage",
                "audit.view",
                "eval.view",
                "eval.run",
                "users.view",
                "account.approve",
            }
        ),
    ),
    RoleSeed(
        "sec_operator",
        "安全运营员",
        "一线值班:监测处置事件、看管控与取证",
        frozenset(
            {
                "overview.view",
                "events.view",
                "events.handle",
                "tools.view",
                "supply.view",
                "audit.view",
                "eval.view",
            }
        ),
    ),
    RoleSeed(
        "auditor",
        "审计员",
        "只读取证:审计溯源与评测结果,不可改配置",
        frozenset({"overview.view", "events.view", "audit.view", "eval.view"}),
    ),
    RoleSeed(
        "viewer",
        "只读访客",
        "只读:仅查看各业务看板,不可操作、不可见系统管理",
        _BOARD_VIEW,
    ),
)

DEFAULT_BOOTSTRAP_ROLE = "super_admin"


# ── 内置组织架构种子(典型政企安全运营组织)──────────────────────
@dataclass(frozen=True, slots=True)
class DeptSeed:
    key: str
    name: str
    parent_key: str | None


BUILTIN_DEPARTMENTS: tuple[DeptSeed, ...] = (
    DeptSeed("root", "信息安全中心", None),
    DeptSeed("soc", "安全运营中心(SOC)", "root"),
    DeptSeed("soc_monitor", "7×24 监控值班组", "soc"),
    DeptSeed("soc_ir", "应急响应组(IR)", "soc"),
    DeptSeed("grc", "安全管理与合规组", "root"),
    DeptSeed("redblue", "攻防与威胁情报组", "root"),
    DeptSeed("platform", "安全平台与运维组", "root"),
)
