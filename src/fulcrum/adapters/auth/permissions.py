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
    key: str
    label: str
    group: str  # 与前端导航分组一致:监测/管控/取证/系统


# ── 权限点目录(唯一真源)──────────────────────────────────────────
PERMISSIONS: tuple[PermissionDef, ...] = (
    # 监测
    PermissionDef("overview.view", "安全总览", "监测"),
    PermissionDef("events.view", "会话事件", "监测"),
    PermissionDef("events.handle", "处置事件", "监测"),
    # 管控
    PermissionDef("policies.view", "策略中心", "管控"),
    PermissionDef("policies.manage", "编辑策略", "管控"),
    PermissionDef("tools.view", "工具网关", "管控"),
    PermissionDef("tools.manage", "管控工具", "管控"),
    PermissionDef("supply.view", "供应链", "管控"),
    PermissionDef("supply.manage", "处置供应链风险", "管控"),
    # 取证
    PermissionDef("audit.view", "审计溯源", "取证"),
    PermissionDef("eval.view", "评测验证", "取证"),
    PermissionDef("eval.run", "发起评测", "取证"),
    # 系统
    PermissionDef("settings.view", "系统设置", "系统"),
    PermissionDef("settings.manage", "修改设置", "系统"),
    PermissionDef("users.view", "查看成员", "系统"),
    PermissionDef("users.manage", "管理成员", "系统"),
    PermissionDef("dept.manage", "管理组织架构", "系统"),
    PermissionDef("roles.manage", "管理角色权限", "系统"),
    PermissionDef("account.approve", "审批账号申请", "系统"),
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
