"""鉴权 / 目录域的只读数据结构(不含框架依赖)。"""

from __future__ import annotations

from dataclasses import dataclass, field

# 账号状态:待审批 → 启用 ↔ 停用;离职为终态(保留留痕,不可登录)。
STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"
STATUS_LEFT = "left"
VALID_STATUSES = frozenset({STATUS_PENDING, STATUS_ACTIVE, STATUS_DISABLED, STATUS_LEFT})


@dataclass(frozen=True, slots=True)
class Department:
    id: int
    name: str
    parent_id: int | None
    sort_order: int


@dataclass(frozen=True, slots=True)
class Membership:
    """成员在某团队(部门升格)里的归属:团队内角色 + 是否团队负责人(maintainer)。

    多对多——一人可在多个团队、各持不同团队角色(plan/13 §5)。team_role 指向团队级角色模板
    的 key(P1b 接 `can(perm, scope)` 时据它算该团队内的生效权限);is_lead 标记团队负责人,
    可读写管理本团队子树。本结构是数据层真源,P1b/P1d 消费。
    """

    user_id: int
    team_id: int
    team_role: str = "member"
    is_lead: bool = False


# 角色范围(plan/13 §4):组织级角色全局生效(平台管理员);团队级角色是团队内模板。
ROLE_SCOPE_ORG = "org"
ROLE_SCOPE_TEAM = "team"
VALID_ROLE_SCOPES = frozenset({ROLE_SCOPE_ORG, ROLE_SCOPE_TEAM})


@dataclass(frozen=True, slots=True)
class Role:
    id: int
    key: str
    name: str
    description: str
    is_system: bool
    permissions: frozenset[str] = field(default_factory=frozenset)
    scope: str = ROLE_SCOPE_ORG  # org=组织级(全局) | team=团队级(团队内模板)


@dataclass(frozen=True, slots=True)
class User:
    """完整用户记录(store 内部 + 管理接口用)。`password_hash` 绝不出 API。"""

    id: int
    username: str
    display_name: str
    password_hash: str
    status: str
    employee_no: str = ""
    email: str = ""
    phone: str = ""
    title: str = ""
    department_id: int | None = None
    role_id: int | None = None
    created_at: int = 0
    last_login_at: int | None = None


@dataclass(frozen=True, slots=True)
class Principal:
    """会话校验通过后的当事人 —— 路由侧拿到的就是它。

    携带角色与**生效权限点集合**,供 require_permission 与前端按权过滤使用;
    绝不暴露口令哈希。

    团队范围(plan/13 P1b):
    - ``team_ids`` —— 本人所属团队 id(展示/未来资源可见范围用);
    - ``managed_teams`` —— 本人作为团队负责人(maintainer)可管的团队 id,**已展开到子树**
      (选父团队即覆盖其下全部子团队);组织级成员管理权(users.manage)另算,见 can_manage_team。
    新增字段都带默认值,旧的 Principal 构造(测试/历史)不受影响。
    """

    user_id: int
    username: str
    display_name: str
    role_key: str | None
    role_name: str | None
    permissions: frozenset[str]
    team_ids: frozenset[int] = field(default_factory=frozenset)
    managed_teams: frozenset[int] = field(default_factory=frozenset)

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def can_manage_team(self, team_id: int | None) -> bool:
        """能否管理某团队的成员:组织级 users.manage 管全部;否则需是该团队(子树)的负责人。

        这是"团队组长只管本团队、不能跨团队"的判据(plan/13 §5)。team_id 为 None(无归属)
        时,仅组织级成员管理权可管。
        """
        if self.has("users.manage"):  # 组织级成员管理 → 跨团队管全部
            return True
        return team_id is not None and team_id in self.managed_teams
