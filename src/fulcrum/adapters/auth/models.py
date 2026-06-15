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
class Role:
    id: int
    key: str
    name: str
    description: str
    is_system: bool
    permissions: frozenset[str] = field(default_factory=frozenset)


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
    """

    user_id: int
    username: str
    display_name: str
    role_key: str | None
    role_name: str | None
    permissions: frozenset[str]

    def has(self, permission: str) -> bool:
        return permission in self.permissions
