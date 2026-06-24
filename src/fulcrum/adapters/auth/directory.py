"""DirectoryService —— 组织/角色/成员的管理编排(供管理员后台调用)。

把"高管管理部门与员工"的真实动作落地:建改删部门、自定义角色与权限点、增减成员、
调岗调权、停用/离职、重置口令、审批账号申请。带真实安全护栏(防自锁、防误删在用对象)。
权限的"谁能调用"由 API 层 require_permission 把关,本层只管业务规则与一致性。
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable

from .models import (
    STATUS_ACTIVE,
    STATUS_PENDING,
    VALID_STATUSES,
    Department,
    Membership,
    Role,
    User,
)
from .passwords import hash_password
from .permissions import DEFAULT_BOOTSTRAP_ROLE, valid_permissions
from .store import _UNSET as _STORE_UNSET
from .store import SQLiteAuthStore

_MIN_PASSWORD_LEN = 8


class DirectoryError(Exception):
    """管理操作失败基类。"""


class NotFound(DirectoryError):
    pass


class Conflict(DirectoryError):
    """违反一致性/护栏(如部门下有人、删最后一个管理员)。"""


def _slugify(name: str) -> str:
    base = "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")
    return base or "role"


class DirectoryService:
    def __init__(self, store: SQLiteAuthStore, *, clock: Callable[[], float] = time.time) -> None:
        self._store = store
        self._clock = clock

    def _now(self) -> int:
        return int(self._clock())

    @staticmethod
    def _gen_temp_password() -> str:
        return secrets.token_urlsafe(9)

    # ── 部门 ──────────────────────────────────────────────────────
    def list_departments(self) -> list[Department]:
        return self._store.list_departments()

    def department_member_count(self, dept_id: int) -> int:
        return self._store.department_member_count(dept_id)

    def role_member_count(self, role_id: int) -> int:
        return self._store.role_member_count(role_id)

    def create_department(
        self, name: str, parent_id: int | None, sort_order: int = 100
    ) -> Department:
        name = name.strip()
        if not name:
            raise Conflict("部门名称不能为空")
        if parent_id is not None and self._get_dept(parent_id) is None:
            raise NotFound("上级部门不存在")
        return self._store.create_department(name, parent_id, sort_order, self._now())

    def update_department(
        self,
        dept_id: int,
        *,
        name: str | None = None,
        parent_id: int | None | object = None,
        sort_order: int | None = None,
        change_parent: bool = False,
    ) -> Department:
        if self._get_dept(dept_id) is None:
            raise NotFound("部门不存在")
        if change_parent and isinstance(parent_id, int):
            if parent_id == dept_id or self._is_descendant(parent_id, dept_id):
                raise Conflict("不能把部门移动到自己或其子部门下")
        self._store.update_department(
            dept_id,
            name=name,
            parent_id=parent_id if change_parent else _STORE_UNSET,
            sort_order=sort_order,
        )
        dept = self._get_dept(dept_id)
        assert dept is not None
        return dept

    def delete_department(self, dept_id: int) -> None:
        if self._get_dept(dept_id) is None:
            raise NotFound("部门不存在")
        if self._store.department_has_children(dept_id):
            raise Conflict("该部门下还有子部门,请先移除或迁移")
        if self._store.department_member_count(dept_id) > 0:
            raise Conflict("该部门下还有成员,请先调整成员归属")
        self._store.delete_department(dept_id)

    def _get_dept(self, dept_id: int) -> Department | None:
        return next((d for d in self._store.list_departments() if d.id == dept_id), None)

    def _is_descendant(self, candidate: int, ancestor: int) -> bool:
        """candidate 是否在 ancestor 的子树内(防止把父挂到自己的后代下成环)。"""
        depts = {d.id: d for d in self._store.list_departments()}
        cur = depts.get(candidate)
        guard = 0
        while cur and cur.parent_id is not None and guard < 1000:
            if cur.parent_id == ancestor:
                return True
            cur = depts.get(cur.parent_id)
            guard += 1
        return False

    def subtree_ids(self, dept_id: int) -> list[int]:
        """含自身在内的整棵子树部门 id(选父部门即看到其下全部成员)。"""
        depts = self._store.list_departments()
        children: dict[int, list[int]] = {}
        for d in depts:
            if d.parent_id is not None:
                children.setdefault(d.parent_id, []).append(d.id)
        out, stack = [], [dept_id]
        while stack:
            cur = stack.pop()
            out.append(cur)
            stack.extend(children.get(cur, []))
        return out

    # ── 团队成员关系(多对多;部门即团队)────────────────────────────
    def list_user_teams(self, user_id: int) -> list[Membership]:
        return self._store.list_user_memberships(user_id)

    def list_team_members(self, team_id: int) -> list[Membership]:
        return self._store.list_team_memberships(team_id)

    def team_member_count(self, team_id: int) -> int:
        return self._store.team_member_count(team_id)

    def add_team_member(
        self, team_id: int, user_id: int, team_role: str = "member", is_lead: bool = False
    ) -> Membership:
        """把某成员加入/更新到某团队(团队不存在或成员不存在即拒)。"""
        if self._get_dept(team_id) is None:
            raise NotFound("团队不存在")
        self._require_user(user_id)
        role = (team_role or "member").strip() or "member"
        self._store.add_membership(user_id, team_id, role, bool(is_lead), self._now())
        return Membership(user_id=user_id, team_id=team_id, team_role=role, is_lead=bool(is_lead))

    def remove_team_member(self, team_id: int, user_id: int) -> None:
        if self._get_dept(team_id) is None:
            raise NotFound("团队不存在")
        self._store.remove_membership(user_id, team_id)

    def set_user_teams(self, user_id: int, teams: list[tuple[int, str, bool]]) -> list[Membership]:
        """整体设置某用户的团队归属(team_id, team_role, is_lead)。团队不存在即拒;按 team 去重。"""
        self._require_user(user_id)
        dept_ids = {d.id for d in self._store.list_departments()}
        cleaned: list[tuple[int, str, bool]] = []
        seen: set[int] = set()
        for team_id, team_role, is_lead in teams:
            if team_id not in dept_ids:
                raise NotFound("团队不存在")
            if team_id in seen:
                continue
            seen.add(team_id)
            cleaned.append((team_id, (team_role or "member").strip() or "member", bool(is_lead)))
        self._store.set_user_memberships(user_id, cleaned, self._now())
        return self._store.list_user_memberships(user_id)

    # ── 角色 ──────────────────────────────────────────────────────
    def list_roles(self) -> list[Role]:
        return self._store.list_roles()

    def create_role(self, name: str, description: str, permissions: list[str]) -> Role:
        name = name.strip()
        if not name:
            raise Conflict("角色名称不能为空")
        perms = valid_permissions(permissions)
        key = self._unique_role_key(_slugify(name))
        return self._store.create_role(key, name, description.strip(), False, perms, self._now())

    def _unique_role_key(self, base: str) -> str:
        existing = {r.key for r in self._store.list_roles()}
        if base not in existing:
            return base
        for _ in range(50):
            cand = f"{base}-{secrets.token_hex(2)}"
            if cand not in existing:
                return cand
        return f"{base}-{secrets.token_hex(4)}"

    def update_role(
        self,
        role_id: int,
        *,
        name: str | None = None,
        description: str | None = None,
        permissions: list[str] | None = None,
    ) -> Role:
        role = self._store.get_role(role_id)
        if role is None:
            raise NotFound("角色不存在")
        self._store.update_role(
            role_id,
            name.strip() if name else None,
            description.strip() if description is not None else None,
            valid_permissions(permissions) if permissions is not None else None,
        )
        updated = self._store.get_role(role_id)
        assert updated is not None
        return updated

    def delete_role(self, role_id: int) -> None:
        role = self._store.get_role(role_id)
        if role is None:
            raise NotFound("角色不存在")
        if self._store.role_member_count(role_id) > 0:
            raise Conflict("仍有成员使用该角色,请先改派后再删除")
        self._store.delete_role(role_id)

    # ── 成员 ──────────────────────────────────────────────────────
    def list_users(
        self,
        *,
        department_id: int | None = None,
        status: str | None = None,
        role_id: int | None = None,
        search: str | None = None,
    ) -> list[User]:
        dept_ids = self.subtree_ids(department_id) if department_id is not None else None
        return self._store.list_users(
            department_ids=dept_ids, status=status, role_id=role_id, search=search
        )

    def status_counts(self) -> dict[str, int]:
        return self._store.count_by_status()

    def get_user(self, user_id: int) -> User | None:
        return self._store.get_user_by_id(user_id)

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        role_id: int | None,
        department_id: int | None,
        password: str | None = None,
        employee_no: str = "",
        email: str = "",
        phone: str = "",
        title: str = "",
    ) -> tuple[User, str | None]:
        """管理员直建成员。无 password 则生成临时口令一次性返回。"""
        username = username.strip()
        display_name = display_name.strip()
        if not username or not display_name:
            raise Conflict("账号与姓名不能为空")
        if self._store.get_user(username) is not None:
            raise Conflict("该账号已存在")
        self._validate_refs(role_id, department_id)
        temp = None
        if password:
            if len(password) < _MIN_PASSWORD_LEN:
                raise Conflict(f"口令至少需要 {_MIN_PASSWORD_LEN} 位")
            pwd = password
        else:
            pwd = temp = self._gen_temp_password()
        user = self._store.create_user(
            username,
            display_name,
            hash_password(pwd),
            STATUS_ACTIVE,
            self._now(),
            employee_no=employee_no.strip(),
            email=email.strip(),
            phone=phone.strip(),
            title=title.strip(),
            department_id=department_id,
            role_id=role_id,
        )
        return user, temp

    def update_user(
        self,
        user_id: int,
        *,
        fields: dict[str, object],
    ) -> User:
        user = self._require_user(user_id)
        role_changed = "role_id" in fields and fields["role_id"] != user.role_id
        if "role_id" in fields or "department_id" in fields:
            self._validate_refs(
                fields.get("role_id", user.role_id),  # type: ignore[arg-type]
                fields.get("department_id", user.department_id),  # type: ignore[arg-type]
            )
        if role_changed and self._is_last_active_admin(user):
            raise Conflict("不能改派最后一个在岗超级管理员的角色")
        clean = {k: v for k, v in fields.items() if k != "status"}  # 状态走独立通道
        self._store.update_user_profile(user_id, clean)
        if role_changed:
            self._store.delete_user_sessions(user_id)  # 权限变更即时生效:踢下线重登
        updated = self._store.get_user_by_id(user_id)
        assert updated is not None
        return updated

    def set_status(self, user_id: int, status: str) -> User:
        user = self._require_user(user_id)
        if status not in VALID_STATUSES:
            raise Conflict("非法状态")
        if status != STATUS_ACTIVE and self._is_last_active_admin(user):
            raise Conflict("不能停用/离职最后一个在岗超级管理员")
        self._store.update_user_profile(user_id, {"status": status})
        if status != STATUS_ACTIVE:
            self._store.delete_user_sessions(user_id)
        updated = self._store.get_user_by_id(user_id)
        assert updated is not None
        return updated

    def reset_password(self, user_id: int, new_password: str | None = None) -> str | None:
        self._require_user(user_id)
        temp = None
        if new_password:
            if len(new_password) < _MIN_PASSWORD_LEN:
                raise Conflict(f"口令至少需要 {_MIN_PASSWORD_LEN} 位")
            pwd = new_password
        else:
            pwd = temp = self._gen_temp_password()
        self._store.update_password_hash(user_id, hash_password(pwd))
        self._store.delete_user_sessions(user_id)  # 重置后旧会话失效
        return temp

    def approve(self, user_id: int, role_id: int | None, department_id: int | None) -> User:
        user = self._require_user(user_id)
        if user.status != STATUS_PENDING:
            raise Conflict("该账号不在待审批状态")
        self._validate_refs(role_id, department_id)
        self._store.update_user_profile(
            user_id,
            {"status": STATUS_ACTIVE, "role_id": role_id, "department_id": department_id},
        )
        updated = self._store.get_user_by_id(user_id)
        assert updated is not None
        return updated

    def reject(self, user_id: int) -> None:
        user = self._require_user(user_id)
        if user.status != STATUS_PENDING:
            raise Conflict("该账号不在待审批状态")
        # 驳回即删除申请记录(未激活、无历史),保持库干净。
        self._store.delete_user(user_id)

    # ── 内部 ──────────────────────────────────────────────────────
    def _require_user(self, user_id: int) -> User:
        user = self._store.get_user_by_id(user_id)
        if user is None:
            raise NotFound("成员不存在")
        return user

    def _validate_refs(self, role_id: int | None, department_id: int | None) -> None:
        if role_id is not None and self._store.get_role(role_id) is None:
            raise NotFound("角色不存在")
        if department_id is not None and self._get_dept(department_id) is None:
            raise NotFound("部门不存在")

    def _is_last_active_admin(self, user: User) -> bool:
        """user 是否为最后一个在岗超级管理员(护栏:防止把自己锁在门外)。"""
        admin_role = self._store.get_role_by_key(DEFAULT_BOOTSTRAP_ROLE)
        if admin_role is None or user.role_id != admin_role.id or user.status != STATUS_ACTIVE:
            return False
        actives = self._store.list_users(status=STATUS_ACTIVE, role_id=admin_role.id)
        return len(actives) <= 1


# 与 store 的 _UNSET 哨兵对应:update_department 未改父级时传它。
