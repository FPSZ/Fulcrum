"""登录鉴权 + RBAC + 成员生命周期。"""

from __future__ import annotations

from pathlib import Path

import pytest

from fulcrum.adapters.auth import (
    AccountDisabled,
    AccountLocked,
    AuthService,
    Conflict,
    DirectoryService,
    InvalidCredentials,
    PendingApproval,
    SQLiteAuthStore,
)
from fulcrum.adapters.auth.passwords import hash_password, verify_password
from fulcrum.adapters.auth.permissions import ALL_PERMISSION_KEYS

ADMIN_PW = "correct horse battery"


def test_password_hash_roundtrip() -> None:
    h = hash_password("S3cret-口令")
    assert h != "S3cret-口令"
    assert verify_password(h, "S3cret-口令") is True
    assert verify_password(h, "wrong") is False


def test_two_hashes_differ_by_salt() -> None:
    assert hash_password("same") != hash_password("same")


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _build(tmp_path: Path, clock: _Clock, **kw: int) -> tuple[AuthService, DirectoryService]:
    store = SQLiteAuthStore(str(tmp_path / "auth.sqlite"))
    auth = AuthService(
        store,
        session_ttl_hours=kw.get("session_ttl_hours", 12),
        max_failures=kw.get("max_failures", 3),
        lockout_minutes=kw.get("lockout_minutes", 15),
        clock=clock,
    )
    auth.seed("admin", ADMIN_PW)
    return auth, DirectoryService(store, clock=clock)


# ── 种子 / 登录 ───────────────────────────────────────────────────
def test_seed_creates_roles_departments_admin(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    assert len(directory.list_roles()) >= 6
    assert len(directory.list_departments()) >= 5
    token = auth.login("admin", ADMIN_PW)
    p = auth.authenticate(token)
    assert p is not None
    # 超级管理员拥有全部权限点
    assert p.permissions == ALL_PERMISSION_KEYS
    assert p.role_key == "super_admin"


def test_seed_idempotent(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    n_roles, n_users = len(directory.list_roles()), len(directory.list_users())
    auth.seed("admin", ADMIN_PW)  # 再来一次不应重复建
    assert len(directory.list_roles()) == n_roles
    assert len(directory.list_users()) == n_users


def test_wrong_password_and_enumeration(tmp_path: Path) -> None:
    clock = _Clock()
    auth, _ = _build(tmp_path, clock)
    with pytest.raises(InvalidCredentials):
        auth.login("admin", "nope")
    with pytest.raises(InvalidCredentials):
        auth.login("ghost", "whatever")  # 未知账号同样的错


def test_lockout(tmp_path: Path) -> None:
    clock = _Clock()
    auth, _ = _build(tmp_path, clock, max_failures=3, lockout_minutes=15)
    for _ in range(3):
        with pytest.raises(InvalidCredentials):
            auth.login("admin", "bad")
    with pytest.raises(AccountLocked):
        auth.login("admin", ADMIN_PW)
    clock.now += 15 * 60 + 1
    assert auth.login("admin", ADMIN_PW)


def test_logout_and_expiry(tmp_path: Path) -> None:
    clock = _Clock()
    auth, _ = _build(tmp_path, clock, session_ttl_hours=1)
    token = auth.login("admin", ADMIN_PW)
    assert auth.authenticate(token) is not None
    auth.logout(token)
    assert auth.authenticate(token) is None
    token2 = auth.login("admin", ADMIN_PW)
    clock.now += 3600 + 1
    assert auth.authenticate(token2) is None


def test_garbage_token(tmp_path: Path) -> None:
    clock = _Clock()
    auth, _ = _build(tmp_path, clock)
    assert auth.authenticate(None) is None
    assert auth.authenticate("not-a-real-token") is None


# ── 申请 → 审批流 ─────────────────────────────────────────────────
def test_register_pending_cannot_login(tmp_path: Path) -> None:
    clock = _Clock()
    auth, _ = _build(tmp_path, clock)
    auth.register("lin", "applicant-pw-123", "林珩")
    with pytest.raises(PendingApproval):
        auth.login("lin", "applicant-pw-123")


def test_approve_then_login_with_role(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    auth.register("lin", "applicant-pw-123", "林珩")
    pending = directory.list_users(status="pending")
    assert len(pending) == 1
    operator = next(r for r in directory.list_roles() if r.key == "sec_operator")
    dept = directory.list_departments()[0]
    directory.approve(pending[0].id, operator.id, dept.id)
    token = auth.login("lin", "applicant-pw-123")
    p = auth.authenticate(token)
    assert p is not None and p.role_key == "sec_operator"
    assert "events.handle" in p.permissions
    assert "users.manage" not in p.permissions  # 运营员无管理权


def test_reject_deletes(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    auth.register("spam", "applicant-pw-123", "可疑")
    pending = directory.list_users(status="pending")
    directory.reject(pending[0].id)
    assert directory.list_users(status="pending") == []


# ── 部门 ─────────────────────────────────────────────────────────
def test_department_tree_and_delete_guards(tmp_path: Path) -> None:
    clock = _Clock()
    _, directory = _build(tmp_path, clock)
    root = directory.list_departments()[0]
    child = directory.create_department("新小组", root.id)
    assert child.id in directory.subtree_ids(root.id)
    with pytest.raises(Conflict):
        directory.delete_department(root.id)  # 有子部门
    directory.delete_department(child.id)  # 叶子可删
    assert child.id not in {d.id for d in directory.list_departments()}


def test_department_no_cycle(tmp_path: Path) -> None:
    clock = _Clock()
    _, directory = _build(tmp_path, clock)
    a = directory.create_department("A", None)
    b = directory.create_department("B", a.id)
    with pytest.raises(Conflict):
        directory.update_department(a.id, parent_id=b.id, change_parent=True)


# ── 角色 RBAC ─────────────────────────────────────────────────────
def test_custom_role_and_system_role_locked(tmp_path: Path) -> None:
    clock = _Clock()
    _, directory = _build(tmp_path, clock)
    role = directory.create_role("值班长", "带班", ["overview.view", "events.handle", "bogus.x"])
    assert role.permissions == frozenset({"overview.view", "events.handle"})  # 非法点被滤掉
    assert role.is_system is False
    system_role = next(r for r in directory.list_roles() if r.is_system)
    with pytest.raises(Conflict):
        directory.update_role(system_role.id, name="改不动")
    with pytest.raises(Conflict):
        directory.delete_role(system_role.id)


def test_delete_role_in_use_refused(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    role = directory.create_role("临时", "", ["overview.view"])
    directory.create_user(
        username="u1",
        display_name="员工一",
        role_id=role.id,
        department_id=None,
        password="member-pw-123",
    )
    with pytest.raises(Conflict):
        directory.delete_role(role.id)


# ── 成员生命周期 ─────────────────────────────────────────────────
def test_create_user_temp_password_then_login(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    user, temp = directory.create_user(
        username="zhao",
        display_name="赵六",
        role_id=None,
        department_id=None,
    )
    assert temp and len(temp) >= 8
    token = auth.login("zhao", temp)  # 临时口令可登录
    assert auth.authenticate(token) is not None


def test_role_change_kicks_sessions(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    role = directory.create_role("R", "", ["overview.view"])
    user, temp = directory.create_user(
        username="qian",
        display_name="钱七",
        role_id=role.id,
        department_id=None,
    )
    token = auth.login("qian", temp or "")
    assert auth.authenticate(token) is not None
    role2 = directory.create_role("R2", "", ["overview.view", "events.view"])
    directory.update_user(user.id, fields={"role_id": role2.id})
    assert auth.authenticate(token) is None  # 改权限即踢下线


def test_disable_kicks_and_blocks_login(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    user, temp = directory.create_user(
        username="sun",
        display_name="孙八",
        role_id=None,
        department_id=None,
    )
    token = auth.login("sun", temp or "")
    directory.set_status(user.id, "disabled")
    assert auth.authenticate(token) is None
    with pytest.raises(AccountDisabled):
        auth.login("sun", temp or "")


def test_cannot_disable_last_super_admin(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    admin = directory.list_users(status="active")[0]
    with pytest.raises(Conflict):
        directory.set_status(admin.id, "disabled")


def test_reset_password_invalidates_and_sets_new(tmp_path: Path) -> None:
    clock = _Clock()
    auth, directory = _build(tmp_path, clock)
    user, temp = directory.create_user(
        username="zhou",
        display_name="周九",
        role_id=None,
        department_id=None,
    )
    token = auth.login("zhou", temp or "")
    new_temp = directory.reset_password(user.id)
    assert auth.authenticate(token) is None  # 旧会话失效
    assert auth.login("zhou", new_temp or "")
