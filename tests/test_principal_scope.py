"""Principal 团队范围(plan/13 P1b.1)—— 鉴权时算出"能管哪些团队",子树继承。

钉死:团队负责人的 managed_teams = 其团队的整棵子树;普通成员无管理范围;组织级 users.manage
跨团队管全部;can_manage_team 据此判"团队组长只管本团队、不能跨团队"。纯加法,旧鉴权不变。
"""

from __future__ import annotations

from pathlib import Path

from fulcrum.adapters.auth.service import AuthService
from fulcrum.adapters.auth.store import SQLiteAuthStore


def _svc(tmp_path: Path) -> tuple[AuthService, SQLiteAuthStore]:
    store = SQLiteAuthStore(str(tmp_path / "auth.sqlite"))
    svc = AuthService(
        store, session_ttl_hours=1, max_failures=5, lockout_minutes=15, clock=lambda: 1000
    )
    return svc, store


def _session(svc: AuthService, store: SQLiteAuthStore, user_id: int, token: str) -> None:
    store.create_session(AuthService._hash_token(token), user_id, 1000, 1_000_000)


def test_team_lead_manages_own_subtree_only(tmp_path: Path) -> None:
    svc, store = _svc(tmp_path)
    soc = store.create_department("SOC", None, 10, 1000)
    soc_mon = store.create_department("监控组", soc.id, 20, 1000)
    grc = store.create_department("合规组", None, 30, 1000)
    alice = store.create_user("alice", "Alice", "h", "active", 1000)
    store.set_user_memberships(alice.id, [(soc.id, "lead", True)], 1000)
    _session(svc, store, alice.id, "tok-alice")

    p = svc.authenticate("tok-alice")
    assert p is not None
    assert p.managed_teams == frozenset({soc.id, soc_mon.id})  # 子树继承:含监控组
    assert p.can_manage_team(soc.id) and p.can_manage_team(soc_mon.id)
    assert not p.can_manage_team(grc.id)  # 跨团队 → 拒
    assert not p.can_manage_team(None)


def test_plain_member_manages_nothing(tmp_path: Path) -> None:
    svc, store = _svc(tmp_path)
    soc = store.create_department("SOC", None, 10, 1000)
    bob = store.create_user("bob", "Bob", "h", "active", 1000)
    store.set_user_memberships(bob.id, [(soc.id, "member", False)], 1000)
    _session(svc, store, bob.id, "tok-bob")

    p = svc.authenticate("tok-bob")
    assert p is not None
    assert p.team_ids == frozenset({soc.id})
    assert p.managed_teams == frozenset()
    assert not p.can_manage_team(soc.id)  # 只是成员,非负责人


def test_builtin_role_scopes(tmp_path: Path) -> None:
    """内置角色按 plan/13 §4 分组:平台管理员=组织级,值班/审计/访客=团队级模板。"""
    svc, store = _svc(tmp_path)
    svc.seed("admin", "seed-admin-pw-123")
    scopes = {r.key: r.scope for r in store.list_roles()}
    assert scopes["super_admin"] == "org" and scopes["sys_admin"] == "org"
    assert scopes["sec_manager"] == "team"
    assert scopes["sec_operator"] == "team"
    assert scopes["auditor"] == "team" and scopes["viewer"] == "team"


def test_org_admin_manages_all_teams(tmp_path: Path) -> None:
    svc, store = _svc(tmp_path)
    soc = store.create_department("SOC", None, 10, 1000)
    grc = store.create_department("合规组", None, 30, 1000)
    admin_role = store.create_role("admin", "管理员", "", True, ["users.manage"], 1000)
    carol = store.create_user("carol", "Carol", "h", "active", 1000, role_id=admin_role.id)
    _session(svc, store, carol.id, "tok-carol")

    p = svc.authenticate("tok-carol")
    assert p is not None
    # 组织级 users.manage:无需团队负责人身份即可跨团队管理
    assert p.managed_teams == frozenset()
    assert p.can_manage_team(soc.id) and p.can_manage_team(grc.id)
    assert p.can_manage_team(None)
