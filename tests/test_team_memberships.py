"""团队成员关系(多对多)数据层回归 —— plan/13 P1a。

钉死:set/list(按人、按团队)、整体替换语义、计数与负责人、外键级联(删人/删团队即清关系)、
目录层校验(团队不存在即拒 + 按 team 去重)。本期只验数据层,鉴权切换在 P1b。
沿用本仓约定:store/directory 直连,clock 注入。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fulcrum.adapters.auth.directory import DirectoryService, NotFound
from fulcrum.adapters.auth.store import SQLiteAuthStore


def _store(tmp_path: Path) -> SQLiteAuthStore:
    return SQLiteAuthStore(str(tmp_path / "auth.sqlite"))


def _seed(store: SQLiteAuthStore):
    soc = store.create_department("SOC", None, 100, 0)
    mon = store.create_department("监控组", soc.id, 100, 0)
    alice = store.create_user("alice", "Alice", "h", "active", 0)
    bob = store.create_user("bob", "Bob", "h", "active", 0)
    return soc, mon, alice, bob


def test_set_and_list_memberships(tmp_path: Path) -> None:
    store = _store(tmp_path)
    soc, mon, alice, _bob = _seed(store)
    store.set_user_memberships(alice.id, [(soc.id, "lead", True), (mon.id, "member", False)], 0)

    teams = store.list_user_memberships(alice.id)
    assert {m.team_id for m in teams} == {soc.id, mon.id}
    soc_m = next(m for m in teams if m.team_id == soc.id)
    assert soc_m.team_role == "lead" and soc_m.is_lead is True
    # 团队视角:SOC 的成员里有 alice
    assert [m.user_id for m in store.list_team_memberships(soc.id)] == [alice.id]


def test_set_replaces_all(tmp_path: Path) -> None:
    store = _store(tmp_path)
    soc, mon, alice, _bob = _seed(store)
    store.set_user_memberships(alice.id, [(soc.id, "member", False)], 0)
    store.set_user_memberships(alice.id, [(mon.id, "member", False)], 0)  # 整体替换
    assert {m.team_id for m in store.list_user_memberships(alice.id)} == {mon.id}


def test_counts_and_leads(tmp_path: Path) -> None:
    store = _store(tmp_path)
    soc, _mon, alice, bob = _seed(store)
    store.set_user_memberships(alice.id, [(soc.id, "lead", True)], 0)
    store.set_user_memberships(bob.id, [(soc.id, "member", False)], 0)
    assert store.team_member_count(soc.id) == 2
    assert store.team_lead_user_ids(soc.id) == [alice.id]


def test_cascade_on_user_delete(tmp_path: Path) -> None:
    store = _store(tmp_path)
    soc, _mon, alice, _bob = _seed(store)
    store.set_user_memberships(alice.id, [(soc.id, "member", False)], 0)
    store.delete_user(alice.id)
    assert store.list_team_memberships(soc.id) == []


def test_cascade_on_team_delete(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _soc, mon, alice, _bob = _seed(store)
    store.set_user_memberships(alice.id, [(mon.id, "member", False)], 0)
    store.delete_department(mon.id)
    assert store.list_user_memberships(alice.id) == []


def test_directory_validates_and_dedups(tmp_path: Path) -> None:
    store = _store(tmp_path)
    soc, _mon, alice, _bob = _seed(store)
    svc = DirectoryService(store, clock=lambda: 0)
    with pytest.raises(NotFound):
        svc.set_user_teams(alice.id, [(99999, "member", False)])  # 团队不存在
    out = svc.set_user_teams(alice.id, [(soc.id, "lead", True), (soc.id, "member", False)])
    assert len(out) == 1 and out[0].team_id == soc.id  # 同团队去重为一条
