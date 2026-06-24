"""账号审批下放(plan/13 §6 / P3)—— 团队负责人可审批"加入本团队"的账号,超管不再是唯一审批人。

在 HTTP 边界钉死:
- 团队负责人把待审账号审进**自己负责的团队** → 放行;审进别团队 / 赋组织级角色 → 403;
- 负责人审"指向别团队"的申请 → 403(不能抢审);驳回亦只能驳本团队的待审申请;
- 普通成员(无 account.approve、非负责人)进不了审批端点 → 403;
- 组织级审批人(account.approve)跨团队照常审全部、可赋任意角色。
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.registry import registry

_ADMIN_PW = "appr-admin-pw-123"
_LEAD_PW = "appr-lead-pw-1234"
_MEMBER_PW = "appr-member-pw-12"


def _build(tmp_path: Path):
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        eval_report_path=str(tmp_path / "no.json"),
        gateway_config_path=str(tmp_path / "gw.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )
    bundle = build_auth_bundle(settings)
    d = bundle.directory
    soc = d.create_department("SOC", None)
    grc = d.create_department("合规组", None)
    lead, _ = d.create_user(
        username="lead", display_name="组长", role_id=None, department_id=soc.id, password=_LEAD_PW
    )
    d.set_user_teams(lead.id, [(soc.id, "lead", True)])
    member, _ = d.create_user(
        username="member",
        display_name="组员",
        role_id=None,
        department_id=soc.id,
        password=_MEMBER_PW,
    )
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    scanner = registry.create("scanner", "manifest")
    client = TestClient(build_api(pipeline, bundle, settings, scanner=scanner))
    team_role = next(r for r in d.list_roles() if r.scope == "team")
    org_role = next(r for r in d.list_roles() if r.scope == "org")
    return (
        client,
        d,
        {"soc": soc.id, "grc": grc.id, "team_role": team_role.id, "org_role": org_role.id},
    )


def _pending(directory, dept_id=None) -> int:
    """造一个待审账号(可指定其"申请加入"的团队 dept_id)。"""
    u, _ = directory.create_user(
        username=f"pend{dept_id}",
        display_name="待审",
        role_id=None,
        department_id=dept_id,
        password="pw12345678",
    )
    directory.set_status(u.id, "pending")
    return u.id


def _login(client: TestClient, username: str, password: str) -> None:
    assert (
        client.post("/auth/login", json={"username": username, "password": password}).status_code
        == 200
    )


def test_lead_approves_into_own_team(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d)
    _login(client, "lead", _LEAD_PW)
    r = client.post(
        f"/admin/users/{uid}/approve",
        json={"department_id": ids["soc"], "role_id": ids["team_role"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"


def test_lead_cannot_approve_into_other_team(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d)
    _login(client, "lead", _LEAD_PW)
    r = client.post(
        f"/admin/users/{uid}/approve",
        json={"department_id": ids["grc"], "role_id": ids["team_role"]},
    )
    assert r.status_code == 403


def test_lead_cannot_grant_org_role(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d)
    _login(client, "lead", _LEAD_PW)
    r = client.post(
        f"/admin/users/{uid}/approve",
        json={"department_id": ids["soc"], "role_id": ids["org_role"]},
    )
    assert r.status_code == 403  # 不能借审批安插组织级角色提权


def test_lead_cannot_steal_other_team_request(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d, dept_id=ids["grc"])  # 申请指向合规组
    _login(client, "lead", _LEAD_PW)
    r = client.post(
        f"/admin/users/{uid}/approve",
        json={"department_id": ids["soc"], "role_id": ids["team_role"]},
    )
    assert r.status_code == 403  # SOC 组长不能抢审合规组的申请


def test_plain_member_cannot_approve(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d)
    _login(client, "member", _MEMBER_PW)  # 无 account.approve、非负责人
    r = client.post(
        f"/admin/users/{uid}/approve",
        json={"department_id": ids["soc"], "role_id": ids["team_role"]},
    )
    assert r.status_code == 403


def test_lead_rejects_own_team_request(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d, dept_id=ids["soc"])
    _login(client, "lead", _LEAD_PW)
    r = client.post(f"/admin/users/{uid}/reject")
    assert r.status_code == 204


def test_lead_cannot_reject_other_team_request(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d, dept_id=ids["grc"])
    _login(client, "lead", _LEAD_PW)
    r = client.post(f"/admin/users/{uid}/reject")
    assert r.status_code == 403


def test_org_admin_approves_anything(tmp_path: Path) -> None:
    client, d, ids = _build(tmp_path)
    uid = _pending(d, dept_id=ids["grc"])
    _login(client, "admin", _ADMIN_PW)
    r = client.post(
        f"/admin/users/{uid}/approve",
        json={"department_id": ids["grc"], "role_id": ids["org_role"]},
    )
    assert r.status_code == 200, r.text
