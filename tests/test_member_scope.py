"""成员管理范围化(plan/13 P1b.2)—— 团队负责人只管本团队,不能跨团队、不能改派角色。

在 HTTP 边界钉死"团队组长读写本团队成员":
- 负责人停用/重置本团队成员 → 放行;碰别团队成员 → 403;
- 负责人改派角色 / 把人移出团队 → 403(防越权升级);
- 普通成员(无 users.manage、非负责人)进不了成员管理端点 → 403;
- 组织管理员(users.manage)跨团队照常管全部。
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.registry import registry

_ADMIN_PW = "scope-admin-pw-1"
_LEAD_PW = "scope-lead-pw-12"
_INSIDER_PW = "insider-pw-123"
_OUTSIDER_PW = "outsider-pw-12"


def _build(tmp_path: Path) -> tuple[TestClient, dict[str, int]]:
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
    # 团队负责人:无组织级 users.manage,仅 SOC 负责人(role_id=None 隔离,纯靠 is_lead 进场)
    lead, _ = d.create_user(
        username="lead", display_name="组长", role_id=None, department_id=soc.id, password=_LEAD_PW
    )
    d.set_user_teams(lead.id, [(soc.id, "lead", True)])
    insider, _ = d.create_user(
        username="insider",
        display_name="本组员",
        role_id=None,
        department_id=soc.id,
        password=_INSIDER_PW,
    )
    outsider, _ = d.create_user(
        username="outsider",
        display_name="他组员",
        role_id=None,
        department_id=grc.id,
        password=_OUTSIDER_PW,
    )
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    scanner = registry.create("scanner", "manifest")
    client = TestClient(build_api(pipeline, bundle, settings, scanner=scanner))
    return client, {"insider": insider.id, "outsider": outsider.id}


def _login(client: TestClient, username: str, password: str) -> None:
    assert (
        client.post("/auth/login", json={"username": username, "password": password}).status_code
        == 200
    )


def test_lead_manages_in_team_member(tmp_path: Path) -> None:
    client, ids = _build(tmp_path)
    _login(client, "lead", _LEAD_PW)
    r = client.post(f"/admin/users/{ids['insider']}/status", json={"status": "disabled"})
    assert r.status_code == 200, r.text


def test_lead_cannot_touch_other_team(tmp_path: Path) -> None:
    client, ids = _build(tmp_path)
    _login(client, "lead", _LEAD_PW)
    r = client.post(f"/admin/users/{ids['outsider']}/status", json={"status": "disabled"})
    assert r.status_code == 403


def test_lead_cannot_change_role(tmp_path: Path) -> None:
    client, ids = _build(tmp_path)
    _login(client, "lead", _LEAD_PW)
    r = client.patch(f"/admin/users/{ids['insider']}", json={"role_id": 1})
    assert r.status_code == 403


def test_plain_member_blocked_from_member_admin(tmp_path: Path) -> None:
    client, ids = _build(tmp_path)
    _login(client, "insider", _INSIDER_PW)  # 普通成员:无 users.manage、非负责人
    r = client.post(f"/admin/users/{ids['outsider']}/status", json={"status": "disabled"})
    assert r.status_code == 403


def test_org_admin_manages_all(tmp_path: Path) -> None:
    client, ids = _build(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    r = client.post(f"/admin/users/{ids['outsider']}/status", json={"status": "disabled"})
    assert r.status_code == 200, r.text
