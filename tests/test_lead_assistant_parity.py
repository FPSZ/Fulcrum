"""团队负责人「助手平权」(plan/13 P3)—— 助手权限与本人共享,且同样被团队范围钉死。

铁律(§3):AI 助手不是独立身份,以当前登录者 Principal 行事、继承其(已范围化)权限。
故团队负责人的助手:
- 可见 / 可确认 team_scoped 写工具(改成员状态/资料/口令、增减团队成员、审批入队);
- 但**目标范围**被钉死——只能管本团队子树成员,碰别团队即业务级拒绝(ok=False,非 500);
- 不得借改资料改派角色 / 把人移出可管团队(防越权升级);审批只能审进本团队、只能赋团队级角色;
- 普通成员(无 users.manage、非负责人)其助手根本看不到这些工具,执行点亦 denied。
组织管理员(users.manage)的助手跨团队管全部,与本人一致。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fulcrum.adapters.assistant import (
    ActionTokenSigner,
    AssistantActuator,
    AssistantServices,
    UndoStore,
)
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.adapters.auth.models import Principal
from fulcrum.adapters.console_settings import ConsoleSettingsStore
from fulcrum.adapters.gateway import GatewayConfigStore
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.operations import operation_registry

_ADMIN_PW = "parity-admin-pw-123"


def _setup(tmp_path: Path):
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        eval_report_path=str(tmp_path / "no-report.json"),
        gateway_config_path=str(tmp_path / "gateway.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    services = AssistantServices(
        pipeline=pipeline,
        eval_report_path=settings.eval_report_path,
        supply_manifest_dir=str(tmp_path / "manifests"),
        directory=bundle.directory,
        gateway_store=GatewayConfigStore(settings.gateway_config_path),
        console_store=ConsoleSettingsStore(settings.console_settings_path),
    )
    return bundle, services


def _org(directory):
    soc = directory.create_department("SOC", None)
    soc_mon = directory.create_department("监控组", soc.id)
    grc = directory.create_department("合规组", None)
    insider, _ = directory.create_user(
        username="insider",
        display_name="本组员",
        role_id=None,
        department_id=soc.id,
        password="pw123456",
    )
    outsider, _ = directory.create_user(
        username="outsider",
        display_name="他组员",
        role_id=None,
        department_id=grc.id,
        password="pw123456",
    )
    return soc, soc_mon, grc, insider, outsider


def _lead(soc_id: int, soc_mon_id: int) -> Principal:
    """SOC 负责人:无组织级权限,仅 ai.operate;managed_teams 含子树(SOC + 监控组)。"""
    return Principal(
        user_id=999,
        username="lead",
        display_name="组长",
        role_key="r",
        role_name="角色",
        permissions=frozenset({"ai.operate"}),
        team_ids=frozenset({soc_id}),
        managed_teams=frozenset({soc_id, soc_mon_id}),
    )


def _plain() -> Principal:
    return Principal(
        user_id=1000,
        username="plain",
        display_name="普通员",
        role_key="r",
        role_name="角色",
        permissions=frozenset({"ai.operate"}),
    )


def _actuator(services):
    signer = ActionTokenSigner()
    return signer, AssistantActuator(operation_registry, services, signer, UndoStore())


def _confirm(act, signer, tool, args, principal, session="s"):
    token = signer.issue(tool=tool, actor=principal.username, session_id=session)
    return asyncio.run(act.confirm(token, args, principal))


# ───────────────────────── 可见性:负责人的助手看得到 team_scoped 工具 ─────────────────────────
def test_lead_sees_member_tools(tmp_path: Path) -> None:
    bundle, _services = _setup(tmp_path)
    soc, soc_mon, _grc, _i, _o = _org(bundle.directory)
    names = {t.name for t in operation_registry.visible_for(_lead(soc.id, soc_mon.id))}
    # 负责人虽无 users.manage,team_scoped 工具仍可见(平权);组织级专属工具不在此列。
    assert {"set_user_status", "update_user", "add_team_member", "approve_account"} <= names


def test_plain_member_sees_no_member_write_tools(tmp_path: Path) -> None:
    _bundle, _services = _setup(tmp_path)
    names = {t.name for t in operation_registry.visible_for(_plain())}
    assert "set_user_status" not in names and "add_team_member" not in names


# ───────────────────────── 执行点:范围钉死 ─────────────────────────
def test_lead_assistant_manages_in_team_member(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, _grc, insider, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    res = _confirm(
        act,
        signer,
        "set_user_status",
        {"user_id": insider.id, "status": "disabled"},
        _lead(soc.id, soc_mon.id),
    )
    assert res.ok, res.summary
    assert bundle.directory.get_user(insider.id).status == "disabled"


def test_lead_assistant_blocked_on_other_team(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, _grc, _i, outsider = _org(bundle.directory)
    signer, act = _actuator(services)
    res = _confirm(
        act,
        signer,
        "set_user_status",
        {"user_id": outsider.id, "status": "disabled"},
        _lead(soc.id, soc_mon.id),
    )
    assert not res.ok and res.error == "forbidden"
    assert bundle.directory.get_user(outsider.id).status == "active"  # 未被改


def test_plain_member_assistant_denied(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    _soc, _mon, _grc, insider, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    res = _confirm(
        act,
        signer,
        "set_user_status",
        {"user_id": insider.id, "status": "disabled"},
        _plain(),
    )
    assert res.denied and not res.ok  # 工具对其不可见 → 执行点 denied


def test_lead_assistant_cannot_change_role(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, _grc, insider, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    res = _confirm(
        act,
        signer,
        "update_user",
        {"user_id": insider.id, "role_id": 1},
        _lead(soc.id, soc_mon.id),
    )
    assert not res.ok and res.error == "forbidden"  # 防越权升级


def test_lead_assistant_adds_member_to_own_team(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, _grc, _i, outsider = _org(bundle.directory)
    signer, act = _actuator(services)
    res = _confirm(
        act,
        signer,
        "add_team_member",
        {"team_id": soc.id, "user_id": outsider.id},
        _lead(soc.id, soc_mon.id),
    )
    assert res.ok, res.summary
    members = {m.user_id for m in bundle.directory.list_team_members(soc.id)}
    assert outsider.id in members


def test_lead_assistant_cannot_add_to_other_team(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, grc, insider, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    res = _confirm(
        act,
        signer,
        "add_team_member",
        {"team_id": grc.id, "user_id": insider.id},
        _lead(soc.id, soc_mon.id),
    )
    assert not res.ok and res.error == "forbidden"


# ───────────────────────── 审批下放(助手侧)─────────────────────────
def _pending(directory, dept_id=None) -> int:
    user, _ = directory.create_user(
        username=f"pend{dept_id}",
        display_name="待审",
        role_id=None,
        department_id=dept_id,
        password="pw123456",
    )
    directory.set_status(user.id, "pending")
    return user.id


def _team_role_id(directory) -> int:
    return next(r for r in directory.list_roles() if r.scope == "team").id


def _org_role_id(directory) -> int:
    return next(r for r in directory.list_roles() if r.scope == "org").id


def test_lead_assistant_approves_into_own_team(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, _grc, _i, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    uid = _pending(bundle.directory)
    res = _confirm(
        act,
        signer,
        "approve_account",
        {"user_id": uid, "department_id": soc.id, "role_id": _team_role_id(bundle.directory)},
        _lead(soc.id, soc_mon.id),
    )
    assert res.ok, res.summary
    assert bundle.directory.get_user(uid).status == "active"


def test_lead_assistant_approve_other_team_dest_forbidden(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, grc, _i, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    uid = _pending(bundle.directory)
    res = _confirm(
        act,
        signer,
        "approve_account",
        {"user_id": uid, "department_id": grc.id, "role_id": _team_role_id(bundle.directory)},
        _lead(soc.id, soc_mon.id),
    )
    assert not res.ok and res.error == "forbidden"
    assert bundle.directory.get_user(uid).status == "pending"


def test_lead_assistant_approve_org_role_forbidden(tmp_path: Path) -> None:
    bundle, services = _setup(tmp_path)
    soc, soc_mon, _grc, _i, _o = _org(bundle.directory)
    signer, act = _actuator(services)
    uid = _pending(bundle.directory)
    res = _confirm(
        act,
        signer,
        "approve_account",
        {"user_id": uid, "department_id": soc.id, "role_id": _org_role_id(bundle.directory)},
        _lead(soc.id, soc_mon.id),
    )
    assert not res.ok and res.error == "forbidden"  # 不能借审批安插组织级角色
