"""AI 操作助手「写类·提案-确认-撤销」(plan/11 P2)的治理回归。

钉死本期红线:
- 令牌防篡改/过期/换工具/转交主体;
- 确认走纵深 RBAC,越权被拒(不靠提案自觉);
- 确认执行命中底层服务(与 REST 写端点同口径),落 ASSISTANT_ACTED;
- 一键撤销凭前态快照正确回滚,落 ASSISTANT_UNDONE,且一次性;
- 端到端:chat 产出提案(不执行)→ confirm 执行 → undo 回滚。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.assistant import (
    ActionTokenSigner,
    AssistantActuator,
    AssistantServices,
    UndoStore,
)
from fulcrum.adapters.assistant.model_client import ModelReply, ModelTurn, ToolCallReq
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.adapters.auth.models import Principal
from fulcrum.adapters.auth.permissions import ALL_PERMISSION_KEYS
from fulcrum.adapters.console_settings import ConsoleSettingsStore
from fulcrum.adapters.gateway import GatewayConfigStore
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.operations import operation_registry

_ADMIN_PW = "actuator-admin-pw-123"


def _principal(perms: frozenset[str], username: str = "tester") -> Principal:
    return Principal(
        user_id=1,
        username=username,
        display_name="测试员",
        role_key="r",
        role_name="角色",
        permissions=perms,
    )


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
    return settings, bundle, pipeline, services


def _make_user(directory) -> int:
    role = directory.list_roles()[0]
    user, _ = directory.create_user(
        username="u1",
        display_name="员工一",
        role_id=role.id,
        department_id=None,
        password="pw123456",
    )
    return user.id


# ───────────────────────── 令牌签发/校验 ─────────────────────────
def test_token_roundtrip_and_tamper() -> None:
    s = ActionTokenSigner()
    tok = s.issue(tool="set_user_status", actor="admin", session_id="s-token", now=1000.0)
    payload = s.verify(tok, now=1001.0)
    assert (
        payload is not None
        and payload["tool"] == "set_user_status"
        and payload["actor"] == "admin"
        and payload["session_id"] == "s-token"
    )
    assert s.verify(tok, now=1000.0 + 10_000) is None  # 过期
    assert s.verify(tok[:-2] + "zz", now=1001.0) is None  # 签名被篡改
    assert s.verify("not-a-token", now=1001.0) is None  # 格式错


# ───────────────────────── 确认 + 撤销 ─────────────────────────
def test_confirm_executes_and_undo_rolls_back(tmp_path: Path) -> None:
    _settings, bundle, pipeline, services = _setup(tmp_path)
    uid = _make_user(bundle.directory)
    signer = ActionTokenSigner()
    act = AssistantActuator(operation_registry, services, signer, UndoStore())
    who = _principal(ALL_PERMISSION_KEYS)

    token = signer.issue(tool="set_user_status", actor="tester", session_id="s-act")
    res = asyncio.run(act.confirm(token, {"user_id": uid, "status": "disabled"}, who))
    assert res.ok and res.action_id and res.reversible
    assert bundle.directory.get_user(uid).status == "disabled"  # 真改了底层服务

    undo = asyncio.run(act.undo(res.action_id, who))
    assert undo.ok
    assert bundle.directory.get_user(uid).status == "active"  # 回滚到前态

    types = {e.event_type.value for e in asyncio.run(pipeline.audit.events("s-act"))}
    assert "assistant_acted" in types and "assistant_undone" in types


def test_confirm_edited_args_take_effect(tmp_path: Path) -> None:
    _settings, bundle, _pipeline, services = _setup(tmp_path)
    uid = _make_user(bundle.directory)
    signer = ActionTokenSigner()
    act = AssistantActuator(operation_registry, services, signer, UndoStore())
    token = signer.issue(tool="set_user_status", actor="tester", session_id="s")
    # 编辑后参数 status=left 生效(而非提案里的任何默认)。
    res = asyncio.run(
        act.confirm(token, {"user_id": uid, "status": "left"}, _principal(ALL_PERMISSION_KEYS))
    )
    assert res.ok
    assert bundle.directory.get_user(uid).status == "left"


def test_confirm_denied_when_missing_permission(tmp_path: Path) -> None:
    _settings, bundle, _pipeline, services = _setup(tmp_path)
    uid = _make_user(bundle.directory)
    signer = ActionTokenSigner()
    act = AssistantActuator(operation_registry, services, signer, UndoStore())
    low = _principal(frozenset({"ai.operate"}))  # 缺 users.manage
    token = signer.issue(tool="set_user_status", actor="tester", session_id="s")
    res = asyncio.run(act.confirm(token, {"user_id": uid, "status": "disabled"}, low))
    assert res.denied and not res.ok
    assert bundle.directory.get_user(uid).status == "active"  # 未被改动


def test_confirm_rejects_actor_mismatch(tmp_path: Path) -> None:
    _settings, bundle, _pipeline, services = _setup(tmp_path)
    uid = _make_user(bundle.directory)
    signer = ActionTokenSigner()
    act = AssistantActuator(operation_registry, services, signer, UndoStore())
    token = signer.issue(
        tool="set_user_status", actor="someone_else", session_id="s"
    )  # 令牌发给别人
    res = asyncio.run(
        act.confirm(token, {"user_id": uid, "status": "disabled"}, _principal(ALL_PERMISSION_KEYS))
    )
    assert res.denied and not res.ok


def test_undo_is_one_time(tmp_path: Path) -> None:
    _settings, bundle, _pipeline, services = _setup(tmp_path)
    uid = _make_user(bundle.directory)
    signer = ActionTokenSigner()
    act = AssistantActuator(operation_registry, services, signer, UndoStore())
    who = _principal(ALL_PERMISSION_KEYS)
    token = signer.issue(tool="set_user_status", actor="tester", session_id="s")
    res = asyncio.run(act.confirm(token, {"user_id": uid, "status": "disabled"}, who))
    assert asyncio.run(act.undo(res.action_id, who)).ok
    second = asyncio.run(act.undo(res.action_id, who))
    assert not second.ok  # 一次性,二次撤销被拒


# ───────────────────────── HTTP 端到端:提案→确认→撤销 ─────────────────────────
def _propose_set_status(holder: dict) -> ModelTurn:
    state = {"n": 0}

    async def turn(_messages: list[dict], _tools: list[dict]) -> ModelReply:
        state["n"] += 1
        if state["n"] == 1:
            return ModelReply(
                tool_calls=[
                    ToolCallReq(
                        id="1",
                        name="set_user_status",
                        arguments={"user_id": holder["user_id"], "status": "disabled"},
                    )
                ]
            )
        return ModelReply(content="已生成待确认提案。")

    return turn


def test_e2e_propose_confirm_undo(tmp_path: Path) -> None:
    holder: dict = {"user_id": 0}
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
    client = TestClient(
        build_api(pipeline, bundle, settings, assistant_model_turn=_propose_set_status(holder))
    )
    assert (
        client.post("/auth/login", json={"username": "admin", "password": _ADMIN_PW}).status_code
        == 200
    )

    role_id = client.get("/admin/roles").json()[0]["id"]
    created = client.post(
        "/admin/users",
        json={
            "username": "victim",
            "display_name": "目标",
            "role_id": role_id,
            "password": "pw123456",
        },
    )
    assert created.status_code == 201, created.text
    uid = created.json()["user"]["id"]
    holder["user_id"] = uid

    # 1) chat 产出提案(不执行)。
    chat = client.post("/assistant/chat", json={"message": "停用该账号", "session_id": "e2e"})
    assert chat.status_code == 200, chat.text
    proposals = chat.json()["proposed_actions"]
    assert len(proposals) == 1 and proposals[0]["tool"] == "set_user_status"
    token = proposals[0]["action_token"]
    assert token
    # 提案阶段绝不执行:状态仍 active。
    assert _user_status(client, uid) == "active"

    # 2) 确认执行。
    confirm = client.post(
        "/assistant/confirm",
        json={"action_token": token, "edited_args": {"user_id": uid, "status": "disabled"}},
    )
    assert confirm.status_code == 200, confirm.text
    body = confirm.json()
    assert body["ok"] and body["reversible"] and body["action_id"]
    assert _user_status(client, uid) == "disabled"

    # 3) 一键撤销回滚。
    undo = client.post("/assistant/undo", json={"action_id": body["action_id"]})
    assert undo.status_code == 200, undo.text
    assert undo.json()["ok"]
    assert _user_status(client, uid) == "active"


def _user_status(client: TestClient, uid: int) -> str:
    users = client.get("/admin/users").json()
    return next(u["status"] for u in users if u["id"] == uid)
