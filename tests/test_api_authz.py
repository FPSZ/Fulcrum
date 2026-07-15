"""API 路由鉴权回归 —— 每条受保护读路由:无会话 401、有会话缺权限 403。

前端隐藏菜单只是体验;真正的访问控制在后端 deps.require。本测试在 HTTP 边界钉死这一点,
未来谁漏掉一个 Depends(can_view) 都会被 CI 挡下(此前路由层零鉴权测试,守卫对但无回归网)。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.registry import registry

_ADMIN_PW = "authz-admin-pw"
_LOW_PW = "authz-low-pw-123"

# (路径, 所需权限点);低权账号只持 overview.view,故除总览外都应 403。
_PROTECTED: list[tuple[str, str]] = [
    ("/overview/stats", "overview.view"),
    ("/events", "events.view"),
    ("/audit", "audit.view"),
    ("/audit/s1", "audit.view"),
    ("/eval/report", "eval.view"),
    ("/policies", "policies.view"),
    ("/supply/scans", "supply.view"),
    ("/tools/calls", "tools.view"),
    ("/assistant/actions", "ai.operate"),
]


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        supply_manifest_dir="samples/supplychain",
        eval_report_path=str(tmp_path / "no-report.json"),
        gateway_config_path=str(tmp_path / "gateway.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )
    bundle = build_auth_bundle(settings)  # 引导超管
    # 低权账号:仅 overview.view 一个权限点。
    role = bundle.directory.create_role("仅总览", "", ["overview.view"])
    bundle.directory.create_user(
        username="low",
        display_name="低权",
        role_id=role.id,
        department_id=None,
        password=_LOW_PW,
    )
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    scanner = registry.create("scanner", "manifest")
    return TestClient(build_api(pipeline, bundle, settings, scanner=scanner))


def _login(client: TestClient, username: str, password: str) -> None:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("path", [p for p, _ in _PROTECTED])
def test_protected_route_rejects_anonymous(tmp_path: Path, path: str) -> None:
    assert _client(tmp_path).get(path).status_code == 401


def test_low_privilege_user_is_forbidden_beyond_its_permission(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "low", _LOW_PW)
    # 持有的权限点 → 放行
    assert client.get("/overview/stats").status_code == 200
    # 其余权限点 → 403(fail-closed,缺权限即拒)
    for path, _perm in _PROTECTED:
        if path == "/overview/stats":
            continue
        assert client.get(path).status_code == 403, f"{path} 应 403"


def test_super_admin_passes_all_guards(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    for path, _perm in _PROTECTED:
        # 超管持全部权限点:不应被鉴权挡下(具体业务码可能 200/空,但绝不能 401/403)。
        assert client.get(path).status_code not in (401, 403), f"{path} 不应被超管鉴权挡下"


def test_patch_role_accepts_permissions_only(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    role = next(r for r in client.get("/admin/roles").json() if r["key"] == "sec_operator")

    resp = client.patch(
        f"/admin/roles/{role['id']}",
        json={"permissions": ["overview.view", "ai.operate"]},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == role["name"]
    assert body["permissions"] == ["ai.operate", "overview.view"]


def test_patch_role_accepts_metadata_only(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    role = next(r for r in client.get("/admin/roles").json() if r["key"] == "sec_operator")

    resp = client.patch(
        f"/admin/roles/{role['id']}",
        json={"name": "Operator Patched", "description": "patched"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "Operator Patched"
    assert body["description"] == "patched"
    assert body["permissions"] == role["permissions"]


def test_approval_request_then_resolve_lifecycle(tmp_path: Path) -> None:
    """发起审批申请 → 进待审批 → 管理员批准放行 → 原工单隐去、代以放行结果行(端到端)。"""
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    sess = "assistant:web:lifecycle"

    # ① 操作员在对话里发起审批申请 → 落一条真·待审批工单
    r = client.post(
        "/assistant/request-approval",
        json={"session_id": sess, "stage": "output", "reason": "需导出名单", "excerpt": "片段"},
    )
    assert r.status_code == 200, r.text
    rows = client.get("/events").json()
    scoped_sess = f"assistant:admin:{sess}"
    tickets = [e for e in rows if e["sess"] == scoped_sess and e["disp"] == "approve"]
    assert len(tickets) == 1, "发起后应有且仅有一条待审批工单上墙"
    ticket_id = tickets[0]["id"]

    # ② 管理员批准放行 → 处置成功
    rr = client.post(f"/events/{ticket_id}/resolve", json={"decision": "allow", "note": "核实无误"})
    assert rr.status_code == 200, rr.text

    rows2 = client.get("/events").json()
    assert all(e["id"] != ticket_id for e in rows2), "处置后原待审工单应从墙上隐去"
    allow_rows = [e for e in rows2 if e["sess"] == scoped_sess and e["disp"] == "allow"]
    assert allow_rows, "处置后应出现一条放行结果行"


def test_resolve_requires_handle_permission(tmp_path: Path) -> None:
    """处置是写操作:仅 overview.view 的低权账号发起处置 → 403(鉴权先于业务)。"""
    client = _client(tmp_path)
    _login(client, "low", _LOW_PW)
    resp = client.post("/events/any-id/resolve", json={"decision": "allow"})
    assert resp.status_code == 403


# ── 垂直提权防护回归(安全审计 CRIT-1/2)──────────────────────────────────
# 红线:持「成员管理」/「角色管理」者绝不能把自己提成超管,也不能授予自己没有的权限。


def _super_role_id(client: TestClient) -> int:
    return next(r for r in client.get("/admin/roles").json() if r["key"] == "super_admin")["id"]


def test_users_manage_holder_cannot_self_assign_super_admin(tmp_path: Path) -> None:
    """持 users.manage 的非超管账号把自己改派成超管 → 409(组织级角色包含性闸)。"""
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    role = client.post(
        "/admin/roles",
        json={
            "name": "成员管理员",
            "description": "",
            "permissions": ["users.view", "users.manage"],
        },
    ).json()
    created = client.post(
        "/admin/users",
        json={
            "username": "mgr",
            "display_name": "成员管理员甲",
            "role_id": role["id"],
            "department_id": None,
            "password": "mgr-pw-123456",
        },
    )
    assert created.status_code == 201, created.text
    mgr_id = created.json()["user"]["id"]
    super_id = _super_role_id(client)

    _login(client, "mgr", "mgr-pw-123456")
    resp = client.patch(f"/admin/users/{mgr_id}", json={"role_id": super_id})
    assert resp.status_code == 409, resp.text
    # 真没提上去:会话权限仍只有原两项,绝无 roles.manage。
    me = client.get("/auth/me").json()
    assert "roles.manage" not in me["permissions"]
    assert set(me["permissions"]) == {"users.view", "users.manage"}


def test_roles_manage_holder_cannot_grant_unheld_permission(tmp_path: Path) -> None:
    """持 roles.manage 但权限有限者,新建/改角色塞入自己没有的权限点 → 409(包含性闸)。"""
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    role = client.post(
        "/admin/roles",
        json={
            "name": "角色管理员",
            "description": "",
            "permissions": ["users.view", "roles.manage"],
        },
    ).json()
    created = client.post(
        "/admin/users",
        json={
            "username": "rmgr",
            "display_name": "角色管理员甲",
            "role_id": role["id"],
            "department_id": None,
            "password": "rmgr-pw-123456",
        },
    )
    assert created.status_code == 201, created.text

    _login(client, "rmgr", "rmgr-pw-123456")
    resp = client.post(
        "/admin/roles",
        json={"name": "提权角色", "description": "", "permissions": ["settings.manage"]},
    )
    assert resp.status_code == 409, resp.text


def test_super_admin_role_is_immutable(tmp_path: Path) -> None:
    """超管角色定义不可被改写/删除(防抽空全权或借编辑自封),即便操作者是超管。"""
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    super_id = _super_role_id(client)
    assert (
        client.patch(
            f"/admin/roles/{super_id}", json={"permissions": ["overview.view"]}
        ).status_code
        == 409
    )
    assert client.delete(f"/admin/roles/{super_id}").status_code == 409
