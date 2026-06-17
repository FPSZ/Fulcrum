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
