"""Walking Skeleton 端到端:空管线跑通 + 审计链可校验。"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.app import create_app
from fulcrum.config import Settings

_ADMIN_PW = "skeleton-admin-pw"


def _make_client(tmp_path: Path) -> TestClient:
    # 临时库 + 已知引导口令:不碰真实 data/runtime/auth.sqlite,审计读取走鉴权后的端点。
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        gateway_config_path=str(tmp_path / "gateway.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )
    return TestClient(create_app(settings))


def test_healthz(tmp_path: Path) -> None:
    resp = _make_client(tmp_path).get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_chat_completions_runs_pipeline_and_audits(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.post(
        "/v1/chat/completions",
        json={"session_id": "s1", "messages": [{"role": "user", "content": "hello"}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "s1"
    # FakeModelClient 产出一个 echo 工具调用,allow_all 放行并执行
    assert "echo" in body["tool_calls"]
    assert body["outcomes"][0]["decision"] == "allow"
    assert body["outcomes"][0]["executed"] is True

    # 审计链读取受 audit.view 鉴权:未登录 401,登录后可读且 hash-chain 校验通过。
    assert client.get("/audit/s1").status_code == 401
    login = client.post("/auth/login", json={"username": "admin", "password": _ADMIN_PW})
    assert login.status_code == 200
    audit = client.get("/audit/s1").json()
    assert audit["verified"] is True
    assert len(audit["events"]) > 0


def test_tools_call_executes_echo(tmp_path: Path) -> None:
    client = _make_client(tmp_path)
    resp = client.post(
        "/tools/call",
        json={"session_id": "s2", "tool_name": "echo", "arguments": {"text": "hi"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["executed"] is True
    assert body["output"] == "hi"
