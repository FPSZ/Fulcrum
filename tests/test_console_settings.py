"""控制台实例设置:只暴露真实落盘字段,不保留未接运行时的假配置。"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.assistant.operations import _update_console_settings
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.adapters.auth.models import Principal
from fulcrum.adapters.console_settings import ConsoleSettingsStore
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config

_ADMIN_PW = "settings-admin-pw"


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        gateway_config_path=str(tmp_path / "gateway.json"),
        console_settings_path=str(tmp_path / "console.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    return TestClient(build_api(pipeline, bundle, settings))


def _login(client: TestClient) -> None:
    resp = client.post("/auth/login", json={"username": "admin", "password": _ADMIN_PW})
    assert resp.status_code == 200, resp.text


def test_console_settings_exposes_only_real_writable_fields(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)

    body = client.get("/admin/settings").json()
    assert {"instance_name", "environment", "backend_model"} <= set(body)
    for removed in (
        "language",
        "timezone",
        "chain_verify_freq",
        "audit_retention",
        "export_format",
        "notify_severe",
        "notify_approval",
        "notify_channel",
    ):
        assert removed not in body


def test_console_settings_persists_instance_metadata(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)

    saved = client.put(
        "/admin/settings",
        json={"instance_name": "市政安全网关", "environment": "prod"},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["instance_name"] == "市政安全网关"
    assert saved.json()["environment"] == "prod"

    reloaded = client.get("/admin/settings")
    assert reloaded.status_code == 200
    assert reloaded.json()["instance_name"] == "市政安全网关"
    assert reloaded.json()["environment"] == "prod"


def test_console_settings_rejects_removed_fake_fields(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)

    resp = client.put(
        "/admin/settings",
        json={
            "instance_name": "市政安全网关",
            "environment": "demo",
            "audit_retention": "forever",
        },
    )

    assert resp.status_code == 422


def test_assistant_console_settings_rejects_unknown_fields(tmp_path: Path) -> None:
    class Services:
        console_store = ConsoleSettingsStore(str(tmp_path / "console.json"))

    principal = Principal(
        user_id=1,
        username="admin",
        display_name="管理员",
        role_key="admin",
        role_name="管理员",
        permissions=frozenset({"settings.manage"}),
    )

    result = asyncio.run(
        _update_console_settings(
            {"instance_name": "市政安全网关", "notify_channel": "webhook"},
            principal,
            Services(),
        )
    )

    assert not result.ok
    assert result.error == "unknown_fields"
    assert Services.console_store.load().instance_name == "枢衡安全控制台"
