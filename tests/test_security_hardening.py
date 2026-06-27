"""安全加固回归(审计 P1)—— SSRF 出站端点闸、未鉴权端点输入上限、网关数据面鉴权。"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fulcrum.adapters.api import build_api
from fulcrum.adapters.api.schemas import ChatMessage, ToolCallRequest
from fulcrum.adapters.assistant.model_config import AssistantModelConfig
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.adapters.gateway.config import GatewayConfig
from fulcrum.adapters.net_guard import validate_endpoint
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.registry import registry


# ── SSRF 出站端点闸 ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434/v1",  # 本地 Ollama —— 私有化必须放行
        "http://192.168.1.10:8000/v1",  # 内网模型 —— 放行
        "https://api.openai.com/v1",
        "",  # 未配置 —— 放行
    ],
)
def test_validate_endpoint_allows_legit(url: str) -> None:
    assert validate_endpoint(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_x",
        "http://169.254.169.254/latest/meta-data/",  # 云元数据(链路本地)
        "http://metadata.google.internal/",
        "ftp://example.com/",
        "http://",  # 缺主机
    ],
)
def test_validate_endpoint_rejects_dangerous(url: str) -> None:
    with pytest.raises(ValueError):
        validate_endpoint(url)


def test_model_config_rejects_metadata_endpoint() -> None:
    with pytest.raises(ValidationError):
        AssistantModelConfig(endpoint="http://169.254.169.254/", model="m", configured=True)


def test_gateway_config_rejects_bad_scheme() -> None:
    with pytest.raises(ValidationError):
        GatewayConfig(endpoint="file:///etc/shadow")


# ── 未鉴权端点输入上限(DoS)─────────────────────────────────────────────
def test_chat_message_content_capped() -> None:
    with pytest.raises(ValidationError):
        ChatMessage(role="user", content="A" * 9000)


def test_toolcall_arguments_size_capped() -> None:
    with pytest.raises(ValidationError):
        ToolCallRequest(session_id="s", tool_name="echo", arguments={"blob": "A" * 20000})


# ── 网关数据面鉴权 + 全局体积闸 ─────────────────────────────────────────
def _client(tmp_path: Path, gateway_api_key: str = "") -> TestClient:
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password="hardening-admin-pw",
        supply_manifest_dir="samples/supplychain",
        eval_report_path=str(tmp_path / "no-report.json"),
        gateway_config_path=str(tmp_path / "gateway.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
        gateway_api_key=gateway_api_key,
    )
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    scanner = registry.create("scanner", "manifest")
    return TestClient(build_api(pipeline, bundle, settings, scanner=scanner))


def test_gateway_chat_requires_key_when_configured(tmp_path: Path) -> None:
    client = _client(tmp_path, gateway_api_key="gw-secret-123")
    body = {"session_id": "s1", "message": "你好"}
    # 缺/错密钥 → 401
    assert client.post("/gateway/chat", json=body).status_code == 401
    assert (
        client.post(
            "/gateway/chat", json=body, headers={"X-Fulcrum-Gateway-Key": "wrong"}
        ).status_code
        == 401
    )
    # 正确密钥 → 放行进管线(非 401)
    ok = client.post("/gateway/chat", json=body, headers={"X-Fulcrum-Gateway-Key": "gw-secret-123"})
    assert ok.status_code != 401, ok.text


def test_gateway_chat_open_when_no_key(tmp_path: Path) -> None:
    """未配密钥(本地/演示默认)→ 不拦,保持既有行为。"""
    client = _client(tmp_path)
    assert (
        client.post("/gateway/chat", json={"session_id": "s", "message": "hi"}).status_code != 401
    )


def test_oversized_body_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    huge = b'{"messages":[{"role":"user","content":"' + b"A" * 1_200_000 + b'"}]}'
    resp = client.post(
        "/v1/chat/completions", content=huge, headers={"content-type": "application/json"}
    )
    assert resp.status_code == 413, resp.status_code
