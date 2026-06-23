"""操作助手模型接入配置(协议/端点/密钥/模型名)—— 落盘存储 + 三协议翻译 + 路由鉴权回归。

钉死本期红线:
- 密钥落盘但**绝不原样回前端**(掩码),api_key=None 保存语义保留原值(防掩码覆盖真值);
- 未配置时对话被拦(真后端纵深兜底),前端再叠呼吸灯/前置提示;
- 「AI 模型配置」是独立高敏权限点 `ai.configure`:默认仅超管 + 系统管理员,其余内置角色无权;
- 三协议消息翻译正确:system 提顶层(Anthropic)、tool 返回合并、工具规格转换。
沿用本仓约定:无 pytest-asyncio。
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.assistant.model_config import (
    AssistantModelConfig,
    AssistantModelConfigPublic,
    AssistantModelConfigStore,
)
from fulcrum.adapters.assistant.model_transports import (
    _anthropic_messages,
    _anthropic_tools,
    _ollama_messages,
    _split_system,
)
from fulcrum.adapters.auth import build_auth_bundle
from fulcrum.adapters.auth.permissions import BUILTIN_ROLES
from fulcrum.app import build_pipeline
from fulcrum.config import Settings, load_capability_config


# ───────────────────────── 落盘存储 + 掩码 ─────────────────────────
def test_store_roundtrip_and_hot_reload(tmp_path: Path) -> None:
    path = str(tmp_path / "model.json")
    store = AssistantModelConfigStore(path)
    store.save(
        AssistantModelConfig(
            protocol="ollama", endpoint="http://localhost:11434", model="qwen2.5", configured=True
        )
    )
    # 新实例从盘读回 → 持久化生效。
    fresh = AssistantModelConfigStore(path).load()
    assert fresh.protocol == "ollama" and fresh.model == "qwen2.5" and fresh.configured


def test_is_ready_requires_configured_endpoint_and_model() -> None:
    assert not AssistantModelConfig().is_ready  # 默认未配置
    assert not AssistantModelConfig(configured=True, endpoint="", model="m").is_ready
    assert not AssistantModelConfig(configured=True, endpoint="http://x", model="").is_ready
    assert AssistantModelConfig(configured=True, endpoint="http://x", model="m").is_ready


def test_public_view_masks_key() -> None:
    pub = AssistantModelConfigPublic.of(
        AssistantModelConfig(api_key="sk-abcdef123456", endpoint="http://x", model="m")
    )
    assert pub.api_key_set
    assert pub.api_key_masked.endswith("3456") and "sk-abcdef" not in pub.api_key_masked
    empty = AssistantModelConfigPublic.of(AssistantModelConfig())
    assert not empty.api_key_set and empty.api_key_masked == ""


# ───────────────────────── 三协议消息翻译 ─────────────────────────
_CANON = [
    {"role": "system", "content": "你是助手"},
    {"role": "user", "content": "看下总览"},
    {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "get_x", "arguments": "{}"}}
        ],
    },
    {"role": "tool", "tool_call_id": "c1", "name": "get_x", "content": "结果A"},
    {"role": "tool", "tool_call_id": "c2", "name": "get_y", "content": "结果B"},
]


def test_split_system_lifts_system_text() -> None:
    system, rest = _split_system(_CANON)
    assert system == "你是助手"
    assert all(m["role"] != "system" for m in rest)


def test_anthropic_translation_blocks_and_merged_results() -> None:
    msgs = _anthropic_messages([m for m in _CANON if m["role"] != "system"])
    # assistant 轮转成含 tool_use 块;两个 tool 返回合并进一个 user 消息。
    assistant = next(m for m in msgs if m["role"] == "assistant")
    assert any(b["type"] == "tool_use" and b["name"] == "get_x" for b in assistant["content"])
    results = [m for m in msgs if isinstance(m["content"], list) and m["content"][0]
               .get("type") == "tool_result"]
    assert len(results) == 1 and len(results[0]["content"]) == 2  # 两条 tool_result 合并


def test_anthropic_tools_shape() -> None:
    spec = [{"type": "function", "function": {"name": "f", "description": "d", "parameters": {}}}]
    out = _anthropic_tools(spec)
    assert out[0]["name"] == "f" and "input_schema" in out[0]


def test_ollama_messages_parse_tool_args_to_dict() -> None:
    out = _ollama_messages(_CANON)
    asst = next(m for m in out if m["role"] == "assistant" and m.get("tool_calls"))
    assert isinstance(asst["tool_calls"][0]["function"]["arguments"], dict)  # 字符串参数转 dict
    assert any(m["role"] == "tool" and m["content"] == "结果A" for m in out)


# ───────────────────────── 权限默认值 ─────────────────────────
def test_ai_configure_default_only_admins() -> None:
    roles = {r.key: r.permissions for r in BUILTIN_ROLES}
    assert "ai.configure" in roles["super_admin"]
    assert "ai.configure" in roles["sys_admin"]
    for low in ("sec_manager", "sec_operator", "auditor", "viewer"):
        assert "ai.configure" not in roles[low], low


# ───────────────────────── HTTP 路由(集成)─────────────────────────
_ADMIN_PW = "model-cfg-admin-pw-123"


def _client(tmp_path: Path) -> TestClient:
    """真后端(不注入假 turn)→ enforce_model_ready=True,未配置即拦对话。"""
    settings = Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        eval_report_path=str(tmp_path / "no-report.json"),
        gateway_config_path=str(tmp_path / "gateway.json"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        assistant_model_config_path=str(tmp_path / "model.json"),
        conversation_dir=str(tmp_path / "conv"),
        frontend_dir="",
        # 隔离 .env:置空模型三项,使种子为「未配置」(否则仓库 .env 的 key 会让它 ready)。
        model_endpoint="",
        model_api_key="",
        model_name="",
    )
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    return TestClient(build_api(pipeline, bundle, settings))


def _login(client: TestClient, username: str, password: str) -> None:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text


def test_get_put_config_masks_and_preserves_key(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)

    # 初始:未配置(.env 无 key)。
    got = client.get("/assistant/model-config").json()
    assert not got["configured"] and not got["ready"]

    # 保存 ollama(本地免 key)→ ready,无密钥。
    put = client.put(
        "/assistant/model-config",
        json={"protocol": "ollama", "endpoint": "http://localhost:11434", "model": "qwen2.5"},
    )
    assert put.status_code == 200, put.text
    assert put.json()["configured"] and put.json()["ready"] and not put.json()["api_key_set"]

    # 设新密钥 → 掩码、set=True;再以 api_key=None 保存 → 保留原密钥(不被掩码覆盖)。
    client.put(
        "/assistant/model-config",
        json={
            "protocol": "openai",
            "endpoint": "https://api.x/v1",
            "model": "gpt",
            "api_key": "sk-secret-987654",
        },
    )
    after = client.put(
        "/assistant/model-config",
        json={"protocol": "openai", "endpoint": "https://api.x/v1", "model": "gpt"},
    ).json()
    assert after["api_key_set"] and after["api_key_masked"].endswith("7654")


def test_chat_blocked_when_model_not_configured(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    resp = client.post("/assistant/chat", json={"message": "你好", "session_id": "m-cfg"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["blocked"] and "配置" in body["reply"]


def test_put_config_denied_without_ai_configure(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client, "admin", _ADMIN_PW)
    # 建一个只有 ai.operate 的角色 + 成员(无 ai.configure)。
    role = client.post(
        "/admin/roles",
        json={"name": "纯操作员", "description": "仅用助手", "permissions": ["ai.operate"]},
    )
    assert role.status_code == 201, role.text
    created = client.post(
        "/admin/users",
        json={
            "username": "op1",
            "display_name": "操作员一",
            "password": "Op1-pw-123456",
            "role_id": role.json()["id"],
        },
    )
    assert created.status_code == 201, created.text

    op = _client_session(client)
    _login(op, "op1", "Op1-pw-123456")
    # 能读(ai.operate),但不能改(缺 ai.configure)→ 403。
    assert op.get("/assistant/model-config").status_code == 200
    denied = op.put(
        "/assistant/model-config",
        json={"protocol": "ollama", "endpoint": "http://x", "model": "m"},
    )
    assert denied.status_code == 403, denied.text


def _client_session(other: TestClient) -> TestClient:
    """复用同一 app、独立 cookie 会话(模拟另一个登录用户)。"""
    return TestClient(other.app)
