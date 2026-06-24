"""策略中心可编辑(PUT /policies)—— 引擎热替换、落盘、合并、HTTP 端到端与鉴权。

钉死:① 编辑通过引擎校验即热生效(下次 decide 读新策略),非法编辑 fail-closed 不替换;
② 停用的规则在 decide 时被跳过;③ 覆盖文档落盘并在重启(重建 app)后沿用;
④ PUT 需 policies.manage(仅 view 的低权账号 403);⑤ 编辑写一条 POLICY_UPDATED 审计。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fulcrum.adapters.api import build_api
from fulcrum.adapters.api.policies_routes import merge_policy_edit
from fulcrum.adapters.api.schemas import PolicyRulePatch, PolicySetWrite
from fulcrum.adapters.auth import AuthBundle, build_auth_bundle
from fulcrum.adapters.policy_store import PolicyDocStore
from fulcrum.app import build_pipeline
from fulcrum.capabilities.policy.yaml_policy import YamlPolicyEngine
from fulcrum.config import Settings, load_capability_config
from fulcrum.core.domain import Context, Disposition, ToolIntent
from fulcrum.core.errors import ConfigError

_ADMIN_PW = "policy-admin-pw"
_LOW_PW = "policy-low-pw"


# ----------------------------- 引擎:热替换 / 校验 / 停用 -----------------------------


def _decide(engine: YamlPolicyEngine, intent: ToolIntent) -> Disposition:
    return asyncio.run(engine.decide(intent, Context(session_id="s"))).decision


def test_replace_document_hot_reloads_decision() -> None:
    """替换文档后,decide 立即按新策略判(把默认 allow 改成 block)。"""
    engine = YamlPolicyEngine("data/policies/default.yml")
    benign = ToolIntent(
        session_id="s", tool_name="file.read", arguments={"path": "data/workspace/a.txt"}
    )
    assert _decide(engine, benign) == Disposition.ALLOW

    doc = engine.policy_document()
    doc["default"] = "block"
    engine.replace_document(doc)
    assert _decide(engine, benign) == Disposition.BLOCK  # 命中新 default


def test_disabled_rule_is_skipped() -> None:
    """停用某规则后,decide 跳过它(用受控单规则策略隔离验证,不受默认策略纵深规则干扰)。"""
    engine = YamlPolicyEngine("data/policies/default.yml")
    doc = {
        "default": "allow",
        "workspace": "data/workspace",
        "rules": [
            {
                "id": "x",
                "when": {"tool_name": "file.read"},
                "decision": "block",
                "risk_level": "high",
            }
        ],
    }
    engine.replace_document(doc)
    intent = ToolIntent(session_id="s", tool_name="file.read", arguments={"path": "a.txt"})
    assert _decide(engine, intent) == Disposition.BLOCK  # 规则命中

    doc["rules"][0]["enabled"] = False
    engine.replace_document(doc)
    assert _decide(engine, intent) == Disposition.ALLOW  # 规则停用 → 跳过,回落默认


def test_replace_document_rejects_invalid_and_keeps_current() -> None:
    """非法处置 → ConfigError,且不替换正在生效的策略(fail-closed)。"""
    engine = YamlPolicyEngine("data/policies/default.yml")
    before = engine.policy_document()
    bad = engine.policy_document()
    bad["rules"][0]["decision"] = "destroy"  # 非法处置
    with pytest.raises(ConfigError):
        engine.replace_document(bad)
    assert engine.policy_document() == before  # 原策略原样未动


def test_validate_rejects_bad_default() -> None:
    engine = YamlPolicyEngine("data/policies/default.yml")
    doc = engine.policy_document()
    doc["default"] = "nope"
    with pytest.raises(ConfigError):
        engine.replace_document(doc)


def test_validate_rejects_unknown_predicate() -> None:
    engine = YamlPolicyEngine("data/policies/default.yml")
    doc = engine.policy_document()
    doc["rules"][0]["when"] = {"totally_unknown": True}
    with pytest.raises(ConfigError):
        engine.replace_document(doc)


# ----------------------------- 落盘 store -----------------------------


def test_policy_store_round_trip(tmp_path: Path) -> None:
    store = PolicyDocStore(str(tmp_path / "policy.yml"))
    assert store.load() is None  # 从未改过 → None,调用方回落种子
    doc = {"default": "block", "rules": [{"id": "r", "when": {}, "decision": "allow"}]}
    store.save(doc)
    assert store.load() == doc


def test_policy_store_corrupt_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "policy.yml"
    p.write_text("{[not valid yaml", encoding="utf-8")
    assert PolicyDocStore(str(p)).load() is None


# ----------------------------- 合并纯函数 -----------------------------


def test_merge_preserves_when_and_deletes_missing() -> None:
    current = {
        "version": 3,
        "default": "allow",
        "workspace": "data/workspace",
        "allow_domains": ["gov.cn"],
        "rules": [
            {
                "id": "a",
                "when": {"tool_name": "file.read"},
                "decision": "block",
                "risk_level": "high",
            },
            {"id": "b", "when": {"path_sensitive": True}, "decision": "approve"},
        ],
    }
    body = PolicySetWrite(
        default="block",
        workspace="data/ws2",
        allow_domains=["gov.cn", "xiongan.gov.cn"],
        # 只保留 a(停用 + 改理由),删掉 b
        rules=[PolicyRulePatch(id="a", enabled=False, decision="block", reason="改后理由")],
    )
    out = merge_policy_edit(current, body)
    assert out["version"] == 4  # +1
    assert out["default"] == "block"
    assert out["workspace"] == "data/ws2"
    assert out["allow_domains"] == ["gov.cn", "xiongan.gov.cn"]
    assert len(out["rules"]) == 1
    a = out["rules"][0]
    assert a["id"] == "a"
    assert a["when"] == {"tool_name": "file.read"}  # 谓词从原文档保留
    assert a["risk_level"] == "high"  # 风险等级保留
    assert a["enabled"] is False
    assert a["reason"] == "改后理由"


# ----------------------------- HTTP 端到端 -----------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        auth_db_path=str(tmp_path / "auth.sqlite"),
        bootstrap_admin_password=_ADMIN_PW,
        gateway_config_path=str(tmp_path / "gateway.json"),
        console_settings_path=str(tmp_path / "console.json"),
        assistant_model_config_path=str(tmp_path / "model.json"),
        conversation_dir=str(tmp_path / "conv"),
        policy_override_path=str(tmp_path / "policy.yml"),
        audit_db_path=str(tmp_path / "audit.sqlite"),
        frontend_dir="",
    )


def _build(settings: Settings) -> tuple[TestClient, AuthBundle]:
    bundle = build_auth_bundle(settings)
    pipeline = build_pipeline(load_capability_config(settings.capability_config))
    return TestClient(build_api(pipeline, bundle, settings)), bundle


def _login(client: TestClient, user: str, pw: str) -> None:
    assert client.post("/auth/login", json={"username": user, "password": pw}).status_code == 200


def test_put_policies_applies_persists_and_audits(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _ = _build(settings)
    _login(client, "admin", _ADMIN_PW)

    cur = client.get("/policies").json()
    base_version = cur["version"]
    body = {
        "default": "block",
        "workspace": cur["workspace"],
        "allow_domains": [*cur["allow_domains"], "demo.gov.cn"],
        "rules": [
            {
                "id": r["id"],
                "enabled": r["id"] != "block-exfil-chain",  # 停用外泄链规则作演示
                "decision": r["decision"],
                "reason": r["reason"],
            }
            for r in cur["rules"]
        ],
    }
    put = client.put("/policies", json=body)
    assert put.status_code == 200, put.text
    saved = put.json()
    assert saved["default"] == "block"
    assert saved["version"] == base_version + 1
    assert "demo.gov.cn" in saved["allow_domains"]
    disabled = {r["id"]: r["enabled"] for r in saved["rules"]}
    assert disabled["block-exfil-chain"] is False

    # GET 反映热生效后的策略
    assert client.get("/policies").json()["default"] == "block"

    # 落盘:覆盖文档已写,且重建 app(模拟重启)后沿用编辑
    assert Path(settings.policy_override_path).is_file()
    client2, _ = _build(settings)
    _login(client2, "admin", _ADMIN_PW)
    assert client2.get("/policies").json()["default"] == "block"

    # 审计:写了一条 POLICY_UPDATED(配置链 config:policy)
    chain = client.get("/audit/config:policy").json()
    kinds = [e["event_type"] for e in chain["events"]]
    assert "policy_updated" in kinds


def test_put_policies_rejects_invalid_without_changing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, _ = _build(settings)
    _login(client, "admin", _ADMIN_PW)

    cur = client.get("/policies").json()
    body = {
        "default": "block",
        "workspace": cur["workspace"],
        "allow_domains": cur["allow_domains"],
        "rules": [
            {"id": r["id"], "enabled": True, "decision": "destroy", "reason": r["reason"]}
            if i == 0
            else {"id": r["id"], "enabled": True, "decision": r["decision"], "reason": r["reason"]}
            for i, r in enumerate(cur["rules"])
        ],
    }
    resp = client.put("/policies", json=body)
    assert resp.status_code == 400  # ConfigError → FulcrumError handler
    # 未生效:策略未变、未落盘
    assert client.get("/policies").json()["default"] == cur["default"]
    assert not Path(settings.policy_override_path).is_file()


def test_put_policies_requires_manage_permission(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, bundle = _build(settings)
    role = bundle.directory.create_role("仅看策略", "", ["policies.view"])  # type: ignore[attr-defined]
    bundle.directory.create_user(  # type: ignore[attr-defined]
        username="low",
        display_name="低权",
        role_id=role.id,
        department_id=None,
        password=_LOW_PW,
    )
    _login(client, "low", _LOW_PW)

    assert client.get("/policies").status_code == 200  # 有 view
    resp = client.put(
        "/policies",
        json={"default": "block", "workspace": "", "allow_domains": [], "rules": []},
    )
    assert resp.status_code == 403  # 缺 policies.manage
