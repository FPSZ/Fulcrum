"""网关上游接入配置:落盘持久化、密钥掩码、协议路径推导。

覆盖企业级"设置页填表 → 存库热加载"的后端契约(不打真实网络)。
"""

from __future__ import annotations

from pathlib import Path

from fulcrum.adapters.gateway import (
    GatewayConfig,
    GatewayConfigPublic,
    GatewayConfigStore,
)


def test_target_url_by_protocol() -> None:
    assert (
        GatewayConfig(protocol="openai", endpoint="https://api.x.com/v1").target_url()
        == "https://api.x.com/v1/chat/completions"
    )
    assert (
        GatewayConfig(protocol="native", endpoint="http://127.0.0.1:8800/").target_url()
        == "http://127.0.0.1:8800/chat"
    )
    assert (
        GatewayConfig(protocol="rest", endpoint="http://h", path="/api/agent").target_url()
        == "http://h/api/agent"
    )


def test_auth_headers() -> None:
    assert GatewayConfig(auth_type="none", auth_value="x").auth_headers() == {}
    assert GatewayConfig(auth_type="bearer", auth_value="k").auth_headers() == {
        "Authorization": "Bearer k"
    }
    header_cfg = GatewayConfig(auth_type="header", auth_header="X-Api-Key", auth_value="k")
    assert header_cfg.auth_headers() == {"X-Api-Key": "k"}


def test_public_view_masks_secret() -> None:
    pub = GatewayConfigPublic.of(GatewayConfig(auth_type="bearer", auth_value="supersecret123"))
    assert pub.auth_value_set is True
    assert "supersecret" not in pub.auth_value_masked
    assert pub.auth_value_masked.endswith("t123")


def test_store_persists_and_reloads(tmp_path: Path) -> None:
    path = str(tmp_path / "gateway.json")
    seed = GatewayConfig(endpoint="http://seed:1", protocol="native")
    store = GatewayConfigStore(path, seed=seed)

    assert store.load().endpoint == "http://seed:1"  # 首启落种子
    assert Path(path).is_file()

    store.save(GatewayConfig(protocol="openai", endpoint="http://x/v1", model="m", auth_value="K"))
    # 新建 store 从磁盘读 → 持久化生效(Docker 卷场景)
    reloaded = GatewayConfigStore(path).load()
    assert reloaded.protocol == "openai"
    assert reloaded.endpoint == "http://x/v1"
    assert reloaded.auth_value == "K"
