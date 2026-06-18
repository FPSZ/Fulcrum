"""上游转发器:回复体字节封顶(纵深防御)+ 协议归一。

经可注入的 MockTransport client 工厂驱动,无需真实上游;此前 forwarder 零测试。
重点守:被攻陷/异常的企业智能体不得用超大响应撑爆枢衡内存或作超量外泄载体。
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from fulcrum.adapters.gateway import upstream as up
from fulcrum.adapters.gateway.config import GatewayConfig
from fulcrum.adapters.gateway.upstream import UpstreamForwarder, _OversizeReply, _read_json_capped


class _Store:
    """最小桩:转发器只需要 load() 返回当前配置。"""

    def __init__(self, cfg: GatewayConfig) -> None:
        self._cfg = cfg

    def load(self) -> GatewayConfig:
        return self._cfg


def _forwarder(cfg: GatewayConfig, handler) -> UpstreamForwarder:
    transport = httpx.MockTransport(handler)
    return UpstreamForwarder(
        _Store(cfg),  # type: ignore[arg-type]
        client_factory=lambda c: httpx.AsyncClient(transport=transport),
    )


def _openai_cfg(**over) -> GatewayConfig:
    return GatewayConfig(protocol="openai", endpoint="http://up.test", **over)


# ---- 正常路径:协议归一 ----
def test_chat_openai_returns_reply() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "您好"}}]})

    fwd = _forwarder(_openai_cfg(), handler)
    reply = asyncio.run(fwd.chat("s1", "你好"))
    assert reply.ok and reply.reply == "您好"


def test_chat_disabled_short_circuits() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("disabled 配置不应发起上游请求")

    fwd = _forwarder(_openai_cfg(enabled=False), handler)
    reply = asyncio.run(fwd.chat("s1", "你好"))
    assert not reply.ok and "未启用" in (reply.error or "")


def test_http_error_mapped_to_unreachable() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"err": "boom"})

    fwd = _forwarder(_openai_cfg(), handler)
    reply = asyncio.run(fwd.chat("s1", "你好"))
    assert not reply.ok and "不可达" in (reply.error or "")


# ---- 封顶:Content-Length 声明超限 → 不起流直接拒 ----
def test_oversize_via_content_length_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up, "_MAX_REPLY_BYTES", 50)

    def handler(req: httpx.Request) -> httpx.Response:
        # 合法 JSON 但远超 50 字节;MockTransport 自动置 content-length → 快速拒。
        return httpx.Response(200, json={"choices": [{"message": {"content": "x" * 300}}]})

    fwd = _forwarder(_openai_cfg(), handler)
    reply = asyncio.run(fwd.chat("s1", "你好"))
    assert not reply.ok and "超出大小上限" in (reply.error or "")


# ---- 封顶:分块传输无 Content-Length → 逐块累计超限中止 ----
def test_oversize_via_streamed_chunks_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up, "_MAX_REPLY_BYTES", 50)

    async def _agen() -> AsyncIterator[bytes]:
        for _ in range(4):
            yield b"x" * 20  # 累计 80 > 50,且响应无 content-length

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_agen())

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await _read_json_capped(client, "http://up.test/x", {}, {})

    with pytest.raises(_OversizeReply):
        asyncio.run(run())


def test_capped_read_parses_normal_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up, "_MAX_REPLY_BYTES", 10_000)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"reply": "ok"})

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await _read_json_capped(client, "http://up.test/x", {}, {})

    assert asyncio.run(run()) == {"reply": "ok"}
