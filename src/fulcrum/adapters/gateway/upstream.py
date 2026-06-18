"""UpstreamForwarder —— 出站:按**运行时配置**把已放行的请求转发给企业智能体。

读当前 GatewayConfig(热加载),按协议(openai/rest/native)组装请求、归一响应。
转发本身不做安全**判断**(判断在转发前由网关完成),但守一条**纵深防御**红线:
上游回复体按字节封顶(`_MAX_REPLY_BYTES`)——被攻陷/异常的企业智能体不得用超大响应
撑爆枢衡内存,或把转发通道当作超量数据外泄载体;超限即 fail-closed,拒绝透传。
另提供 probe() 做"测试连接"。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import GatewayConfig, GatewayConfigStore

# 上游回复体字节上限:政务问答回复绰绰有余;超此即判异常上游,拒绝透传(纵深防御)。
_MAX_REPLY_BYTES = 2_000_000


class _OversizeReply(Exception):
    """上游回复体超出 `_MAX_REPLY_BYTES`,中止读取以免撑爆内存。"""


def _default_client_factory(cfg: GatewayConfig) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls)


async def _read_json_capped(
    client: httpx.AsyncClient, url: str, body: dict[str, Any], headers: dict[str, str]
) -> Any:
    """流式 POST 并把上游回复体封顶在 `_MAX_REPLY_BYTES`,再解析 JSON。

    两道闸:① 上游若**声明** Content-Length 超限,连流都不起,直接拒;
    ② 未声明(分块传输)时逐块累计,一超限即中止——确保超大响应永远不会被完整读进内存。
    """
    cap = _MAX_REPLY_BYTES  # 取调用时模块值,便于测试按需下调
    async with client.stream("POST", url, json=body, headers=headers) as resp:
        resp.raise_for_status()
        declared = resp.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > cap:
            raise _OversizeReply(int(declared))
        buf = bytearray()
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) > cap:
                raise _OversizeReply(len(buf))
    return json.loads(bytes(buf))


@dataclass(slots=True)
class UpstreamReply:
    ok: bool
    reply: str
    tools: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class ProbeResult:
    ok: bool
    latency_ms: int
    detail: str
    status_code: int | None = None


def _dig(data: Any, dotted: str) -> str:
    """按点路径取值(如 data.answer / choices.0.message.content)。取不到返回空串。"""
    cur: Any = data
    for part in dotted.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return ""
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
        if cur is None:
            return ""
    return cur if isinstance(cur, str) else json_compact(cur)


def json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


class UpstreamForwarder:
    def __init__(
        self,
        store: GatewayConfigStore,
        *,
        client_factory: Callable[[GatewayConfig], httpx.AsyncClient] | None = None,
    ) -> None:
        self._store = store
        # 可注入 client 工厂:默认按配置建 httpx 客户端;测试可注入 MockTransport。
        self._client_factory = client_factory or _default_client_factory

    @property
    def config(self) -> GatewayConfig:
        return self._store.load()

    async def chat(self, session_id: str, message: str) -> UpstreamReply:
        cfg = self._store.load()
        if not cfg.enabled:
            return UpstreamReply(ok=False, reply="", error="上游接入未启用(设置页开启并保存)")
        try:
            return await self._dispatch(cfg, session_id, message)
        except _OversizeReply:
            return UpstreamReply(
                ok=False,
                reply="",
                error=f"上游响应超出大小上限({_MAX_REPLY_BYTES} 字节),已拒绝透传"
                "(防异常上游撑爆内存/超量外泄)。",
            )
        except httpx.HTTPError as exc:
            return UpstreamReply(
                ok=False, reply="", error=f"企业智能体不可达:{type(exc).__name__}: {exc}"
            )

    async def _dispatch(self, cfg: GatewayConfig, session_id: str, message: str) -> UpstreamReply:
        headers = {"Content-Type": "application/json", **cfg.auth_headers()}
        url = cfg.target_url()
        async with self._client_factory(cfg) as client:
            if cfg.protocol == "openai":
                body = {
                    "model": cfg.model or "default",
                    "messages": [{"role": "user", "content": message}],
                }
                data = await _read_json_capped(client, url, body, headers)
                return UpstreamReply(ok=True, reply=_dig(data, "choices.0.message.content"))

            if cfg.protocol == "rest":
                body = {cfg.rest_message_field: message, "session_id": session_id}
                data = await _read_json_capped(client, url, body, headers)
                return UpstreamReply(ok=True, reply=_dig(data, cfg.rest_response_path))

            # native:我们自己的 /chat {session_id, message} -> {reply, tools}
            body = {"session_id": session_id, "message": message}
            data = await _read_json_capped(client, url, body, headers)
            return UpstreamReply(
                ok=True, reply=str(data.get("reply", "")), tools=list(data.get("tools") or [])
            )

    async def probe(self, cfg: GatewayConfig | None = None) -> ProbeResult:
        """测试连接:做一次轻量探活(校验地址 + 认证),不跑真实推理。"""
        cfg = cfg or self._store.load()
        # 探活路径:openai→/models(顺带验密钥);native→/healthz;rest→配置路径或根。
        if cfg.protocol == "openai":
            url = f"{cfg.endpoint.rstrip('/')}/models"
        elif cfg.protocol == "native":
            url = f"{cfg.endpoint.rstrip('/')}/healthz"
        else:
            url = cfg.target_url()
        headers = cfg.auth_headers()
        import time

        start = time.perf_counter()
        try:
            timeout = min(cfg.timeout_seconds, 15.0)
            async with httpx.AsyncClient(timeout=timeout, verify=cfg.verify_tls) as client:
                resp = await client.get(url, headers=headers)
            ms = int((time.perf_counter() - start) * 1000)
        except httpx.HTTPError as exc:
            ms = int((time.perf_counter() - start) * 1000)
            return ProbeResult(ok=False, latency_ms=ms, detail=f"{type(exc).__name__}: {exc}")
        if resp.status_code == 401 or resp.status_code == 403:
            return ProbeResult(
                ok=False, latency_ms=ms, detail="认证被拒,请检查密钥", status_code=resp.status_code
            )
        ok = resp.status_code < 500
        detail = "连接正常" if ok else f"上游返回 {resp.status_code}"
        return ProbeResult(ok=ok, latency_ms=ms, detail=detail, status_code=resp.status_code)
