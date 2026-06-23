"""三协议模型传输层 —— 把助手 Agent 的「OpenAI 规范消息」翻译成各协议线格式并回收。

Agent 循环只产出一种**规范消息**(OpenAI 风格:system/user/assistant+tool_calls/tool),
本层按运行时配置(`AssistantModelConfig.protocol`)动态分发到:
- ``openai``    —— /chat/completions(消息/工具直通)
- ``ollama``    —— /api/chat(NDJSON 流;消息近似直通,tool 参数转 dict)
- ``anthropic`` —— /v1/messages(消息需翻成 content blocks;system 提到顶层;SSE 流)

每种协议都实现**非流式 + 流式 + 工具调用**,统一回收成 `ModelReply` / `StreamChunk`,
对 Agent 透明。失败一律软降级(空回复 / 用已收内容收尾),绝不抛断整轮。

密钥解析:有效 key = 配置内 api_key,空则回退 `fallback_key`(.env 注入,本地模型可全空)。
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Callable

from ..model.openai_client import _parse_args
from .model_client import ModelReply, StreamChunk, ToolCallReq
from .model_config import AssistantModelConfig

_LOG = logging.getLogger(__name__)

# 配置提供者:每次调用读当前配置(热加载)。
ConfigProvider = Callable[[], AssistantModelConfig]


def _effective_key(cfg: AssistantModelConfig, fallback: str) -> str:
    return cfg.api_key or fallback


# ─────────────────────────── 消息/工具翻译 ───────────────────────────
def _split_system(messages: list[dict]) -> tuple[str, list[dict]]:
    """抽出 system 文本(Anthropic 放顶层),其余按序返回。"""
    system_parts: list[str] = []
    rest: list[dict] = []
    for m in messages:
        if m.get("role") == "system":
            system_parts.append(str(m.get("content") or ""))
        else:
            rest.append(m)
    return "\n\n".join(p for p in system_parts if p), rest


def _ollama_messages(messages: list[dict]) -> list[dict]:
    """规范消息 → Ollama /api/chat 消息:tool_calls 参数转 dict,tool 角色保留 content。"""
    out: list[dict] = []
    for m in messages:
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            out.append(
                {
                    "role": "assistant",
                    "content": m.get("content") or "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": tc["function"]["name"],
                                "arguments": _parse_args(tc["function"].get("arguments")),
                            }
                        }
                        for tc in m["tool_calls"]
                    ],
                }
            )
        elif role == "tool":
            out.append(
                {"role": "tool", "content": str(m.get("content") or ""), "tool_name": m.get("name")}
            )
        else:
            out.append({"role": role, "content": str(m.get("content") or "")})
    return out


def _anthropic_messages(messages: list[dict]) -> list[dict]:
    """规范消息 → Anthropic /v1/messages:assistant 转 text+tool_use 块,tool 转 tool_result 块。

    同一 assistant 轮的多个 tool 返回须合并进**一个** user 消息(Anthropic 要求 user/assistant
    交替,且 tool_result 必须紧跟其 tool_use)。这里把连续的 tool 消息聚成一条 user。
    """
    out: list[dict] = []
    pending_results: list[dict] = []

    def flush_results() -> None:
        nonlocal pending_results
        if pending_results:
            out.append({"role": "user", "content": pending_results})
            pending_results = []

    for m in messages:
        role = m.get("role")
        if role == "tool":
            pending_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": str(m.get("tool_call_id") or m.get("name") or ""),
                    "content": str(m.get("content") or ""),
                }
            )
            continue
        flush_results()
        if role == "assistant":
            blocks: list[dict] = []
            if m.get("content"):
                blocks.append({"type": "text", "text": str(m["content"])})
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": str(tc.get("id") or fn.get("name") or ""),
                        "name": fn.get("name") or "",
                        "input": _parse_args(fn.get("arguments")),
                    }
                )
            out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
        else:  # user
            out.append({"role": "user", "content": str(m.get("content") or "")})
    flush_results()
    return out


def _anthropic_tools(tools: list[dict]) -> list[dict]:
    """OpenAI function 规格 → Anthropic tools(name/description/input_schema)。"""
    out: list[dict] = []
    for t in tools:
        fn = t.get("function") or {}
        out.append(
            {
                "name": fn.get("name"),
                "description": fn.get("description") or "",
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            }
        )
    return out


# ─────────────────────────── OpenAI 兼容 ───────────────────────────
def _openai_payload(cfg: AssistantModelConfig, messages: list[dict], tools: list[dict]) -> dict:
    payload: dict = {"model": cfg.model, "messages": messages, "temperature": 0.2}
    if tools:
        payload["tools"] = tools
    return payload


def _openai_headers(key: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _parse_openai(data: dict) -> ModelReply:
    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    calls: list[ToolCallReq] = []
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function") or {}
        calls.append(
            ToolCallReq(
                id=str(tc.get("id") or ""),
                name=str(fn.get("name") or ""),
                arguments=_parse_args(fn.get("arguments")),
            )
        )
    return ModelReply(content=str(message.get("content") or ""), tool_calls=calls)


async def _openai_turn(
    cfg: AssistantModelConfig, key: str, messages: list[dict], tools: list[dict]
) -> ModelReply:
    import httpx

    url = cfg.endpoint.rstrip("/") + "/chat/completions"
    async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls) as client:
        resp = await client.post(
            url, json=_openai_payload(cfg, messages, tools), headers=_openai_headers(key)
        )
        resp.raise_for_status()
        return _parse_openai(resp.json())


async def _openai_stream(
    cfg: AssistantModelConfig, key: str, messages: list[dict], tools: list[dict]
) -> AsyncIterator[StreamChunk]:
    import httpx

    url = cfg.endpoint.rstrip("/") + "/chat/completions"
    payload = {**_openai_payload(cfg, messages, tools), "stream": True}
    content = ""
    tool_acc: dict[int, dict] = {}
    async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls) as client:
        async with client.stream("POST", url, json=payload, headers=_openai_headers(key)) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                delta = (obj.get("choices") or [{}])[0].get("delta") or {}
                if delta.get("content"):
                    content += delta["content"]
                    yield StreamChunk(delta=delta["content"])
                for tc in delta.get("tool_calls") or []:
                    idx = tc.get("index", 0)
                    slot = tool_acc.setdefault(idx, {"id": "", "name": "", "args": ""})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] = fn["name"]
                    if fn.get("arguments"):
                        slot["args"] += fn["arguments"]
    calls = [
        ToolCallReq(id=s["id"] or s["name"], name=s["name"], arguments=_parse_args(s["args"]))
        for s in tool_acc.values()
        if s["name"]
    ]
    yield StreamChunk(final=ModelReply(content=content, tool_calls=calls))


# ─────────────────────────── Ollama 原生 ───────────────────────────
def _parse_ollama(data: dict) -> ModelReply:
    message = data.get("message") or {}
    calls: list[ToolCallReq] = []
    for i, tc in enumerate(message.get("tool_calls") or []):
        fn = tc.get("function") or {}
        args = fn.get("arguments")
        calls.append(
            ToolCallReq(
                id=str(fn.get("name") or i),
                name=str(fn.get("name") or ""),
                arguments=args if isinstance(args, dict) else _parse_args(args),
            )
        )
    return ModelReply(content=str(message.get("content") or ""), tool_calls=calls)


async def _ollama_turn(
    cfg: AssistantModelConfig, key: str, messages: list[dict], tools: list[dict]
) -> ModelReply:
    import httpx

    url = cfg.endpoint.rstrip("/") + "/api/chat"
    payload: dict = {
        "model": cfg.model,
        "messages": _ollama_messages(messages),
        "stream": False,
        "options": {"temperature": 0.2},
    }
    if tools:
        payload["tools"] = tools
    headers = _openai_headers(key)  # Ollama 亦接受 Bearer(如挂反代鉴权)
    async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return _parse_ollama(resp.json())


async def _ollama_stream(
    cfg: AssistantModelConfig, key: str, messages: list[dict], tools: list[dict]
) -> AsyncIterator[StreamChunk]:
    import httpx

    url = cfg.endpoint.rstrip("/") + "/api/chat"
    payload: dict = {
        "model": cfg.model,
        "messages": _ollama_messages(messages),
        "stream": True,
        "options": {"temperature": 0.2},
    }
    if tools:
        payload["tools"] = tools
    content = ""
    calls: list[ToolCallReq] = []
    async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls) as client:
        async with client.stream("POST", url, json=payload, headers=_openai_headers(key)) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():  # Ollama 是 NDJSON,一行一个 JSON
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = obj.get("message") or {}
                if msg.get("content"):
                    content += msg["content"]
                    yield StreamChunk(delta=msg["content"])
                for i, tc in enumerate(msg.get("tool_calls") or []):
                    fn = tc.get("function") or {}
                    args = fn.get("arguments")
                    calls.append(
                        ToolCallReq(
                            id=str(fn.get("name") or i),
                            name=str(fn.get("name") or ""),
                            arguments=args if isinstance(args, dict) else _parse_args(args),
                        )
                    )
    yield StreamChunk(final=ModelReply(content=content, tool_calls=[c for c in calls if c.name]))


# ─────────────────────────── Anthropic ───────────────────────────
def _anthropic_headers(key: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
    if key:
        headers["x-api-key"] = key
    return headers


def _anthropic_payload(
    cfg: AssistantModelConfig, messages: list[dict], tools: list[dict]
) -> dict:
    system, rest = _split_system(messages)
    payload: dict = {
        "model": cfg.model,
        "max_tokens": 2048,
        "messages": _anthropic_messages(rest),
        "temperature": 0.2,
    }
    if system:
        payload["system"] = system
    if tools:
        payload["tools"] = _anthropic_tools(tools)
    return payload


def _parse_anthropic(data: dict) -> ModelReply:
    content = ""
    calls: list[ToolCallReq] = []
    for block in data.get("content") or []:
        if block.get("type") == "text":
            content += str(block.get("text") or "")
        elif block.get("type") == "tool_use":
            calls.append(
                ToolCallReq(
                    id=str(block.get("id") or ""),
                    name=str(block.get("name") or ""),
                    arguments=block.get("input") if isinstance(block.get("input"), dict) else {},
                )
            )
    return ModelReply(content=content, tool_calls=calls)


async def _anthropic_turn(
    cfg: AssistantModelConfig, key: str, messages: list[dict], tools: list[dict]
) -> ModelReply:
    import httpx

    url = cfg.endpoint.rstrip("/") + "/v1/messages"
    async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls) as client:
        resp = await client.post(
            url, json=_anthropic_payload(cfg, messages, tools), headers=_anthropic_headers(key)
        )
        resp.raise_for_status()
        return _parse_anthropic(resp.json())


async def _anthropic_stream(
    cfg: AssistantModelConfig, key: str, messages: list[dict], tools: list[dict]
) -> AsyncIterator[StreamChunk]:
    import httpx

    url = cfg.endpoint.rstrip("/") + "/v1/messages"
    payload = {**_anthropic_payload(cfg, messages, tools), "stream": True}
    content = ""
    blocks: dict[int, dict] = {}  # index -> {type,id,name,json}
    async with httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls) as client:
        async with client.stream(
            "POST", url, json=payload, headers=_anthropic_headers(key)
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                try:
                    obj = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                etype = obj.get("type")
                if etype == "content_block_start":
                    cb = obj.get("content_block") or {}
                    blocks[obj.get("index", 0)] = {
                        "type": cb.get("type"),
                        "id": cb.get("id", ""),
                        "name": cb.get("name", ""),
                        "json": "",
                    }
                elif etype == "content_block_delta":
                    delta = obj.get("delta") or {}
                    if delta.get("type") == "text_delta" and delta.get("text"):
                        content += delta["text"]
                        yield StreamChunk(delta=delta["text"])
                    elif delta.get("type") == "input_json_delta":
                        slot = blocks.setdefault(
                            obj.get("index", 0),
                            {"type": "tool_use", "id": "", "name": "", "json": ""},
                        )
                        slot["json"] += delta.get("partial_json") or ""
                elif etype == "message_stop":
                    break
    calls = [
        ToolCallReq(id=b["id"] or b["name"], name=b["name"], arguments=_parse_args(b["json"]))
        for b in blocks.values()
        if b.get("type") == "tool_use" and b.get("name")
    ]
    yield StreamChunk(final=ModelReply(content=content, tool_calls=calls))


# ─────────────────────────── 分发器(配置驱动)───────────────────────────
def make_config_model_backend(provider: ConfigProvider, fallback_key: str = ""):
    """非流式后端:每轮读当前配置 → 按协议分发。失败软降级为空回复。"""

    async def turn(messages: list[dict], tools: list[dict]) -> ModelReply:
        cfg = provider()
        key = _effective_key(cfg, fallback_key)
        try:
            if cfg.protocol == "ollama":
                return await _ollama_turn(cfg, key, messages, tools)
            if cfg.protocol == "anthropic":
                return await _anthropic_turn(cfg, key, messages, tools)
            return await _openai_turn(cfg, key, messages, tools)
        except Exception as exc:  # noqa: BLE001 —— 端点不可达/未配置 → 空回复,Agent 据此收尾
            _LOG.warning("assistant 模型调用失败(protocol=%s):%s", cfg.protocol, exc)
            return ModelReply()

    return turn


def make_config_stream_backend(provider: ConfigProvider, fallback_key: str = ""):
    """流式后端:每轮读当前配置 → 按协议分发逐帧吐;断流软降级用已收内容收尾。"""

    async def stream_turn(messages: list[dict], tools: list[dict]) -> AsyncIterator[StreamChunk]:
        cfg = provider()
        key = _effective_key(cfg, fallback_key)
        if cfg.protocol == "ollama":
            gen = _ollama_stream(cfg, key, messages, tools)
        elif cfg.protocol == "anthropic":
            gen = _anthropic_stream(cfg, key, messages, tools)
        else:
            gen = _openai_stream(cfg, key, messages, tools)
        try:
            async for chunk in gen:
                yield chunk
        except Exception as exc:  # noqa: BLE001 —— 断流软降级,收尾给空 final 防 Agent 卡死
            _LOG.warning("assistant 流式调用失败(protocol=%s):%s", cfg.protocol, exc)
            yield StreamChunk(final=ModelReply())

    return stream_turn
