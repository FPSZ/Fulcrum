"""动态工具模型客户端 —— 助手 Agent 循环用的 OpenAI 兼容多轮 function-calling 调用。

与安全管线的 `openai_client`(写死 4 工具、单轮、不回填)不同(plan/11 §3.2):本客户端
**每轮动态传 tools 列表**(由 operation_registry 按角色派生)+ 支持把上一轮工具结果作为
`role:"tool"` 消息**回填**续推 + 多轮。注入式后端契约 `ModelTurn` 可换成确定性假后端供测试。

复用 `openai_client._parse_args`:被攻陷/犯浑的模型给出非法/非对象 arguments 时恒收敛成 dict,
绝不让畸形输出在解析阶段抛错而漏过后续闸门(fail-closed)。
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field

from ...core.operations import AssistantTool
from ..model.openai_client import _parse_args

_LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class ToolCallReq:
    """模型本轮请求调用的一个工具(已收敛参数)。"""

    id: str
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass(slots=True)
class ModelReply:
    """模型一轮输出:要么给最终答复(content),要么请求若干工具调用(tool_calls)。"""

    content: str = ""
    tool_calls: list[ToolCallReq] = field(default_factory=list)


# 后端契约:(messages, tools) -> ModelReply。失败应返回空 ModelReply 而非抛错。
ModelTurn = Callable[[list[dict], list[dict]], Awaitable[ModelReply]]


@dataclass(slots=True)
class StreamChunk:
    """流式一帧:要么是一段文本增量(delta),要么是本轮装配完成的最终回复(final)。"""

    delta: str | None = None
    final: ModelReply | None = None


# 流式后端契约:(messages, tools) -> 逐帧异步迭代;最后一帧带 final=ModelReply。
StreamTurn = Callable[[list[dict], list[dict]], AsyncIterator[StreamChunk]]


def to_function_spec(tool: AssistantTool) -> dict:
    """把 operation 描述符转成 OpenAI function-calling 工具规格(模型线格式,属适配层)。"""
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters or {"type": "object", "properties": {}},
        },
    }


def _parse_reply(data: dict) -> ModelReply:
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


def make_dynamic_stream_backend(
    endpoint: str, api_key: str, model: str, timeout: float = 90.0
) -> StreamTurn:
    """流式后端:OpenAI 兼容 /chat/completions(stream=true),逐帧吐文本增量 + 装配 tool_calls。

    模型一轮要么吐 content(最终答复,逐字流给前端),要么吐 tool_calls(增量分片,按 index
    拼回完整名/参数)。失败软降级:把已收到的内容装配成 final 返回,绝不抛断流。
    """

    async def stream_turn(messages: list[dict], tools: list[dict]) -> AsyncIterator[StreamChunk]:
        import httpx

        url = endpoint.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload: dict = {"model": model, "messages": messages, "temperature": 0.2, "stream": True}
        if tools:
            payload["tools"] = tools

        content = ""
        tool_acc: dict[int, dict] = {}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream("POST", url, json=payload, headers=headers) as resp:
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
                        piece = delta.get("content")
                        if piece:
                            content += piece
                            yield StreamChunk(delta=piece)
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
        except Exception as exc:  # noqa: BLE001 —— 断流软降级,用已收内容收尾
            _LOG.warning("assistant 流式调用失败:%s", exc)

        calls = [
            ToolCallReq(id=s["id"] or s["name"], name=s["name"], arguments=_parse_args(s["args"]))
            for s in tool_acc.values()
            if s["name"]
        ]
        yield StreamChunk(final=ModelReply(content=content, tool_calls=calls))

    return stream_turn


def make_dynamic_model_backend(
    endpoint: str, api_key: str, model: str, timeout: float = 60.0
) -> ModelTurn:
    """默认后端:异步调 OpenAI 兼容 /chat/completions(动态 tools + tool 回填);失败回空。"""

    async def turn(messages: list[dict], tools: list[dict]) -> ModelReply:
        import httpx

        url = endpoint.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload: dict = {"model": model, "messages": messages, "temperature": 0.2}
        if tools:
            payload["tools"] = tools
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                return _parse_reply(resp.json())
        except Exception as exc:  # noqa: BLE001 —— 端点不可达/未配置 → 空回复,Agent 据此收尾
            _LOG.warning("assistant 动态模型调用失败:%s", exc)
            return ModelReply()

    return turn
