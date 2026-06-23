"""动态工具模型客户端 —— 助手 Agent 循环用的 OpenAI 兼容多轮 function-calling 调用。

与安全管线的 `openai_client`(写死 4 工具、单轮、不回填)不同(plan/11 §3.2):本客户端
**每轮动态传 tools 列表**(由 operation_registry 按角色派生)+ 支持把上一轮工具结果作为
`role:"tool"` 消息**回填**续推 + 多轮。注入式后端契约 `ModelTurn` 可换成确定性假后端供测试。

复用 `openai_client._parse_args`:被攻陷/犯浑的模型给出非法/非对象 arguments 时恒收敛成 dict,
绝不让畸形输出在解析阶段抛错而漏过后续闸门(fail-closed)。
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
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
