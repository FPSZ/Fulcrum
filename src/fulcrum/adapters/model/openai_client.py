"""OpenAICompatModelClient —— 出站模型适配器,连接任意 OpenAI 兼容端点(默认 MiMo)。

读取 Settings(.env 注入)里的 endpoint / key / model;向模型声明枢衡受控的 4 个工具,
把模型返回的 function tool_calls 映射回领域 `ToolCall`(函数名 file_read ↔ 内部 file.read)。
密钥只经环境变量注入,绝不写入代码或日志。
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ...config import Settings
from ...core.domain import ModelRequest, ModelResponse, ToolCall
from ...core.registry import capability

# 向模型声明的受控工具(OpenAI function 规范;函数名用下划线以满足 ^[a-zA-Z0-9_-]+$)。
_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "读取受控工作区内的文本文件并返回内容",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "文件路径"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "file_write",
            "description": "向受控工作区写入文本文件",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "发起 HTTP 请求(受外联白名单约束)",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell_exec",
            "description": "执行系统命令(默认需人工审批)",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
]
# 模型函数名 ↔ 枢衡内部工具名。
_FN_TO_TOOL = {
    "file_read": "file.read",
    "file_write": "file.write",
    "http_request": "http.request",
    "shell_exec": "shell.exec",
}


@capability("model", "openai")
class OpenAICompatModelClient:
    def __init__(self, settings: Settings | None = None) -> None:
        s = settings or Settings()
        self._base = s.model_endpoint.rstrip("/")
        self._key = s.model_api_key
        self._model = s.model_name

    async def chat(self, req: ModelRequest) -> ModelResponse:
        payload = {
            "model": self._model,
            "messages": [self._msg(m) for m in req.messages],
            "tools": _TOOLS,
            "temperature": 0.3,
        }
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._base}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
        return self._to_response(req.request_id, data)

    @staticmethod
    def _msg(m: Any) -> dict[str, str]:
        out = {"role": m.role, "content": m.content}
        if m.name:
            out["name"] = m.name
        return out

    @staticmethod
    def _to_response(request_id: str, data: dict[str, Any]) -> ModelResponse:
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        tool_calls: list[ToolCall] = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function") or {}
            raw_name = str(fn.get("name") or "")
            name = _FN_TO_TOOL.get(raw_name, raw_name)
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_raw": fn.get("arguments", "")}
            tool_calls.append(ToolCall(tool_name=name, arguments=args))
        return ModelResponse(
            request_id=request_id,
            content=message.get("content") or "",
            tool_calls=tool_calls,
        )
