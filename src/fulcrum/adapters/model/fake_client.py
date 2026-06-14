"""FakeModelClient —— M0 桩:不连真实模型,回固定响应并产出一个 echo 工具调用。

目的:让 /v1/chat/completions 端到端走完"输入检测 -> 模型 -> 工具意图 -> 策略 -> 执行 -> 审计"。
M1+ 替换为 OpenAI 兼容 HTTP client(默认本地 Ollama/vLLM)。
"""

from __future__ import annotations

from ...core.domain import ModelRequest, ModelResponse, ToolCall
from ...core.registry import capability


@capability("model", "fake")
class FakeModelClient:
    async def chat(self, req: ModelRequest) -> ModelResponse:
        last_user = next((m.content for m in reversed(req.messages) if m.role == "user"), "")
        return ModelResponse(
            request_id=req.request_id,
            content=f"(FakeModelClient) 已收到 {len(req.messages)} 条消息。",
            tool_calls=[ToolCall(tool_name="echo", arguments={"text": last_user})],
        )
