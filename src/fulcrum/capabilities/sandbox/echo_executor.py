"""EchoExecutor —— M0 桩:直接调用工具,不做真实隔离。

M1+ 替换为真沙箱(容器/受限子进程 + 路径白名单 + 网络开关 + 超时),见 arch/00 §6.3。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...core.domain import Context, ExecResult, ToolIntent
from ...core.registry import capability

if TYPE_CHECKING:
    from ...core.ports import Tool


@capability("executor", "echo")
class EchoExecutor:
    async def execute(self, tool: Tool, intent: ToolIntent, ctx: Context) -> ExecResult:
        # Tool 端口仍同步(file IO 用 sqlite3 同等同步即可);真沙箱落地后这里 await 子进程。
        return tool.call(intent.arguments, ctx)
