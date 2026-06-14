"""EchoTool —— M0 桩工具:回显参数,用于跑通管线。

M1+ 替换为受控的 file.read / file.write / http.request / shell.exec。
"""

from __future__ import annotations

from ...core.domain import Context, ExecResult
from ...core.registry import capability


@capability("tool", "echo")
class EchoTool:
    name = "echo"

    def call(self, arguments: dict, ctx: Context) -> ExecResult:
        return ExecResult(ok=True, output=str(arguments.get("text", "")))
