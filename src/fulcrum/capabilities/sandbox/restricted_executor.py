"""RestrictedExecutor —— 高危工具的执行时强制边界 + 超时(对应赛题目标②,arch §6.3)。

定位:管线在**策略放行后**才调执行器;本执行器是放行之后的**最后一道纵深防御**——
即便策略被误配/绕过,执行前仍按固定边界把关,涉密/越界/高危/外联一律拒绝执行。

MVP 边界(对齐 arch §6.3,诚实声明降级):
- **路径**:涉密路径直接拒;越出受控工作区拒(复用 argrisk,与策略同一口径,避免漂移)。
- **命令**:高危命令(rm -rf / 反弹 shell / 提权等)直接拒。
- **网络**:默认关闭外联——目标域名不在白名单一律拒(白名单经 options 注入,默认空=全关)。
- **超时**:工具调用放进线程并设墙钟超时,超时即判失败返回(不阻塞管线)。
- **资源(CPU/内存)/ 进程级隔离**:需容器或受限子进程,属 P3 增强,本 MVP 不覆盖,
  在此明确标注边界,不夸大为"完全隔离"。

无 options 条目时用保守默认(工作区 data/workspace、外联全关、超时 5s)。
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from ...core.domain import Context, ExecResult, ToolIntent
from ...core.registry import capability
from ..toolguard import argrisk

if TYPE_CHECKING:
    from ...core.ports import Tool


def _deny(reason: str) -> ExecResult:
    return ExecResult(ok=False, error=f"[沙箱拒绝] {reason}", side_effects={"sandbox": "denied"})


@capability("executor", "restricted")
class RestrictedExecutor:
    """执行时强制边界 + 超时。注册名 `restricted`,在 fulcrum.yml 启用;echo 为最小桩。"""

    def __init__(
        self,
        workspace: str = "data/workspace",
        allow_domains: list[str] | None = None,
        timeout_seconds: float = 5.0,
        max_output_chars: int = 16384,
    ) -> None:
        self._workspace = workspace
        self._allow_domains = list(allow_domains or [])  # 默认空 = 外联全关(默认关闭)
        self._timeout = float(timeout_seconds)
        self._max_output = int(max_output_chars)  # 工具返回大小上限(防内存撑爆 / 超量外泄)

    async def execute(self, tool: Tool, intent: ToolIntent, ctx: Context) -> ExecResult:
        args = intent.arguments

        # ---- 执行前强制边界(纵深防御,与策略同口径但独立把关)----
        if argrisk.path_sensitive(args):
            return _deny("涉密/敏感路径,拒绝执行")
        if argrisk.path_outside_workspace(args, self._workspace):
            return _deny("路径越出受控工作区,拒绝执行")
        if argrisk.command_dangerous(args):
            return _deny("命令含高危操作,拒绝执行")
        if not argrisk.domain_allowed(args, self._allow_domains):
            return _deny("目标域名不在沙箱外联白名单(默认关闭外联)")

        # ---- 超时受限执行:工具调用入线程 + 墙钟超时,超时不阻塞管线 ----
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: tool.call(args, ctx)),
                timeout=self._timeout,
            )
        except TimeoutError:
            return _deny(f"执行超时(> {self._timeout:g}s),强制终止")
        except Exception as exc:  # noqa: BLE001 —— 执行异常不外泄细节给调用方,统一判失败
            return ExecResult(ok=False, error=f"执行异常:{type(exc).__name__}")

        # ---- 执行后输出边界:超大返回截断(防内存撑爆 + 超量数据外泄)----
        return self._bound_output(result)

    def _bound_output(self, result: ExecResult) -> ExecResult:
        out = result.output
        if out is None or len(out) <= self._max_output:
            return result
        return ExecResult(
            ok=result.ok,
            output=out[: self._max_output] + f"\n…[沙箱截断:输出超 {self._max_output} 字符上限]",
            side_effects={**result.side_effects, "sandbox": "output_truncated"},
            error=result.error,
        )
