"""RestrictedExecutor —— 高危工具的执行时强制边界 + 超时(对应赛题目标②,arch §6.3)。

定位:管线在**策略放行后**才调执行器;本执行器是放行之后的**最后一道纵深防御**——
即便策略被误配/绕过,执行前仍按固定边界把关,涉密/越界/高危/外联一律拒绝执行。

MVP 边界(对齐 arch §6.3,诚实声明降级):
- **路径**:涉密路径直接拒;越出受控工作区拒(复用 argrisk,与策略同一口径,避免漂移)。
- **命令**:高危命令(rm -rf / 反弹 shell / 提权等)直接拒。
- **网络**:默认关闭外联——目标域名不在白名单一律拒(白名单经 options 注入,默认空=全关);
  且 URL 协议须为 http/https,file/gopher/dict/ftp 等(借工具读本地文件/打内部协议)一律拒。
- **载荷**:出站参数体积设上限——即便目标域名在白名单内,超大参数体(批量数据)一律拒,
  堵"经允许通道批量外泄"。与执行后输出截断对称:入口防灌出、出口防批量回。
- **超时**:工具调用放进线程并设墙钟超时,超时即判失败返回(不阻塞管线)。
- **资源(CPU/内存)/ 进程级隔离**:需容器或受限子进程,属 P3 增强,本 MVP 不覆盖,
  在此明确标注边界,不夸大为"完全隔离"。

无 options 条目时用保守默认(工作区 data/workspace、外联全关、超时 5s、入站载荷上限 64KB)。
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ...core.domain import Context, ExecResult, ToolIntent
from ...core.registry import capability
from ..toolguard import argrisk

if TYPE_CHECKING:
    from ...core.ports import Tool

# 允许的 URL 协议:仅 http/https。file/gopher/dict/ftp/ldap/jar… 是借工具读本地文件(LFI)、
# 打内部协议(SSRF)的经典面;且 file:/// 等**无主机**协议会让 domain_allowed 返回 True 直接绕过
# 外联白名单。故执行前按协议白名单 fail-closed:非 http/https 一律拒。
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def _deny(reason: str) -> ExecResult:
    return ExecResult(ok=False, error=f"[沙箱拒绝] {reason}", side_effects={"sandbox": "denied"})


def _url_scheme(arguments: dict) -> str | None:
    """取 url 参数的协议(小写);无 url 或无协议返回 None。"""
    url = str(arguments.get("url") or "")
    if not url:
        return None
    return urlparse(url).scheme.lower() or None


def _payload_size(value: object) -> int:
    """估算出站参数的字符体积:递归求和,作为"批量外泄/资源占用"的粗粒度上界。

    含键名一并计入(攻击者可把数据塞进键),容器逐项展开;标量按其字符串长度计。
    """
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        return sum(_payload_size(k) + _payload_size(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return sum(_payload_size(v) for v in value)
    return len(str(value))


@capability("executor", "restricted")
class RestrictedExecutor:
    """执行时强制边界 + 超时。注册名 `restricted`,在 fulcrum.yml 启用;echo 为最小桩。"""

    def __init__(
        self,
        workspace: str = "data/workspace",
        allow_domains: list[str] | None = None,
        timeout_seconds: float = 5.0,
        max_output_chars: int = 16384,
        max_input_chars: int = 65536,
    ) -> None:
        self._workspace = workspace
        self._allow_domains = list(allow_domains or [])  # 默认空 = 外联全关(默认关闭)
        self._timeout = float(timeout_seconds)
        self._max_output = int(max_output_chars)  # 工具返回大小上限(防内存撑爆 / 超量外泄)
        self._max_input = int(max_input_chars)  # 出站参数体积上限(防经允许通道批量外泄)

    async def execute(self, tool: Tool, intent: ToolIntent, ctx: Context) -> ExecResult:
        args = intent.arguments

        # ---- 执行前强制边界(纵深防御,与策略同口径但独立把关)----
        if argrisk.path_sensitive(args):
            return _deny("涉密/敏感路径,拒绝执行")
        if argrisk.path_outside_workspace(args, self._workspace):
            return _deny("路径越出受控工作区,拒绝执行")
        if argrisk.command_dangerous(args):
            return _deny("命令含高危操作,拒绝执行")
        scheme = _url_scheme(args)
        if scheme is not None and scheme not in _ALLOWED_URL_SCHEMES:
            # file:///etc/passwd 这类无主机协议会绕过下面的域名白名单,故先按协议白名单拦下。
            return _deny(f"URL 协议 {scheme}:// 不在允许清单(仅 http/https),拒绝执行")
        if not argrisk.domain_allowed(args, self._allow_domains):
            return _deny("目标域名不在沙箱外联白名单(默认关闭外联)")
        if _payload_size(args) > self._max_input:
            return _deny(f"出站载荷超体积上限({self._max_input} 字符),拒绝执行(防批量外泄)")

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
