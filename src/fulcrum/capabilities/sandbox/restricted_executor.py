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
- **超时**:工具调用放进线程并设墙钟超时,超时即解除管线等待、判失败返回(不阻塞管线)。
  注意:超时**不杀线程**(Python 无法安全强杀),工具会在后台跑完、副作用照发;真正阻止副作用
  须靠可取消的子进程/容器(P3)。此处只保证管线不被慢工具拖住。
- **资源(CPU/内存)/ 进程级隔离**:需容器或受限子进程,属 P3 增强,本 MVP 不覆盖,
  在此明确标注边界,不夸大为"完全隔离"。

无 options 条目时用保守默认(工作区 data/workspace、外联全关、超时 5s、入站载荷上限 64KB)。
"""

from __future__ import annotations

import asyncio
import os
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

# 无 `://` 主机段、但仍是 LFI/SSRF 面的"不透明"协议(`file:/etc/passwd`、`jar:a!/b`、`dict:…`)。
# 协议判定以"含 `://`"为主信号(排除 `localhost:6379`/`12:30`/`user@host` 这类带冒号的良性值被
# 误读成协议),再叠加本集合兜住无双斜杠的危险协议。集中定义便于扩。
_RISKY_OPAQUE_SCHEMES: frozenset[str] = frozenset(
    {
        "file",
        "gopher",
        "dict",
        "ftp",
        "ftps",
        "sftp",
        "tftp",
        "ldap",
        "ldaps",
        "jar",
        "data",
        "javascript",
        "php",
        "expect",
        "netdoc",
        "smb",
        "redis",
    }
)

# 目的地参数键集单一真源见 `argrisk.DEST_KEYS`(URL 形态 + 地址形态并集)。协议白名单、域名/内网
# 判定共用同一键集,避免"协议检查覆盖某键、域名检查漏该键"的漂移(曾致 {to:https://…} 绕过白名单)。

# 路径参数键集(软链容纳检查覆盖面)。与目的地键互斥:这些键承载文件系统路径,执行前对其
# 真实路径(realpath,跟随软链)做工作区容纳判定。集中定义便于以后随工具形态扩。
_PATH_ARG_KEYS: frozenset[str] = frozenset(
    {
        "path",
        "file",
        "filename",
        "filepath",
        "file_path",
        "src",
        "source",
        "dir",
        "directory",
        "folder",
        "input",
        "input_path",
        "output",
        "output_path",
    }
)


def _deny(reason: str) -> ExecResult:
    return ExecResult(ok=False, error=f"[沙箱拒绝] {reason}", side_effects={"sandbox": "denied"})


def _disallowed_url_scheme(arguments: dict) -> tuple[str, str] | None:
    """扫描**所有目的地键**,返回首个带非 http/https 协议的 (键名, 协议);全合规返回 None。

    纵深兜底:`_url_scheme` 旧实现只读 `url` 键,协议白名单只护住一个键,改键名(endpoint=
    `file:///etc/passwd`、webhook=`gopher://…`)即绕过。这里对 `argrisk.DEST_KEYS` 全集判协议
    (与域名/内网判定同一键集真源)。协议成立须满足"含 `://`(权威形 URL)或属
    `_RISKY_OPAQUE_SCHEMES`(file:/jar:…)",据此把 `localhost:6379`/`12:30`/`user@host`/`C:/x`
    这类带冒号的良性值排除在外(只做加法、不误伤)。
    """
    for key in argrisk.DEST_KEYS:
        raw = str(arguments.get(key) or "")
        if not raw:
            continue
        scheme = urlparse(raw).scheme.lower()
        if not scheme or scheme in _ALLOWED_URL_SCHEMES:
            continue
        if "://" in raw or scheme in _RISKY_OPAQUE_SCHEMES:
            return key, scheme
    return None


def _realpath_escapes(raw: str, workspace: str) -> bool:
    """纯函数:路径经 realpath(跟随软链)解析后,是否仍越出受控工作区。

    缺口:`argrisk.path_outside_workspace` 是纯字符串判定(看 `..`/workspace 前缀/盘符),
    **不解析软链**——工作区内一条软链(data/workspace/x → /etc/passwd)字符串检查全过、却读到
    区外。本检查独立于 argrisk:对路径与 workspace **两侧都 realpath** 后再比对(/tmp 本身可能
    是软链,只解析一侧会误伤合法区内访问),解析后真实路径不在 workspace 根内即为逃逸。
    """
    if not raw:
        return False
    real_ws = os.path.realpath(workspace)
    # 相对路径按"工作区内"解释(与受控工作区语义一致,故裸名 notice.txt 仍判区内、不误伤);
    # 绝对/盘符路径照原样解析。两侧都 realpath 后再比,避免 /tmp 软链一侧未解析的假阳。
    candidate = raw if os.path.isabs(raw) else os.path.join(workspace, raw)
    real_target = os.path.realpath(candidate)
    try:
        # commonpath 归一分隔符/末尾斜杠;真实路径落在 ws 内 → 公共前缀正是 ws。
        return os.path.commonpath([real_ws, real_target]) != real_ws
    except ValueError:
        # 不同盘符 / 一方为相对一方为绝对无公共前缀(Windows)→ 视为越界。
        return True


def _symlink_escape_key(arguments: dict, workspace: str) -> str | None:
    """扫描**所有路径键**,返回首个 realpath 解析后逃逸出工作区的键名;全部容纳返回 None。"""
    for key in _PATH_ARG_KEYS:
        raw = str(arguments.get(key) or "")
        if raw and _realpath_escapes(raw, workspace):
            return key
    return None


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
        # 软链逃逸兜底(纵深,不依赖 argrisk 的纯字符串判定):realpath 跟随软链解析后再判容纳。
        escaped_key = _symlink_escape_key(args, self._workspace)
        if escaped_key is not None:
            return _deny(f"路径参数 {escaped_key} 经软链解析后越出受控工作区,拒绝执行")
        if argrisk.command_dangerous(args):
            return _deny("命令含高危操作,拒绝执行")
        # 协议白名单兜底覆盖**所有目的地键**(非仅 url):file:///etc/passwd(LFI)、gopher://(SSRF)
        # 这类无主机协议会让下面的域名白名单返回 True 直接绕过,故先按协议白名单拦下。
        bad_scheme = _disallowed_url_scheme(args)
        if bad_scheme is not None:
            key, scheme = bad_scheme
            return _deny(
                f"目的地参数 {key} 的 URL 协议 {scheme}:// 不在允许清单(仅 http/https),拒绝执行"
            )
        if not argrisk.domain_allowed(args, self._allow_domains):
            return _deny("目标域名不在沙箱外联白名单(默认关闭外联)")
        if _payload_size(args) > self._max_input:
            return _deny(f"出站载荷超体积上限({self._max_input} 字符),拒绝执行(防批量外泄)")

        # ---- 超时受限执行:工具调用入线程 + 墙钟超时 ----
        # 诚实边界(P3):超时只**解除管线等待**、让本次调用即刻判失败返回,并**不**能杀死底层
        # 工作线程——Python 无法安全强杀线程,tool.call 会在后台跑完,其副作用(写盘/外联)照发,
        # 且连续超时会占满默认线程池。真正的"超时即终止副作用"须靠可取消的子进程/容器执行
        # (进程隔离,见模块头 P3)。此处仅保证管线不被单个慢工具拖住。
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: tool.call(args, ctx)),
                timeout=self._timeout,
            )
        except TimeoutError:
            return _deny(f"执行超时(> {self._timeout:g}s),已解除管线等待(工具线程可能仍在后台运行)")
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
