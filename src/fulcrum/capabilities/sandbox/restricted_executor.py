"""RestrictedExecutor —— 高危工具的可终止受限子进程(对应赛题目标②,arch §6.3)。

定位:管线在**策略放行后**才调执行器;本执行器是放行之后的**最后一道纵深防御**——
即便策略被误配/绕过,执行前仍按固定边界把关,涉密/越界/高危/外联一律拒绝执行。

MVP 边界(对齐 arch §6.3,诚实声明降级):
- **路径**:涉密路径直接拒;越出受控工作区拒(复用 argrisk,与策略同一口径,避免漂移)。
- **命令**:高危命令(rm -rf / 反弹 shell / 提权等)直接拒。
- **网络**:默认关闭外联——目标域名不在白名单一律拒(白名单经 options 注入,默认空=全关);
  且 URL 协议须为 http/https,file/gopher/dict/ftp 等(借工具读本地文件/打内部协议)一律拒。
- **载荷**:出站参数体积设上限——即便目标域名在白名单内,超大参数体(批量数据)一律拒,
  堵"经允许通道批量外泄"。与执行后输出截断对称:入口防灌出、出口防批量回。
- **进程/超时**:每次调用使用 ``spawn`` 独立子进程;超时时父进程终止子进程(POSIX 同时清理
  进程组),不会留下原先线程模型的后台工具调用。
- **工作目录/资源**:子进程固定切入工作区,并施加 CPU、地址空间(Windows 为 Job Object
  进程内存)上限;输入和输出体积上限仍在父/子两侧生效。
- **网络**:默认在子进程拦截 Python socket API;需要外联时必须显式开启 ``allow_network`` 且通过
  既有域名白名单。它不是网络命名空间,非 Python 原生程序或恶意原生代码不在本实现防护范围。

无 options 条目时用保守默认(工作区 data/workspace、外联全关、超时 5s、入站载荷上限 64KB)。
"""

from __future__ import annotations

import asyncio
import math
import multiprocessing as mp
import os
import signal
import socket
import subprocess
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from typing import TYPE_CHECKING, Any
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


def _bound_result(result: ExecResult, max_output: int) -> ExecResult:
    """在子进程发送 IPC 前截断,避免大输出先进入 Pipe 占用父进程内存。"""
    out = result.output
    if out is None or len(out) <= max_output:
        return result
    return ExecResult(
        ok=result.ok,
        output=out[:max_output] + f"\n…[沙箱截断:输出超 {max_output} 字符上限]",
        side_effects={**result.side_effects, "sandbox": "output_truncated"},
        error=result.error,
    )


def _block_network() -> None:
    """拒绝子进程中经 Python 标准 socket API 发起的网络连接。"""

    def blocked(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("沙箱默认禁止网络访问")

    socket.socket = blocked  # type: ignore[assignment]
    socket.create_connection = blocked  # type: ignore[assignment]
    socket.getaddrinfo = blocked  # type: ignore[assignment]
    socket.gethostbyname = blocked  # type: ignore[assignment]


def _apply_posix_limits(max_cpu_seconds: float, max_memory_bytes: int) -> None:
    """POSIX 资源上限;资源模块仅在支持的平台导入。"""
    resource: Any = __import__("resource")
    cpu_limit = max(1, math.ceil(max_cpu_seconds))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
    resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))
    # 抗 fork 炸弹 / 磁盘灌满(对抗审查 C1/C2 补强):进程数与单文件写入体积上限。
    # NPROC 按每 uid 计,当前用量已超限时 setrlimit 抛错——尽力而为,失败不阻断执行边界。
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    except (ValueError, OSError):
        pass


# 环境白名单:子进程只保留运行时必需变量,其余(API 密钥/FULCRUM_*/业务凭据)一律清除——
# 对抗实测(P1):worker 原样继承父进程 env,`.env` 注入的模型密钥在沙箱内可读即外泄面。
# 在 worker 启动即执行(先于任何工具代码);PYTHON* 解释器变量一并清除,防经注入路径加载代码。
_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "TZ",
        "HOME",  # HOME 保留:ssl/工具按 ~ 解析证书;文件面本身不设 OS 边界(见诚实边界)
    }
)


def _scrub_environment() -> None:
    """清除白名单之外的全部环境变量(密钥/凭据/解释器注入面)。"""
    for key in list(os.environ):
        if key not in _ENV_ALLOWLIST:
            os.environ.pop(key, None)


def _silence_stdio() -> None:
    """子进程 stdout/stderr 重定向到 DEVNULL:工具刷屏不得污染网关日志/占满管道。"""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)
    except OSError:
        pass


def _apply_windows_limits(max_cpu_seconds: float, max_memory_bytes: int) -> object | None:
    """为当前 worker 绑定 Windows Job Object;宿主禁用嵌套 Job 时返回 ``None``。"""
    import ctypes
    from ctypes import wintypes

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    # ``ctypes`` 在非 Windows 类型存根中不暴露这些属性；实际调用仍仅发生在 Windows worker。
    win_dll: Any = getattr(ctypes, "WinDLL", None)
    get_last_error: Any = getattr(ctypes, "get_last_error", None)
    if win_dll is None or get_last_error is None:
        return None
    kernel32 = win_dll("kernel32", use_last_error=True)
    # 第一性原理:HANDLE 是指针宽度,ctypes 默认 restype=c_int 会把 64 位句柄截断/失真
    # (含 GetCurrentProcess 的伪句柄 -1)——Job 静默失败的根因类别。显式声明全部签名。
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.restype = ctypes.c_int
    kernel32.SetInformationJobObject.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    kernel32.AssignProcessToJobObject.restype = ctypes.c_int
    kernel32.AssignProcessToJobObject.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(get_last_error(), "CreateJobObjectW failed")
    limits = _ExtendedLimit()
    limits.BasicLimitInformation.PerProcessUserTimeLimit = int(max_cpu_seconds * 10_000_000)
    # PROCESS_TIME | PROCESS_MEMORY | KILL_ON_JOB_CLOSE
    limits.BasicLimitInformation.LimitFlags = 0x0002 | 0x0100 | 0x2000
    limits.ProcessMemoryLimit = max_memory_bytes
    try:
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise OSError(get_last_error(), "SetInformationJobObject failed")
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            raise OSError(get_last_error(), "AssignProcessToJobObject failed")
    except OSError:
        kernel32.CloseHandle(job)
        # 某些 CI/企业终端已把父进程放进不可嵌套 Job。不能因此回退为进程内执行;
        # 仍保留进程终止、输入/输出和墙钟边界,并在结果中标注资源限制未能附加。
        return None
    return job


def _worker(
    connection: Connection,
    tool: Tool,
    arguments: dict,
    ctx: Context,
    workspace: str,
    max_output: int,
    max_cpu_seconds: float,
    max_memory_bytes: int,
    allow_network: bool,
) -> None:
    """独立进程入口:只经 IPC 向父进程返回已限长的 ``ExecResult``。"""
    job: object | None = None
    resource_limits_applied = True
    try:
        _scrub_environment()
        _silence_stdio()
        os.makedirs(workspace, exist_ok=True)
        # 既有文件工具的根目录不能再从子进程 CWD 推导，否则会把 workspace 相对路径拼两次。
        os.environ["FULCRUM_RESTRICTED_WORKSPACE"] = workspace
        os.chdir(workspace)
        if os.name == "nt":
            job = _apply_windows_limits(max_cpu_seconds, max_memory_bytes)
            resource_limits_applied = job is not None
        else:
            os.setsid()
            _apply_posix_limits(max_cpu_seconds, max_memory_bytes)
        if not allow_network:
            _block_network()
        result = tool.call(arguments, ctx)
        if not isinstance(result, ExecResult):
            raise TypeError("工具返回值不是 ExecResult")
        if not resource_limits_applied:
            result = result.model_copy(
                update={
                    "side_effects": {
                        **result.side_effects,
                        "sandbox_resource_limits": "wall_clock_input_output_only",
                    }
                }
            )
        connection.send(("result", _bound_result(result, max_output).model_dump()))
    except Exception as exc:  # noqa: BLE001 - 子进程错误不泄露给外部调用方
        try:
            connection.send(("error", type(exc).__name__))
        except (BrokenPipeError, EOFError):
            pass
    finally:
        if job is not None:
            import ctypes

            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(job)
        connection.close()


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
        max_cpu_seconds: float = 5.0,
        max_memory_bytes: int = 256 * 1024 * 1024,
        allow_network: bool = False,
    ) -> None:
        if timeout_seconds <= 0 or max_cpu_seconds <= 0:
            raise ValueError("timeout_seconds 和 max_cpu_seconds 必须为正数")
        if max_output_chars < 0 or max_input_chars < 0 or max_memory_bytes <= 0:
            raise ValueError("资源与体积上限必须为非负值")
        self._workspace = workspace
        self._allow_domains = list(allow_domains or [])  # 默认空 = 外联全关(默认关闭)
        self._timeout = float(timeout_seconds)
        self._max_output = int(max_output_chars)  # 工具返回大小上限(防内存撑爆 / 超量外泄)
        self._max_input = int(max_input_chars)  # 出站参数体积上限(防经允许通道批量外泄)
        self._max_cpu = float(max_cpu_seconds)
        self._max_memory = int(max_memory_bytes)
        self._allow_network = bool(allow_network)

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

        # ``spawn`` 在 Linux/Windows/macOS 使用同一序列化语义;启动/等待放进线程,不阻塞事件循环。
        return await asyncio.to_thread(self._execute_in_process, tool, args, ctx)

    def _execute_in_process(self, tool: Tool, arguments: dict, ctx: Context) -> ExecResult:
        mp_context = mp.get_context("spawn")
        parent, child = mp_context.Pipe(duplex=False)
        workspace = os.path.abspath(self._workspace)
        process = mp_context.Process(
            target=_worker,
            args=(
                child,
                tool,
                arguments,
                ctx,
                workspace,
                self._max_output,
                self._max_cpu,
                self._max_memory,
                self._allow_network,
            ),
        )
        try:
            process.start()
        except Exception as exc:  # noqa: BLE001 - 不可序列化的工具不可绕过进程边界
            return _deny(f"无法启动受限子进程({type(exc).__name__}),拒绝执行")
        finally:
            child.close()

        try:
            if not parent.poll(self._timeout):
                self._terminate(process)
                return _deny(f"执行超时(> {self._timeout:g}s),受限子进程已终止")
            try:
                state, payload = parent.recv()
            except EOFError:
                return _deny("受限子进程未返回结果,拒绝执行")
            if state == "result":
                return ExecResult.model_validate(payload)
            return ExecResult(ok=False, error=f"执行异常:{payload}")
        finally:
            parent.close()
            process.join(timeout=0.2)
            if process.is_alive():
                self._terminate(process)

    @staticmethod
    def _terminate(process: BaseProcess) -> None:
        """超时时终止 worker;POSIX 还清理 worker 建立的独立进程组。"""
        if not process.is_alive():
            process.join(timeout=0.2)
            return
        if os.name != "nt" and process.pid is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
            # 树杀兜底(对抗实测:Job 降级时 TerminateProcess 只杀 worker,孙进程存活)。
            # 强制点收回到父进程(沙箱外):taskkill /T 按 PID 树终止全部后代。
            if process.pid is not None:
                subprocess.run(
                    ["taskkill", "/T", "/F", "/PID", str(process.pid)],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
        process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)

    def _bound_output(self, result: ExecResult) -> ExecResult:
        return _bound_result(result, self._max_output)
