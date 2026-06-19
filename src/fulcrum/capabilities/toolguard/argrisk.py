"""工具参数风险判定 —— risk_scorer 与 policy 共用的确定性纯函数。

约定的参数形态(与内置 4 工具对齐,见路线图 P0-b):
    file.read / file.write : {"path": "..."}
    http.request           : {"url": "...", "method": "GET", "body": "..."}
    shell.exec             : {"command": "..."}

纯函数、无副作用、可解释:同一份判断同时服务"风险评分"与"策略匹配",避免两处口径漂移。
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# 敏感文件/路径:系统账户、SSH/证书私钥、云与服务凭据、Shell 历史、Web 配置(中英 + Win/Linux)。
# 政务现场多为 Windows,故同时覆盖 SAM/SYSTEM 注册表蜂巢、NTDS、各类凭据落盘点。
_SENSITIVE_PATH = re.compile(
    r"("
    # 系统账户 / 提权配置(Linux)
    r"/etc/(passwd|shadow|sudoers)|/root/|/proc/self/environ|"
    # SSH / 证书 / 密钥库
    r"id_rsa|id_ed25519|authorized_keys|\.ssh|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.jks\b|\.keystore\b|"
    # 云原生 / 服务凭据落盘点
    r"\.aws[\\/]+credentials|\.kube[\\/]+config|\.docker[\\/]+config|\.gnupg|\.netrc|\.pgpass|"
    r"\.git-credentials|\.npmrc|\.env\b|"
    # Shell / DB 历史(常含明文口令)
    r"\.bash_history|\.mysql_history|"
    # Windows 凭据存储:注册表蜂巢 / 域库
    r"system32[\\/]+config[\\/]+(sam|system|security)|ntds\.dit|"
    # Web 应用敏感配置
    r"web\.config|wp-config\.php|\.htpasswd|"
    # 通用关键词兜底(中英)
    r"secret|credential|password|confidential|密钥|私钥|口令|凭据|凭证|涉密|机密)",
    re.IGNORECASE,
)
# 危险 shell 片段:删除/磁盘、外联下载、管道喂 shell、反弹/交互 shell、提权改账户、
# Windows LOLBins(无文件执行 / 日志清除 / 持久化)、fork bomb。规则保守,宁可转人工。
_DANGEROUS_CMD = re.compile(
    r"("
    # 删除 / 磁盘 / 关机
    r"rm\s+-rf|mkfs|dd\s+if=|shutdown|reboot|wipefs|del\s+/[a-z]|rmdir\s+/s|format\s+[a-z]:|"
    # 外联下载(含 Windows 下载器 LOLBin)
    r"\b(curl|wget)\b|certutil\s+.*-urlcache|bitsadmin|"
    # 管道把下载内容直接喂给 shell(下载即执行)
    r"\|\s*(ba|z)?sh\b|\|\s*powershell|"
    # 反弹 / 交互 shell + 内联解释器执行
    r"\bnc\b\s+-e|/bin/sh|/dev/tcp/|bash\s+-[ic]|\bsh\s+-i|mkfifo|\bsocat\b|"
    r"python\d?\s+-c|perl\s+-e|php\s+-r|ruby\s+-e|"
    # 提权 / 编码绕过 / 改账户
    r"base64\s+-d|chmod\s+777|chattr\s|setcap\s|\bsudo\s|net\s+user|net\s+localgroup|"
    r"useradd|usermod|"
    # Windows LOLBins:无文件执行 / 服务管控 / 日志与卷影清除 / 计划任务 / 注册表 / 关防护
    r"powershell|invoke-expression|\biex\b|invoke-webrequest|mshta|regsvr32|rundll32|"
    r"wmic|vssadmin|wevtutil|schtasks|\breg\s+(add|delete)|\b(set|add)-mppreference|"
    # fork bomb
    r":\(\)\s*\{)",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_WIN_DRIVE = re.compile(r"^[A-Za-z]:")
_GLOB = re.compile(r"[*?]")
# 公认的本机主机名(非 IP 字面量,ipaddress 解析不了,单列)。
_INTERNAL_HOSTNAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def _arg_path(arguments: dict) -> str:
    return str(arguments.get("path") or arguments.get("file") or "")


def path_sensitive(arguments: dict) -> bool:
    return bool(_SENSITIVE_PATH.search(_arg_path(arguments)))


def path_outside_workspace(arguments: dict, workspace: str) -> bool:
    """上级穿越、或不在 workspace 前缀内的绝对/盘符路径 → 越界。"""
    raw = _arg_path(arguments)
    if not raw:
        return False
    norm = raw.replace("\\", "/")
    if ".." in norm:
        return True
    ws = workspace.replace("\\", "/").rstrip("/")
    if norm == ws or norm.startswith(ws + "/"):
        return False
    return norm.startswith("/") or bool(_WIN_DRIVE.match(norm))


def command_dangerous(arguments: dict) -> bool:
    cmd = str(arguments.get("command") or arguments.get("cmd") or "")
    return bool(_DANGEROUS_CMD.search(cmd))


def destructive_action(arguments: dict) -> bool:
    """不可逆批量破坏:递归(`recursive: true`)或目标路径含通配符(glob `*`/`?`)。

    针对 `*.delete` / `*.drop` 类破坏性工具:删单个明确文件尚可控,但**递归或通配批量删除**
    (如 `data/approvals/*` + `recursive`)会不可逆地抹掉成批记录,须由策略硬拦。
    与工具名无关(纯判参数形态),具体由策略 `tool_in` 圈定破坏性工具后再叠加本谓词。
    """
    if arguments.get("recursive"):
        return True
    return bool(_GLOB.search(_arg_path(arguments)))


def url_host(arguments: dict) -> str | None:
    url = str(arguments.get("url") or "")
    if not url:
        return None
    host = urlparse(url if "://" in url else f"//{url}").hostname
    return host.lower() if host else None


def domain_allowed(arguments: dict, allow_domains: list[str]) -> bool:
    """无 URL → 不涉及白名单,返回 True;有 URL → 命中白名单(含子域)才放行。"""
    host = url_host(arguments)
    if host is None:
        return True
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in allow_domains)


def is_raw_ip(arguments: dict) -> bool:
    host = url_host(arguments)
    return bool(host and _IPV4.match(host))


def url_is_internal(arguments: dict) -> bool:
    """URL 指向内网/回环/链路本地/云元数据等**非公网可路由**地址 → SSRF 风险。

    经典的"借智能体打内部面":URL 指向 127.0.0.1 内部管理口、10/172.16/192.168 内网主机、
    或 169.254.169.254 云元数据端点(窃取实例凭据)——域名白名单按字符串匹配,管不到这层。
    仅对 URL 里**字面 IP**(及 localhost 等公认本机名)做确定性判定;不做 DNS 解析,
    域名→私网的重绑定(DNS rebinding)属 P3 增强。`not is_global` 一并覆盖私网/回环/
    链路本地/保留/未指定地址,跨 Python 版本稳定。
    """
    host = url_host(arguments)
    if host is None:
        return False
    if host in _INTERNAL_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # 普通域名:不做解析,不在此判定(交由白名单/其它规则)
    return not ip.is_global
