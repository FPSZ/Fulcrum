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
from urllib.parse import unquote, urlparse

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
    # 外联下载 / 本地解码落盘(含 Windows 下载器 LOLBin;certutil 既能下载也能 -decode 还原载荷)
    r"\b(curl|wget)\b|certutil\s+.*-(urlcache|decode)|bitsadmin|"
    # 空格规避:${IFS}/$IFS 替空格(绕"含空格危险串"规则,见 cmd.obfuscation.ifs_substitution)
    r"\$\{?IFS\b|"
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
    r"wmic|vssadmin|wevtutil|schtasks|\breg\s+(add|delete|save)|\b(set|add)-mppreference|"
    # fork bomb
    r":\(\)\s*\{)",
    re.IGNORECASE,
)
# argv 注入面:**二进制名看似无害,危险藏在参数里**(GTFOBins 类「借刀执行」)。
# 上面的 _DANGEROUS_CMD 按二进制名/显式片段匹配,管不到 `tar --checkpoint-action=`、
# `find -exec`、`git -c core.sshCommand=`、`ssh -o ProxyCommand=` 这类——命令头是
# tar/find/git/ssh 等白名单常用工具,却用一个选项把任意命令喂进去。规则只盯**有判别力的
# 危险选项 token**,不盯通用短参,守住「正常 tar/git/find 不误伤」的下界。
_ARG_INJECTION = re.compile(
    r"("
    # tar/zip 借「动作钩子 / 外部压缩器」执行任意命令
    r"--checkpoint-action=|--to-command=|--use-compress-program=|--unzip-command=|"
    # find / xargs 借 -exec(dir) 执行
    r"-execdir\b|-exec\b|"
    # ssh / scp / rsync 借连接命令执行(ProxyCommand / 本地命令 / 远端 shell)
    r"proxycommand=|localcommand=|--rsh=|"
    # 远端 shell 选项 -e 限定在 rsync 上下文,避免误伤通用 -e
    r"\brsync\b[^\n]{0,60}?\s-e\s|"
    # git 借配置项执行(sshCommand / pager / fsmonitor)或自定义 pack 程序
    r"core\.sshcommand=|core\.pager=|core\.fsmonitor=|--upload-pack=|--receive-pack=|"
    # askpass 钩子执行外部程序
    r"--use-askpass=|\bsshpass\b|"
    # awk / gawk 内联 system() 执行
    r"\bg?awk\b[^\n]{0,60}?system\s*\(|"
    # env VAR=VAL cmd 形式绕过 allowlist / sudo
    r"\benv\s+\w+=\S+\s+\w)",
    re.IGNORECASE,
)
_WIN_DRIVE = re.compile(r"^[A-Za-z]:")
_GLOB = re.compile(r"[*?]")
# 承载外联目的地的参数键(按优先级):`url` 先,其次 webhook / 回调 / 端点等。
# 之所以不止看 `url` —— SSRF 不只走 http.request:webhook.send / external.post / notify 这类
# 工具用 endpoint / webhook / callback 等键承载目标,只盯 `url` 会让它们打内网/元数据漏判。
# 仅纳入**URL 形态**的键(不含 to/recipient/email 这类地址形态,避免 urlparse 误解析邮箱)。
_DEST_URL_KEYS = (
    "url",
    "endpoint",
    "webhook",
    "callback",
    "callback_url",
    "uri",
    "target",
    "dest",
    "destination",
)
# 公认的本机主机名(非 IP 字面量,ipaddress 解析不了,单列)。
_INTERNAL_HOSTNAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def _unquote_recursive(text: str, max_depth: int = 3) -> str:
    """递归 URL 解码(限深),救双重/多重百分号编码(`%252e`→`%2e`→`.`)。

    路径围栏只看字面 `..`/绝对前缀,攻击者用 `%252e%252e%252f` 可让 `..` 不以字面出现而绕过。
    在匹配副本上逐层解码到稳定不动点(或触顶),再判定;限深防构造的解码炸弹。
    """
    prev = text
    for _ in range(max_depth):
        cur = unquote(prev)
        if cur == prev:
            break
        prev = cur
    return prev


def _arg_path(arguments: dict) -> str:
    # 解码后再判定:路径围栏与敏感路径匹配都看解码副本(原文不留存,argrisk 只产 bool)。
    return _unquote_recursive(str(arguments.get("path") or arguments.get("file") or ""))


def _token_int(token: str) -> int | None:
    """把单段按其进制前缀折算成整数:0x→十六进制、前导 0→八进制、否则十进制;非数字 → None。"""
    t = token.strip()
    if not t:
        return None
    try:
        if t[:2].lower() == "0x":
            return int(t, 16)
        if t[0] == "0" and len(t) > 1:
            return int(t, 8)
        return int(t, 10)
    except ValueError:
        return None


def _coerce_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """把各种进制/缩写形态的 IPv4 字面量按 inet_aton 语义折算成 IPv4Address;非此形态 → None。

    覆盖 `2130706433`(十进制)、`0x7f000001`(十六进制)、`0177.0.0.1`(八进制)、`127.1`
    (缺段:末段吸收剩余低位字节)——都等价 127.0.0.1,是绕"点分四段"正则的经典 SSRF 混淆。
    真实主机名(含非数字段)任一段折算失败即返回 None,不会误判。
    """
    s = host.strip()
    if not s or s.endswith("."):
        return None
    parts = s.split(".")
    if len(parts) > 4:
        return None
    nums: list[int] = []
    for part in parts:
        n = _token_int(part)
        if n is None or n < 0:
            return None
        nums.append(n)
    *head, last = nums
    if any(h > 0xFF for h in head):
        return None
    span = 4 - len(head)  # 末段占的字节数(inet_aton:a.b → b 占低 24 位)
    if last > (1 << (8 * span)) - 1:
        return None
    value = 0
    for octet in head:
        value = (value << 8) | octet
    value = (value << (8 * span)) | last
    return ipaddress.IPv4Address(value)


def _host_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """把主机名解析成 IP 地址对象:标准点分/IPv6 字面量,或进制混淆的 IPv4;否则 None。

    IPv4-mapped IPv6(`::ffff:127.0.0.1`)折回内嵌的 IPv4 判定,免被 IPv4-only 黑名单绕过。
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return _coerce_ipv4(host)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


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


def command_arg_injection(arguments: dict) -> bool:
    """命令头是无害工具(tar/git/find/ssh…),但某个选项把任意命令喂进去 → argv 注入。"""
    cmd = str(arguments.get("command") or arguments.get("cmd") or "")
    return bool(_ARG_INJECTION.search(cmd))


def command_dangerous(arguments: dict) -> bool:
    cmd = str(arguments.get("command") or arguments.get("cmd") or "")
    return bool(_DANGEROUS_CMD.search(cmd) or _ARG_INJECTION.search(cmd))


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
    """从外联目的地参数(按 `_DEST_URL_KEYS` 优先级)取主机名;无则 None。

    `url` 优先以保持 http.request 既有行为不变;其后的 webhook/endpoint 等键让非 http.request
    的对外工具(webhook.send / external.post …)也进入 SSRF / 白名单判定的视野。
    """
    url = next((str(arguments[k]) for k in _DEST_URL_KEYS if arguments.get(k)), "")
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
    """URL 主机是 IP 字面量(含十进制/十六进制/八进制/缺段/IPv6 等混淆形态),而非域名。"""
    host = url_host(arguments)
    return bool(host and _host_ip(host) is not None)


def url_is_internal(arguments: dict) -> bool:
    """URL 指向内网/回环/链路本地/云元数据等**非公网可路由**地址 → SSRF 风险。

    经典的"借智能体打内部面":URL 指向 127.0.0.1 内部管理口、10/172.16/192.168 内网主机、
    或 169.254.169.254 云元数据端点(窃取实例凭据)——域名白名单按字符串匹配,管不到这层。
    对 URL 里**字面 IP**(含进制混淆 / 缺段 / IPv4-mapped IPv6,见 `_host_ip`)及 localhost 等
    公认本机名做确定性判定;不做 DNS 解析,域名→私网的重绑定(DNS rebinding)交由出口白名单兜。
    `not is_global` 一并覆盖私网/回环/链路本地/保留/未指定地址(含阿里云 100.64/10、云元数据
    169.254.169.254),跨 Python 版本稳定。
    """
    host = url_host(arguments)
    if host is None:
        return False
    if host in _INTERNAL_HOSTNAMES:
        return True
    ip = _host_ip(host)
    if ip is None:
        return False  # 普通域名:不做解析,不在此判定(交由白名单/其它规则)
    return not ip.is_global
