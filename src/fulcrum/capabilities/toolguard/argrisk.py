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
# 承载外联目的地的参数键 —— 全模块**单一真源**:沙箱协议白名单、域名白名单、内网/元数据判定、
# 链分析都据此,避免"改键名塞地址"绕过(SSRF 不只走 http.request:webhook.send / external.post /
# notify / forward 各用不同键)。分两类形态:
#   • URL 形态键 `_DEST_URL_KEYS`:值就是 URL,即便省略 scheme(webhook=`evil.com/x`)也按 URL 判。
#   • 地址形态键 `_DEST_ADDR_KEYS`:值可能是邮箱(to=`a@corp.com`)或 URL(to=`https://evil.com`)。
#     **仅当带显式 `://` 时**才当外联目的地——否则邮箱会被 urlparse 误解析成主机而误报。
_DEST_URL_KEYS = (
    "url",
    "endpoint",
    "webhook",
    "webhook_url",
    "callback",
    "callback_url",
    "uri",
    "target",
    "target_url",
    "dest",
    "destination",
    "redirect_url",
)
_DEST_ADDR_KEYS = (
    "to",
    "recipient",
    "forward_to",
    "redirect",
    "cc",
    "bcc",
    "address",
    "addr",
    "location",
    "link",
)
# 协议白名单等"扫全部目的地键"的判定复用此并集(单一真源,供沙箱执行器导入)。
DEST_KEYS = _DEST_URL_KEYS + _DEST_ADDR_KEYS


def _dest_raw(arguments: dict) -> str:
    """按优先级取外联目的地原始串:URL 形态键取值即可;地址形态键仅当带显式 `://` 时才算
    (否则把邮箱 to=`a@corp.com` 误当外联主机)。无则空串。"""
    for k in _DEST_URL_KEYS:
        if arguments.get(k):
            return str(arguments[k])
    for k in _DEST_ADDR_KEYS:
        v = arguments.get(k)
        if v and "://" in str(v):
            return str(v)
    return ""


# 标准点分四段 IPv4 字面量(每段 1-3 位数字)。裸值只有长这样才当地目的地候选——
# `2130706433`/`0x7f000001` 等进制混淆形态**必须**由目的地键或 `://` 引入,否则嵌套参数
# 里的普通数字(count/size/port)会被误当外联目标。
_STANDARD_IPV4_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAX_DEST_DEPTH = 6

# 无 `://` 主机段、但仍是 LFI/SSRF 面的"不透明"协议(`file:/etc/passwd`、`jar:a!/b`、`dict:…`)。
# 单一真源:候选围栏与沙箱执行器的协议白名单共用此表(协议判定以"含 `://`"为主信号,
# 再叠加本表兜住无双斜杠的危险协议;`localhost:6379`/`12:30`/`user@host`/`C:/x` 的伪 scheme
# 均不在表内,不会被误当协议)。
RISKY_OPAQUE_SCHEMES: frozenset[str] = frozenset(
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
_OPAQUE_SCHEME_RX = re.compile(r"^(" + "|".join(RISKY_OPAQUE_SCHEMES) + r"):", re.IGNORECASE)


def _iter_string_leaves(value: object, key: str | None = None, depth: int = 0):
    """递归产出参数树中的 (键名, 字符串叶子);list 继承父键名(endpoint=["a","b"])。"""
    if depth > _MAX_DEST_DEPTH:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _iter_string_leaves(v, str(k).lower(), depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_string_leaves(v, key, depth + 1)
    elif isinstance(value, str):
        yield key, value


def _is_dest_leaf(key: str | None, s: str) -> bool:
    """字符串叶子是否构成外联目的地候选(四重围栏,防裸扫误报)。

    ① 含 `://` 的权威 URL——客观外联形态,与所处键无关;
    ② 键名属 URL 形态键(任意深度)——沿 `_dest_raw` 键语义,省 scheme 的 endpoint/webhook 也算;
       地址形态键嵌套时仍须 `://`(防 `to=` 邮箱被 urlparse 误析出主机);
    ③ 以危险不透明协议前缀开头(`file:`/`jar:`/`dict:`… 无 `://` 也是真实 URL 语法)——
       与键无关、与深度无关,协议白名单必须看得见它(回归:`forward_to="jar:nested!/a"` 曾被
       ②的收紧漏掉);
    ④ 无键语义的裸值仅当是**标准点分四段 IPv4**(见 `_STANDARD_IPV4_RX`)——版本号
       `2.31.0`(三段)与普通数字不入候选,守住良性参数的 FP 面。
    """
    if not s or len(s) > 2048:
        return False
    if "://" in s:
        return True
    if _OPAQUE_SCHEME_RX.match(s):
        return True
    if key in _DEST_URL_KEYS:
        return True
    if key in _DEST_ADDR_KEYS:
        return False
    return bool(_STANDARD_IPV4_RX.match(s.strip()))


def dest_candidates(arguments: dict) -> list[str]:
    """收集参数树(含嵌套 dict/list)中全部外联目的地候选串,顶层 `_dest_raw` 优先、去重保序。

    对抗实测(2026-09-04):URL 藏进二层 dict(`{"config":{"endpoint":"http://198.51.100.9/x"}}`)
    可全链穿透外联白名单——目的地判定必须作用于**参数树全部叶子**中被围栏筛出的候选,
    而非仅顶层几个键(攻击者不挑键的位置放值)。
    """
    cands: list[str] = []
    raw = _dest_raw(arguments)
    if raw:
        cands.append(raw)
    for key, val in _iter_string_leaves(arguments):
        if val == raw:
            continue
        if _is_dest_leaf(key, val):
            cands.append(val)
    return list(dict.fromkeys(cands))


def url_hosts(arguments: dict) -> list[str]:
    """从全部目的地候选取主机名集合(去重保序);空列表=无外联目的地。"""
    hosts: list[str] = []
    for c in dest_candidates(arguments):
        host = urlparse(c if "://" in c else f"//{c}").hostname
        if host:
            hosts.append(host.lower())
    return list(dict.fromkeys(hosts))


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
    # 非盘符冒号 fail-closed(对抗实测 2026-09-04):`note.txt:hidden` 这类 NTFS 交替流不越出
    # 工作区,但构成**隐蔽信道**——外泄数据写进流,表面文件内容不变,审计/人工检查全盲。
    # 受控文件边界不接受未定义语义的路径成分:除 Windows 盘符(`C:/x`)与 UNC 双斜杠外,
    # 含冒号(交替流 / `data:` URI / path 里塞 URL)一律视为越界拒绝。Linux 相对路径无冒号不受影响。
    if ":" in norm and not re.match(r"^[A-Za-z]:/", norm):
        return True
    # 只认**路径段**恰为 `..` 的上级穿越,不把含 `..` 子串的合法文件名(如 `..hidden`、
    # `my..notes.txt`)误判为越界。
    if ".." in norm.split("/"):
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
    """从外联目的地参数(见 `_dest_raw` 的键优先级/形态规则)取主机名;无则 None。

    `url` 优先以保持 http.request 既有行为不变;其后的 webhook/endpoint 及带 scheme 的
    to/forward_to 等键让非 http.request 的对外工具(webhook.send / notify / forward …)
    也进入 SSRF / 白名单判定的视野。
    """
    url = _dest_raw(arguments)
    if not url:
        return None
    host = urlparse(url if "://" in url else f"//{url}").hostname
    return host.lower() if host else None


def domain_allowed(arguments: dict, allow_domains: list[str]) -> bool:
    """无外联目的地 → 不涉及白名单,返回 True;有 → **全部**目的地主机都在白名单(含子域)才放行。

    多目的地(顶层 + 嵌套候选,见 `url_hosts`)任一不在白名单即 False——任放一个都是外泄通道。
    """
    hosts = url_hosts(arguments)
    if not hosts:
        return True
    return all(
        any(host == d.lower() or host.endswith("." + d.lower()) for d in allow_domains)
        for host in hosts
    )


def dest_is_url(arguments: dict) -> bool:
    """目的地参数是否为 **URL 形态**(有 scheme,或主机含点 / 是 IP 字面量 / 是公认内网名)。

    给 tool-agnostic 的外联白名单规则加形态围栏:把 `target`/`dest` 当**非 URL** 字段用的工具
    (如 `{"target": "section3"}`)主机会被 urlparse 解成裸词 `section3`,而 `domain_allowed`
    对裸词恒 False——若直接据此做 tool-agnostic 拦截会误伤。要求目的地像个真 URL(scheme 或
    带点域名 / IP / 内网名)才参与判定,守住「非 URL 字段不被误判为外联」的下界。
    `url_is_internal` 只对 IP 字面量为真,天然无此问题,故仅外联白名单规则需要本围栏。
    """
    raw = _dest_raw(arguments)
    if not raw:
        return False
    if "://" in raw:
        return True
    host = url_host(arguments)
    if host is None:
        return False
    return "." in host or host in _INTERNAL_HOSTNAMES or _host_ip(host) is not None


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
    for host in url_hosts(arguments):
        if host in _INTERNAL_HOSTNAMES:
            return True
        ip = _host_ip(host)
        if ip is not None and not ip.is_global:
            return True  # 普通域名不解析(交白名单);字面 IP 落非公网段即 SSRF 面
    return False
