"""嵌入式载荷扫描 —— 堵 DDIPE(文档驱动隐式载荷执行)缺口。

`manifest_scanner` 只扫固定字段(description / instructions / permissions / endpoints…),
攻击者把危险载荷藏进**任意字段**(documentation / examples / readme / setup_template /
x_custom…)里的**代码块或配置模板**就能绕过:装载/复制粘贴这些"用法示例"即隐式执行。

本模块对 manifest **任意深度**的字符串叶子与嵌套结构做**面通用化**抽取,只在真正的"块"
(围栏代码块 / 结构化配置)上跑既有成熟检测器,与具体载荷字符串解耦(换字段/换库/换变量/
换措辞都不失效)。三层设计:

  L1 面通用化(零签名):递归收字符串叶子 + stringify 嵌套子树;从中抽"块"——围栏代码块、
     裸结构化配置。**自由散文绝不成块**(无围栏且非结构化配置的说明文字一律不抽)→ 0 FP。
  L2 复用既有检测器,但口径按**文档面**收紧:危险命令走嵌入面专用判据 `_embedded_rce`
     (裸 `curl`/`wget`/`sudo`/`base64 -d`/`powershell` 是 README 常见良性用法示例,**不**单独
     判危;只认「下载即执行链」与无条件 RCE 原语,见该函数);decode_variants+复扫(编码载荷);
     KeywordRuleDetector 仅取 critical 注入/越狱类散文做"可疑文本"(命令/外泄类交由 `_embedded_rce`
     与 L3 行为类精判,避免把"调用某 API 的用法示例"误判)。
  L3 行为类共现:读敏感 ∧ 网络出口 ∧ 错误抑制 三者同块共现 = 静默外泄(皇冠信号);
     另有单要素高确定性类:包源重定向 / 持久化 / 提权逃逸。

所有命中走**独立** `embedded.*` finding kinds(绝不合并回原字段扫描,避免横向拉宽原检测器
作用域致顶层良性字段 FP),并带 `evidence['severity']`,经 manifest_scanner 既有映射汇总评级
(critical→BLOCK, high→APPROVE)。本模块只**调用**既有检测器/argrisk,绝不修改其判定口径。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...core.domain import Context, Finding, SourceSpan, SourceType, TrustLevel
from ...core.normalize import decode_variants
from ..detectors.keyword_rules import KeywordRuleDetector
from ..toolguard import argrisk

# 严重度 → 分值(与 manifest_scanner 的映射对齐:critical→BLOCK, high→APPROVE)。
_SEV_SCORE = {"critical": 0.9, "high": 0.7}

# 复用既有多源规则检测器(@capability 类,直接实例化);启动时建一次。
_DETECTOR = KeywordRuleDetector()
# KeywordRuleDetector 危险类:
#  - 解码后复扫(编码载荷)用全集——刻意编码本身即恶意意图,藏的命令/外泄都算数;
#  - 明文块的"可疑文本"只取注入/越狱类散文:命令类(`curl https://…`)与外泄类(`curl … -d`)
#    是工具用法示例里最常见的良性形态,在文档面用 KeywordRuleDetector 判它们会横向 FP,
#    改由 `_embedded_rce`(真危险命令)与 L3 行为类(silent_exfil)精判。
_DANGER_KINDS = frozenset({"injection", "jailbreak", "exfiltration", "command_exec"})
_PROSE_INJECT_KINDS = frozenset({"injection", "jailbreak"})

# ── L1:块抽取 ──────────────────────────────────────────────────────────────
# 围栏代码块 ```lang\n...\n```(去围栏与 lang 标签,取正文)。
_FENCE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
# ini section 头 [global] / [tool.x] 之类。
_INI_HEADER = re.compile(r"^[ \t]*\[[A-Za-z][\w.\- ]*\][ \t]*$", re.MULTILINE)
# 强配置行:`key = value` / `key: value`,值为**单 token**(无内部空格、占满整行)。
# 单 token 约束把自由散文(`Note: do this thing` 这类多词值)挡在外面,只认真正的配置赋值。
_CONFIG_LINE = re.compile(r"^[ \t]*([A-Za-z_][\w.\-]*)[ \t]*[:=][ \t]*(\S+)[ \t]*$", re.MULTILINE)

# ── L2:嵌入面「危险命令」判据 —— 比 argrisk.command_dangerous 收紧 ──────────────────
# argrisk.command_dangerous 是为**真实工具调用参数**校准的(那里拦裸 `curl`/`wget` 送人工可
# 接受);用到**文档散文代码块**上就过宽了:README 里 `curl https://api…`、`wget …csv`、
# `sudo apt install`、裸 `powershell`/`base64 -d` 都是最常见的良性「用法示例」。嵌入面只认两类:
#   ① 无条件 RCE 原语(任何上下文都危险):管道喂 shell、反弹/交互 shell、内联解释器执行、
#      毁灭性磁盘命令、IEX/Invoke-Expression、`${IFS}` 规避、fork bomb、argv 注入(GTFOBins)。
#   ② 「下载即执行链」:取/解码 verb(curl/wget/base64 -d/certutil/bitsadmin/iwr)**与执行落点
#      同块共现** —— `curl …| sh`、`base64 -d …| sh`(已被①的管道覆盖),或多步 `curl …&& ./x`。
# 裸 fetch / 裸 sudo / 裸 powershell **单独出现不判危**(→ 0 FP)。
_RCE_UNCONDITIONAL = re.compile(
    r"("
    # 毁灭性磁盘 / 删除 / 关机
    r"rm\s+-rf|\bmkfs\b|dd\s+if=|\bwipefs\b|del\s+/[a-z]|rmdir\s+/s|format\s+[a-z]:|"
    # 管道把(下载/解码)内容直接喂 shell(下载即执行的核心信号)
    r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\|\s*powershell|\|\s*cmd\b|"
    # 反弹 / 交互 shell + 内联解释器执行
    r"\bnc\b\s+-e|/dev/tcp/|/bin/sh\b|bash\s+-[ic]\b|\bsh\s+-i\b|\bmkfifo\b|\bsocat\b|"
    r"python\d?\s+-c|perl\s+-e|php\s+-r|ruby\s+-e|"
    # 内联 eval / 无文件执行 LOLBin
    r"invoke-expression|\biex\b|\bmshta\b|\bregsvr32\b|\brundll32\b|"
    # 空格规避 / fork bomb
    r"\$\{?IFS\b|:\(\)\s*\{)",
    re.IGNORECASE,
)
# 取/解码 verb(单独出现是良性用法示例,需与执行落点共现才判危)。
_FETCH_DECODE = re.compile(
    r"\b(?:curl|wget)\b|certutil\s+.*-(?:urlcache|decode)|\bbitsadmin\b|invoke-webrequest|\biwr\b|"
    r"base64\s+-d|downloadstring|downloadfile",
    re.IGNORECASE,
)
# 执行落点:取/解码到的内容随后被执行(多步下载执行链)。要求是 shell/解释器或运行本地文件,
# **不**把 `| jq`/`| grep` 这类良性管道当落点(故只匹配 `;`/`&&`/`||` 后接 sh/python/./ 或 IEX)。
_RUN_SINK = re.compile(
    r"(?:;|&&|\|\|)\s*(?:sudo\s+)?(?:ba|z)?sh\b|"  # ; sh   && bash
    r"(?:;|&&|\|\|)\s*(?:sudo\s+)?(?:\./|/|~/)|"  # && /tmp/x.sh   ; ./x   ~/x
    r"(?:;|&&|\|\|)\s*(?:sudo\s+)?python\d?\b|"
    r"(?:;|&&|\|\|)\s*powershell\b|"
    r"\biex\b|invoke-expression",
    re.IGNORECASE,
)


def _embedded_rce(text: str) -> bool:
    """嵌入式代码块是否含**真危险命令**(下载即执行 / 无条件 RCE),裸 fetch/sudo/powershell 不算。"""
    if _RCE_UNCONDITIONAL.search(text):
        return True
    # argv 注入(`tar --checkpoint-action=`、`find -exec`、`ssh -o ProxyCommand=` …)无条件危险。
    if argrisk.command_arg_injection({"command": text}):
        return True
    # 下载即执行链:取/解码 verb 与执行落点同块共现。
    return bool(_FETCH_DECODE.search(text) and _RUN_SINK.search(text))


# ── L3:行为类同义指示符(多语言/多工具,与具体载荷字符串解耦)──────────────────
# 读敏感(环境变量型);文件型走 argrisk.path_sensitive。
_ENV_READ = re.compile(
    r"os\.environ|getenv|process\.env|\bENV\[|\$env:|dict\(os\.environ",
    re.IGNORECASE,
)
# 网络出口(多同义词:Python/JS/Go/Shell/PowerShell)。
_NET_EGRESS = re.compile(
    r"requests\.\w+\s*\(|urllib|urlopen|httpx|\bfetch\s*\(|axios|socket\.|http\.client|"
    r"net\.Dial|Invoke-WebRequest|\bcurl\b|\bwget\b",
    re.IGNORECASE,
)
# 错误抑制(吞异常 / 静默)。带 logging/raise 的正常 try/except 不算(其 except 后非 pass)。
_ERROR_SUPPRESS = re.compile(
    r"except[^\n:]*:\s*(?:\n\s*)?pass\b|catch\s*\([^)]*\)\s*\{\s*\}|2>\s*/dev/null|"
    r"-ErrorAction\s+SilentlyContinue|\|\|\s*true\b",
    re.IGNORECASE,
)
# 提权逃逸(容器特权 / docker.sock / 危险 capability / 敏感宿主挂载)。
# hostPath 仅当挂到**根 `/` 或敏感目录**(/etc /root /proc /sys /var/run /var/lib/docker)才算
# 逃逸——良性日志挂载(path: /var/log/app)不报,避免企业 manifest FP。
_PRIV_ESCAPE = re.compile(
    r"privileged\s*[:=]\s*(?:true|yes|on|1)\b|docker\.sock|CAP_SYS_ADMIN|--privileged|"
    r"hostPath[\s\S]{0,80}?path:\s*['\"]?/(?:\s|$|['\"]|etc\b|root\b|proc\b|sys\b|var/run\b|"
    r"var/lib/docker\b)",
    re.IGNORECASE,
)
# 持久化原语(要有写/追加/启用动作,避免纯提及散文 FP)。
_PERSISTENCE = re.compile(
    r">>\s*\S*(?:authorized_keys|\.bashrc|\.zshrc|\.profile|\.bash_profile)|crontab\s+-|"
    r"systemctl\s+enable|reg\s+add\s+[^\n]*\\Run|launchctl\s+load|LaunchAgents|LaunchDaemons",
    re.IGNORECASE,
)

# 包源重定向:这些键的值若是 URL 且 host 非官方源 → 重定向到投毒仓库。
# 仅保留语义无歧义的真正「包索引」键——source/repository/index/channel 是常见良性字段名
# (源码引用 / 仓库主页 / conda 频道),纳入会对企业 manifest 误报。
_REDIRECT_KEYS = frozenset({"extra-index-url", "index-url", "registry"})
# 官方源白名单(host 等于或为其子域才放行)。
_OFFICIAL_HOSTS = (
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "npmjs.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "crates.io",
    "rubygems.org",
    "registry.yarnpkg.com",
    "goproxy.io",
    "proxy.golang.org",
)


def _scalar(value: object) -> str:
    """标量渲染:bool → 小写 true/false(让 `privileged: True` 这类配置能被规则匹到)。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _stringify(node: object, indent: int = 0) -> str:
    """把嵌套 dict/list 子树渲染成 `key: value` 多行文本,使"配置即嵌套结构"也能被下游扫到。"""
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(_stringify(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(node, list):
        for v in node:
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}-")
                lines.append(_stringify(v, indent + 1))
            else:
                lines.append(f"{pad}- {_scalar(v)}")
    else:
        lines.append(f"{pad}{_scalar(node)}")
    return "\n".join(lines)


def _blocks_from_string(text: str) -> list[str]:
    """从一个字符串叶子抽"块":围栏代码块 +(无围栏时)裸结构化配置。

    **自由散文返回 []**:没有围栏、也不是结构化配置(无 ini 头、强配置行 < 2)的普通说明
    文字一律不成块 → 不进 L2/L3 → 不产 finding。这是 0 FP 红线(良性 README/裸命令)。
    """
    blocks: list[str] = []
    for m in _FENCE.finditer(text):
        body = m.group(1).strip()
        if body:
            blocks.append(body)
    # 去掉围栏区域后,在剩余文本上找裸结构化配置(只取强配置行 + ini 头,不含周围散文)。
    rest = _FENCE.sub("\n", text)
    config_lines = [m.group(0).strip() for m in _CONFIG_LINE.finditer(rest)]
    headers = [m.group(0).strip() for m in _INI_HEADER.finditer(rest)]
    # 判据严格:有 ini 头,或 ≥2 条强配置行,才认定为结构化配置(单条疑似散文 → 不成块)。
    if headers or len(config_lines) >= 2:
        bare = "\n".join(headers + config_lines).strip()
        if bare:
            blocks.append(bare)
    return blocks


def _collect_blocks(manifest: dict) -> list[str]:
    """递归遍历 manifest 任意深度,收集所有"块"(去重)。

    - 字符串叶子 → 从中抽围栏/裸配置块;
    - 嵌套(非根)dict/list 子树 → stringify 成块(根 manifest 本身不整体 stringify,避免把
      顶层良性字段拼成巨块横向拉宽扫描面)。
    """
    blocks: list[str] = []
    seen: set[str] = set()

    def add(block: str) -> None:
        b = block.strip()
        if b and b not in seen:
            seen.add(b)
            blocks.append(b)

    def walk(node: object, is_root: bool) -> None:
        if isinstance(node, dict):
            if not is_root:
                add(_stringify(node))
            for v in node.values():
                walk(v, False)
        elif isinstance(node, list):
            if not is_root:
                add(_stringify(node))
            for v in node:
                walk(v, False)
        elif isinstance(node, str):
            for b in _blocks_from_string(node):
                add(b)

    walk(manifest, True)
    return blocks


def _kw_critical_danger(text: str, ctx: Context, kinds: frozenset[str] = _DANGER_KINDS) -> bool:
    """用既有 KeywordRuleDetector 扫文本:仅当返回 critical 且 kind ∈ `kinds` 才算命中。

    不因 medium/low 或 sensitive_file 单提及就报(否则良性 `pip install requests` /
    `requests.get(公开接口)` 会 FP)。明文"可疑文本"传 `_PROSE_INJECT_KINDS`(仅注入/越狱),
    解码后复扫传默认全集。
    """
    span = SourceSpan(
        source_type=SourceType.PLUGIN_MANIFEST,
        trust_level=TrustLevel.UNTRUSTED,
        content_hash="x",
        excerpt=text,
    )
    for f in _DETECTOR.detect([span], ctx):
        if str(f.evidence.get("severity")) == "critical" and f.kind in kinds:
            return True
    return False


def _is_official_host(host: str) -> bool:
    return any(host == w or host.endswith("." + w) for w in _OFFICIAL_HOSTS)


def _redirect_host(value: str) -> str | None:
    """从配置值取 host(仅当其形似 URL:有 host 且含点)。`stable` / `main` 等非 URL → None。"""
    host = urlparse(value if "://" in value else "//" + value).hostname
    return host.lower() if host and "." in host else None


def _source_redirect(block: str) -> bool:
    """块内有包源键(extra-index-url/registry/index/source…)指向非官方源 host → True。"""
    for m in _CONFIG_LINE.finditer(block):
        if m.group(1).lower() in _REDIRECT_KEYS:
            host = _redirect_host(m.group(2))
            if host is not None and not _is_official_host(host):
                return True
    return False


def _read_sensitive(block: str) -> bool:
    """读敏感:文件型(.ssh/id_rsa、.aws、.env、凭据…)∪ 环境变量型(os.environ/getenv…)。"""
    return argrisk.path_sensitive({"path": block}) or bool(_ENV_READ.search(block))


def _detect_block(block: str, ctx: Context) -> list[tuple[str, str]]:
    """对单个块跑 L2 + L3,返回 (kind, severity) 列表(本块内去重)。"""
    hits: list[tuple[str, str]] = []

    def mark(kind: str, severity: str) -> None:
        if (kind, severity) not in hits:
            hits.append((kind, severity))

    # L2:危险命令(嵌入面专用判据:裸 fetch/sudo/powershell 不算,需下载即执行 / 无条件 RCE)
    if _embedded_rce(block):
        mark("embedded.dangerous_code", "critical")
    # L2:编码载荷 —— 只看**真解出来的**变体(刻意编码即恶意意图)。decode_variants 含恒等变体
    # (原文本身),跳过它:对明文再跑全类关键词等于重做 suspicious_text,会把"裸 curl 用法示例"
    # 当编码载荷误报(明文已由收窄后的 suspicious_text 走注入/越狱类精判)。
    norm_block = block.strip()
    for decoded in decode_variants(block):
        if decoded.strip() == norm_block:
            continue
        if _embedded_rce(decoded) or _kw_critical_danger(decoded, ctx):
            mark("embedded.encoded_payload", "critical")
            break
    # L2:可疑文本(仅 critical 注入/越狱散文;命令/外泄类交由 _embedded_rce 与 L3 精判)
    if _kw_critical_danger(block, ctx, _PROSE_INJECT_KINDS):
        mark("embedded.suspicious_text", "critical")

    # L3:高确定性单要素行为类
    if _source_redirect(block):
        mark("embedded.source_redirect", "critical")
    if _PRIV_ESCAPE.search(block):
        mark("embedded.privilege_escape", "critical")
    if _PERSISTENCE.search(block):
        mark("embedded.persistence", "high")
    # L3:皇冠信号「静默外泄」= 读敏感 ∧ 网络出口 ∧ 错误抑制 三者同块共现
    if _read_sensitive(block) and _NET_EGRESS.search(block) and _ERROR_SUPPRESS.search(block):
        mark("embedded.silent_exfil", "critical")
    return hits


def scan_embedded(manifest: dict, ctx: Context) -> list[Finding]:
    """扫描 manifest 任意字段里嵌入的危险载荷,返回独立 `embedded.*` findings(全局去重)。"""
    if not isinstance(manifest, dict):
        return []
    findings: list[Finding] = []
    emitted: set[tuple[str, str]] = set()  # (kind, block) 去重,避免多处重复 finding
    for block in _collect_blocks(manifest):
        for kind, severity in _detect_block(block, ctx):
            key = (kind, block)
            if key in emitted:
                continue
            emitted.add(key)
            findings.append(
                Finding(
                    kind=kind,
                    score=_SEV_SCORE[severity],
                    evidence={
                        "severity": severity,
                        "detail": f"嵌入式载荷({kind}):{block[:80]}",
                        "excerpt": block[:200],
                    },
                )
            )
    return findings
